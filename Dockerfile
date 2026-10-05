# syntax=docker/dockerfile:1
#
# NewAgentUniverseByDeepSeek — the node, in a container.
#
# # WHAT THIS IMAGE IS, AND WHAT IT IS NOT
#
# It runs `nau-daemon`: the HTTP API, the ledger, the plugin host and its 26 T0 plugins. That is the
# whole of what this repository is at runtime, and it needs no database, no cache and no middleware —
# state is a directory, and the store is a file.
#
# It is NOT a sandbox host with the kernel's enforcement mechanisms. This is the honest part, and it
# is the same discipline the code already applies on every platform it cannot fully serve:
#
#   * `AppArmor` and `eBPF` enforcement need privileges a default container does not have. The code
#     already reports that as `EnforcementSupport::Refused { reason }` rather than degrading
#     silently (`crates/nau-sandbox/src/enforcement.rs`, and the `defence-in-depth` gate), so the
#     container is consistent with the rest of the system rather than an exception to it.
#   * `--privileged` would change that, and this Dockerfile deliberately does not ask for it. A
#     deployment that needs kernel enforcement should run on the host, or grant the specific
#     capabilities and accept that it is now trusting the image with them.
#
# The `defence-in-depth` gate is what keeps this paragraph honest: it refuses a claim of enforcement
# that the platform does not provide.
#
# # BUILD
#
#   docker build -t nau:3.9.8 .
#   docker build -t nau:3.9.8 --build-arg CARGO_BUILD_JOBS=2 .     # a small machine
#
# The workspace is large and the Rust build is the slow part. There is NO dependency-layer caching
# here; the note above the build step explains why that is stated rather than assumed.

# ---------------------------------------------------------------- builder
FROM rust:1.85-bookworm AS builder

# `CARGO_BUILD_JOBS` is a build-time knob the repository already documents for constrained
# machines: a parallel build of this workspace can exhaust memory, and it does so SILENTLY, which is
# why `.env.example` and `docs/DEPLOYMENT.md` both name it.
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}

# `--locked` so the image is built from `Cargo.lock` rather than from whatever resolves today.
# Without it, two builds of the same commit can differ, and a release is supposed to be reproducible.
#
# # About layer caching, stated accurately because an earlier draft of this file overstated it
#
# That draft said "the dependency layer is cached separately from the source layer". It is NOT. This
# Dockerfile copies all of `crates/` before the build, so **any** change to any `.rs` file invalidates
# the layer and the dependencies rebuild too — a cold build of this 18-crate workspace every time.
#
# The comment was wrong in the way this repository keeps finding: a claim about a property the file
# does not have. It is corrected rather than deleted, because the reason it is not implemented is
# worth recording: a correct dependency-only layer needs a stage that copies the manifests, builds a
# dummy target, then copies the real sources — and a *slightly wrong* version of that trick produces
# a stale build that compiles and is not the code in the repository. For a node that holds a ledger,
# a wrong build is worse than a slow one.
#
# If the build time matters, `cargo-chef` does it correctly and is a deliberate dependency to add.
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY conformance ./conformance
COPY contracts ./contracts
COPY scripts ./scripts
# Three binaries, because v3.9.9's composed topologies need all three:
#   `nau`             the CLI, so a container can be debugged without the host's toolchain
#   `nau-daemon`      the single node
#   `nau-p2p-daemon`  the node WITH a libp2p swarm, which `docker-compose.yml`'s `p2p` profile runs
#
# Building one image with both daemons rather than two images is deliberate: they share every
# dependency, and two images would double the build for a difference of one binary that the entry
# point already selects.
RUN cargo build --release --locked --bin nau --bin nau-daemon --bin nau-p2p-daemon \
    && strip target/release/nau target/release/nau-daemon target/release/nau-p2p-daemon

# ---------------------------------------------------------------- runtime
FROM debian:bookworm-slim AS runtime

# `ca-certificates` because the node makes outbound TLS connections; `curl` because a HEALTHCHECK
# that does not reach the API is not a health check; `tini` so that PID 1 forwards signals and reaps
# orphans, which matters because the daemon stops its plugins on shutdown and a container that sends
# SIGTERM to a shell wrapper never reaches that code.
RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/*

# A NON-ROOT user, and a fixed uid so that a bind-mounted data directory can be chowned to it.
# Running the node as root would make every path-escape defect in a plugin a host compromise rather
# than a container one.
RUN groupadd --gid 10001 nau \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin nau

COPY --from=builder /build/target/release/nau /usr/local/bin/nau
COPY --from=builder /build/target/release/nau-daemon /usr/local/bin/nau-daemon
COPY --from=builder /build/target/release/nau-p2p-daemon /usr/local/bin/nau-p2p-daemon
# The verification suite travels with the image, so that a deployment can re-run the 59 deployment
# checks and the 24 gates against the binary it is actually running rather than the one it built.
COPY --from=builder /build/scripts /opt/nau/scripts
COPY --from=builder /build/conformance /opt/nau/conformance

# The state directory, owned by the user that will write to it. A volume is mounted here.
RUN install -d -o nau -g nau -m 0750 /var/lib/nau
VOLUME ["/var/lib/nau"]

# `0.0.0.0` and NOT `127.0.0.1`: a container that binds loopback is unreachable from outside itself,
# and that failure looks like a broken port mapping rather than a bind address.
#
# * * * AND IT REQUIRES `NAU_API_HOSTS` * * *
#
# Once the bind is not loopback, the request's Host header is not `127.0.0.1` either, and the
# built-in policy refuses it. `docker-compose.yml` sets it; a bare `docker run` must pass it too, or
# the node will answer connections and refuse requests. This is the single most likely way to
# mis-deploy this image, which is why it is written out here rather than left in the documentation.
ENV NAU_API_HOSTS=localhost,127.0.0.1,nau \
    RUST_LOG=info

EXPOSE 4002
# The libp2p swarm port, for `nau-p2p-daemon`. Declared here rather than only in compose so that a
# reader of this file can see the node has two ports and not one.
EXPOSE 4001

# A REAL health check: it asks the API the question the API answers.
#
# The first version of this line ran `nau-daemon --help`, which prints usage and exits 0 whatever the
# node is doing -- so it would have reported healthy for a daemon that had crashed its listeners, and
# a container orchestrator would have kept routing to it. A health check that cannot fail is not one.
#
# `/health` is a real route: `nau-daemon`'s own help lists `GET /health /version /stats ...`.
#
# `--start-period` is generous because the daemon boots 26 plugins, each with its own lifecycle.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:4002/health > /dev/null || exit 1

# NOTE: the data directory is a FLAG, not an environment variable. There is no `NAU_DATA_DIR`, and
# listing one here would be inventing a variable that nothing reads -- the same defect this audit
# found and corrected in an earlier draft of `.env.example`. The `CMD` below passes `--data-dir`.
USER nau
WORKDIR /var/lib/nau
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/nau-daemon"]
CMD ["--api-addr", "0.0.0.0:4002", "--data-dir", "/var/lib/nau"]
