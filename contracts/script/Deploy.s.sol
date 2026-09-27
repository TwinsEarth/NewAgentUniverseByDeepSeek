// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";

import {GovernanceToken} from "../src/GovernanceToken.sol";
import {AgentCardAnchor} from "../src/AgentCardAnchor.sol";
import {Settlement} from "../src/Settlement.sol";
import {ReputationRegistry} from "../src/ReputationRegistry.sol";

/// @title Deploy — deploy the whole contract set from a JSON config
///
/// Upstream shipped no deploy script at all, which is part of why three of its
/// four contracts were not deployable: nothing had ever tried.
///
/// ## Usage
///
/// ```sh
/// cp contracts/deploy.config.example.json contracts/deploy.config.json   # then edit
/// forge script script/Deploy.s.sol:Deploy \
///   --rpc-url "$RPC_URL" --broadcast --verify
/// ```
///
/// Env vars honoured:
///   * `DEPLOY_CONFIG` — path to the JSON config (relative paths resolve
///     against the Foundry project root, i.e. `contracts/`).
///
/// ## Always reads `VERSION`
///
/// `contracts/VERSION` is a copy of the repository-root `VERSION` (see
/// `contracts/README.md` and the `contracts` job in `.github/workflows/ci.yml`).
/// The script reads it and refuses to run if it disagrees with the `version`
/// field in the deploy config, so a release cannot silently ship contracts
/// labelled with a different version than the Rust binaries. The version is
/// emitted in a log line *and* returned from `run()`, which makes it:
///   * assertable from a test with `vm.expectRevert` / direct return;
///   * greppable from CI without a Solidity compiler having run.
contract Deploy is Script {
    struct Config {
        string version;
        address owner;
        address governanceHolder;
        uint256 governanceSupply;
        uint256 maxAnchorsPerAgent;
        uint32 maxSettlementVerifiers;
        uint32 settlementQuorum;
        uint256 requiredStake;
        uint32 maxReputationVerifiers;
        address[] settlementVerifiers;
        address[] reputationVerifiers;
    }

    /// @notice Config path used when `DEPLOY_CONFIG` is unset.
    string internal constant DEFAULT_CONFIG = "deploy.config.json";

    /// @notice Deployed addresses, returned so a test or script can assert on them.
    struct Deployment {
        string version;
        address governanceToken;
        address agentCardAnchor;
        address settlement;
        address reputationRegistry;
    }

    /// @notice Emitted with the version that was actually deployed, so the
    ///         release can be reconstructed from the broadcast transcript alone.
    event VersionDeployed(string version);

    error ConfigNotFound(string path);
    error VersionMismatch(string fromVersionFile, string fromConfig);
    error EmptyVersionFile(string path);
    error InvalidConfig(string field);

    /// @notice Read `contracts/VERSION` and return it, trimmed.
    function deployedVersion() public view returns (string memory) {
        return _readAndTrim("VERSION");
    }

    function run() external returns (Deployment memory deployment) {
        string memory configPath = vm.envOr("DEPLOY_CONFIG", DEFAULT_CONFIG);
        if (!vm.exists(configPath)) revert ConfigNotFound(configPath);

        string memory json = vm.readFile(configPath);
        Config memory config = _parse(json);

        // VERSION is the single source of truth; the config must agree with it.
        string memory version = deployedVersion();
        if (bytes(version).length == 0) revert EmptyVersionFile("VERSION");
        if (keccak256(bytes(version)) != keccak256(bytes(config.version))) {
            revert VersionMismatch(version, config.version);
        }

        if (config.owner == address(0)) revert InvalidConfig("owner");
        if (config.governanceHolder == address(0)) revert InvalidConfig("governanceHolder");
        if (config.governanceSupply == 0) revert InvalidConfig("governanceSupply");
        if (config.maxAnchorsPerAgent == 0) revert InvalidConfig("maxAnchorsPerAgent");

        // Signing is supplied by the caller (`forge script --private-key`,
        // `--ledger`, ...), never by this script: a script that reads a raw key
        // out of an environment variable is a key-handling hazard with no
        // benefit over letting forge do it.
        vm.startBroadcast();

        GovernanceToken token =
            new GovernanceToken(config.owner, config.governanceHolder, config.governanceSupply);

        AgentCardAnchor anchors = new AgentCardAnchor(config.maxAnchorsPerAgent);

        Settlement settlement = new Settlement(
            config.owner,
            config.settlementVerifiers,
            config.settlementQuorum,
            config.maxSettlementVerifiers,
            config.requiredStake
        );

        ReputationRegistry reputation = new ReputationRegistry(
            config.owner, config.reputationVerifiers, config.maxReputationVerifiers
        );

        vm.stopBroadcast();

        deployment = Deployment({
            version: version,
            governanceToken: address(token),
            agentCardAnchor: address(anchors),
            settlement: address(settlement),
            reputationRegistry: address(reputation)
        });

        // Logged so the version that was actually deployed is recoverable from
        // the broadcast transcript alone.
        emit VersionDeployed(version);
    }

    // --------------------------------------------------------------- internals

    function _parse(string memory json) private view returns (Config memory config) {
        config.version = vm.parseJsonString(json, ".version");
        config.owner = vm.parseJsonAddress(json, ".owner");
        config.governanceHolder = vm.parseJsonAddress(json, ".governanceHolder");
        config.governanceSupply = vm.parseJsonUint(json, ".governanceSupply");
        config.maxAnchorsPerAgent = vm.parseJsonUint(json, ".maxAnchorsPerAgent");
        config.maxSettlementVerifiers = uint32(vm.parseJsonUint(json, ".maxSettlementVerifiers"));
        config.settlementQuorum = uint32(vm.parseJsonUint(json, ".settlementQuorum"));
        config.requiredStake = vm.parseJsonUint(json, ".requiredStake");
        config.maxReputationVerifiers = uint32(vm.parseJsonUint(json, ".maxReputationVerifiers"));
        config.settlementVerifiers = vm.parseJsonAddressArray(json, ".settlementVerifiers");
        config.reputationVerifiers = vm.parseJsonAddressArray(json, ".reputationVerifiers");
    }

    /// @dev Reads a file from the Foundry project root and trims ASCII
    ///      whitespace. `VERSION` is a one-line plain-text file, so this is the
    ///      cheapest way to read a non-JSON fixture with cheatcodes.
    function _readAndTrim(string memory relativePath) private view returns (string memory) {
        string memory path = string.concat(vm.projectRoot(), "/", relativePath);
        if (!vm.exists(path)) revert ConfigNotFound(path);
        bytes memory raw = bytes(vm.readFile(path));
        uint256 start = 0;
        uint256 end = raw.length;
        while (start < end && _isWhitespace(raw[start])) {
            ++start;
        }
        while (end > start && _isWhitespace(raw[end - 1])) {
            --end;
        }
        bytes memory trimmed = new bytes(end - start);
        for (uint256 i = start; i < end; ++i) {
            trimmed[i - start] = raw[i];
        }
        return string(trimmed);
    }

    function _isWhitespace(bytes1 c) private pure returns (bool) {
        return c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d;
    }
}
