/**
 * Package entry point.
 *
 * Deliberately empty. What a profile mounts from this bundle is the `tools` subpath
 * (`@twinsearth/nau-dsh-plugin/tools`), named explicitly by the `insert` in `cordis.patch.yml`,
 * so that reading the profile tells a reader which of this package's modules becomes a plugin
 * rather than leaving it to a convention about the root export.
 *
 * The file exists because `package.json` names it as `main` and as `exports['.']`, and a manifest
 * pointing at a file that is not there fails at load with a resolution error instead of a message
 * about what the package is for.
 */

export {};
