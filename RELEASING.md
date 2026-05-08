# Releasing eth-historian

The release workflow at `.github/workflows/release.yml` publishes to four registries on tag push:

| Registry | Package | Source |
|---|---|---|
| crates.io | `eth-historian` | `Cargo.toml` |
| npm | `@willow-network/eth-historian` | `bindings/ts/package.json` |
| PyPI | `eth-historian` | `bindings/python/pyproject.toml` |
| GitHub Releases (Go) | per-platform `libeth_historian.a` tarballs | `bindings/go/` |

## One-time setup

Add these GitHub repo secrets (Settings → Secrets and variables → Actions):

* `CARGO_REGISTRY_TOKEN` — from <https://crates.io/me>, "API Tokens"
* `NPM_TOKEN` — npm "Automation" token with publish access to the `@willow-network` org
* `PYPI_API_TOKEN` — PyPI scoped token for the `eth-historian` project

`GITHUB_TOKEN` is provided automatically.

## Cutting a release

1. **Bump versions in lockstep** across:
   * `Cargo.toml` (Rust core)
   * `bindings/ts/package.json` (TypeScript)
   * `bindings/python/pyproject.toml` and `bindings/python/Cargo.toml` (Python)
   * The Go binding inherits the version from the git tag — no file change needed.

   The release workflow checks each manifest's version equals the tag's version (without the `v` prefix) and fails fast if they drift. Keep them aligned.

2. **Push the version-bump commit** to `main` and confirm CI is green.

3. **Tag the release** locally:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
   This triggers `.github/workflows/release.yml`. Each registry job is independent; if one fails (e.g. PyPI tokens expired), the other three still publish and the failed step can be re-run.

4. **Verify** at:
   * <https://crates.io/crates/eth-historian>
   * <https://www.npmjs.com/package/@willow-network/eth-historian>
   * <https://pypi.org/project/eth-historian/>
   * <https://github.com/willow-network/eth-historian/releases>

## Go consumers

Go modules are versioned by git tags directly — once `v0.1.0` is pushed, `go get github.com/willow-network/eth-historian/bindings/go@v0.1.0` works.

The release workflow additionally publishes pre-built static libs as GitHub release assets, so Go consumers don't need a local Rust toolchain to build the cgo dep:

* `libeth_historian-darwin-arm64.tar.gz`
* `libeth_historian-linux-amd64.tar.gz`
* `libeth_historian-windows-amd64.tar.gz`

Each tarball contains `libeth_historian.a` + `eth_historian.h`. Drop them into `bindings/go/target/release/` (or wherever cgo `LDFLAGS -L` is pointing) and the Go module compiles without cargo.
