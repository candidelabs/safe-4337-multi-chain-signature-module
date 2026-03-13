# Audit Scope

## Contracts in Scope

| Contract | Path | Lines |
|---|---|---|
| `Safe4337MultiChainSignatureModule` | `contracts/Safe4337MultiChainSignatureModule.sol` | 562 |
| `ISafe` (interface) | `contracts/Safe.sol` | 66 |
| **Total** | | **628** |

## Compiler Settings

- **Solidity version**: `0.8.28` (pinned)
- **EVM target**: default (Shanghai)
- **Optimizer**: enabled, 1,000,000 runs
- **Framework**: Foundry

Configured in [`foundry.toml`](./foundry.toml).

## Dependencies

| Package | Version | Source |
|---|---|---|
| `@account-abstraction` | `v0.9.0` | [eth-infinitism/account-abstraction](https://github.com/eth-infinitism/account-abstraction) (git, pinned) |
| `@safe-global/safe-contracts` | `^1.4.1-build.0` | npm |
| `forge-std` | `v1.9.4` | [foundry-rs/forge-std](https://github.com/foundry-rs/forge-std) (git, pinned) |

## Out of Scope

- Test files (`contracts/test/`)
- Dependencies (`node_modules/`)
- Safe core contracts (`@safe-global/safe-contracts`)
- EntryPoint contracts (`@account-abstraction`)
- Build artifacts (`out/`, `artifacts/`, `cache/`)

## Build & Test

```bash
# Prerequisites
# - Foundry (https://book.getfoundry.sh/getting-started/installation)
# - Node.js >= 18
# - Yarn

# Install dependencies
yarn install

# Build
forge build

# Run tests (188 tests across 9 suites)
forge test -vvv

# Coverage (see note below)
forge coverage --ir-minimum
```

## Test Coverage

- **Test suites**: 9
- **Tests**: 188 (all passing)
- **Test-to-source ratio**: ~11:1

> **Note**: `forge coverage` requires the `--ir-minimum` flag due to a known Foundry limitation with coverage instrumentation on the `EntryPoint` dependency contract (stack-too-deep). This is a tooling issue, not a code issue — all 188 tests pass with the optimizer enabled.

## Related Documentation

- [ARCHITECTURE.md](./ARCHITECTURE.md) — System design and trust model
- [KNOWN_ISSUES.md](./KNOWN_ISSUES.md) — Acknowledged findings
