# Safe 4337 Multi-Chain Signature Module

The `Safe4337MultiChainSignatureModule` extends the [Safe4337Module](https://github.com/safe-fndn/safe-modules/tree/main/modules/4337) to support multi-chain signatures. It targets EntryPoint v0.9 with the new paymaster signature scheme, where the paymaster signature is stripped from `paymasterAndData` before hashing so that users can sign operations without knowing the paymaster signature in advance. By using a merkle tree, multiple user operations across different chains can be signed once and validated independently on each chain.

> **Status**: This contract is pending a professional security audit. Do not use in production until the audit is complete.

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- [Node.js](https://nodejs.org/) >= 20
- [Yarn](https://yarnpkg.com/)

## Installation

```bash
git clone https://github.com/<org>/safe-4337-multi-chain-signature-module.git
cd safe-4337-multi-chain-signature-module
yarn install
```

## Build

```bash
forge build
```

## Test

```bash
forge test -vvv
```

## Coverage

```bash
forge coverage
```

## Documentation

- [AUDIT_SCOPE.md](./AUDIT_SCOPE.md) — Contracts in scope, compiler settings, dependencies
- [ARCHITECTURE.md](./ARCHITECTURE.md) — System design, signature modes, trust model
- [KNOWN_ISSUES.md](./KNOWN_ISSUES.md) — Acknowledged findings and accepted risks

## References

- [Safe Modules](https://github.com/safe-fndn/safe-modules)
- [ERC-4337: Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)
