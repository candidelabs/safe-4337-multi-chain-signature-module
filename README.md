# Safe 4337 Multi-Chain Signature Module

The Safe4337MultiChainSignatureModule extends Safe4337Module to support a multi chain signature. By using a merkle tree, multiple useroperations across different chains can be signed once and validated independently on each chain.

## ⚠️ Disclaimer

**This contract has not been audited and is a work in progress. Do not use in production.**

## References

- [Safe Modules](https://github.com/safe-fndn/safe-modules)
- [ERC-4337: Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)