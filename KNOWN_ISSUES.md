# Known Issues

This document lists known issues and accepted risks in the `Safe4337MultiChainSignatureModule`. These items have been reviewed and are intentionally accepted. They are documented here to save auditor time.

## K-01: Contract Signature Length Manipulation

**Severity**: Low (accepted)

**Description**: The `_checkSignaturesLength` function sets a strict upper bound on signature data length to prevent gas griefing by malicious bundlers. However, for Smart Contract signatures (type 0), the dynamic part is encoded as `{32-bytes signature length}{bytes signature data}`. A malicious bundler can manipulate the signature length field and pad additional bytes to the dynamic part, causing `_checkSignaturesLength` to return `true` for padded signatures.

**Rationale**: This is an inherent limitation of the Safe signature encoding. The responsibility for checking additional bytes in Smart Contract signatures lies with the Safe signature validator implementation (the account owner). The gas overhead from this edge case is bounded by the `verificationGasLimit`.

**Reference**: See `_checkSignaturesLength` NatSpec in the source contract.

## K-02: Multi-Chain Merkle Leaf Verification Depends on Signing Client

**Severity**: Medium (accepted, by design)

**Description**: When using multi-chain signatures (merkleTreeDepth > 0), the module verifies a merkle proof from the current chain's SafeOp leaf to the signed root. However, it does **not** validate other leaves in the tree. If a malicious party constructs a merkle tree containing unauthorized operations on other chains, and a user signs the root without verifying all leaves, those operations would be valid.

**Rationale**: On-chain verification of all leaves would require cross-chain communication and is not feasible. The security model explicitly delegates leaf verification to the signing client. This is documented in the contract's NatSpec and is a fundamental trust assumption of the multi-chain design.

**Mitigation**: Signing clients MUST verify ALL leaves in the merkle tree before the root is signed.

## K-03: Paymaster Magic Byte False Positive

**Severity**: Informational (accepted)

**Description**: The paymaster signature detection relies on matching the last 8 bytes of `paymasterAndData` against the magic value `0x22e325a297439656` (`keccak("PaymasterSignature")[:8]`). If a paymaster's data naturally ends with these bytes (without intending a signature suffix), the module would incorrectly strip a portion of the data before hashing.

**Rationale**: The probability of a false positive is approximately 1/2^64 (~5.4 x 10^-20), which is negligible. The magic value is derived from a domain-specific hash to minimize collision likelihood.

## K-04: Assembly Functions Use Scratch Space / Free Memory Without Bumping Pointer

**Severity**: Informational (accepted)

**Description**: The `_efficientHash`, `calldataKeccak`, and `calldataKeccakWithSuffix` functions use memory starting at the free memory pointer (or scratch space) without incrementing it. This means the memory they write to may be overwritten by subsequent Solidity memory allocations.

**Rationale**: This is an intentional gas optimization. These functions compute a hash and return the result immediately — the temporary memory is not needed after the `keccak256` call. The functions are marked `memory-safe` because they follow the Solidity convention of restoring memory semantics (the free memory pointer is not moved, so Solidity treats the memory as unused).

## K-05: `validAfter > validUntil` Not Validated

**Severity**: Informational (accepted)

**Description**: The module does not check whether `validAfter > validUntil` (which would make the operation never valid). This validation is delegated to the EntryPoint.

**Rationale**: The EntryPoint already validates these timestamps when processing the packed validation data. Adding a redundant check in the module would increase gas costs without security benefit.
