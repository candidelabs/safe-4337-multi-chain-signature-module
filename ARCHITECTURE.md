# Architecture

## Overview

`Safe4337MultiChainSignatureModule` is an ERC-4337 module for Safe smart accounts that adds multi-chain signature support. It serves as both a **module** (executes transactions) and a **fallback handler** (receives `validateUserOp` calls).

## Call Flow

```
                                   +-----------------+
                                   |    Bundler      |
                                   +--------+--------+
                                            |
                                            | handleOps()
                                            v
                                   +-----------------+
                                   |   EntryPoint    |
                                   |   (v0.9.0)      |
                                   +--------+--------+
                                            |
                          +-----------------+-----------------+
                          |                                   |
                  validateUserOp()                   executeUserOp()
                  (fallback handler)                 (module tx)
                          |                                   |
                          v                                   v
                   +------+------+                   +--------+--------+
                   |  Safe Proxy |                   |   Safe Proxy    |
                   |  (delegatecall                  |  execTransaction|
                   |   to module)|                   |  FromModule()   |
                   +------+------+                   +-----------------+
                          |
                          v
              +-----------+-----------+
              | Safe4337MultiChain    |
              | SignatureModule       |
              |                       |
              |  _validateSignatures()|
              +-----------+-----------+
                          |
              +-----------+-----------+
              |                       |
         depth == 0             depth > 0
         (single-chain)         (multi-chain)
              |                       |
              v                       v
     EIP-712 SafeOp          EIP-712 MerkleRoot
     hash + checkSig         hash + checkSig +
                              merkle proof verify
```

## Signature Modes

### Single-Chain (merkleTreeDepth == 0)

Standard ERC-4337 signature validation:

1. Encode `SafeOp` struct from `PackedUserOperation` fields
2. Compute EIP-712 hash: `domainSeparator(chainId, moduleAddress) + SafeOp struct hash`
3. Call `Safe.checkSignatures()` to verify owner signatures

The signature is encoded as:
```
abi.encodePacked(
    uint8(0),           // merkleTreeDepth = 0
    uint48 validAfter,
    uint48 validUntil,
    bytes  signatures   // Safe owner signatures
)
```

### Multi-Chain (merkleTreeDepth > 0)

Enables signing a batch of operations across multiple chains with a single signature:

1. Each chain's `SafeOp` is hashed as a **leaf** (using chain-bound domain separator)
2. Leaves are assembled into a **merkle tree**
3. The **merkle root** is signed via a chain-agnostic domain separator (no `chainId`)
4. On each chain, the module verifies:
   - The owner signature over the merkle root
   - The merkle proof from the chain's SafeOp leaf to the root

The signature is encoded as:
```
abi.encodePacked(
    uint8  merkleTreeDepth,   // 1-10
    uint48 validAfter,
    uint48 validUntil,
    bytes32 merkleRoot,       // proof[0]
    bytes32[] merkleProof,    // proof[1..depth]
    bytes  signatures         // Safe owner signatures
)
```

Maximum depth is 10 (1024 leaves), enforced to prevent gas griefing.

## EIP-712 Domain Separation

Two distinct domain separators are used:

| Domain | Fields | Purpose |
|---|---|---|
| `SafeOp` domain | `chainId`, `verifyingContract` | Chain-bound — ties each operation to a specific chain |
| `MerkleTreeRoot` domain | `verifyingContract` | Chain-agnostic — shared across all chains for multi-chain signing |

This separation ensures a single-chain SafeOp signature cannot be replayed as a multi-chain signature and vice versa.

## Paymaster Signature Stripping

When a paymaster appends its own signature to `paymasterAndData`, it must be excluded from the `SafeOp` hash (otherwise the user would need to know the paymaster signature at signing time).

Detection mechanism:
1. Check if `paymasterAndData` ends with magic bytes `0x22e325a297439656` (`keccak("PaymasterSignature")[:8]`)
2. If present, read the preceding 2 bytes as `pmSignatureLength`
3. Hash only `paymasterAndData[0 : len - pmSignatureLength - 10]`, appending the magic bytes

The magic byte suffix layout:
```
paymasterAndData = [paymaster(20) | paymasterData | pmSignature(var) | pmSigLen(2) | magic(8)]
```

## Trust Assumptions

1. **EntryPoint is trusted**: The module relies on EntryPoint for replay protection (nonces), gas accounting, and correct prefund calculation.

2. **Safe owner signatures are authoritative**: Signature verification is delegated to `Safe.checkSignatures()`, which supports EOA, EIP-1271 contract signatures, and approved hashes.

3. **Signing client verifies merkle leaves** (critical for multi-chain): The module verifies a merkle *proof* but does not validate other leaves. A user signing a merkle root **must** verify ALL leaves before signing. A malicious tree constructor could otherwise include unauthorized operations on other chains.

4. **Module is bound to a single EntryPoint**: Set at construction, immutable. If the EntryPoint needs upgrading, a new module must be deployed.

## Key Invariants

- Only `executeUserOp` and `executeUserOpWithErrorString` selectors are allowed in `userOp.callData`
- The caller of `validateUserOp` must match `userOp.sender` (prevents cross-Safe validation)
- All `userOp` fields except `signature` are represented in the `SafeOp` hash
- Signature length is bounded by `_checkSignaturesLength` to limit gas griefing by malicious bundlers
- Merkle tree depth is capped at 10 (`MAX_MERKLE_DEPTH`)
