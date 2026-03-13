// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {HandlerContext} from "@safe-global/safe-contracts/contracts/handler/HandlerContext.sol";
import {CompatibilityFallbackHandler} from "@safe-global/safe-contracts/contracts/handler/CompatibilityFallbackHandler.sol";
import {IAccount} from "@account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {_packValidationData} from "@account-abstraction/contracts/core/Helpers.sol";
import {UserOperationLib} from "@account-abstraction/contracts/core/UserOperationLib.sol";
import {ISafe} from "./Safe.sol";

/**
 * @title Safe4337MultiChainSignatureModule - An extension to the Safe contract that implements the ERC4337 interface.
 * @dev The contract is both a module and fallback handler.
 *      Safe forwards the `validateUserOp` call to this contract, it validates the user operation and returns the result.
 *      It also executes a module transaction to pay the prefund. Similar flow for the actual operation execution.
 *      Security considerations:
 *      - The module is limited to the entry point address specified in the constructor.
 *      - The user operation hash is signed by the Safe owner(s) and validated by the module.
 *      - The user operation is not allowed to execute any other function than `executeUserOp` and `executeUserOpWithErrorString`.
 *      - Replay protection is handled by the entry point.
 *      - Multi-chain signatures: When using merkle tree signatures (merkleTreeDepth > 0), the user signs a single
 *        merkle root covering SafeOps across multiple chains. The signing client MUST verify ALL leaves in the
 *        merkle tree before the root is signed. Failure to do so allows a malicious tree constructor to include
 *        unauthorized operations on other chains.
 */
contract Safe4337MultiChainSignatureModule is IAccount, HandlerContext, CompatibilityFallbackHandler {
    using UserOperationLib for PackedUserOperation;

    /**
     * @notice The EIP-712 type-hash for the domain separator used for verifying Safe operation signatures.
     * @dev keccak256("EIP712Domain(uint256 chainId,address verifyingContract)") = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218
     */
    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    /**
     * @notice The EIP-712 type-hash for a SafeOp, representing the structure of a User Operation for the Safe.
     *  {address} safe - The address of the safe on which the operation is performed.
     *  {uint256} nonce - A unique number associated with the user operation, preventing replay attacks by ensuring each operation is unique.
     *  {bytes} initCode - The packed encoding of a factory address and its factory-specific data for creating a new Safe account.
     *  {bytes} callData - The bytes representing the data of the function call to be executed.
     *  {uint128} verificationGasLimit - The maximum amount of gas allowed for the verification process.
     *  {uint128} callGasLimit - The maximum amount of gas allowed for executing the function call.
     *  {uint256} preVerificationGas - The amount of gas allocated for pre-verification steps before executing the main operation.
     *  {uint128} maxPriorityFeePerGas - The maximum priority fee per gas that the user is willing to pay for the transaction.
     *  {uint128} maxFeePerGas - The maximum fee per gas that the user is willing to pay for the transaction.
     *  {bytes} paymasterAndData - The packed encoding of a paymaster address and its paymaster-specific data for sponsoring the user operation.
     *  {uint48} validAfter - A timestamp representing from when the user operation is valid.
     *  {uint48} validUntil - A timestamp representing until when the user operation is valid, or 0 to indicated "forever".
     *  {address} entryPoint - The address of the entry point that will execute the user operation.
     * @dev When validating the user operation, the signature timestamps are pre-pended to the signature bytes. Equal to:
     * keccak256(
     *     "SafeOp(address safe,uint256 nonce,bytes initCode,bytes callData,uint128 verificationGasLimit,uint128 callGasLimit,uint256 preVerificationGas,uint128 maxPriorityFeePerGas,uint128 maxFeePerGas,bytes paymasterAndData,uint48 validAfter,uint48 validUntil,address entryPoint)"
     * ) = 0xc03dfc11d8b10bf9cf703d558958c8c42777f785d998c62060d85a4f0ef6ea7f
     */
    bytes32 private constant SAFE_OP_TYPEHASH = 0xc03dfc11d8b10bf9cf703d558958c8c42777f785d998c62060d85a4f0ef6ea7f;

    /**
     * @dev A structure used internally for manually encoding a Safe operation for when computing the EIP-712 struct hash.
     */
    struct EncodedSafeOpStruct {
        bytes32 typeHash;
        address safe;
        uint256 nonce;
        bytes32 initCodeHash;
        bytes32 callDataHash;
        uint128 verificationGasLimit;
        uint128 callGasLimit;
        uint256 preVerificationGas;
        uint128 maxPriorityFeePerGas;
        uint128 maxFeePerGas;
        bytes32 paymasterAndDataHash;
        uint48 validAfter;
        uint48 validUntil;
        address entryPoint;
    }

    /**
     * @notice The EIP-712 type-hash for the domain separator used for verifying multi chain merkle root signatures.
     * @dev keccak256("EIP712Domain(address verifyingContract)") = 0x035aff83d86937d35b32e04f0ddc6ff469290eef2f1b692d8a815c89404d4749
     */
    bytes32 private constant MERKLE_TREE_ROOT_DOMAIN_SEPARATOR_TYPEHASH = 0x035aff83d86937d35b32e04f0ddc6ff469290eef2f1b692d8a815c89404d4749;

    /**
     * @notice The EIP-712 type-hash for multi chain merkle tree root.
     * keccak256("MerkleTreeRoot(bytes32 merkleTreeRoot)") = 0x63c29879ec9239fe654591f460bc775cd5294088db68113b8065faa722cb0d24
     */
    bytes32 private constant MERKLE_TREE_ROOT_TYPEHASH = 0x63c29879ec9239fe654591f460bc775cd5294088db68113b8065faa722cb0d24;

    struct EncodedMerkleTreeRootStruct {
        bytes32 typeHash;
        bytes32 MerkleTreeRoot;
    }

    /**
     * @notice An error indicating that the entry point used when deploying a new module instance is invalid.
     */
    error InvalidEntryPoint();

    /**
     * @notice An error indicating that the caller does not match the Safe in the corresponding user operation.
     * @dev This indicates that the module is being used to validate a user operation for a Safe that did not directly
     * call this module.
     */
    error InvalidCaller();

    /**
     * @notice An error indicating that the call validating or executing a user operation was not called by the
     * supported entry point contract.
     */
    error UnsupportedEntryPoint();

    /**
     * @notice An error indicating that the user operation `callData` does not correspond to one of the two supported
     * execution functions: `executeUserOp` or `executeUserOpWithErrorString`.
     */
    error UnsupportedExecutionFunction(bytes4 selector);

    /**
     * @notice An error indicating that the user operation failed to execute successfully.
     * @dev The contract reverts with this error when `executeUserOp` is used instead of bubbling up the original revert
     * data. When bubbling up revert data is desirable, `executeUserOpWithErrorString` should be used instead.
     */
    error ExecutionFailed();

    error InvalidPaymasterSignatureLength(uint256 dataLength, uint256 pmSignatureLength);

    /**
     * @notice An error indicating that the merkle tree depth exceeds the maximum allowed depth.
     */
    error MerkleDepthTooLarge(uint256 depth);

    /**
     * @notice An error indicating that the merkle proof length is invalid for the specified depth.
     */
    error InvalidMerkleProofLength(uint256 expectedLength, uint256 actualLength);

    /**
     * @notice The address of the EntryPoint contract supported by this module.
     */
    address public immutable SUPPORTED_ENTRYPOINT;

    /**
     * @notice Maximum allowed merkle tree depth to prevent gas griefing attacks.
     * @dev A depth of 10 allows for 2^10 (1024) operations in a single merkle tree,
     * which is more than sufficient for any reasonable multi-chain batch while preventing
     * excessive gas consumption during verification.
     */
    uint256 public constant MAX_MERKLE_DEPTH = 10;

    uint256 public constant PAYMASTER_DATA_OFFSET = 52;
    uint256 constant internal PAYMASTER_SIG_MAGIC_LEN = 8;
    uint256 constant internal PAYMASTER_SUFFIX_LEN = PAYMASTER_SIG_MAGIC_LEN + 2; // suffix length (signature length + magic)
    bytes8 constant internal  PAYMASTER_SIG_MAGIC = 0x22e325a297439656; // keccak("PaymasterSignature")[:8]
    uint256 constant internal MIN_PAYMASTER_DATA_WITH_SUFFIX_LEN = PAYMASTER_DATA_OFFSET + PAYMASTER_SUFFIX_LEN; // minimum length of paymasterData that can contain a paymaster signature.


    constructor(address entryPoint) {
        if (entryPoint == address(0)) {
            revert InvalidEntryPoint();
        }

        SUPPORTED_ENTRYPOINT = entryPoint;
    }

    /**
     * @notice Validates the call is initiated by the entry point.
     */
    modifier onlySupportedEntryPoint() {
        if (_msgSender() != SUPPORTED_ENTRYPOINT) {
            revert UnsupportedEntryPoint();
        }
        _;
    }

    /**
     * @notice Validates a user operation provided by the entry point.
     * @inheritdoc IAccount
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32,
        uint256 missingAccountFunds
    ) external onlySupportedEntryPoint returns (uint256 validationData) {
        address payable safeAddress = payable(userOp.sender);
        // The entry point address is appended to the calldata by the Safe in the `FallbackManager` contract,
        // following ERC-2771. Because of this, the relayer may manipulate the entry point address, therefore
        // we have to verify that the sender is the Safe specified in the userOperation.
        if (safeAddress != msg.sender) {
            revert InvalidCaller();
        }

        // We check the execution function signature to make sure the entry point can't call any other function
        // and make sure the execution of the user operation is handled by the module
        bytes4 selector = bytes4(userOp.callData);
        if (selector != this.executeUserOp.selector && selector != this.executeUserOpWithErrorString.selector) {
            revert UnsupportedExecutionFunction(selector);
        }

        // The userOp nonce is validated in the entry point (for 0.6.0+), therefore we will not check it again
        validationData = _validateSignatures(userOp);

        // We trust the entry point to set the correct prefund value, based on the operation params
        // We need to perform this even if the signature is not valid, else the simulation function of the entry point will not work.
        if (missingAccountFunds != 0) {
            // We intentionally ignore errors in paying the missing account funds, as the entry point is responsible for
            // verifying the prefund has been paid. This behaviour matches the reference base account implementation.
            ISafe(safeAddress).execTransactionFromModule(SUPPORTED_ENTRYPOINT, missingAccountFunds, "", 0);
        }
    }

    /**
     * @notice Executes a user operation provided by the entry point.
     * @param to Destination address of the user operation.
     * @param value Ether value of the user operation.
     * @param data Data payload of the user operation.
     * @param operation Operation type of the user operation.
     */
    function executeUserOp(address to, uint256 value, bytes memory data, uint8 operation) external onlySupportedEntryPoint {
        if (!ISafe(msg.sender).execTransactionFromModule(to, value, data, operation)) {
            revert ExecutionFailed();
        }
    }

    /**
     * @notice Executes a user operation provided by the entry point and returns error message on failure.
     * @param to Destination address of the user operation.
     * @param value Ether value of the user operation.
     * @param data Data payload of the user operation.
     * @param operation Operation type of the user operation.
     */
    function executeUserOpWithErrorString(address to, uint256 value, bytes memory data, uint8 operation) external onlySupportedEntryPoint {
        (bool success, bytes memory returnData) = ISafe(msg.sender).execTransactionFromModuleReturnData(to, value, data, operation);
        if (!success) {
            // solhint-disable-next-line no-inline-assembly
            assembly ("memory-safe") {
                revert(add(returnData, 0x20), mload(returnData))
            }
        }
    }

    /**
     * @notice Computes the 32-byte domain separator used in used in EIP-712 multi chain merkle root signature verification.
     * @return domainSeparatorHashMultiChain The EIP-712 domain separator hash for this contract.
     */
    function domainSeparatorMultiChain() public view returns (bytes32 domainSeparatorHashMultiChain) {
        domainSeparatorHashMultiChain = keccak256(abi.encode(MERKLE_TREE_ROOT_DOMAIN_SEPARATOR_TYPEHASH, this));
    }

    /**
     * @notice Computes the 32-byte domain separator used in EIP-712 signature verification for Safe operations.
     * @return domainSeparatorHash The EIP-712 domain separator hash for this contract.
     */
    function domainSeparator() public view returns (bytes32 domainSeparatorHash) {
        domainSeparatorHash = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, this));
    }

    /**
     * @notice Returns the 32-byte Safe operation hash to be signed by owners for the specified ERC-4337 user operation.
     * @dev The Safe operation timestamps are pre-pended to the signature bytes as `abi.encodePacked(validAfter, validUntil, signatures)`.
     * @param userOp The ERC-4337 user operation.
     * @return operationHash Operation hash.
     */
    function getOperationHash(PackedUserOperation calldata userOp) external view returns (bytes32 operationHash) {
        (bytes memory operationData, , , , ,) = _getSafeOp(userOp);
        operationHash = keccak256(operationData);
    }

    /**
     * @notice Checks if the signatures length is correct and does not contain additional bytes. The function does not
     * check the integrity of the signature encoding, as this is expected to be checked by the {Safe} implementation
     * of {checkSignatures}.
     * @dev Safe account has two types of signatures: EOA and Smart Contract signatures. While the EOA signature is
     * fixed in size, the Smart Contract signature can be of arbitrary length. If appropriate length checks are not
     * performed during the signature verification then a malicious bundler can pad additional bytes to the signatures
     * data and make the account pay more gas than needed for user operation validation and reach the
     * `verificationGasLimit`. _checkSignaturesLength ensures that the signatures data cannot be longer than the
     * canonical encoding of Safe signatures, thus setting a strict upper bound on how long the signatures bytes can
     * be, greatly limiting a malicious bundler's ability to pad signature bytes. However, there is an edge case that
     * `_checkSignaturesLength` function cannot detect.
     * Signatures data for Smart Contracts contains a dynamic part that is encoded as:
     *     {32-bytes signature length}{bytes signature data}
     * A malicious bundler can manipulate the field(s) storing the signature length and pad additional bytes to the
     * dynamic part of the signatures which will make `_checkSignaturesLength` to return true.  In such cases, it is
     * the responsibility of the Safe signature validator implementation, as an account owner, to check for additional
     * bytes.
     * @param signatures Signatures data.
     * @param threshold Signer threshold for the Safe account.
     * @return isValid True if length check passes, false otherwise.
     */
    function _checkSignaturesLength(bytes calldata signatures, uint256 threshold) internal pure returns (bool isValid) {
        uint256 maxLength = threshold * 0x41;

        // Make sure that `signatures` bytes are at least as long as the static part of the signatures for the specified
        // threshold (i.e. we have at least 65 bytes per signer). This avoids out-of-bound access reverts when decoding
        // the signature in order to adhere to the ERC-4337 specification.
        if (signatures.length < maxLength) {
            return false;
        }

        for (uint256 i = 0; i < threshold; i++) {
            // Each signature is 0x41 (65) bytes long, where fixed part of a Safe contract signature is encoded as:
            //      {32-bytes signature verifier}{32-bytes dynamic data position}{1-byte signature type}
            // and the dynamic part is encoded as:
            //      {32-bytes signature length}{bytes signature data}
            //
            // For each signature we check whether or not the signature is a contract signature (signature type of 0).
            // If it is, we need to read the length of the contract signature bytes from the signature data, and add it
            // to the maximum signatures length.
            //
            // In order to keep the implementation simpler, and unlike in the length check above, we intentionally
            // revert here on out-of-bound bytes array access as well as arithmetic overflow, as you would have to
            // **intentionally** build invalid `signatures` data to trigger these conditions. Furthermore, there are no
            // security issues associated with reverting in these cases, just not optimally following the ERC-4337
            // standard (specifically: "SHOULD return `SIG_VALIDATION_FAILED` (and not revert) on signature mismatch").

            uint256 signaturePos = i * 0x41;
            uint8 signatureType = uint8(signatures[signaturePos + 0x40]);

            if (signatureType == 0) {
                uint256 signatureOffset = uint256(bytes32(signatures[signaturePos + 0x20:]));
                uint256 signatureLength = uint256(bytes32(signatures[signatureOffset:]));
                maxLength += 0x20 + signatureLength;
            }
        }

        isValid = signatures.length <= maxLength;
    }

    /**
     * @dev Validates that the user operation is correctly signed and returns an ERC-4337 packed validation data
     * of `validAfter || validUntil || authorizer`:
     *  - `authorizer`: 20-byte address, 0 for valid signature or 1 to mark signature failure (this module does not make use of signature aggregators).
     *  - `validUntil`: 6-byte timestamp value, or zero for "infinite". The user operation is valid only up to this time.
     *  - `validAfter`: 6-byte timestamp. The user operation is valid only after this time.
     * @param userOp User operation struct.
     * @return validationData An integer indicating the result of the validation.
     */
    function _validateSignatures(PackedUserOperation calldata userOp) internal view returns (uint256 validationData) {
        (bytes memory operationData, bytes calldata proof, uint8 merkleTreeDepth, uint48 validAfter, uint48 validUntil, bytes calldata signatures) = _getSafeOp(userOp);
        // The `checkSignatures` function in the Safe contract does not force a fixed size on signature length.
        // A malicious bundler can pad the Safe operation `signatures` with additional bytes, causing the account to pay
        // more gas than needed for user operation validation (capped by `verificationGasLimit`).
        // `_checkSignaturesLength` ensures that there are no additional bytes in the `signature` than are required.
        bool validSignature = _checkSignaturesLength(signatures, ISafe(payable(userOp.sender)).getThreshold());

        if(merkleTreeDepth == 0){ // single userOp signature
            try ISafe(payable(userOp.sender)).checkSignatures(keccak256(operationData), operationData, signatures) {} catch {
                validSignature = false;
            }
        }else { // muti chain userOp signature
            bytes32 merkleTreeRootStruct;
            EncodedMerkleTreeRootStruct memory encodedMerkleTreeRootStruct = EncodedMerkleTreeRootStruct({
                typeHash: MERKLE_TREE_ROOT_TYPEHASH,
                MerkleTreeRoot: bytes32(proof[0:0x20])
            });
            
            // solhint-disable-next-line no-inline-assembly
            assembly ("memory-safe") {
                // Since the `encodedMerkleTreeRootStruct` value's memory layout is identical to the result of `abi.encode`-ing the
                // individual `MerkleTreeRoot` fields, we can pass it directly to `keccak256`. Additionally, there are 2
                // 32-byte fields to hash, for a length of `2 * 32 = 64` bytes.
                merkleTreeRootStruct := keccak256(encodedMerkleTreeRootStruct, 64)
            }

            bytes memory merkleRootHashData = 
                abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparatorMultiChain(), merkleTreeRootStruct);

            try ISafe(payable(userOp.sender)).checkSignatures(keccak256(merkleRootHashData), merkleRootHashData, signatures) {
                bytes32 computedHash = keccak256(operationData);
                // Verify merkle proof by computing hash from leaf to root
                for (uint256 i = merkleTreeDepth; i > 0; i--) {
                    uint256 offset = i * 0x20;
                    computedHash = _hashPair(computedHash, bytes32(proof[offset:offset+0x20]));
                }
                if(computedHash != bytes32(proof[0:0x20])){ //computedHash != MerkleTreeRoot
                    validSignature = false;
                }
            } catch {
                validSignature = false;
            }
        }

        // The timestamps are validated by the entry point, therefore we will not check them again.
        validationData = _packValidationData(!validSignature, validUntil, validAfter);
    }

    /**
     * @notice Sorts two bytes32 values and hashes them, ensuring a canonical ordering for merkle tree nodes.
     * @param a First hash.
     * @param b Second hash.
     * @return The hash of the sorted pair.
     */
    function _hashPair(bytes32 a, bytes32 b) private pure returns(bytes32) {
        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);
    }

    /**
     * @notice Computes keccak256 of two bytes32 values using scratch space for gas efficiency.
     * @dev Writes to memory at 0x00 without bumping the free memory pointer, since the result is consumed immediately.
     * @param a First 32-byte value.
     * @param b Second 32-byte value.
     * @return value The keccak256 hash of `abi.encodePacked(a, b)`.
     */
    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }

    function _getSafeOp(
        PackedUserOperation calldata userOp
    ) internal view returns (bytes memory operationData, bytes calldata proof, uint8 merkleTreeDepth, uint48 validAfter, uint48 validUntil, bytes calldata signatures) {
        // Extract additional Safe operation fields from the user operation signature which is encoded as:
        // `abi.encodePacked(merkleTreeDepth, validAfter, validUntil, proof, signatures)`
        {
            bytes calldata sig = userOp.signature;
            merkleTreeDepth = uint8(bytes1(sig[:1]));

            // Validate merkle tree depth to prevent gas griefing attacks
            if (merkleTreeDepth > MAX_MERKLE_DEPTH) {
                revert MerkleDepthTooLarge(merkleTreeDepth);
            }

            validAfter = uint48(bytes6(sig[1:7]));
            validUntil = uint48(bytes6(sig[7:13]));
            uint256 proofEnd = 0;
            if(merkleTreeDepth == 0){
                proofEnd = 13;
                proof = sig[0:1]; // point anywhere to make the compiler happy
            }else{
                uint256 expectedProofLength = (uint256(merkleTreeDepth) + 1) * 0x20;
                proofEnd = 13 + expectedProofLength;

                // Validate proof length before accessing to prevent out-of-bounds access
                if (sig.length < proofEnd) {
                    revert InvalidMerkleProofLength(expectedProofLength, sig.length - 13);
                }

                proof = sig[13:proofEnd];
            }
            signatures = sig[proofEnd:];
        }

        // It is important that **all** user operation fields are represented in the `SafeOp` data somehow, to prevent
        // user operations from being submitted that do not fully respect the user preferences. The only exception is
        // the `signature` bytes. Note that even `initCode` needs to be represented in the operation data, otherwise
        // it can be replaced with a more expensive initialization that would charge the user additional fees.
        {
            // In order to work around Solidity "stack too deep" errors related to too many stack variables, manually
            // encode the `SafeOp` fields into a memory `struct` for computing the EIP-712 struct-hash. This works
            // because the `EncodedSafeOpStruct` struct has no "dynamic" fields so its memory layout is identical to the
            // result of `abi.encode`-ing the individual fields.
            EncodedSafeOpStruct memory encodedSafeOp = EncodedSafeOpStruct({
                typeHash: SAFE_OP_TYPEHASH,
                safe: userOp.sender,
                nonce: userOp.nonce,
                initCodeHash: keccak256(userOp.initCode),
                callDataHash: keccak256(userOp.callData),
                verificationGasLimit: uint128(userOp.unpackVerificationGasLimit()),
                callGasLimit: uint128(userOp.unpackCallGasLimit()),
                preVerificationGas: userOp.preVerificationGas,
                maxPriorityFeePerGas: uint128(userOp.unpackMaxPriorityFeePerGas()),
                maxFeePerGas: uint128(userOp.unpackMaxFeePerGas()),
                paymasterAndDataHash: paymasterDataKeccak(userOp.paymasterAndData),
                validAfter: validAfter,
                validUntil: validUntil,
                entryPoint: SUPPORTED_ENTRYPOINT
            });

            bytes32 safeOpStructHash;
            // solhint-disable-next-line no-inline-assembly
            assembly ("memory-safe") {
                // Since the `encodedSafeOp` value's memory layout is identical to the result of `abi.encode`-ing the
                // individual `SafeOp` fields, we can pass it directly to `keccak256`. Additionally, there are 14
                // 32-byte fields to hash, for a length of `14 * 32 = 448` bytes.
                safeOpStructHash := keccak256(encodedSafeOp, 448)
            }

            operationData = abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), safeOpStructHash);
        }
    }

    /**
    * @notice Computes the Keccak-256 hash of a slice of calldata, followed by an 8-byte suffix.
    * This function copies the first `len` bytes from the given calldata array `data` into memory.
    * The assembly code is equivalent to:
    *      keccak256(abi.encodePacked(data[0:len], suffix))
    * But more efficient, and doesn't move the free memory pointer, allowing the memory to be reused later.
    *
    * @param data   Calldata byte array to read from.
    * @param len    Number of bytes to copy from `data` starting at its offset.
    * @param suffix 8-byte value appended to the data bytes before hashing.
    *
    * @return ret The hash of (data[0:len] || suffix).
    */
    function calldataKeccakWithSuffix(bytes calldata data, uint256 len, bytes8 suffix) internal pure returns (bytes32 ret) {
        assembly ("memory-safe") {
            let mem := mload(0x40)
            calldatacopy(mem, data.offset, len)
            mstore(add(mem, len), suffix)
            len := add(len, 8)
            ret := keccak256(mem, len)
        }
    }

    /**
    * @notice Computes the keccak256 hash of a calldata byte array.
    * @dev Copies calldata into memory at the free memory pointer without bumping it, then hashes.
    * This is more gas-efficient than Solidity's built-in keccak256 on calldata.
    *
    * @param data - the calldata bytes array to perform keccak on.
    * @return ret - the keccak hash of the 'data' array.
    */
    function calldataKeccak(bytes calldata data) internal pure returns (bytes32 ret) {
        assembly ("memory-safe") {
            let mem := mload(0x40)
            let len := data.length
            calldatacopy(mem, data.offset, len)
            ret := keccak256(mem, len)
        }
    }

    /**
    * Keccak function over paymaster data.
    * If data ends with `PAYMASTER_SIG_MAGIC`, then
    * read the previous 2 bytes as pmSignatureLength,
    * and ignore this suffix from the hash.
    * This means that the trailing pmSignatureLength+10 bytes are not covered by the UserOpHash, and thus are not signed.
    * @dev copy calldata into memory, do keccak and drop allocated memory. Strangely, this is more efficient than letting solidity do it.
    *
    * @param data - the calldata bytes array to perform keccak on.
    * @return ret - the keccak hash of the 'data' array.
    */
    function paymasterDataKeccak(bytes calldata data) internal pure returns (bytes32 ret) {
        uint256 pmSignatureLength = getPaymasterSignatureLength(data);
        if (pmSignatureLength > 0) {
            unchecked {
                //keccak everything up to the paymasterSignature, but still append the sig magic.
                return calldataKeccakWithSuffix(data, data.length - (pmSignatureLength + PAYMASTER_SUFFIX_LEN), PAYMASTER_SIG_MAGIC);
            }
        }
        return calldataKeccak(data);
    }

    /**
     * @notice Returns the length of the paymaster signature appended to `paymasterAndData`.
     * @dev Returns 0 if no paymaster signature is detected (i.e. the magic suffix is absent or the data is too short).
     * The paymaster signature is not part of the userOpHash and is therefore not signed by the user.
     * @param paymasterAndData The packed paymaster address and associated data from the user operation.
     * @return paymasterSignatureLength Length of the paymaster signature in bytes, or 0 if none.
     */
    function getPaymasterSignatureLength(
        bytes calldata paymasterAndData
    ) internal pure returns (uint256 paymasterSignatureLength) {
        unchecked {
            uint256 dataLength = paymasterAndData.length;
            if (dataLength < MIN_PAYMASTER_DATA_WITH_SUFFIX_LEN) {
                return 0;
            }
            bytes8 suffix8 = bytes8(paymasterAndData[dataLength - PAYMASTER_SIG_MAGIC_LEN : dataLength]);
            if (suffix8 != PAYMASTER_SIG_MAGIC) {
                return 0;
            }
            uint256 pmSignatureLength = uint16(bytes2(paymasterAndData[dataLength - PAYMASTER_SUFFIX_LEN :]));

            if (pmSignatureLength > dataLength - MIN_PAYMASTER_DATA_WITH_SUFFIX_LEN) {
                // paymasterSignature cannot extend before the paymasterData
                revert InvalidPaymasterSignatureLength(dataLength, pmSignatureLength);
            }
            return pmSignatureLength;
        }
    }
}

