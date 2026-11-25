// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface AnonymousHandleVerifier {
    function verifyProof(
        uint256[8] calldata proof,
        bytes32 handleId,
        bytes32 recordCommitment,
        bytes32 ownerCommitment,
        bytes32 nullifier,
        uint64 epoch,
        uint256 chainId,
        uint8 actionTag
    ) external view returns (bool);

    /// @notice Fail-closed provenance marker exposed by the proof adapters.
    ///         True until the underlying verifying key is regenerated from an
    ///         approved production ceremony.
    function isDevelopmentSetup() external view returns (bool);

    /// @notice The Groth16 verifying-key contract this adapter wraps.
    /// @dev Adapter identity says nothing about the key. The register and
    ///      rotate adapters are byte-identical sources apart from their file
    ///      paths, so their deployed bytecode differs only in the trailing solc
    ///      metadata hash — a function of the path, not of the key. Two
    ///      adapters over the SAME key therefore always differ in both address
    ///      and codehash. A consumer that must not accept one key in two slots
    ///      has to compare this, not the adapter.
    function verifier() external view returns (address);
}
