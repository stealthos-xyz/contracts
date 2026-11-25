// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaCheckpointRef} from "./VantaCheckpointRef.sol";
import {VantaEpochCheckpointRef} from "./VantaEpochCheckpointRef.sol";
import {VantaDummyPolicy} from "./VantaDummyPolicy.sol";
import {VantaKzgUpdateKeyResearch} from "./VantaKzgUpdateKeyResearch.sol";
import {VantaFamilyScopedRowKeyPreAudit} from "./VantaFamilyScopedRowKeyPreAudit.sol";
import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";

/// @notice Family-bound five-row KZG update arithmetic (pre-audit only).
/// @dev Isolated family adaptation preserves the legacy Base contract verbatim.
/// The row arithmetic and public ABI are unchanged; only deployment binding differs.
/// @dev Uses an immutable per-SRS research root. The historically frozen
///      D2F5 root remains unchanged in the original verifier.
/// Every row's public Lagrange update key must be Merkle-authenticated and
/// byte-identical to its canonical Arkworks curve-point compression.
/// NO CUSTODY, NO STATE ADVANCE, NO TABLE REGISTRY, NO FUNDS AUTHORITY.
/// The real pool must require this source state is its currently accepted
/// checkpoint and atomically update it with verified three-gate proofs.
contract VantaFamilyFiveRowKzgPreAudit is VantaFamilyReleaseBinding {
    uint256 internal constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant TABLE_SIZE = 65_536;
    uint256 internal constant OMEGA =
        0x0eeb2cb5981ed45649abebde081dcff16c8601de4347e7dd1628ba2daac43b7;
    uint256 internal constant INV_N =
        0x30641e0e92bebef818268d663bcad6dbcfd6c0149170f6d7d350b1b1fa6c1001;

    struct RowKey {
        VantaKzgUpdateKeyResearch.G1Point a;
        VantaKzgUpdateKeyResearch.G1Point u;
        bytes32 aCompressed;
        bytes32 uCompressed;
        bytes32[16] siblings;
    }

    VantaFamilyScopedRowKeyPreAudit public immutable keys;
    bytes32 public immutable keysCodehash;
    uint64 public immutable deployedChainId;

    error WrongChain();
    error InvalidSourceRow();
    error InvalidRowCount();
    error InvalidOutputCommitment();
    error UnauthenticatedRowKey();
    error BadBn254Precompile();
    error ResearchVerifierChanged();

    constructor(bytes32 acceptedResearchRoot, bytes32 setupId, bytes32 generationId,
        bytes32 familyTag, uint256 chainId)
        VantaFamilyReleaseBinding(setupId,generationId,familyTag,chainId)
    {
        if (chainId >= (uint256(1) << 53) || uint256(familyTag) >= FR) revert WrongChain();
        deployedChainId = uint64(block.chainid);
        // A native OsRng research SRS has a distinct root each invocation.
        // Freeze that single SRS root at construction, never per proof call.
        // This is NOT a production parameter approval ceremony.
        VantaFamilyScopedRowKeyPreAudit verifier =
            new VantaFamilyScopedRowKeyPreAudit(acceptedResearchRoot,setupId,generationId,familyTag,chainId);
        keys = verifier;
        keysCodehash = address(verifier).codehash;
    }

    /// @notice Prove five sequential output additions from the same canonical
    /// source KZG commitment to the expected new commitment and checkpoint.
    /// @dev This is only deterministic EVM arithmetic over *public* output
    /// commitments. The settlement pool must independently authorize all
    /// five commitments and their source through the pinned three-gate proof.
    function verifyFiveRows(
        uint64 sourceSlotCount,
        uint256 sourceX,
        uint256 sourceY,
        uint256[5] calldata outputs,
        RowKey[5] calldata authenticatedKeys
    ) external view returns (uint256, uint256, uint256, uint256) {
        return _verifyRows(0, false, sourceSlotCount, sourceX, sourceY, 5, outputs, authenticatedKeys);
    }

    /// @notice Authenticate 1..5 sequential deposit rows, including the
    /// final partial batch of an 8- or 32-note source inventory.
    /// @dev No custody or state mutation; five-output spend updates still
    /// use verifyFiveRows and must authenticate all five output slots.
    function verifyRows(
        uint64 sourceSlotCount,
        uint256 sourceX,
        uint256 sourceY,
        uint8 rowCount,
        uint256[5] calldata outputs,
        RowKey[5] calldata authenticatedKeys
    ) external view returns (uint256, uint256, uint256, uint256) {
        return _verifyRows(0, false, sourceSlotCount, sourceX, sourceY, rowCount, outputs, authenticatedKeys);
    }

    /// @notice Generation-aware public row arithmetic for future Vanta pools.
    /// @dev Reuses ONE pinned KZG setup, but domain-separates the source and
    ///      resulting checkpoint with V1 epoch IDs. A custody pool MUST
    ///      separately authenticate the active target epoch and the full
    ///      Gate0/Gate1/CP_link proof before accepting an update.
    ///      Never use this view as authority to debit funds.
    function verifyEpochRows(
        uint64 epochId,
        uint64 sourceSlotCount,
        uint256 sourceX,
        uint256 sourceY,
        uint8 rowCount,
        uint256[5] calldata outputs,
        RowKey[5] calldata authenticatedKeys
    ) external view returns (uint256, uint256, uint256, uint256) {
        return _verifyRows(
            epochId, true, sourceSlotCount, sourceX, sourceY,
            rowCount, outputs, authenticatedKeys
        );
    }

    function _verifyRows(
        uint64 epochId,
        bool epochV1,
        uint64 sourceSlotCount,
        uint256 sourceX,
        uint256 sourceY,
        uint8 rowCount,
        uint256[5] calldata outputs,
        RowKey[5] calldata authenticatedKeys
    ) private view returns (
        uint256 sourceRef,
        uint256 finalRef,
        uint256 finalX,
        uint256 finalY
    ) {
        if (rowCount == 0 || rowCount > 5) revert InvalidRowCount();
        if (block.chainid != deployedChainId) revert WrongChain();
        if (address(keys).codehash != keysCodehash)
            revert ResearchVerifierChanged();
        if (sourceSlotCount < 32 || uint256(sourceSlotCount) + rowCount > TABLE_SIZE)
            revert InvalidSourceRow();

        sourceRef = epochV1
            ? VantaEpochCheckpointRef.compute(
                epochId, sourceSlotCount, sourceX, sourceY
            )
            : VantaCheckpointRef.compute(
                0, sourceSlotCount, sourceX, sourceY
            );
        finalX = sourceX;
        finalY = sourceY;
        for (uint256 i; i < rowCount; ++i) {
            uint256 cm = outputs[i];
            if (cm == 0 || cm >= FR ||
                VantaDummyPolicy.isDisallowedRealCommitment(cm))
                revert InvalidOutputCommitment();

            uint256 row = uint256(sourceSlotCount) + i;
            RowKey calldata key = authenticatedKeys[i];
            if (!keys.verifyScopedRowKeyPoints(
                row, key.a, key.u, key.aCompressed, key.uCompressed,
                key.siblings
            )) revert UnauthenticatedRowKey();

            // Matches the native 65,536-point Lagrange KZG update:
            // delta = cm * omega^row / N * A_row, C' = C + delta.
            uint256 omegaPow = 1;
            uint256 base = OMEGA;
            uint256 exponent = row;
            while (exponent != 0) {
                if ((exponent & 1) != 0) {
                    omegaPow = mulmod(omegaPow, base, FR);
                }
                base = mulmod(base, base, FR);
                exponent >>= 1;
            }
            uint256 scalar = mulmod(cm, mulmod(omegaPow, INV_N, FR), FR);
            (bool ok, bytes memory mulOut) = address(0x07).staticcall(
                abi.encode(key.a.x, key.a.y, scalar)
            );
            if (!ok || mulOut.length != 64) revert BadBn254Precompile();
            (uint256 dx, uint256 dy) = abi.decode(mulOut, (uint256, uint256));
            (ok, mulOut) = address(0x06).staticcall(
                abi.encode(finalX, finalY, dx, dy)
            );
            if (!ok || mulOut.length != 64) revert BadBn254Precompile();
            (finalX, finalY) = abi.decode(mulOut, (uint256, uint256));
        }
        finalRef = epochV1
            ? VantaEpochCheckpointRef.compute(
                epochId, sourceSlotCount + rowCount, finalX, finalY
            )
            : VantaCheckpointRef.compute(
                0, sourceSlotCount + rowCount, finalX, finalY
            );
    }
}
