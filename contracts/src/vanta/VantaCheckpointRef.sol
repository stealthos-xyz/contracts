// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Fixed v0 KZG checkpoint-ref representation for Vanta Gate 0 / Gate 1.
/// @dev Not an authenticated checkpoint registry and not a settlement verifier.
///      Wire: keccak256(domain32 || u64BE(table_id) || u64BE(slot_count)
///             || FqBE32(C.x) || FqBE32(C.y)) reduced modulo Fr.
///      No arkworks compressed-point layout or SHA-256 shortcut is accepted.
library VantaCheckpointRef {
    uint256 internal constant FQ =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    bytes32 internal constant DOMAIN = keccak256("STEALTHOS_VANTA_CREF_V0");

    error InvalidCheckpointTable();
    error InvalidCheckpointCount();
    error InvalidCheckpointPoint();

    function compute(uint64 tableId, uint64 slotCount, uint256 x, uint256 y)
        internal pure returns (uint256)
    {
        if (tableId != 0) revert InvalidCheckpointTable();
        if (slotCount < 32 || slotCount > 65_536) revert InvalidCheckpointCount();
        // Infinity has the special EVM encoding (0, 0). Both coordinates must
        // be canonical BN254 base-field values; G1 has cofactor one.
        if ((x == 0 && y == 0) || x >= FQ || y >= FQ) {
            revert InvalidCheckpointPoint();
        }
        if (mulmod(y, y, FQ) != addmod(mulmod(mulmod(x, x, FQ), x, FQ), 3, FQ)) {
            revert InvalidCheckpointPoint();
        }
        return uint256(keccak256(abi.encodePacked(DOMAIN, tableId, slotCount, x, y))) % FR;
    }
}
