// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Versioned epoch-aware checkpoint identity for future Vanta pools.
/// @dev This is a public-data helper, NOT an authenticated table registry,
///      proof verifier or authorization to custody assets. All settlement must
///      separately authenticate table state, acceptance/finality and proofs.
///      V0 permits only table zero; V1 uses a new domain and supports uint64
///      epoch IDs. Never substitute this digest in V0 proof artifacts.
library VantaEpochCheckpointRef {
    uint256 internal constant FQ =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    bytes32 internal constant DOMAIN = keccak256("STEALTHOS_VANTA_CREF_V1");

    error InvalidCheckpointCount();
    error InvalidCheckpointPoint();

    /// @dev Exact wire: keccak256(domain32 || tableId:u64BE || count:u64BE
    ///      || C.x:FqBE32 || C.y:FqBE32) modulo BN254 Fr. Requires the
    ///      caller to authenticate that the table ID and commitment are
    ///      accepted by the pool, rather than trusting prover-supplied values.
    function compute(uint64 tableId, uint64 slotCount, uint256 x, uint256 y)
        internal pure returns (uint256)
    {
        if (slotCount < 32 || slotCount > 65_536) revert InvalidCheckpointCount();
        if ((x == 0 && y == 0) || x >= FQ || y >= FQ) revert InvalidCheckpointPoint();
        if (mulmod(y, y, FQ) != addmod(mulmod(mulmod(x, x, FQ), x, FQ), 3, FQ)) {
            revert InvalidCheckpointPoint();
        }
        return uint256(keccak256(abi.encodePacked(DOMAIN, tableId, slotCount, x, y))) % FR;
    }
}
