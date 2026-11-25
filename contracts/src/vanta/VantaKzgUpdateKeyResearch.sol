// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Authenticates PUBLIC research update-key leaves against the frozen
///         65536-row deterministic Vanta research SRS LAG_ROOT.
/// @dev NO KZG checkpoint acceptance or custody/settlement entrypoint.
///      SHA-256 Merkle membership plus optional strict EVM G1 coordinate
///      binding are proven here. This does NOT perform group updates, bind
///      actual deposit rows or authenticate a checkpoint.
///      The known-tau SRS is NOT fund-safe.
contract VantaKzgUpdateKeyResearch {
    uint256 public constant FIRST_REAL_ROW = 32;
    uint256 public constant TABLE_SIZE = 65_536;
    uint256 public constant MERKLE_DEPTH = 16;
    uint256 internal constant FQ =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 x;
        uint256 y;
    }
    // leaf = SHA256(ark_compress(a_j)||ark_compress(u_j))
    // node = SHA256(left||right), indexed by row position.
    // Pinned native N=65536 research SRS, never passed by a caller.
    bytes32 public constant PINNED_LAG_ROOT =
        hex"d2f5cf4039e77b90e0aadc731e15b5dca66198a7e5d93677b0d211c3867cdb54";

    function verifyRowKey(
        uint256 row,
        bytes32 aCompressed,
        bytes32 uCompressed,
        bytes32[16] calldata siblings
    ) external pure returns (bool) {
        return _verifyRowKey(row, aCompressed, uCompressed, siblings);
    }

    /// @notice Verify both the row's Merkle leaf and each native Arkworks
    ///         compressed key's identity as a canonical BN254 EVM G1 point.
    /// @dev No compressed-point caller alias, infinity or negative-y substitution.
    ///      Fq is 254 bits. Arkworks serializes x little-endian with bits 6/7
    ///      of the final byte reserved for infinity/sign, respectively.
    function verifyRowKeyPoints(
        uint256 row,
        G1Point calldata a,
        G1Point calldata u,
        bytes32 aCompressed,
        bytes32 uCompressed,
        bytes32[16] calldata siblings
    ) external pure returns (bool) {
        return _matchesArkCompressed(a, aCompressed)
            && _matchesArkCompressed(u, uCompressed)
            && _verifyRowKey(row, aCompressed, uCompressed, siblings);
    }

    function _matchesArkCompressed(G1Point calldata point, bytes32 data)
        internal pure returns (bool)
    {
        uint256 x = point.x;
        uint256 y = point.y;
        if (x >= FQ || y >= FQ || (x == 0 && y == 0)) return false;
        if (mulmod(y, y, FQ) != addmod(mulmod(mulmod(x, x, FQ), x, FQ), 3, FQ)) {
            return false;
        }

        // Arkworks SWFlags: 0x40 = infinity (always reject in an update key),
        // 0x80 = y > -y, where Fq elements are in their canonical order.
        uint8 flags = uint8(data[31]);
        if ((flags & 0x40) != 0 || ((flags & 0x80) != 0) != (y > FQ - y)) {
            return false;
        }

        // Decode precisely the same 32 little-endian bytes as Arkworks Fq.
        // The two high flags are not part of the 254-bit x coordinate.
        uint256 encoded;
        for (uint256 i = 0; i < 32; ++i) {
            encoded |= uint256(uint8(data[i])) << (8 * i);
        }
        return (encoded & (type(uint256).max >> 2)) == x;
    }

    function _verifyRowKey(
        uint256 row,
        bytes32 aCompressed,
        bytes32 uCompressed,
        bytes32[16] calldata siblings
    ) internal pure returns (bool) {
        // Preserve the original frozen research key root and its callers.
        return _verifyRowKeyAgainstRoot(
            row, aCompressed, uCompressed, siblings, PINNED_LAG_ROOT
        );
    }

    /// @dev Internal-only root parameterization for a *separate* one-setup
    /// research contract. Never expose a caller-chosen root as a fund-moving
    /// verifier input: the accepted root must be pinned by a qualified pool.
    function _verifyRowKeyAgainstRoot(
        uint256 row,
        bytes32 aCompressed,
        bytes32 uCompressed,
        bytes32[16] calldata siblings,
        bytes32 expectedRoot
    ) internal pure returns (bool) {
        if (expectedRoot == bytes32(0) ||
            row < FIRST_REAL_ROW || row >= TABLE_SIZE) return false;
        bytes32 acc = sha256(abi.encodePacked(aCompressed, uCompressed));
        for (uint256 level = 0; level < MERKLE_DEPTH; ++level) {
            acc = ((row >> level) & 1) == 0
                ? sha256(abi.encodePacked(acc, siblings[level]))
                : sha256(abi.encodePacked(siblings[level], acc));
        }
        return acc == expectedRoot;
    }
}
