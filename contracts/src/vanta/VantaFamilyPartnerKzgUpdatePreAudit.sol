// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaKzgUpdateKeyResearch} from "./VantaKzgUpdateKeyResearch.sol";
import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";

/// @notice Authenticated six-row arithmetic for the P0.1 policy-table candidate.
/// @dev No ownership authority, custody or state mutation. The registry must
/// supply its actual current commitment and stored old leaves. The inherited
/// SHA-256 paths authenticate PUBLIC immutable SRS update keys, never policies.
/// A production generation still requires independently qualified parameters.
/// The inherited historical-root views are arithmetic research utilities only;
/// they never authenticate this registry's updates or admit policy membership.
contract VantaFamilyPartnerKzgUpdatePreAudit is
    VantaKzgUpdateKeyResearch, VantaFamilyReleaseBinding
{
    uint256 private constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant OMEGA =
        0x0eeb2cb5981ed45649abebde081dcff16c8601de4347e7dd1628ba2daac43b7;
    uint256 private constant INV_N =
        0x30641e0e92bebef818268d663bcad6dbcfd6c0149170f6d7d350b1b1fa6c1001;

    struct RowKey {
        G1Point a;
        G1Point u;
        bytes32 aCompressed;
        bytes32 uCompressed;
        bytes32[16] siblings;
    }

    bytes32 public immutable acceptedUpdateKeyRoot;

    error InvalidUpdateSetup();
    error InvalidSourceCommitment();
    error InvalidRowRange();
    error InvalidPolicyLeaf();
    error UnauthenticatedRowKey();
    error BadBn254Precompile();

    constructor(bytes32 root, bytes32 setupId, bytes32 generationId,
        bytes32 familyTag, uint256 chainId)
        VantaFamilyReleaseBinding(setupId, generationId, familyTag, chainId)
    {
        if (root == bytes32(0) || chainId >= (uint256(1) << 53) ||
            uint256(familyTag) >= FR) revert InvalidUpdateSetup();
        acceptedUpdateKeyRoot = root;
    }

    /// @notice C' = C + sum((new_i-old_i) * omega^i/N * A_i).
    /// @dev Reserved rows 0..31 remain zero. Infinity is the correct empty
    /// table commitment; update keys themselves can never be infinity.
    function updateSix(
        uint32 firstSlot, uint256 sourceX, uint256 sourceY,
        uint256[6] calldata oldLeaves, uint256[6] calldata newLeaves,
        RowKey[6] calldata rowKeys
    ) external view onlyReleaseChain returns (uint256 finalX, uint256 finalY) {
        if (firstSlot < FIRST_REAL_ROW || uint256(firstSlot) + 6 > TABLE_SIZE)
            revert InvalidRowRange();
        if (!_validCommitment(sourceX, sourceY)) revert InvalidSourceCommitment();
        finalX = sourceX;
        finalY = sourceY;
        uint256 omegaRow = _omegaPower(firstSlot);
        for (uint256 i; i < 6; ++i) {
            if (oldLeaves[i] >= FR || newLeaves[i] >= FR) revert InvalidPolicyLeaf();
            RowKey calldata key = rowKeys[i];
            if (!_matchesArkCompressed(key.a, key.aCompressed) ||
                !_matchesArkCompressed(key.u, key.uCompressed) ||
                !_verifyRowKeyAgainstRoot(
                    uint256(firstSlot) + i, key.aCompressed, key.uCompressed,
                    key.siblings, acceptedUpdateKeyRoot
                )) revert UnauthenticatedRowKey();
            uint256 delta = addmod(newLeaves[i], FR - oldLeaves[i], FR);
            uint256 scalar = mulmod(delta, mulmod(omegaRow, INV_N, FR), FR);
            (bool ok, bytes memory result) = address(0x07).staticcall(
                abi.encode(key.a.x, key.a.y, scalar)
            );
            if (!ok || result.length != 64) revert BadBn254Precompile();
            (uint256 dx, uint256 dy) = abi.decode(result, (uint256, uint256));
            (ok, result) = address(0x06).staticcall(
                abi.encode(finalX, finalY, dx, dy)
            );
            if (!ok || result.length != 64) revert BadBn254Precompile();
            (finalX, finalY) = abi.decode(result, (uint256, uint256));
            omegaRow = mulmod(omegaRow, OMEGA, FR);
        }
    }

    function _validCommitment(uint256 x, uint256 y) private pure returns (bool) {
        if (x >= FQ || y >= FQ) return false;
        return (x == 0 && y == 0) ||
            mulmod(y, y, FQ) == addmod(mulmod(mulmod(x, x, FQ), x, FQ), 3, FQ);
    }

    function _omegaPower(uint256 exponent) private pure returns (uint256 result) {
        result = 1;
        uint256 base = OMEGA;
        while (exponent != 0) {
            if ((exponent & 1) != 0) result = mulmod(result, base, FR);
            base = mulmod(base, base, FR);
            exponent >>= 1;
        }
    }
}
