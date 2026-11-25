// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaKzgUpdateKeyResearch as RowArithmetic} from "./VantaKzgUpdateKeyResearch.sol";
import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";

/// @notice Immutable family-scoped root for one qualified KZG setup.
/// @dev Reuses the exact historical compression and Merkle arithmetic. This
/// contract proves public update-key membership, never ownership or custody.
contract VantaFamilyScopedRowKeyPreAudit is RowArithmetic, VantaFamilyReleaseBinding {
    bytes32 public immutable acceptedResearchRoot;

    error InvalidResearchRoot();

    constructor(bytes32 root, bytes32 setupId, bytes32 generationId,
        bytes32 familyTag, uint256 chainId)
        VantaFamilyReleaseBinding(setupId,generationId,familyTag,chainId)
    {
        if (root == bytes32(0) || chainId >= (uint256(1) << 53) ||
            uint256(familyTag) >=
                21888242871839275222246405745257275088548364400416034343698204186575808495617)
            revert InvalidResearchRoot();
        acceptedResearchRoot = root;
    }

    function verifyScopedRowKeyPoints(
        uint256 row, G1Point calldata a, G1Point calldata u,
        bytes32 aCompressed, bytes32 uCompressed, bytes32[16] calldata siblings
    ) external view onlyReleaseChain returns (bool) {
        return _matchesArkCompressed(a,aCompressed) &&
            _matchesArkCompressed(u,uCompressed) &&
            _verifyRowKeyAgainstRoot(row,aCompressed,uCompressed,siblings,acceptedResearchRoot);
    }
}
