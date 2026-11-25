// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaKzgUpdateKeyResearch as Frozen} from "./VantaKzgUpdateKeyResearch.sol";
import {VantaBaseChainPolicy} from "./VantaBaseChainPolicy.sol";

/// @notice Immutable, explicitly scoped root for a SINGLE research KZG SRS.
/// @dev A fresh native fixture uses an OsRng-generated trapdoor and therefore
/// cannot match the separately frozen D2F5... historical research root.
/// This is an ephemeral research comparator, NOT an approved root authority.
/// Never authorize actual funds based on the constructor's caller-chosen root.
contract VantaV8ScopedRowKeyResearch is Frozen {
    bytes32 public immutable acceptedResearchRoot;

    error InvalidResearchRoot();

    constructor(bytes32 root) {
        if (!VantaBaseChainPolicy.isSupported(block.chainid) || root == bytes32(0)) {
            revert InvalidResearchRoot();
        }
        acceptedResearchRoot = root;
    }

    /// @notice Verify native G1 points against immutable 65,536-row Merkle root.
    /// @dev Neither the leaf root nor source setup can vary per proof call.
    function verifyScopedRowKeyPoints(
        uint256 row,
        G1Point calldata a,
        G1Point calldata u,
        bytes32 aCompressed,
        bytes32 uCompressed,
        bytes32[16] calldata siblings
    ) external view returns (bool) {
        return _matchesArkCompressed(a,aCompressed) &&
            _matchesArkCompressed(u,uCompressed) &&
            _verifyRowKeyAgainstRoot(
                row,aCompressed,uCompressed,siblings,acceptedResearchRoot
            );
    }
}
