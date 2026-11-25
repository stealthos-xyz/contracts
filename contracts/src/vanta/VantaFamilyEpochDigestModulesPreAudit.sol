// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaFamilyEpochStatementPreAudit as EpochStatement}
    from "./VantaFamilyEpochStatementPreAudit.sol";
import {VantaV8StatementResearch as Statement8}
    from "./VantaV8StatementResearch.sol";
import {VantaV8Statement32Research as Statement32}
    from "./VantaV8Statement32Research.sol";
import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";
import {VantaV8EpochPoseidon40Research, VantaV8EpochPoseidon64Research}
    from "./VantaV8EpochDigestHashersResearch.sol";

/// @notice Public statement-only digest module for the genuine 8x5 epoch profile.
/// @dev No custody, fee authority, table writes or user secrets. Its bytecode
/// is independently pinned by VantaV8EpochProofVerifierResearch.
contract VantaFamilyEpochDigestEightPreAudit is VantaFamilyReleaseBinding {
    uint64 public immutable deployedChainId;
    VantaV8EpochPoseidon40Research private immutable hasher;

    error WrongChain();

    constructor(bytes32 setupId, bytes32 generationId, bytes32 familyTag,
        uint256 chainId) VantaFamilyReleaseBinding(setupId, generationId, familyTag, chainId) {
        if (chainId > type(uint64).max) revert WrongChain();
        deployedChainId = uint64(chainId);
        hasher = new VantaV8EpochPoseidon40Research();
    }

    function digest(
        Statement8.LegPublic calldata action,
        uint64 sourceEpoch,
        uint64 targetEpoch,
        bool privateMerge
    ) external view returns (uint256) {
        if (block.chainid != deployedChainId) revert WrongChain();
        uint256[40] memory fields = EpochStatement.orderedEight(action, sourceEpoch, targetEpoch, privateMerge);
        return hasher.digest40(fields);
    }
}

/// @notice Public statement-only digest module for the genuine 32x5 profile.
/// @dev Separate deployment keeps both real width-specific Poseidon statement
/// implementations below EIP-170, without changing their field order or hash.
contract VantaFamilyEpochDigestThirtyTwoPreAudit is VantaFamilyReleaseBinding {
    uint64 public immutable deployedChainId;
    VantaV8EpochPoseidon64Research private immutable hasher;

    error WrongChain();

    constructor(bytes32 setupId, bytes32 generationId, bytes32 familyTag,
        uint256 chainId) VantaFamilyReleaseBinding(setupId, generationId, familyTag, chainId) {
        if (chainId > type(uint64).max) revert WrongChain();
        deployedChainId = uint64(chainId);
        hasher = new VantaV8EpochPoseidon64Research();
    }

    function digest(
        Statement32.LegPublic calldata action,
        uint64 sourceEpoch,
        uint64 targetEpoch,
        bool privateMerge
    ) external view returns (uint256) {
        if (block.chainid != deployedChainId) revert WrongChain();
        uint256[64] memory fields = EpochStatement.orderedThirtyTwo(action, sourceEpoch, targetEpoch, privateMerge);
        return hasher.digest64(fields);
    }
}

