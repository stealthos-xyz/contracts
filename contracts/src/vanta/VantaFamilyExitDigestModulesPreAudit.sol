// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";
import {VantaFamilyEpochStatementPreAudit as ExitStatement}
    from "./VantaFamilyEpochStatementPreAudit.sol";
import {VantaV8EpochPoseidon40Research, VantaV8EpochPoseidon64Research}
    from "./VantaV8EpochDigestHashersResearch.sol";
import {VantaV8StatementResearch as Statement8}
    from "./VantaV8StatementResearch.sol";
import {VantaV8Statement32Research as Statement32}
    from "./VantaV8Statement32Research.sol";

/// @notice Family-locked pure statement adapter. No keys, funds or roles.
contract VantaFamilyExitDigestEightPreAudit is VantaFamilyReleaseBinding {
    VantaV8EpochPoseidon40Research private immutable hasher;
    constructor(bytes32 setupId, bytes32 generationId, bytes32 familyTag,
        uint256 chainId) VantaFamilyReleaseBinding(
        setupId, generationId, familyTag, chainId) { hasher = new VantaV8EpochPoseidon40Research(); }

    function digest(Statement8.LegPublic calldata action, uint64 sourceEpoch,
        uint128 protocolFee, uint128 partnerFee)
        external view onlyReleaseChain returns (uint256)
    {
        return hasher.digest40(ExitStatement.exitEight(action,sourceEpoch,protocolFee,partnerFee));
    }
}

/// @notice Independent 32-input module keeps no-append verification under EIP-170.
contract VantaFamilyExitDigestThirtyTwoPreAudit is VantaFamilyReleaseBinding {
    VantaV8EpochPoseidon64Research private immutable hasher;
    constructor(bytes32 setupId, bytes32 generationId, bytes32 familyTag,
        uint256 chainId) VantaFamilyReleaseBinding(
        setupId, generationId, familyTag, chainId) { hasher = new VantaV8EpochPoseidon64Research(); }

    function digest(Statement32.LegPublic calldata action, uint64 sourceEpoch,
        uint128 protocolFee, uint128 partnerFee)
        external view onlyReleaseChain returns (uint256)
    {
        return hasher.digest64(ExitStatement.exitThirtyTwo(action,sourceEpoch,protocolFee,partnerFee));
    }
}
