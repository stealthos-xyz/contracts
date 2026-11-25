// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaV8StatementResearch as Statement8} from "./VantaV8StatementResearch.sol";
import {VantaV8Statement32Research as Statement32} from "./VantaV8Statement32Research.sol";
import {VantaEpochCheckpointRef} from "./VantaEpochCheckpointRef.sol";
import {VantaTokenHash} from "./VantaTokenHash.sol";

/// @notice Exact existing epoch field order for immutable family deployments.
/// @dev The calling family digest module pins the actual chain. The frozen
/// Base-only statement builders remain unchanged. No hash or R1CS is changed.
library VantaFamilyEpochStatementPreAudit {
    uint256 private constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    error InvalidFamilyAction();
    error InvalidFamilyField();

    function _check(address pool, address recipient, uint256 batch, uint256 quote,
        uint256 amount, uint8 leg, uint8 feeLeg, uint8 count, bool privateMerge) private view
    {
        if (block.chainid == 0 || block.chainid > (uint256(1) << 53) - 1 ||
            pool == address(0) || (privateMerge ? recipient != address(0) : recipient == address(0)) ||
            batch == 0 || batch >= FR || quote == 0 || quote >= FR || amount == 0 || amount >= FR ||
            count == 0 || count > 8 || leg >= count || feeLeg >= count) revert InvalidFamilyAction();
    }
    function _field(uint256 value) private pure {
        if (value == 0 || value >= FR) revert InvalidFamilyField();
    }

    function orderedEight(Statement8.LegPublic memory a, uint64 sourceEpoch,
        uint64 targetEpoch, bool privateMerge) internal view returns (uint256[40] memory f)
    {
        _check(a.pool,a.recipient,a.batchDigestField,a.feeQuoteDigestField,a.saltedAmountHash,
            a.legIndex,a.feeLegIndex,a.legCount,privateMerge);
        f[0]=2; f[1]=8; f[2]=8; f[3]=block.chainid;
        f[4]=uint160(a.pool); f[5]=privateMerge ? 1 : 6;
        f[6]=sourceEpoch; f[7]=targetEpoch; f[8]=uint160(a.token); f[9]=uint160(a.recipient);
        f[10]=0; f[11]=uint160(a.protocolFeeRecipient); f[12]=0; f[13]=uint160(a.partnerFeeRecipient);
        f[14]=0; f[15]=VantaEpochCheckpointRef.compute(sourceEpoch,a.sourceSlotCount,a.checkpointX,a.checkpointY);
        for (uint256 i; i<8; ++i) { _field(a.nullifiers[i]); f[16+i]=a.nullifiers[i]; }
        for (uint256 i; i<5; ++i) { _field(a.outputs[i]); f[24+i]=a.outputs[i]; }
        f[29]=VantaTokenHash.compute(block.chainid,a.pool,a.token);
        f[30]=a.batchDigestField; f[31]=a.feeQuoteDigestField;
        f[32]=a.legIndex; f[33]=a.feeLegIndex; f[34]=a.legCount;
        f[35]=a.protocolFeeCap; f[36]=a.partnerFeeCap; f[37]=a.saltedAmountHash;
        f[38]=5; f[39]=1;
    }

    function orderedThirtyTwo(Statement32.LegPublic memory a, uint64 sourceEpoch,
        uint64 targetEpoch, bool privateMerge) internal view returns (uint256[64] memory f)
    {
        _check(a.pool,a.recipient,a.batchDigestField,a.feeQuoteDigestField,a.saltedAmountHash,
            a.legIndex,a.feeLegIndex,a.legCount,privateMerge);
        f[0]=2; f[1]=8; f[2]=32; f[3]=block.chainid;
        f[4]=uint160(a.pool); f[5]=privateMerge ? 1 : 6;
        f[6]=sourceEpoch; f[7]=targetEpoch; f[8]=uint160(a.token); f[9]=uint160(a.recipient);
        f[10]=0; f[11]=uint160(a.protocolFeeRecipient); f[12]=0; f[13]=uint160(a.partnerFeeRecipient);
        f[14]=0; f[15]=VantaEpochCheckpointRef.compute(sourceEpoch,a.sourceSlotCount,a.checkpointX,a.checkpointY);
        for (uint256 i; i<32; ++i) { _field(a.nullifiers[i]); f[16+i]=a.nullifiers[i]; }
        for (uint256 i; i<5; ++i) { _field(a.outputs[i]); f[48+i]=a.outputs[i]; }
        f[53]=VantaTokenHash.compute(block.chainid,a.pool,a.token);
        f[54]=a.batchDigestField; f[55]=a.feeQuoteDigestField;
        f[56]=a.legIndex; f[57]=a.feeLegIndex; f[58]=a.legCount;
        f[59]=a.protocolFeeCap; f[60]=a.partnerFeeCap; f[61]=a.saltedAmountHash;
        f[62]=5; f[63]=1;
    }

    function _exitCheck(uint8 leg, uint8 feeLeg, uint8 count, address protocolRecipient,
        address partnerRecipient, uint128 protocolFee, uint128 partnerFee, uint128 protocolCap,
        uint128 partnerCap) private pure
    {
        if (count != 1 || leg != 0 || feeLeg != 0 || protocolFee > protocolCap || partnerFee > partnerCap ||
            protocolRecipient == address(0) || (partnerFee != 0 && partnerRecipient == address(0)))
            revert InvalidFamilyAction();
    }
    function exitEight(Statement8.LegPublic memory a, uint64 sourceEpoch,
        uint128 protocolFee, uint128 partnerFee) internal view returns (uint256[40] memory f)
    {
        _exitCheck(a.legIndex,a.feeLegIndex,a.legCount,a.protocolFeeRecipient,a.partnerFeeRecipient,
            protocolFee,partnerFee,a.protocolFeeCap,a.partnerFeeCap);
        f=orderedEight(a,sourceEpoch,0,false); f[10]=protocolFee; f[12]=partnerFee; f[39]=2;
    }
    function exitThirtyTwo(Statement32.LegPublic memory a, uint64 sourceEpoch,
        uint128 protocolFee, uint128 partnerFee) internal view returns (uint256[64] memory f)
    {
        _exitCheck(a.legIndex,a.feeLegIndex,a.legCount,a.protocolFeeRecipient,a.partnerFeeRecipient,
            protocolFee,partnerFee,a.protocolFeeCap,a.partnerFeeCap);
        f=orderedThirtyTwo(a,sourceEpoch,0,false); f[10]=protocolFee; f[12]=partnerFee; f[63]=2;
    }
}
