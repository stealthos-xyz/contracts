// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaPoseidonV832Fast} from "./VantaPoseidonV832Fast.sol";
import {VantaCheckpointRef} from "./VantaCheckpointRef.sol";
import {VantaTokenHash} from "./VantaTokenHash.sol";
import {VantaBaseChainPolicy} from "./VantaBaseChainPolicy.sol";

/// @title Exact Vanta V8 32x5 action statement (research)
/// @notice Recreates the 64-field BN254 Poseidon T4 statement from PUBLIC,
///         explicitly typed action data. Per-leg withdrawn amounts and fees
///         stay private: only independently salted amounts and fee caps appear.
/// @dev NOT CUSTODY AUTHORIZATION. This does not authenticate fee quote/batch
///      signatures, verify proofs or approve the KZG checkpoint. Never accept
///      caller-provided token hash, source checkpoint ref, chain id, or protocol
///      version in a settlement path. An actual pool must also bind the typed
///      batch digest and fee-quote digest to its independently verified intent.
library VantaV8Statement32Research {
    uint256 internal constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant DOMAIN = 0x53544f5356384830; // STOSV8H0
    uint256 internal constant FIELD_COUNT = 64;

    struct LegPublic {
        address pool;
        address token;
        address recipient;
        address protocolFeeRecipient;
        address partnerFeeRecipient;
        uint64 sourceSlotCount;
        uint256 checkpointX;
        uint256 checkpointY;
        uint256 batchDigestField;
        uint256 feeQuoteDigestField;
        uint8 legIndex;
        uint8 feeLegIndex;
        uint8 legCount;
        uint128 protocolFeeCap;
        uint128 partnerFeeCap;
        uint256 saltedAmountHash;
        uint256[32] nullifiers;
        uint256[5] outputs;
    }

    error WrongChain();
    error InvalidAction();
    error InvalidField();

    function _orderedFields(LegPublic memory action, bool privateMerge)
        private view returns (uint256[64] memory f)
    {
        if (!VantaBaseChainPolicy.isSupported(block.chainid)) revert WrongChain();
        // Native ETH is the canonical zero-address asset, not a missing token.
        // The asset is separately authenticated by pool admission and token_hash.
        if (action.pool == address(0) ||
            (privateMerge ? (action.recipient != address(0) ||
                action.protocolFeeCap != 0 || action.partnerFeeCap != 0)
              : action.recipient == address(0)) ||
            action.batchDigestField == 0 || action.batchDigestField >= FR ||
            action.feeQuoteDigestField == 0 || action.feeQuoteDigestField >= FR ||
            action.saltedAmountHash == 0 || action.saltedAmountHash >= FR ||
            action.legCount < 1 || action.legCount > 8 ||
            action.legIndex >= action.legCount ||
            action.feeLegIndex >= action.legCount) revert InvalidAction();

        // Reconstruct chain, token, checkpoint, and fixed statement constants.
        // V8 disables public per-leg fees, withdrawal amount and output count.
        // The hidden fee amounts are constrained by Gate0 against these caps.
        f[0] = 2; // protocol version
        f[1] = 8; // circuit version
        f[2] = 32; // physical input slots
        f[3] = block.chainid;
        f[4] = uint160(action.pool);
        f[5] = privateMerge ? 1 : 6; // private joinsplit / withdrawal batch
        f[6] = 0; // source table zero
        f[7] = 0; // target table zero
        f[8] = uint160(action.token);
        f[9] = privateMerge ? 0 : uint160(action.recipient);
        f[10] = 0; // actual private protocol fee is NOT public
        f[11] = uint160(action.protocolFeeRecipient);
        f[12] = 0; // actual private partner fee is NOT public
        f[13] = uint160(action.partnerFeeRecipient);
        f[14] = 0; // P0 aux data hash
        f[15] = VantaCheckpointRef.compute(
            0, action.sourceSlotCount, action.checkpointX, action.checkpointY
        );
        for (uint256 i = 0; i < 32; ++i) {
            uint256 nf = action.nullifiers[i];
            if (nf == 0 || nf >= FR) revert InvalidField();
            f[16 + i] = nf;
        }
        for (uint256 i = 0; i < 5; ++i) {
            uint256 cm = action.outputs[i];
            if (cm == 0 || cm >= FR) revert InvalidField();
            f[48 + i] = cm;
        }
        f[53] = VantaTokenHash.compute(
            block.chainid, action.pool, action.token
        );
        f[54] = action.batchDigestField;
        f[55] = action.feeQuoteDigestField;
        f[56] = action.legIndex;
        f[57] = action.feeLegIndex;
        f[58] = action.legCount;
        f[59] = action.protocolFeeCap;
        f[60] = action.partnerFeeCap;
        f[61] = action.saltedAmountHash;
        f[62] = 5; // physical output slots
        f[63] = 0; // reserved
    }

    /// @notice Existing public-payout V8 action. No opcode changes.
    function orderedFields(LegPublic memory action)
        internal view returns (uint256[64] memory)
    {
        return _orderedFields(action, false);
    }

    /// @notice Zero-payout private joinsplit/consolidation action. The
    /// caller must use a separately pinned V8 setup and prove all three
    /// gates. Fee caps and public recipient are exactly zero.
    function privateMergeOrderedFields(LegPublic memory action)
        internal view returns (uint256[64] memory)
    {
        return _orderedFields(action, true);
    }

    function privateMergeDigest(LegPublic memory action)
        internal view returns (uint256)
    {
        return VantaPoseidonV832Fast.digest64(
            privateMergeOrderedFields(action)
        );
    }

    function digest(LegPublic memory action)
        internal view returns (uint256 running)
    {
        // Identical Rust Poseidon T4 permutation and V8 domain, but the
        // canonical round constants/MDS are loaded ONCE for all 20 absorbs.
        // Independent native-to-EVM proof fixtures guard every field.
        uint256[64] memory f = orderedFields(action);
        running = VantaPoseidonV832Fast.digest64(f);
    }
}

/// @notice Read-only cross-language research oracle. No settlement methods.
contract VantaV8Statement32ResearchHarness {
    function orderedFields(VantaV8Statement32Research.LegPublic memory action)
        external view returns (uint256[64] memory)
    {
        return VantaV8Statement32Research.orderedFields(action);
    }

    function privateMergeOrderedFields(VantaV8Statement32Research.LegPublic memory action)
        external view returns (uint256[64] memory)
    {
        return VantaV8Statement32Research.privateMergeOrderedFields(action);
    }

    function privateMergeDigest(VantaV8Statement32Research.LegPublic memory action)
        external view returns (uint256)
    {
        return VantaV8Statement32Research.privateMergeDigest(action);
    }

    function digest(VantaV8Statement32Research.LegPublic memory action)
        external view returns (uint256)
    {
        return VantaV8Statement32Research.digest(action);
    }
}
