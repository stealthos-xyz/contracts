// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaFamilyAggregateGroth16PreAudit as Agg} from "./VantaFamilyAggregateGroth16PreAudit.sol";
import {VantaEpochStateV1} from "./VantaEpochStateV1.sol";
import {VantaV8FiveRowKzgResearch as Kzg} from "./VantaV8FiveRowKzgResearch.sol";
import {VantaFamilyEpochProofVerifierPreAudit as EpochVerifier} from "./VantaFamilyEpochProofVerifierPreAudit.sol";
import {VantaV8StatementResearch as Statement8} from "./VantaV8StatementResearch.sol";
import {VantaV8Statement32Research as Statement32} from "./VantaV8Statement32Research.sol";
import {VantaFamilyFullBundleVerifierPreAudit as Bundle} from "./VantaFamilyFullBundleVerifierPreAudit.sol";
import {VantaFamilyEnhancedFeeAdapterPreAudit as FeeAdapter} from "./VantaFamilyEnhancedFeeAdapterPreAudit.sol";
import {VantaEnhancedTreesPreAudit as Trees, IVantaEnhancedAuthorizationProof}
    from "./VantaEnhancedClaimLogicPreAudit.sol";

library VantaEnhancedFundingTypes {
    struct FundingHeader {
        uint8 width;
        uint64 sourceEpoch;
        uint256 sourceCheckpoint;
        uint64 targetEpoch;
        uint256 targetCheckpoint;
        uint256 reservationCommitment;
        uint256 authorizationDigest;
        uint256 amountHash;
        uint256 scopeDigest;
        uint256 feeTermsHash;
        uint256 partnerRegistryRoot;
        uint64 authorizationEpoch;
        bytes32 nonce;
        uint64 deadline;
        address relayer;
        bytes32 nullifiersHash;
        bytes32 outputsHash;
        bytes32 envelopesHash;
        uint8[3] feeSlots;
    }
    struct FundingProof8 {
        Statement8.LegPublic action;
        Bundle.V8Gate0Data gate0;
        Bundle.Gate1Data gate1;
        Bundle.LinkData link;
        Kzg.RowKey[5] rowKeys;
        bytes[5] encryptedOutputs;
        bytes feeProof;
        bytes authorizationProof;
    }
    struct FundingProof32 {
        Statement32.LegPublic action;
        Bundle.V8Gate0Data gate0;
        Bundle.Gate1Data gate1;
        Bundle.LinkData link;
        Kzg.RowKey[5] rowKeys;
        bytes[5] encryptedOutputs;
        bytes feeProof;
        bytes authorizationProof;
    }
    struct PublicBatch {
        address[] recipients;
        uint128[] amounts;
    }
    struct FundingPins {
        Trees.Pins enhanced;
        address normalVerifier;
        bytes32 normalVerifierCodehash;
        address feeVerifier;
        bytes32 feeVerifierCodehash;
        address kzgUpdater;
        bytes32 kzgCodehash;
        address protocolRecipient;
        address partnerRecipient;
    }
}

/// @notice Atomic funding of one private reservation in the existing pool.
/// @dev Linked delegatecall only, through the pool's reentrancy/signature guard.
///      No asset transfer or escrow decrement occurs here. Gate0 consumes the
///      inputs and conserves five private outputs plus the privately reserved
///      net value. The hidden-fee proof allocates the mandatory fee notes.
library VantaEnhancedFundingLogicPreAudit {
    using VantaEpochStateV1 for VantaEpochStateV1.State;
    using Trees for Trees.State;

    struct ActionView {
        address pool;
        address token;
        address recipient;
        address protocolRecipient;
        address partnerRecipient;
        uint128 protocolCap;
        uint128 partnerCap;
        uint256 amountHash;
        uint256 batchDigest;
        uint256 quoteField;
        uint8 legIndex;
        uint8 feeLegIndex;
        uint8 legCount;
        bytes32 nullifiersHash;
        bytes32 outputsHash;
    }

    bytes32 private constant PUBLIC_BATCH_DOMAIN = keccak256("VANTA_V8_ATOMIC_PUBLIC_BATCH_V1");

    error InvalidPublicBatch();
    error ReservationCapacityReached();
    error InvalidFundingHeader();
    error InvalidFundingSource();
    error InvalidFundingProof();
    error InvalidFundingFeeProof();
    error FundingTargetUnavailable();
    error FundingDependencyChanged();

    event CanonicalKzgRow(uint64 indexed epoch, uint64 indexed row, uint256 indexed commitment);
    event CanonicalEncryptedNote(
        uint64 indexed epoch, uint64 indexed row, uint256 indexed commitment,
        bytes32 envelopeHash, bytes encryptedEnvelope
    );
    event NullifierConsumed(uint256 indexed nullifier, uint8 indexed width);

    /// @dev Decode the large nested proof only inside the linked library.
    /// Keeping one bytes envelope at the pool boundary avoids duplicating
    /// 8x5/32x5 ABI decoders in the funds-holding contract.
    function authorize(
        VantaEpochStateV1.State storage epochs,
        mapping(bytes32 => bool) storage usedNonce,
        mapping(uint256 => bool) storage commitmentSeen,
        Trees.State storage enhanced,
        VantaEnhancedFundingTypes.FundingHeader calldata h,
        bytes calldata encodedProof,
        bytes32 signedQuoteHash,
        VantaEnhancedFundingTypes.FundingPins memory pins
    ) external returns (uint256) {
        // Every admitted reservation permanently needs three spent-tree slots.
        // Index zero is the sentinel. Do not admit obligations that could
        // outlive the finite global nullifier-tree capacity.
        if (enhanced.reservations.count >= ((uint64(1) << 32) - 1) / 3)
            revert ReservationCapacityReached();
        return _dispatch(epochs,usedNonce,commitmentSeen,enhanced,h,encodedProof,signedQuoteHash,pins,0);
    }

    /// @notice Exact ordered recipient/amount binding, domain-separated from
    /// a reservation. Repeated recipients are allowed and retain list order.
    function publicBatchDigest(
        bytes32 nonce, uint8 width, VantaEnhancedFundingTypes.PublicBatch calldata batch,
        Trees.Pins memory p
    ) public view returns (uint256 digest, uint128 total) {
        uint256 count = batch.recipients.length;
        if (count < 2 || count > 32 || batch.amounts.length != count || nonce == bytes32(0) ||
            (width != 8 && width != 32)) revert InvalidPublicBatch();
        uint256 sum;
        for (uint256 i; i < count; ++i) {
            if (batch.recipients[i] == address(0) || batch.recipients[i] == address(this) ||
                batch.amounts[i] == 0 || uint256(batch.amounts[i]) >= (uint256(1) << 120))
                revert InvalidPublicBatch();
            sum += batch.amounts[i];
        }
        if (sum >= (uint256(1) << 120)) revert InvalidPublicBatch();
        digest = uint256(keccak256(abi.encode(PUBLIC_BATCH_DOMAIN,p.domain.familyTag,
            p.domain.chainId,address(this),p.domain.asset,p.domain.genesisHash,p.domain.generationId,
            p.feePolicyHash,nonce,width,batch.recipients,batch.amounts))) % Trees.FR;
        if (digest == 0) revert InvalidPublicBatch();
        total = uint128(sum);
    }

    function settlePublicBatch(
        VantaEpochStateV1.State storage epochs,
        mapping(bytes32 => bool) storage usedNonce,
        mapping(uint256 => bool) storage commitmentSeen,
        Trees.State storage enhanced,
        VantaEnhancedFundingTypes.FundingHeader calldata h,
        bytes calldata encodedProof,
        VantaEnhancedFundingTypes.PublicBatch calldata batch,
        bytes32 signedQuoteHash,
        VantaEnhancedFundingTypes.FundingPins memory pins
    ) external returns (uint128 total) {
        uint256 digest;
        (digest,total) = publicBatchDigest(h.nonce,h.width,batch,pins.enhanced);
        if (h.authorizationDigest != digest) revert InvalidPublicBatch();
        _dispatch(epochs,usedNonce,commitmentSeen,enhanced,h,encodedProof,signedQuoteHash,pins,total);
    }

    function _dispatch(
        VantaEpochStateV1.State storage epochs,
        mapping(bytes32 => bool) storage usedNonce,
        mapping(uint256 => bool) storage commitmentSeen,
        Trees.State storage enhanced,
        VantaEnhancedFundingTypes.FundingHeader calldata h,
        bytes calldata encodedProof,
        bytes32 signedQuoteHash,
        VantaEnhancedFundingTypes.FundingPins memory pins,
        uint128 publicBatchTotal
    ) private returns (uint256) {
        if (h.width == 8) {
            VantaEnhancedFundingTypes.FundingProof8 memory proof =
                abi.decode(encodedProof,(VantaEnhancedFundingTypes.FundingProof8));
            return _authorizeEight(epochs,usedNonce,commitmentSeen,enhanced,h,proof,signedQuoteHash,pins,publicBatchTotal);
        }
        if (h.width == 32) {
            VantaEnhancedFundingTypes.FundingProof32 memory proof =
                abi.decode(encodedProof,(VantaEnhancedFundingTypes.FundingProof32));
            return _authorizeThirtyTwo(epochs,usedNonce,commitmentSeen,enhanced,h,proof,signedQuoteHash,pins,publicBatchTotal);
        }
        revert InvalidFundingHeader();
    }

    function _authorizeEight(
        VantaEpochStateV1.State storage epochs,
        mapping(bytes32 => bool) storage usedNonce,
        mapping(uint256 => bool) storage commitmentSeen,
        Trees.State storage enhanced,
        VantaEnhancedFundingTypes.FundingHeader calldata h,
        VantaEnhancedFundingTypes.FundingProof8 memory p,
        bytes32 signedQuoteHash,
        VantaEnhancedFundingTypes.FundingPins memory pins,
        uint128 publicBatchTotal
    ) private returns (uint256 nextCheckpoint) {
        if (h.width != 8) revert InvalidFundingHeader();
        _requirePins(pins);
        VantaEpochStateV1.Snapshot memory source = epochs.requireSpendSource(h.sourceEpoch, h.sourceCheckpoint);
        Statement8.LegPublic memory a = p.action;
        if (a.sourceSlotCount != source.slotCount || a.checkpointX != source.x || a.checkpointY != source.y)
            revert InvalidFundingSource();
        _check(epochs, usedNonce, commitmentSeen, h, _viewEight(a), a.outputs, p.encryptedOutputs, signedQuoteHash, pins, publicBatchTotal != 0);
        if (!EpochVerifier(pins.normalVerifier).verifyEpoch8(a, p.gate0, p.gate1, p.link,
            false, h.sourceEpoch, h.targetEpoch, source.slotCount, source.x, source.y))
            revert InvalidFundingProof();
        if (publicBatchTotal == 0) _verifyAuthorization(h, p.authorizationProof, pins.enhanced);
        else _verifyPublicTotal(h,p.authorizationProof,pins.normalVerifier,publicBatchTotal);
        _verifyFees(h, a.outputs, p.feeProof, signedQuoteHash, pins.feeVerifier, publicBatchTotal == 0 ? 0 : 3);
        (uint256 verifiedRef, uint256 x, uint256 y, uint64 firstRow) = _verifiedAppend(epochs, h, a.outputs, p.rowKeys, pins.kzgUpdater);
        nextCheckpoint = epochs.recordVerifiedCrossEpochEight(h.sourceEpoch, h.sourceCheckpoint,
            h.targetEpoch, h.targetCheckpoint, x, y, a.nullifiers);
        for (uint256 i; i < 8; ++i) emit NullifierConsumed(a.nullifiers[i], 8);
        _finish(usedNonce, commitmentSeen, enhanced, h, a.outputs, p.encryptedOutputs,
            firstRow, verifiedRef, nextCheckpoint, pins.enhanced.hasher, publicBatchTotal == 0);
    }

    function _authorizeThirtyTwo(
        VantaEpochStateV1.State storage epochs,
        mapping(bytes32 => bool) storage usedNonce,
        mapping(uint256 => bool) storage commitmentSeen,
        Trees.State storage enhanced,
        VantaEnhancedFundingTypes.FundingHeader calldata h,
        VantaEnhancedFundingTypes.FundingProof32 memory p,
        bytes32 signedQuoteHash,
        VantaEnhancedFundingTypes.FundingPins memory pins,
        uint128 publicBatchTotal
    ) private returns (uint256 nextCheckpoint) {
        if (h.width != 32) revert InvalidFundingHeader();
        _requirePins(pins);
        VantaEpochStateV1.Snapshot memory source = epochs.requireSpendSource(h.sourceEpoch, h.sourceCheckpoint);
        Statement32.LegPublic memory a = p.action;
        if (a.sourceSlotCount != source.slotCount || a.checkpointX != source.x || a.checkpointY != source.y)
            revert InvalidFundingSource();
        _check(epochs, usedNonce, commitmentSeen, h, _viewThirtyTwo(a), a.outputs, p.encryptedOutputs, signedQuoteHash, pins, publicBatchTotal != 0);
        if (!EpochVerifier(pins.normalVerifier).verifyEpoch32(a, p.gate0, p.gate1, p.link,
            false, h.sourceEpoch, h.targetEpoch, source.slotCount, source.x, source.y))
            revert InvalidFundingProof();
        if (publicBatchTotal == 0) _verifyAuthorization(h, p.authorizationProof, pins.enhanced);
        else _verifyPublicTotal(h,p.authorizationProof,pins.normalVerifier,publicBatchTotal);
        _verifyFees(h, a.outputs, p.feeProof, signedQuoteHash, pins.feeVerifier, publicBatchTotal == 0 ? 0 : 3);
        (uint256 verifiedRef, uint256 x, uint256 y, uint64 firstRow) = _verifiedAppend(epochs, h, a.outputs, p.rowKeys, pins.kzgUpdater);
        nextCheckpoint = epochs.recordVerifiedCrossEpochThirtyTwo(h.sourceEpoch, h.sourceCheckpoint,
            h.targetEpoch, h.targetCheckpoint, x, y, a.nullifiers);
        for (uint256 i; i < 32; ++i) emit NullifierConsumed(a.nullifiers[i], 32);
        _finish(usedNonce, commitmentSeen, enhanced, h, a.outputs, p.encryptedOutputs,
            firstRow, verifiedRef, nextCheckpoint, pins.enhanced.hasher, publicBatchTotal == 0);
    }

    function _requirePins(VantaEnhancedFundingTypes.FundingPins memory p) private view {
        Trees.requirePins(p.enhanced);
        if (p.normalVerifier.code.length == 0 || p.feeVerifier.code.length == 0 || p.kzgUpdater.code.length == 0 ||
            p.normalVerifier.codehash != p.normalVerifierCodehash || p.feeVerifier.codehash != p.feeVerifierCodehash ||
            p.kzgUpdater.codehash != p.kzgCodehash || p.protocolRecipient == address(0) ||
            p.enhanced.feePolicyHash == bytes32(0) ||
            p.enhanced.minimumDelayEpochs <= p.enhanced.maximumAuthorizationAgeEpochs ||
            uint256(p.enhanced.maximumWindowEpochs) < uint256(p.enhanced.minimumDelayEpochs) + 2)
            revert FundingDependencyChanged();
    }

    function _check(
        VantaEpochStateV1.State storage epochs,
        mapping(bytes32 => bool) storage usedNonce,
        mapping(uint256 => bool) storage commitmentSeen,
        VantaEnhancedFundingTypes.FundingHeader calldata h,
        ActionView memory a,
        uint256[5] memory outputs,
        bytes[5] memory envelopes,
        bytes32 signedQuoteHash,
        VantaEnhancedFundingTypes.FundingPins memory pins,
        bool publicBatch
    ) private view {
        uint64 nowEpoch = uint64(block.timestamp / Trees.EPOCH_SECONDS);
        if (h.nonce == bytes32(0) || usedNonce[h.nonce] || h.relayer == address(0) || h.deadline < block.timestamp ||
            h.deadline > block.timestamp + 3600 ||
            (publicBatch
                ? (h.reservationCommitment != 0 || h.scopeDigest != 0 || h.authorizationEpoch != 0)
                : (h.authorizationEpoch == 0 || h.authorizationEpoch > nowEpoch ||
                    nowEpoch - h.authorizationEpoch > pins.enhanced.maximumAuthorizationAgeEpochs ||
                    h.reservationCommitment == 0 || h.reservationCommitment >= Trees.FR || commitmentSeen[h.reservationCommitment] ||
                    h.scopeDigest == 0 || h.scopeDigest >= Trees.FR)) ||
            h.authorizationDigest == 0 || h.authorizationDigest >= Trees.FR ||
            h.amountHash == 0 || h.amountHash >= Trees.FR ||
            h.feeTermsHash == 0 || h.feeTermsHash >= Trees.FR ||
            h.partnerRegistryRoot == 0 || h.partnerRegistryRoot >= Trees.FR ||
            a.pool != address(this) || a.token != pins.enhanced.domain.asset || a.recipient != address(this) ||
            a.protocolRecipient != pins.protocolRecipient || a.partnerRecipient != pins.partnerRecipient ||
            a.protocolCap != 0 || a.partnerCap != 0 || a.legIndex != 0 || a.feeLegIndex != 0 || a.legCount != 1 ||
            a.amountHash != h.amountHash || a.batchDigest != h.authorizationDigest ||
            a.quoteField == 0 || a.quoteField != uint256(signedQuoteHash) % Trees.FR ||
            a.nullifiersHash != h.nullifiersHash || a.outputsHash != h.outputsHash ||
            h.feeSlots[0] >= h.feeSlots[1] || h.feeSlots[1] >= h.feeSlots[2] || h.feeSlots[2] >= 5)
            revert InvalidFundingHeader();

        bytes32[5] memory hashes;
        for (uint256 i; i < 5; ++i) {
            uint256 cm = outputs[i];
            if (cm == 0 || cm >= Trees.FR || commitmentSeen[cm] || cm == h.reservationCommitment ||
                envelopes[i].length < 64 || envelopes[i].length > 2048 || envelopes[i][0] != bytes1(uint8(1)))
                revert InvalidFundingHeader();
            for (uint256 j; j < i; ++j) if (outputs[j] == cm) revert InvalidFundingHeader();
            hashes[i] = keccak256(envelopes[i]);
        }
        if (h.envelopesHash != keccak256(abi.encode(hashes))) revert InvalidFundingHeader();
        VantaEpochStateV1.Epoch storage target = epochs.epochs[epochs.currentEpoch];
        if (h.targetEpoch != epochs.currentEpoch || h.targetCheckpoint != target.currentRef || target.closed ||
            uint256(target.slotCount) + 5 > 65_536) revert FundingTargetUnavailable();
    }

    function _verifyAuthorization(VantaEnhancedFundingTypes.FundingHeader calldata h, bytes memory proof, Trees.Pins memory p)
        private view
    {
        if (proof.length != 256) revert InvalidFundingProof();
        uint256[19] memory s;
        s[0] = h.reservationCommitment; s[1] = h.authorizationDigest; s[2] = h.amountHash; s[3] = h.scopeDigest;
        s[4] = p.domain.familyTag; s[5] = p.domain.chainId; s[6] = uint160(address(this)); s[7] = uint160(p.domain.asset);
        s[8] = uint128(uint256(p.domain.genesisHash)); s[9] = uint256(p.domain.genesisHash) >> 128;
        s[10] = uint128(uint256(p.domain.generationId)); s[11] = uint256(p.domain.generationId) >> 128;
        s[12] = h.authorizationEpoch; s[13] = uint128(uint256(p.feePolicyHash)); s[14] = uint256(p.feePolicyHash) >> 128;
        s[15] = h.feeTermsHash; s[16] = h.width; s[17] = p.maximumWindowEpochs; s[18] = p.minimumDelayEpochs;
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) =
            abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));
        if (!IVantaEnhancedAuthorizationProof(p.authorizationVerifier).verifyProof(a, b, c, s)) revert InvalidFundingProof();
    }

    /// @dev Only immediate PUBLIC batches expose the public sum. Enhanced
    /// authorization never routes through the legacy payout aggregate.
    function _verifyPublicTotal(VantaEnhancedFundingTypes.FundingHeader calldata h,
        bytes memory encodedAggregate, address verifier, uint128 total) private view
    {
        (Agg.VerifyingKey memory vk,Agg.Proof memory proof,uint256[11] memory inputs) =
            abi.decode(encodedAggregate,(Agg.VerifyingKey,Agg.Proof,uint256[11]));
        if (!EpochVerifier(verifier).verifyPayout(vk,proof,inputs,h.authorizationDigest,h.amountHash,total))
            revert InvalidFundingProof();
    }

    function _verifyFees(VantaEnhancedFundingTypes.FundingHeader calldata h, uint256[5] memory outputs,
        bytes memory proof, bytes32 quoteHash, address verifier, uint8 mode) private view
    {
        FeeAdapter.CanonicalQuote memory q = FeeAdapter.CanonicalQuote({
            signedQuoteHash: quoteHash, outputs: outputs, feeSlots: h.feeSlots,
            feeTermsHash: h.feeTermsHash, width: h.width, mode: mode, amountHash: h.amountHash,
            batchDigest: h.authorizationDigest, partnerRegistryRoot: h.partnerRegistryRoot,
            signedPartnerNonce: h.nonce, relayer: h.relayer
        });
        if (!FeeAdapter(verifier).verifyCombined(q, proof)) revert InvalidFundingFeeProof();
    }

    function _verifiedAppend(VantaEpochStateV1.State storage epochs,
        VantaEnhancedFundingTypes.FundingHeader calldata h, uint256[5] memory outputs,
        Kzg.RowKey[5] memory rowKeys, address updater)
        private view returns (uint256 toRef, uint256 x, uint256 y, uint64 firstRow)
    {
        VantaEpochStateV1.Epoch storage target = epochs.epochs[h.targetEpoch];
        firstRow = target.slotCount;
        uint256 fromRef;
        (fromRef, toRef, x, y) = Kzg(updater).verifyEpochRows(h.targetEpoch, firstRow, target.x, target.y, 5, outputs, rowKeys);
        if (fromRef != h.targetCheckpoint) revert FundingTargetUnavailable();
    }

    function _finish(mapping(bytes32 => bool) storage usedNonce, mapping(uint256 => bool) storage commitmentSeen,
        Trees.State storage enhanced, VantaEnhancedFundingTypes.FundingHeader calldata h,
        uint256[5] memory outputs, bytes[5] memory envelopes,
        uint64 firstRow, uint256 verifiedRef, uint256 recordedRef, address hasher, bool reserve) private
    {
        if (verifiedRef != recordedRef) revert InvalidFundingProof();
        usedNonce[h.nonce] = true;
        for (uint256 i; i < 5; ++i) {
            commitmentSeen[outputs[i]] = true;
            emit CanonicalKzgRow(h.targetEpoch, firstRow + uint64(i), outputs[i]);
            emit CanonicalEncryptedNote(h.targetEpoch, firstRow + uint64(i), outputs[i], keccak256(envelopes[i]), envelopes[i]);
        }
        // A repeated reservation would reuse the same three claim nullifiers
        // and strand the second funding amount. Reserve its identity once.
        if (reserve) {
            commitmentSeen[h.reservationCommitment] = true;
            enhanced.publish();
            uint64 index = Trees.append(enhanced.reservations, enhanced.zeros, hasher, h.reservationCommitment);
            emit Trees.EnhancedReservation(index, h.reservationCommitment);
        }
    }

    function _viewEight(Statement8.LegPublic memory a) private pure returns (ActionView memory) {
        return ActionView(a.pool, a.token, a.recipient, a.protocolFeeRecipient, a.partnerFeeRecipient,
            a.protocolFeeCap, a.partnerFeeCap, a.saltedAmountHash, a.batchDigestField, a.feeQuoteDigestField,
            a.legIndex, a.feeLegIndex, a.legCount, keccak256(abi.encode(a.nullifiers)), keccak256(abi.encode(a.outputs)));
    }

    function _viewThirtyTwo(Statement32.LegPublic memory a) private pure returns (ActionView memory) {
        return ActionView(a.pool, a.token, a.recipient, a.protocolFeeRecipient, a.partnerFeeRecipient,
            a.protocolFeeCap, a.partnerFeeCap, a.saltedAmountHash, a.batchDigestField, a.feeQuoteDigestField,
            a.legIndex, a.feeLegIndex, a.legCount, keccak256(abi.encode(a.nullifiers)), keccak256(abi.encode(a.outputs)));
    }
}
