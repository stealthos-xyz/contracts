// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaFamilyUnifiedPoolPreAudit} from "./VantaFamilyUnifiedPoolPreAudit.sol";
import {VantaFamilyEnhancedFeeAdapterPreAudit as EnhancedFees} from "./VantaFamilyEnhancedFeeAdapterPreAudit.sol";
import {VantaEnhancedTreesPreAudit as Trees,
    VantaEnhancedClaimLogicPreAudit as Claims} from "./VantaEnhancedClaimLogicPreAudit.sol";
import {VantaEnhancedFundingTypes as Funding,
    VantaEnhancedFundingLogicPreAudit as FundingLogic} from "./VantaEnhancedFundingLogicPreAudit.sol";

/// @notice Candidate integration only. Requires fresh keys, full qualification
/// and P0 signoff. Never deploy this candidate with production funds.
/// @dev Inherits deposits, instant withdrawals, private sends, historical
/// spending, permissionless rollover and no-append emergency exits. Reserved
/// amounts remain part of the SAME escrow liability until individual claims
/// pay. There is no public reserved-total delta and no reserve cancellation.
contract VantaFamilyEnhancedPoolPreAudit is VantaFamilyUnifiedPoolPreAudit {
    struct BaseConfiguration {
        address protocolFeePolicy;
        address asset;
        address exitVerifier;
        address normalVerifier;
        address combinedFeeVerifier;
        address kzg;
        uint256 initialX;
        uint256 initialY;
        address feeSigner;
        address protocolRecipient;
        address partnerRecipient;
        uint128 minimumFee;
        uint128 fixedPartnerExitFee;
        bytes32 policyHash;
        uint16[2] exitFeeRates;
        bytes32 generationId;
        address retirementAuthority;
        bytes32 setupId;
        bytes32 familyTag;
        uint256 chainId;
    }
    struct EnhancedConfiguration {
        address authorizationVerifier;
        address claimVerifier;
        address feeVerifier;
        address poseidon;
        bytes32 genesisHash;
        uint64 maximumWindowEpochs;
        uint64 minimumDelayEpochs;
        uint64 maximumAuthorizationAgeEpochs;
    }
    bytes32 private constant ENHANCED_TYPEHASH = keccak256(
        "EnhancedEpochFunding(bytes32 generationId,bytes32 genesisHash,bytes32 feePolicyHash,bytes32 headerHash)"
    );
    bytes32 public immutable releaseGenesisHash;
    address public immutable enhancedAuthorizationVerifier;
    address public immutable enhancedClaimVerifier;
    address public immutable enhancedFeeVerifier;
    address public immutable enhancedPoseidon;
    bytes32 private immutable enhancedAuthorizationVerifierCodehash;
    bytes32 private immutable enhancedClaimVerifierCodehash;
    bytes32 private immutable enhancedFeeVerifierCodehash;
    bytes32 private immutable enhancedPoseidonCodehash;
    bytes32 private immutable enhancedFundingLogicCodehash;
    bytes32 private immutable enhancedClaimLogicCodehash;
    uint64 public immutable maximumWindowEpochs;
    uint64 public immutable minimumDelayEpochs;
    uint64 public immutable maximumAuthorizationAgeEpochs;
    Trees.State private enhancedState;

    error InvalidEnhancedSetup();
    event PublicBatchSettled(bytes32 indexed nonce,uint256 indexed batchDigest,uint8 recipients,uint128 total);
    event EnhancedClaimSettled(uint256 indexed nullifier, address indexed recipient, uint128 amount);

    constructor(BaseConfiguration memory b, EnhancedConfiguration memory e)
        VantaFamilyUnifiedPoolPreAudit(
            b.asset,b.exitVerifier,b.normalVerifier,b.combinedFeeVerifier,b.kzg,
            b.initialX,b.initialY,b.feeSigner,b.protocolRecipient,b.partnerRecipient,
            b.minimumFee,b.fixedPartnerExitFee,b.policyHash,b.exitFeeRates,b.generationId,
            b.retirementAuthority,b.setupId,b.familyTag,b.chainId,b.protocolFeePolicy
        )
    {
        // Partners receive their own private KZG fee notes after SDK onboarding.
        // Bootstrap has no global partner recipient, vault or public fee.
        if (b.partnerRecipient != address(0) || b.fixedPartnerExitFee != 0 || b.exitFeeRates[1] != 0)
            revert InvalidEnhancedSetup();
        if (e.authorizationVerifier.code.length == 0 || e.claimVerifier.code.length == 0 ||
            e.feeVerifier.code.length == 0 || e.poseidon.code.length == 0 ||
            e.genesisHash == bytes32(0) || e.maximumWindowEpochs < 3 ||
            e.minimumDelayEpochs <= e.maximumAuthorizationAgeEpochs ||
            uint256(e.minimumDelayEpochs) + 2 > e.maximumWindowEpochs ||
            e.authorizationVerifier == e.claimVerifier || e.feeVerifier == b.combinedFeeVerifier)
            revert InvalidEnhancedSetup();
        EnhancedFees fee = EnhancedFees(e.feeVerifier);
        if (fee.releaseSetupId() != b.setupId || fee.releaseGenerationId() != b.generationId ||
            fee.releaseFamilyTag() != b.familyTag || fee.releaseChainId() != b.chainId ||
            fee.releaseGenesisHash() != e.genesisHash || fee.asset() != b.asset ||
            fee.policyHash() != feePolicyHash() || fee.minimumFee() != b.minimumFee ||
            address(fee.protocolFeePolicy()) != b.protocolFeePolicy)
            revert InvalidEnhancedSetup();
        releaseGenesisHash = e.genesisHash;
        enhancedAuthorizationVerifier = e.authorizationVerifier;
        enhancedClaimVerifier = e.claimVerifier;
        enhancedFeeVerifier = e.feeVerifier;
        enhancedPoseidon = e.poseidon;
        enhancedAuthorizationVerifierCodehash = e.authorizationVerifier.codehash;
        enhancedClaimVerifierCodehash = e.claimVerifier.codehash;
        enhancedFeeVerifierCodehash = e.feeVerifier.codehash;
        enhancedPoseidonCodehash = e.poseidon.codehash;
        enhancedFundingLogicCodehash = address(FundingLogic).codehash;
        enhancedClaimLogicCodehash = address(Claims).codehash;
        maximumWindowEpochs = e.maximumWindowEpochs;
        minimumDelayEpochs = e.minimumDelayEpochs;
        maximumAuthorizationAgeEpochs = e.maximumAuthorizationAgeEpochs;
        Claims.initialize(enhancedState,e.poseidon);
    }

    function _enhancedPins() private view returns (Trees.Pins memory p) {
        p.domain = Trees.Domain(address(asset),releaseGenesisHash,releaseGenerationId,
            uint256(releaseFamilyTag),releaseChainId);
        p.hasher=enhancedPoseidon; p.hasherCodehash=enhancedPoseidonCodehash;
        p.authorizationVerifier=enhancedAuthorizationVerifier;
        p.authorizationVerifierCodehash=enhancedAuthorizationVerifierCodehash;
        p.claimVerifier=enhancedClaimVerifier; p.claimVerifierCodehash=enhancedClaimVerifierCodehash;
        // Existing claim obligations do not consult a mutable fee policy.
        // New funding and batch quotes set the current policy explicitly.
        p.maximumWindowEpochs=maximumWindowEpochs; p.minimumDelayEpochs=minimumDelayEpochs;
        p.maximumAuthorizationAgeEpochs=maximumAuthorizationAgeEpochs;
    }
    function _fundingPins() private view returns (Funding.FundingPins memory p) {
        p.enhanced=_enhancedPins();
        p.enhanced.feePolicyHash=feePolicyHash();
        p.normalVerifier=address(normalVerifier); p.normalVerifierCodehash=normalVerifierCodehash;
        p.feeVerifier=enhancedFeeVerifier; p.feeVerifierCodehash=enhancedFeeVerifierCodehash;
        p.kzgUpdater=approvedKzgUpdater; p.kzgCodehash=approvedKzgCodehash;
        p.protocolRecipient=protocolFeeRecipient; p.partnerRecipient=partnerFeeRecipient;
    }
    function _fundingStructHash(Funding.FundingHeader calldata q) private view returns (bytes32) {
        return keccak256(abi.encode(ENHANCED_TYPEHASH,releaseGenerationId,releaseGenesisHash,
            feePolicyHash(),keccak256(abi.encode(q))));
    }
    function enhancedFundingDigest(Funding.FundingHeader calldata q) external view returns (bytes32) {
        return _typedDigest(_fundingStructHash(q));
    }
    function _prepareEnhancedFunding(Funding.FundingHeader calldata q, bytes calldata feeSignature)
        private view returns (bytes32)
    {
        _setup();
        if (address(FundingLogic).codehash != enhancedFundingLogicCodehash ||
            address(Claims).codehash != enhancedClaimLogicCodehash)
            revert InvalidEnhancedSetup();
        if (plannedExitOnlyAt != 0 && block.timestamp >= plannedExitOnlyAt) revert GenerationExitOnly();
        if (q.deadline > block.timestamp + 3600 || q.relayer != msg.sender) revert InvalidNormalSpend();
        return _authorize(_fundingStructHash(q),q.nonce,q.deadline,feeSignature);
    }
    /// @notice Exactly one authorization transaction for either note width.
    /// The SDK encodes the typed proof; the linked verifier logic decodes it.
    function authorizeEnhanced(Funding.FundingHeader calldata q, bytes calldata encodedProof,
        bytes calldata feeSignature) external noReentry
    {
        bytes32 signed = _prepareEnhancedFunding(q,feeSignature);
        FundingLogic.authorize(epochState,usedNonce,commitmentSeen,enhancedState,
            q,encodedProof,signed,_fundingPins());
        // Escrow balance and accountedLiability remain unchanged.
    }

    function publicBatchDigest(bytes32 nonce, uint8 width, Funding.PublicBatch calldata batch)
        external view returns (uint256 digest,uint128 total)
    {
        Trees.Pins memory p=_enhancedPins();
        p.feePolicyHash=feePolicyHash();
        return FundingLogic.publicBatchDigest(nonce,width,batch,p);
    }

    /// @notice One authorization and one atomic public settlement for 2-32
    /// recipients. All transfers revert together if any recipient rejects.
    function settlePublicBatch(Funding.FundingHeader calldata q, bytes calldata encodedProof,
        Funding.PublicBatch calldata batch, bytes calldata feeSignature) external noReentry
    {
        bytes32 signed = _prepareEnhancedFunding(q,feeSignature);
        uint128 total = FundingLogic.settlePublicBatch(epochState,usedNonce,commitmentSeen,
            enhancedState,q,encodedProof,batch,signed,_fundingPins());
        if (total > accountedLiability) revert InsufficientEscrow();
        accountedLiability -= total;
        for (uint256 i; i < batch.recipients.length; ++i)
            _transferExact(batch.recipients[i],batch.amounts[i]);
        emit PublicBatchSettled(q.nonce,q.authorizationDigest,uint8(batch.recipients.length),total);
    }

    /// @notice Any executor may submit a fixed-destination claim. Recovery
    /// uses the same nullifier and amount; it never releases the input notes.
    /// Delayed obligations survive signer failure and planned retirement.
    function executeEnhancedClaim(Trees.Claim calldata claim, bytes calldata proof) external noReentry {
        if (address(Claims).codehash != enhancedClaimLogicCodehash) revert InvalidEnhancedSetup();
        Claims.claim(enhancedState,epochState,_enhancedPins(),claim,proof);
        if (claim.amount > accountedLiability) revert InsufficientEscrow();
        accountedLiability -= claim.amount;
        _transferExact(claim.recipient,claim.amount);
        emit EnhancedClaimSettled(claim.nullifier,claim.recipient,claim.amount);
    }
    function checkpointEnhancedRoots() external noReentry {
        if (address(Claims).codehash != enhancedClaimLogicCodehash) revert InvalidEnhancedSetup();
        Claims.checkpoint(enhancedState);
    }
    /// @notice Roots the next claim transaction will see at its execution
    /// epoch. These are shared global checkpoints, never plan-specific roots.
    function enhancedClaimRoots() external view returns (uint256 reservationRoot,uint256 spentRoot,uint64 epoch) {
        return Trees.nextRoots(enhancedState);
    }
    function enhancedTreeCounts() external view returns (uint64 reservations,uint64 spentClaims) {
        return (enhancedState.reservations.count,enhancedState.spentClaims.count-1);
    }
}
