// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaFamilyNoAppendExitCustodyPreAudit as ExitPool}
    from "./VantaFamilyNoAppendExitCustodyPreAudit.sol";
import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {VantaFamilyProtocolFeePolicy} from "./VantaFamilyProtocolFeePolicy.sol";
import {PoseidonT4} from "../libraries/PoseidonT4.sol";
import {VantaTokenHash} from "./VantaTokenHash.sol";
import {VantaDummyPolicy} from "./VantaDummyPolicy.sol";
import {VantaNativeSwapWalletClearance} from "./VantaNativeSwapWalletClearance.sol";
import {VantaNativeWalletClearance} from "./VantaNativeWalletClearance.sol";
import {VantaEpochStateV1} from "./VantaEpochStateV1.sol";
import {VantaV8FiveRowKzgResearch as Kzg} from "./VantaV8FiveRowKzgResearch.sol";
import {VantaFamilyEpochProofVerifierPreAudit as EpochVerifier}
    from "./VantaFamilyEpochProofVerifierPreAudit.sol";
import {VantaV8StatementResearch as Statement8} from "./VantaV8StatementResearch.sol";
import {VantaV8Statement32Research as Statement32} from "./VantaV8Statement32Research.sol";
import {VantaFamilyFullBundleVerifierPreAudit as Bundle} from "./VantaFamilyFullBundleVerifierPreAudit.sol";
import {VantaFamilyAggregateGroth16PreAudit as Agg}
    from "./VantaFamilyAggregateGroth16PreAudit.sol";
import {VantaFamilyCombinedFeePartnerAdapterPreAudit as Combined}
    from "./VantaFamilyCombinedFeePartnerAdapterPreAudit.sol";

/// @notice Fresh family-scoped PRE-AUDIT candidate, NOT approved for value.
/// @notice Unified PRE-AUDIT V8 asset pool: historical-source normal 8/32x5
/// spending and V1-style no-append exit use ONE escrow and nullifier map.
/// @dev NOT AUDITED. Never deploy with real assets. The mandatory fee-proof
/// verifier must be independently built, ceremony-pinned and audited. The
/// inherited public-fee ingress is permanently disabled.
/// This candidate is an integration boundary, NOT a deployable final pool.
contract VantaFamilyUnifiedPoolPreAudit is ExitPool, VantaFamilyReleaseBinding {
    using VantaEpochStateV1 for VantaEpochStateV1.State;

    uint256 private constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant MAX_NORMAL_VALUE = (uint256(1) << 120) - 1;
    uint256 private constant MAX_ENVELOPE_BYTES = 2048;
    bytes32 internal constant NORMAL_TYPEHASH = keccak256(
        "NormalEpochQuote(uint64 chainId,address pool,address asset,uint8 width,uint8 mode,uint64 sourceEpoch,uint256 sourceCheckpoint,uint64 targetEpoch,uint256 targetCheckpoint,address recipient,uint128 payout,uint128 protocolFeeCap,uint128 partnerFeeCap,uint128 relayerFeeCap,address protocolRecipient,address partnerRecipient,address relayer,bytes32 nullifiersHash,bytes32 outputsHash,bytes32 envelopesHash,uint256 saltedAmountHash,bytes32 feeSlotsHash,uint256 feeTermsHash,uint256 partnerRegistryRoot,bytes32 nonce,uint64 deadline,bytes32 feePolicyHash)"
    );
    bytes32 internal constant PRIVATE_DEPOSIT_TYPEHASH = keccak256(
        "PrivateFeeDepositQuote(uint64 chainId,address pool,address asset,uint64 epoch,uint256 checkpoint,address payer,uint8 count,uint128 gross,uint128 protocolFeeCap,uint128 partnerFeeCap,address protocolRecipient,address partnerRecipient,bytes32 outputsHash,bytes32 envelopesHash,bytes32 feeSlotsHash,uint256 feeTermsHash,uint256 partnerRegistryRoot,bytes32 nonce,uint64 deadline,bytes32 feePolicyHash)"
    );
    bytes32 private constant NORMAL_BATCH_DOMAIN =
        keccak256("STEALTHOS_VANTA_V8_NORMAL_EPOCH_BATCH_V1");
    uint8 private constant WITHDRAW = 0;
    uint8 private constant PRIVATE_TRANSFER = 1;

    struct NormalEpochQuote {
        uint64 chainId;
        address pool;
        address asset;
        uint8 width;
        uint8 mode;
        uint64 sourceEpoch;
        uint256 sourceCheckpoint;
        uint64 targetEpoch;
        uint256 targetCheckpoint;
        address recipient;
        uint128 payout;
        uint128 protocolFeeCap;
        uint128 partnerFeeCap;
        uint128 relayerFeeCap;
        address protocolRecipient;
        address partnerRecipient;
        address relayer;
        bytes32 nullifiersHash;
        bytes32 outputsHash;
        bytes32 envelopesHash;
        uint256 saltedAmountHash;
        bytes32 feeSlotsHash;
        uint256 feeTermsHash;
        uint256 partnerRegistryRoot;
        bytes32 nonce;
        uint64 deadline;
        bytes32 feePolicyHash;
    }

    struct PrivateFeeDepositQuote {
        uint64 chainId;
        address pool;
        address asset;
        uint64 epoch;
        uint256 checkpoint;
        address payer;
        uint8 count;
        uint128 gross;
        uint128 protocolFeeCap;
        uint128 partnerFeeCap;
        address protocolRecipient;
        address partnerRecipient;
        bytes32 outputsHash;
        bytes32 envelopesHash;
        bytes32 feeSlotsHash;
        uint256 feeTermsHash;
        uint256 partnerRegistryRoot;
        bytes32 nonce;
        uint64 deadline;
        bytes32 feePolicyHash;
    }

    struct ActionView {
        address pool;
        address token;
        address recipient;
        uint128 protocolCap;
        uint128 partnerCap;
        address protocolRecipient;
        address partnerRecipient;
        uint256 saltedAmountHash;
        uint256 quoteField;
        uint256 batchField;
        bytes32 nullifiersHash;
        bytes32 outputsHash;
    }

    struct EpochSpend8 {
        Statement8.LegPublic action;
        Bundle.V8Gate0Data gate0;
        Bundle.Gate1Data gate1;
        Bundle.LinkData link;
        Agg.VerifyingKey aggregateVk;
        Agg.Proof aggregateProof;
        uint256[11] aggregateInputs;
        Kzg.RowKey[5] rowKeys;
        bytes[5] encryptedOutputs;
        uint8[3] feeSlots;
        bytes combinedFeePartnerProof;
    }

    struct EpochSpend32 {
        Statement32.LegPublic action;
        Bundle.V8Gate0Data gate0;
        Bundle.Gate1Data gate1;
        Bundle.LinkData link;
        Agg.VerifyingKey aggregateVk;
        Agg.Proof aggregateProof;
        uint256[11] aggregateInputs;
        Kzg.RowKey[5] rowKeys;
        bytes[5] encryptedOutputs;
        uint8[3] feeSlots;
        bytes combinedFeePartnerProof;
    }

    EpochVerifier public immutable normalVerifier;
    Combined public immutable combinedFeePartnerVerifier;
    bytes32 public immutable normalVerifierCodehash;
    bytes32 public immutable combinedFeePartnerVerifierCodehash;
    /// @notice Linked normal-operations module is immutable and fail-closed.
    ///         No governance, registry or relayer can substitute its bytecode.
    bytes32 public immutable normalLogicCodehash;
    VantaFamilyProtocolFeePolicy public immutable protocolFeePolicy;
    bytes32 private immutable protocolFeePolicyCodehash;
    /// @notice One closed, chain-specific ceremony. Never mutable or repointed.
    /// @notice Can schedule an exit-only transition, but cannot pause exits.
    address public immutable retirementAuthority;
    /// @notice Zero until a one-way retirement notice has been posted.
    uint64 public plannedExitOnlyAt;
    uint64 public constant MIN_PLANNED_RETIREMENT_NOTICE = 30 days;

    error UnapprovedNormalProofSetup();
    error InvalidReleaseGeneration();
    error PlannedRetirementNotAuthorized();
    error PlannedRetirementAlreadyAnnounced();
    error RetirementNoticeTooShort();
    error GenerationExitOnly();
    error InvalidNormalSpend();
    error InvalidNormalProof();
    error InvalidNormalFeeProof();
    error TargetUnavailable();

    event PreAuditNormalSettlement(
        bytes32 indexed quoteNonce, uint64 indexed sourceEpoch,
        uint64 indexed targetEpoch, uint8 width, uint8 mode,
        uint128 payout, uint256 targetCheckpoint
    );
    event PlannedRetirement(
        bytes32 indexed generationId, uint64 indexed exitOnlyAt,
        address indexed authority
    );

    constructor(
        address assetAddress, address exitVerifierAddress, address normalVerifierAddress,
        address combinedFeePartnerVerifierAddress, address kzgAddress,
        uint256 initialX, uint256 initialY,
        address signer, address protocolRecipient, address partnerRecipient,
        uint128 minimumFee, uint128 fixedPartnerExitFee, bytes32 policyHash,
        uint16[2] memory exitFeeRates, bytes32 generationId,
        address plannedRetirementAuthority,
        bytes32 familySetupId, bytes32 familyTag, uint256 familyChainId,
        address protocolFeePolicyAddress
    ) ExitPool(
        assetAddress, exitVerifierAddress, kzgAddress, initialX, initialY,
        signer, protocolRecipient, partnerRecipient,
        minimumFee, fixedPartnerExitFee, policyHash, exitFeeRates
    ) VantaFamilyReleaseBinding(familySetupId, generationId, familyTag, familyChainId) {
        VantaFamilyProtocolFeePolicy policy = VantaFamilyProtocolFeePolicy(protocolFeePolicyAddress);
        if (protocolFeePolicyAddress.code.length == 0 || policy.releaseSetupId() != familySetupId ||
            policy.releaseGenerationId() != generationId || policy.releaseFamilyTag() != familyTag ||
            policy.releaseChainId() != familyChainId || policy.basePolicyHash() != policyHash ||
            policy.administrator() != plannedRetirementAuthority || policy.rate(2) != 0)
            revert InvalidReleaseGeneration();
        protocolFeePolicy = policy;
        protocolFeePolicyCodehash = protocolFeePolicyAddress.codehash;
        // No old research verifier is accepted in a fresh generation.
        // All bound verifiers must independently identify the exact setup,
        // generation, family and chain fixed at construction.
        if (approvedChainId != releaseChainId)
            revert UnapprovedNormalProofSetup();
        _requireBoundVerifier(exitVerifierAddress);
        _requireBoundVerifier(normalVerifierAddress);
        _requireBoundVerifier(combinedFeePartnerVerifierAddress);
        if (generationId == bytes32(0) ||
            plannedRetirementAuthority == address(0))
            revert InvalidReleaseGeneration();
        retirementAuthority = plannedRetirementAuthority;
        if (normalVerifierAddress.code.length == 0 ||
            combinedFeePartnerVerifierAddress.code.length == 0 ||
            normalVerifierAddress == exitVerifierAddress ||
            combinedFeePartnerVerifierAddress == exitVerifierAddress ||
            combinedFeePartnerVerifierAddress == normalVerifierAddress ||
            combinedFeePartnerVerifierAddress == kzgAddress)
            revert UnapprovedNormalProofSetup();
        normalVerifier = EpochVerifier(normalVerifierAddress);
        combinedFeePartnerVerifier = Combined(combinedFeePartnerVerifierAddress);
        normalVerifierCodehash = normalVerifierAddress.codehash;
        combinedFeePartnerVerifierCodehash = combinedFeePartnerVerifierAddress.codehash;
        normalLogicCodehash = address(VantaV8UnifiedNormalSpendLogic).codehash;
        if (normalLogicCodehash == bytes32(0))
            revert UnapprovedNormalProofSetup();
        if (normalVerifier.CHAIN_ID() != block.chainid)
            revert UnapprovedNormalProofSetup();
    }

    /// @dev Fail closed until a NEW, generation-aware verifier is deployed.
    ///      A self-asserted getter is insufficient: independent partners must
    ///      derive and compare the actual deployed runtime from ceremony keys.
    function _requireBoundVerifier(address target) private view {
        if (target.code.length == 0) revert InvalidFamilyRelease();
        (bool a, bytes memory x) = target.staticcall(
            abi.encodeWithSignature("releaseSetupId()"));
        (bool b, bytes memory y) = target.staticcall(
            abi.encodeWithSignature("releaseGenerationId()"));
        (bool c, bytes memory z) = target.staticcall(
            abi.encodeWithSignature("releaseFamilyTag()"));
        (bool d, bytes memory w) = target.staticcall(
            abi.encodeWithSignature("releaseChainId()"));
        if (!a || x.length != 32 || abi.decode(x,(bytes32)) != releaseSetupId ||
            !b || y.length != 32 || abi.decode(y,(bytes32)) != releaseGenerationId ||
            !c || z.length != 32 || abi.decode(z,(bytes32)) != releaseFamilyTag ||
            !d || w.length != 32 || abi.decode(w,(uint256)) != releaseChainId)
            revert InvalidFamilyRelease();
    }

    /// @notice A planned release retirement requires at least 30 days' notice.
    ///         This transition is one-way and can NEVER block the inherited
    ///         permissionless, public no-append exit selectors. There is no
    ///         emergency pause role, cancellation or deadline on those exits.
    function announcePlannedRetirement(uint64 exitOnlyAt) external onlyReleaseChain {
        if (msg.sender != retirementAuthority)
            revert PlannedRetirementNotAuthorized();
        if (plannedExitOnlyAt != 0)
            revert PlannedRetirementAlreadyAnnounced();
        if (uint256(exitOnlyAt) < block.timestamp + MIN_PLANNED_RETIREMENT_NOTICE)
            revert RetirementNoticeTooShort();
        plannedExitOnlyAt = exitOnlyAt;
        emit PlannedRetirement(releaseGenerationId, exitOnlyAt, msg.sender);
    }

    /// @notice Disable the inherited PUBLIC-fee research ingress in the
    /// final candidate. There is one fee-enforced private deposit selector.
    function depositWithSignedFee(
        DepositQuote calldata, DepositRow[5] calldata,
        Kzg.RowKey[5] calldata, bytes calldata
    ) external payable override returns (uint256) {
        revert FeeAuthorizationRequired();
    }

    function privateDepositQuoteDigest(PrivateFeeDepositQuote calldata q)
        external view returns (bytes32)
    {
        return _typedDigest(keccak256(abi.encode(PRIVATE_DEPOSIT_TYPEHASH, q)));
    }

    /// @notice Single pre-audit ingress. Sender funds exactly the gross
    /// amount while mandatory cryptographic allocation verification proves
    /// the hidden value split, zero protocol fee and exact registered partner fee.
    function depositWithPrivateFeeNotes(
        PrivateFeeDepositQuote calldata q, uint256[5] calldata outputs,
        bytes[5] calldata encryptedOutputs, Kzg.RowKey[5] calldata rowKeys,
        uint8[2] calldata feeSlots, bytes calldata combinedProof,
        bytes calldata feeSignature
    ) external payable virtual noReentry returns (uint256 nextCheckpoint) {
        // Planned retirement immediately closes new deposits, then the
        // publicly announced deadline makes the whole pool exit-only.
        if (plannedExitOnlyAt != 0) revert GenerationExitOnly();
        _requireNormalSetup();
        bytes32 quoteHash = _authorize(
            keccak256(abi.encode(PRIVATE_DEPOSIT_TYPEHASH, q)),
            q.nonce, q.deadline, feeSignature
        );
        nextCheckpoint = VantaV8UnifiedNormalSpendLogic.deposit(
            epochState, usedNonce, commitmentSeen, q, outputs,
            encryptedOutputs, rowKeys, feeSlots, combinedProof,
            quoteHash, _normalPins()
        );
        _receiveExact(q.gross);
        accountedLiability += q.gross;
    }

    /// @notice The wallet and fee signer bind the SAME quote into both Gate0
    /// and the independently authenticated fee-note allocation proof.
    function normalQuoteDigest(NormalEpochQuote calldata q)
        external view returns (bytes32)
    {
        return _typedDigest(keccak256(abi.encode(NORMAL_TYPEHASH, q)));
    }

    /// @dev Independent of the salted payout commitment. Otherwise the
    /// normal signed quote and its amount hash depend on each other and
    /// cannot be constructed by a genuine browser prover.
    function _normalBatchField(NormalEpochQuote calldata q)
        private pure returns (uint256)
    {
        return uint256(keccak256(abi.encode(
            NORMAL_BATCH_DOMAIN, q.chainId, q.pool, q.width, q.mode,
            q.sourceEpoch, q.sourceCheckpoint,
            q.targetEpoch, q.targetCheckpoint, q.nonce
        ))) % FIELD_MODULUS;
    }

    function normalDigestFields(NormalEpochQuote calldata q)
        external view returns (uint256 quoteField, uint256 batchField)
    {
        bytes32 signed = _typedDigest(keccak256(abi.encode(NORMAL_TYPEHASH, q)));
        quoteField = uint256(signed) % FIELD_MODULUS;
        batchField = _normalBatchField(q);
    }

    function _requireNormalSetup() internal view {
        if (plannedExitOnlyAt != 0 && block.timestamp >= plannedExitOnlyAt)
            revert GenerationExitOnly();
        _requireNormalProofSetup();
    }

    function _requireNormalProofSetup() internal view {
        _setup(); // Existing pool + writer pins must remain valid.
        if (address(normalVerifier).codehash != normalVerifierCodehash ||
            address(combinedFeePartnerVerifier).codehash != combinedFeePartnerVerifierCodehash ||
            address(VantaV8UnifiedNormalSpendLogic).codehash != normalLogicCodehash ||
            normalVerifier.CHAIN_ID() != block.chainid)
            revert UnapprovedNormalProofSetup();
    }

    /// @dev Only a statically linked library may handle normal spend
    ///      checks, KZG updates, fee proofs and global nullifier writes.
    ///      This keeps ONE escrow and one public ABI below EIP-170.
    function feePolicyHash() public view override returns (bytes32 digest) {
        address policy = address(protocolFeePolicy);
        bytes32 expectedCodehash = protocolFeePolicyCodehash;
        bytes4 selector = VantaFamilyProtocolFeePolicy.policyHash.selector;
        bytes4 invalidSelector = UnapprovedNormalProofSetup.selector;
        // The fixed-size static call keeps this shared escrow below EIP-170.
        // Check both the pinned code and the exact ABI return width. Only the
        // Solidity scratch space is touched; no allocation or storage changes.
        assembly ("memory-safe") {
            if iszero(eq(extcodehash(policy), expectedCodehash)) {
                mstore(0, invalidSelector)
                revert(0, 4)
            }
            mstore(0, selector)
            if iszero(staticcall(gas(), policy, 0, 4, 0, 32)) { revert(0, 0) }
            if iszero(eq(returndatasize(), 32)) { revert(0, 0) }
            digest := mload(0)
        }
    }
    function _normalPins() internal view returns (VantaV8UnifiedNormalSpendLogic.Pins memory) {
        return VantaV8UnifiedNormalSpendLogic.Pins(
            address(asset), protocolFeeRecipient, partnerFeeRecipient,
            minimumProtocolFee, feePolicyHash(), address(normalVerifier),
            address(combinedFeePartnerVerifier), approvedKzgUpdater
        );
    }

    function _finishNormalPayout(NormalEpochQuote calldata q, uint256 recorded) private {
        if (q.payout > accountedLiability) revert InsufficientEscrow();
        accountedLiability -= q.payout;
        if (q.payout > 0) _transferExact(q.recipient, q.payout);
        emit PreAuditNormalSettlement(
            q.nonce, q.sourceEpoch, q.targetEpoch, q.width, q.mode,
            q.payout, recorded
        );
    }

    /// @notice Normal 8x5 and 32x5 routes preserve the same calldata ABI.
    ///      The only added execution hop is an immutable linked delegatecall.
    function settleNormalEpoch8(
        NormalEpochQuote calldata q, EpochSpend8 calldata p,
        bytes calldata feeSignature
    ) external noReentry {
        _requireNormalSetup();
        bytes32 signedQuoteHash = _authorize(
            keccak256(abi.encode(NORMAL_TYPEHASH, q)), q.nonce, q.deadline,
            feeSignature
        );
        uint256 recorded = VantaV8UnifiedNormalSpendLogic.settleEight(
            epochState, usedNonce, commitmentSeen, q, p, signedQuoteHash,
            _normalBatchField(q), _normalPins()
        );
        _finishNormalPayout(q, recorded);
    }

    function settleNormalEpoch32(
        NormalEpochQuote calldata q, EpochSpend32 calldata p,
        bytes calldata feeSignature
    ) external noReentry {
        _requireNormalSetup();
        bytes32 signedQuoteHash = _authorize(
            keccak256(abi.encode(NORMAL_TYPEHASH, q)), q.nonce, q.deadline,
            feeSignature
        );
        uint256 recorded = VantaV8UnifiedNormalSpendLogic.settleThirtyTwo(
            epochState, usedNonce, commitmentSeen, q, p, signedQuoteHash,
            _normalBatchField(q), _normalPins()
        );
        _finishNormalPayout(q, recorded);
    }
}

/// @notice Immutable, externally linked normal-spend logic for the ONE V8 pool.
/// @dev Quote expiration/replay authorization is enforced by the guarded pool
/// selectors before entering this library (_authorize or directDeposit). The
/// direct-deposit selector also supplies its own isolated nonce storage. A
/// library helper is not an independently callable custody entrypoint.
/// @dev Solidity performs a delegatecall to this statically linked library.
///      It receives only the pool's existing storage references and immutable
///      pins. It cannot select a separate custody address, fee route, epoch
///      registry, nullifier store, or verifier at runtime. Entry selectors in
///      the custody pool remain exactly the same, and no updater/admin exists.
library VantaV8UnifiedNormalSpendLogic {
    using VantaEpochStateV1 for VantaEpochStateV1.State;
    using SafeERC20 for IERC20;

    uint256 private constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant MAX_VALUE = (uint256(1) << 120) - 1;
    uint256 private constant MAX_ENVELOPE_BYTES = 2048;
    uint8 private constant PRIVATE_TRANSFER = 1;

    struct Pins {
        address asset;
        address protocolRecipient;
        address partnerRecipient;
        uint128 minimumProtocolFee;
        bytes32 feePolicyHash;
        address normalVerifier;
        address combinedVerifier;
        address kzgUpdater;
    }

    error InvalidNormalSpend();
    error InvalidNormalProof();
    error InvalidNormalFeeProof();
    error InvalidSource();
    error TargetUnavailable();
    error AssetTransferMismatch();

    /// @dev Delegatecall retains the pool address, original payer and msg.value.
    /// Receipt is exact and occurs before the guarded pool credits liability.
    /// Reverts undo nonce, commitment and epoch updates in the same transaction.
    function _receiveDirectDeposit(address asset, uint256 gross) private {
        if (asset == address(0)) {
            if (msg.value != gross) revert AssetTransferMismatch();
            return;
        }
        if (msg.value != 0) revert AssetTransferMismatch();
        IERC20 token = IERC20(asset);
        uint256 beforeBalance = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), gross);
        if (token.balanceOf(address(this)) - beforeBalance != gross)
            revert AssetTransferMismatch();
    }

    function directDeposit(
        VantaEpochStateV1.State storage state,
        mapping(bytes32 => bool) storage usedNonce,
        mapping(uint256 => bool) storage commitmentSeen,
        VantaFamilyUnifiedPoolPreAudit.PrivateFeeDepositQuote calldata q,
        uint256[5] calldata outputs, bytes[5] calldata encryptedOutputs,
        Kzg.RowKey[5] calldata rowKeys, uint8[2] calldata feeSlots,
        bytes calldata combinedProof, bytes32 domain, Pins memory pins,
        address clearanceGate, bytes calldata clearance
    ) external returns (uint256 nextCheckpoint) {
        if (q.nonce == bytes32(0) ||
            usedNonce[q.nonce] || block.timestamp > q.deadline) revert InvalidNormalSpend();
        VantaNativeWalletClearance(clearanceGate).requireClearance(msg.sender, clearance);
        // Only the immutable gateway's active, exact DEX-credit claim may use
        // this one-note ingress. Ordinary deposits still require the complete
        // registered partner-fee proof below, even when its rate is zero.
        if (q.count == 1) {
            if (!VantaNativeSwapWalletClearance(clearanceGate).isSwapIngress(msg.sender,address(this),keccak256(abi.encodeWithSelector(VantaFamilyUnifiedPoolPreAudit.depositWithPrivateFeeNotes.selector,q,outputs,encryptedOutputs,rowKeys,feeSlots,combinedProof,clearance))))
                revert InvalidNormalSpend();
            nextCheckpoint = _depositSwapOutput(state,usedNonce,commitmentSeen,q,outputs,encryptedOutputs,rowKeys,feeSlots,combinedProof,pins);
        } else {
            bytes32 depositType = keccak256("PrivateFeeDepositQuote(uint64 chainId,address pool,address asset,uint64 epoch,uint256 checkpoint,address payer,uint8 count,uint128 gross,uint128 protocolFeeCap,uint128 partnerFeeCap,address protocolRecipient,address partnerRecipient,bytes32 outputsHash,bytes32 envelopesHash,bytes32 feeSlotsHash,uint256 feeTermsHash,uint256 partnerRegistryRoot,bytes32 nonce,uint64 deadline,bytes32 feePolicyHash)");
            bytes32 intentHash = keccak256(abi.encodePacked(hex"1901", domain, keccak256(abi.encode(depositType, q))));
            nextCheckpoint = deposit(state, usedNonce, commitmentSeen, q, outputs,
                encryptedOutputs, rowKeys, feeSlots, combinedProof, intentHash, pins);
        }
        _receiveDirectDeposit(pins.asset, q.gross);
    }

    /// Public DEX proceeds need no hidden amount-allocation proof. Poseidon
    /// enforces the exact value in the wallet's one-time note commitment; the
    /// ceremony-authenticated KZG key enforces its canonical append. Neither
    /// wallet MPK nor note randomness is exposed. No deposit fee is collected.
    function _depositSwapOutput(VantaEpochStateV1.State storage state,
        mapping(bytes32=>bool) storage usedNonce,mapping(uint256=>bool) storage commitmentSeen,
        VantaFamilyUnifiedPoolPreAudit.PrivateFeeDepositQuote calldata q,
        uint256[5] calldata outputs,bytes[5] calldata envelopes,Kzg.RowKey[5] calldata keys,
        uint8[2] calldata slots,bytes calldata opening,Pins memory pins) private returns(uint256 next) {
        if (q.chainId!=block.chainid || q.pool!=address(this) || q.asset!=pins.asset || q.payer!=msg.sender ||
            q.gross==0 || q.gross>MAX_VALUE || q.protocolFeeCap!=0 || q.partnerFeeCap!=0 ||
            q.protocolRecipient!=address(0) || q.partnerRecipient!=address(0) || q.feeTermsHash!=0 || q.partnerRegistryRoot!=0 ||
            q.feePolicyHash!=pins.feePolicyHash || q.deadline>block.timestamp+3600 ||
            slots[0]!=0 || slots[1]!=0 || q.feeSlotsHash!=keccak256(abi.encode(slots)) || opening.length!=32)
            revert InvalidNormalSpend();
        uint256 npk=abi.decode(opening,(uint256));
        if (npk==0 || npk>=FR || outputs[0]==0 || outputs[0]>=FR || commitmentSeen[outputs[0]] ||
            VantaDummyPolicy.isDisallowedRealCommitment(outputs[0]) || envelopes[0].length!=829 || envelopes[0][0]!=0x01 ||
            PoseidonT4.hash([npk,VantaTokenHash.compute(block.chainid,address(this),pins.asset),uint256(q.gross)])!=outputs[0])
            revert InvalidNormalSpend();
        bytes32[5] memory hashes; hashes[0]=keccak256(envelopes[0]);
        for(uint256 i=1;i<5;++i)if(outputs[i]!=0 || envelopes[i].length!=0)revert InvalidNormalSpend();
        if(q.outputsHash!=keccak256(abi.encode(outputs)) || q.envelopesHash!=keccak256(abi.encode(hashes)))revert InvalidNormalSpend();
        VantaEpochStateV1.Epoch storage target=state.epochs[state.currentEpoch];
        if(q.epoch!=state.currentEpoch || q.checkpoint!=target.currentRef || target.closed || target.slotCount>=65536)revert TargetUnavailable();
        (uint256 from,uint256 to,uint256 x,uint256 y)=Kzg(pins.kzgUpdater).verifyEpochRows(q.epoch,target.slotCount,target.x,target.y,1,outputs,keys);
        if(from!=q.checkpoint)revert TargetUnavailable();
        uint64 row=target.slotCount; next=state.append(q.epoch,row+1,x,y);
        if(next!=to)revert InvalidNormalProof();
        usedNonce[q.nonce]=true; commitmentSeen[outputs[0]]=true;
        emit CanonicalKzgRow(q.epoch,row,outputs[0]);
        emit CanonicalEncryptedNote(q.epoch,row,outputs[0],hashes[0],envelopes[0]);
        emit PreAuditDeposit(q.nonce,q.epoch,1,q.gross,next);
    }

    event CanonicalKzgRow(uint64 indexed epoch, uint64 indexed row, uint256 indexed commitment);
    event CanonicalEncryptedNote(
        uint64 indexed epoch, uint64 indexed row, uint256 indexed commitment,
        bytes32 envelopeHash, bytes encryptedEnvelope
    );
    event NullifierConsumed(uint256 indexed nullifier, uint8 indexed width);
    event PreAuditDeposit(
        bytes32 indexed quoteNonce, uint64 indexed epoch, uint8 count,
        uint256 totalValue, uint256 checkpoint
    );

    /// @dev The only admitted private-fee ingress. The guarded pool selector
    ///      checks the EIP-712 signer, then delegatecalls this statically
    ///      linked verifier/update logic and transfers exactly q.gross.
    ///      A failed asset transfer reverts ALL proof and state changes.
    function deposit(
        VantaEpochStateV1.State storage state,
        mapping(bytes32 => bool) storage usedNonce,
        mapping(uint256 => bool) storage commitmentSeen,
        VantaFamilyUnifiedPoolPreAudit.PrivateFeeDepositQuote calldata q,
        uint256[5] calldata outputs, bytes[5] calldata encryptedOutputs,
        Kzg.RowKey[5] calldata rowKeys, uint8[2] calldata feeSlots,
        bytes calldata combinedProof,
        bytes32 quoteHash, Pins memory pins
    ) public returns (uint256 nextCheckpoint) {
        if (q.chainId != block.chainid || q.pool != address(this) ||
            q.asset != pins.asset || q.payer != msg.sender ||
            q.count < 3 || q.count > 5 || q.gross == 0 ||
            q.gross > MAX_VALUE ||
            q.protocolFeeCap != 0 || q.partnerFeeCap >= q.gross ||
            q.feeTermsHash == 0 || q.feeTermsHash >= FR ||
            q.partnerRegistryRoot == 0 || q.partnerRegistryRoot >= FR ||
            q.protocolRecipient != pins.protocolRecipient ||
            q.partnerRecipient != pins.partnerRecipient ||
            q.feePolicyHash != pins.feePolicyHash ||
            q.deadline > block.timestamp + 3600)
            revert InvalidNormalSpend();
        VantaEpochStateV1.Epoch storage target = state.epochs[state.currentEpoch];
        // The 1,024-row lead is a rollover trigger, not a hard cutoff.
        // Genuine KZG-authenticated deposits may use remaining real capacity
        // while a permissionless maintenance transaction is pending.
        if (q.epoch != state.currentEpoch ||
            q.checkpoint != target.currentRef || target.closed ||
            uint256(target.slotCount) + q.count > 65_536)
            revert TargetUnavailable();
        if (feeSlots[0] == 0 || feeSlots[0] >= feeSlots[1] ||
            feeSlots[1] >= q.count ||
            q.feeSlotsHash != keccak256(abi.encode(feeSlots)))
            revert InvalidNormalSpend();

        bytes32[5] memory hashes;
        for (uint256 i; i < 5; ++i) {
            if (i >= q.count) {
                if (outputs[i] != 0 || encryptedOutputs[i].length != 0)
                    revert InvalidNormalSpend();
                continue;
            }
            if (outputs[i] == 0 || outputs[i] >= FR ||
                commitmentSeen[outputs[i]] ||
                encryptedOutputs[i].length < 64 ||
                encryptedOutputs[i].length > MAX_ENVELOPE_BYTES ||
                encryptedOutputs[i][0] != bytes1(uint8(1)))
                revert InvalidNormalSpend();
            for (uint256 j; j < i; ++j)
                if (outputs[j] == outputs[i]) revert InvalidNormalSpend();
            hashes[i] = keccak256(encryptedOutputs[i]);
        }
        if (q.outputsHash != keccak256(abi.encode(outputs)) ||
            q.envelopesHash != keccak256(abi.encode(hashes)))
            revert InvalidNormalSpend();

        uint8[3] memory completeFeeSlots = [feeSlots[0], feeSlots[1], uint8(5)];
        Combined.CanonicalQuote memory feeQuote = Combined.CanonicalQuote({
            signedQuoteHash: quoteHash,
            outputs: outputs,
            feeSlots: completeFeeSlots,
            outputCount: q.count,
            depositGross: q.gross,
            protocolCap: q.protocolFeeCap,
            partnerCap: q.partnerFeeCap,
            relayerCap: 0,
            feeTermsHash: q.feeTermsHash,
            width: 0,
            mode: 2,
            amountHash: 0,
            batchDigest: 0,
            feeLegIndex: 0,
            partnerRegistryRoot: q.partnerRegistryRoot,
            signedPartnerNonce: q.nonce,
            relayer: address(0),
            withdrawalPayout: 0
        });
        if (!Combined(pins.combinedVerifier).verifyCombined(feeQuote, combinedProof))
            revert InvalidNormalFeeProof();

        uint256[5] memory commitments = outputs;
        (uint256 fromRef, uint256 toRef, uint256 x, uint256 y) =
            Kzg(pins.kzgUpdater).verifyEpochRows(
                q.epoch, target.slotCount, target.x, target.y,
                q.count, commitments, rowKeys
            );
        if (fromRef != q.checkpoint) revert TargetUnavailable();
        uint64 firstRow = target.slotCount;
        nextCheckpoint = state.append(q.epoch, firstRow + q.count, x, y);
        if (nextCheckpoint != toRef) revert InvalidNormalProof();
        usedNonce[q.nonce] = true;
        for (uint256 i; i < q.count; ++i) {
            commitmentSeen[outputs[i]] = true;
            emit CanonicalKzgRow(q.epoch, firstRow + uint64(i), outputs[i]);
            emit CanonicalEncryptedNote(
                q.epoch, firstRow + uint64(i), outputs[i],
                hashes[i], encryptedOutputs[i]
            );
        }
        emit PreAuditDeposit(q.nonce, q.epoch, q.count, q.gross, nextCheckpoint);
    }

    function _viewEight(Statement8.LegPublic calldata a)
        private pure returns (VantaFamilyUnifiedPoolPreAudit.ActionView memory v)
    {
        return VantaFamilyUnifiedPoolPreAudit.ActionView(
            a.pool, a.token, a.recipient, a.protocolFeeCap, a.partnerFeeCap,
            a.protocolFeeRecipient, a.partnerFeeRecipient, a.saltedAmountHash,
            a.feeQuoteDigestField, a.batchDigestField,
            keccak256(abi.encode(a.nullifiers)), keccak256(abi.encode(a.outputs))
        );
    }

    function _viewThirtyTwo(Statement32.LegPublic calldata a)
        private pure returns (VantaFamilyUnifiedPoolPreAudit.ActionView memory v)
    {
        return VantaFamilyUnifiedPoolPreAudit.ActionView(
            a.pool, a.token, a.recipient, a.protocolFeeCap, a.partnerFeeCap,
            a.protocolFeeRecipient, a.partnerFeeRecipient, a.saltedAmountHash,
            a.feeQuoteDigestField, a.batchDigestField,
            keccak256(abi.encode(a.nullifiers)), keccak256(abi.encode(a.outputs))
        );
    }

    function _checkNormal(
        VantaEpochStateV1.State storage state,
        mapping(uint256 => bool) storage commitmentSeen,
        VantaFamilyUnifiedPoolPreAudit.NormalEpochQuote calldata q,
        VantaFamilyUnifiedPoolPreAudit.ActionView memory a,
        uint256[5] calldata outputs, bytes[5] calldata envelopes,
        uint8[3] calldata feeSlots, bytes32 quoteDigest,
        uint256 batchField, Pins memory pins
    ) private view {
        if (q.chainId != block.chainid || q.pool != address(this) ||
            q.asset != pins.asset || q.width != 8 && q.width != 32 ||
            a.pool != address(this) || a.token != pins.asset ||
            q.recipient != a.recipient || q.protocolFeeCap != a.protocolCap ||
            q.partnerFeeCap != a.partnerCap ||
            q.protocolRecipient != pins.protocolRecipient ||
            q.partnerRecipient != pins.partnerRecipient ||
            a.protocolRecipient != pins.protocolRecipient ||
            a.partnerRecipient != pins.partnerRecipient ||
            q.relayer != msg.sender || q.feePolicyHash != pins.feePolicyHash ||
            q.saltedAmountHash != a.saltedAmountHash ||
            q.nullifiersHash != a.nullifiersHash || q.outputsHash != a.outputsHash ||
            q.deadline > block.timestamp + 3600 ||
            (q.mode > PRIVATE_TRANSFER && q.mode != 4 && q.mode != 5) || q.payout > MAX_VALUE ||
            q.protocolFeeCap < pins.minimumProtocolFee ||
            q.feeTermsHash == 0 || q.feeTermsHash >= FR ||
            q.partnerRegistryRoot == 0 || q.partnerRegistryRoot >= FR ||
            (q.mode != PRIVATE_TRANSFER && (q.recipient == address(0) || q.payout == 0)) ||
            (q.mode == PRIVATE_TRANSFER && (q.recipient != address(0) || q.payout != 0)))
            revert InvalidNormalSpend();
        if (q.feeSlotsHash != keccak256(abi.encode(feeSlots)))
            revert InvalidNormalSpend();
        // The epoch Gate0 transfer relation prices output0's recipient
        // amount and proves output4 is sender-owned change. Protocol,
        // partner and gas notes must occupy the three intervening slots.
        // Without this canonical layout a wallet could camouflage a
        // recipient payment as an unpriced fee/change output.
        if (q.mode == PRIVATE_TRANSFER &&
            (feeSlots[0] != 1 || feeSlots[1] != 2 || feeSlots[2] != 3))
            revert InvalidNormalSpend();
        for (uint256 i; i < 3; ++i) {
            if (feeSlots[i] >= 5 ||
                (q.mode == PRIVATE_TRANSFER && feeSlots[i] == 0) ||
                (i != 0 && feeSlots[i] <= feeSlots[i - 1]))
                revert InvalidNormalSpend();
        }
        bytes32[5] memory hashes;
        for (uint256 i; i < 5; ++i) {
            uint256 cm = outputs[i];
            if (cm == 0 || cm >= FR || commitmentSeen[cm])
                revert InvalidNormalSpend();
            for (uint256 j; j < i; ++j)
                if (outputs[j] == cm) revert InvalidNormalSpend();
            bytes calldata e = envelopes[i];
            if (e.length < 64 || e.length > MAX_ENVELOPE_BYTES ||
                e[0] != bytes1(uint8(1)))
                revert InvalidNormalSpend();
            hashes[i] = keccak256(e);
        }
        if (q.envelopesHash != keccak256(abi.encode(hashes)))
            revert InvalidNormalSpend();

        VantaEpochStateV1.Epoch storage target = state.epochs[state.currentEpoch];
        // Keep the emergency capacity reserve usable during rollover lag;
        // overflow still fails before any global nullifier is consumed.
        if (q.targetEpoch != state.currentEpoch ||
            q.targetCheckpoint != target.currentRef || target.closed ||
            uint256(target.slotCount) + 5 > 65_536)
            revert TargetUnavailable();
        if (a.quoteField == 0 || a.batchField == 0 ||
            a.quoteField != uint256(quoteDigest) % FR ||
            a.batchField != batchField)
            revert InvalidNormalSpend();
    }

    function _checkCombinedFeePartnerProof(
        VantaFamilyUnifiedPoolPreAudit.NormalEpochQuote calldata q,
        uint256[5] calldata outputs, uint8[3] calldata feeSlots,
        bytes calldata proof, bytes32 quoteHash, uint256 amountHash,
        uint256 batchDigest, uint8 feeLegIndex, Pins memory pins
    ) private view {
        Combined.CanonicalQuote memory feeQuote = Combined.CanonicalQuote({
            signedQuoteHash: quoteHash,
            outputs: outputs,
            feeSlots: feeSlots,
            outputCount: 5,
            depositGross: 0,
            protocolCap: q.protocolFeeCap,
            partnerCap: q.partnerFeeCap,
            relayerCap: q.relayerFeeCap,
            feeTermsHash: q.feeTermsHash,
            width: q.width,
            mode: q.mode,
            amountHash: amountHash,
            batchDigest: batchDigest,
            feeLegIndex: feeLegIndex,
            partnerRegistryRoot: q.partnerRegistryRoot,
            signedPartnerNonce: q.nonce,
            relayer: q.relayer,
            withdrawalPayout: q.mode == 0 ? q.payout : 0
        });
        if (!Combined(pins.combinedVerifier).verifyCombined(feeQuote, proof))
            revert InvalidNormalFeeProof();
    }

    /// @dev The unchanged combined relation opens a public payout only for
    /// mode 0. Modes 4/5 therefore require the existing aggregate relation to
    /// open Gate0's identical salted amount before any escrow value moves.
    /// Their protocol fee is the exact operation-specific policy rate, never
    /// the withdrawal rate or an unchecked signer-selected cap.
    function _checkRoutedPayout(
        VantaFamilyUnifiedPoolPreAudit.NormalEpochQuote calldata q,
        Agg.VerifyingKey calldata vk, Agg.Proof calldata proof,
        uint256[11] calldata input, uint256 batchDigest,
        uint256 amountHash, uint8 feeLegIndex, Pins memory pins
    ) private view {
        if (q.mode != 4 && q.mode != 5) return;
        uint256 due = (uint256(q.payout) *
            Combined(pins.combinedVerifier).protocolBpsFor(q.mode) + 9_999) / 10_000;
        if (due < pins.minimumProtocolFee) due = pins.minimumProtocolFee;
        if (q.protocolFeeCap != due) revert InvalidNormalFeeProof();
        if (feeLegIndex != 0 || !EpochVerifier(pins.normalVerifier).verifyPayout(
            vk, proof, input, batchDigest, amountHash, q.payout
        )) revert InvalidNormalProof();
    }

    function _verifiedAppend(
        VantaEpochStateV1.State storage state,
        VantaFamilyUnifiedPoolPreAudit.NormalEpochQuote calldata q,
        uint256[5] calldata outputs, Kzg.RowKey[5] calldata rowKeys,
        address writer
    ) private view returns (uint256 toRef, uint256 x, uint256 y, uint64 firstRow) {
        VantaEpochStateV1.Epoch storage target = state.epochs[q.targetEpoch];
        firstRow = target.slotCount;
        (uint256 fromRef, uint256 verifiedTo, uint256 newX, uint256 newY) =
            Kzg(writer).verifyEpochRows(
                q.targetEpoch, firstRow, target.x, target.y, 5, outputs, rowKeys
            );
        if (fromRef != q.targetCheckpoint) revert TargetUnavailable();
        return (verifiedTo, newX, newY, firstRow);
    }

    function _finish(
        mapping(bytes32 => bool) storage usedNonce,
        mapping(uint256 => bool) storage commitmentSeen,
        VantaFamilyUnifiedPoolPreAudit.NormalEpochQuote calldata q,
        uint256[5] calldata outputs, bytes[5] calldata envelopes,
        uint64 firstRow, uint256 verifiedRef, uint256 recordedRef
    ) private {
        if (verifiedRef != recordedRef) revert InvalidNormalProof();
        usedNonce[q.nonce] = true;
        for (uint256 i; i < 5; ++i) {
            uint256 cm = outputs[i];
            commitmentSeen[cm] = true;
            emit CanonicalKzgRow(q.targetEpoch, firstRow + uint64(i), cm);
            emit CanonicalEncryptedNote(
                q.targetEpoch, firstRow + uint64(i), cm,
                keccak256(envelopes[i]), envelopes[i]
            );
        }
    }

    /// @dev Delegatecalled exactly once from the reentrancy-guarded custody
    ///      selector. Every storage pointer is to the ONE escrow pool.
    function settleEight(
        VantaEpochStateV1.State storage state,
        mapping(bytes32 => bool) storage usedNonce,
        mapping(uint256 => bool) storage commitmentSeen,
        VantaFamilyUnifiedPoolPreAudit.NormalEpochQuote calldata q,
        VantaFamilyUnifiedPoolPreAudit.EpochSpend8 calldata p,
        bytes32 quoteHash, uint256 batchField, Pins memory pins
    ) external returns (uint256 recorded) {
        VantaEpochStateV1.Snapshot memory source =
            state.requireSpendSource(q.sourceEpoch, q.sourceCheckpoint);
        Statement8.LegPublic calldata a = p.action;
        if (a.sourceSlotCount != source.slotCount ||
            a.checkpointX != source.x || a.checkpointY != source.y)
            revert InvalidSource();
        _checkNormal(state,commitmentSeen,q,_viewEight(a),a.outputs,
            p.encryptedOutputs,p.feeSlots,quoteHash,batchField,pins);
        if (q.width != 8) revert InvalidNormalSpend();
        bool privateTransfer = q.mode == PRIVATE_TRANSFER;
        EpochVerifier verifier = EpochVerifier(pins.normalVerifier);
        if (!verifier.verifyEpoch8(
            a,p.gate0,p.gate1,p.link,privateTransfer,q.sourceEpoch,
            q.targetEpoch,source.slotCount,source.x,source.y
        )) revert InvalidNormalProof();
        _checkRoutedPayout(q,p.aggregateVk,p.aggregateProof,p.aggregateInputs,
            a.batchDigestField,a.saltedAmountHash,a.feeLegIndex,pins);
        // For a single public withdrawal, the combined proof now proves
        // the identical salted Gate0 amount opens to signed q.payout. The
        // standalone aggregate SNARK is redundant for this one-leg route.
        // Private transfers still prove hidden conservation in Gate0.
        _checkCombinedFeePartnerProof(q,a.outputs,p.feeSlots,p.combinedFeePartnerProof,
            quoteHash,a.saltedAmountHash,a.batchDigestField,a.feeLegIndex,pins);
        (uint256 toRef, uint256 x, uint256 y, uint64 firstRow) =
            _verifiedAppend(state,q,a.outputs,p.rowKeys,pins.kzgUpdater);
        recorded = state.recordVerifiedCrossEpochEight(
            q.sourceEpoch,q.sourceCheckpoint,q.targetEpoch,q.targetCheckpoint,
            x,y,a.nullifiers
        );
        for (uint256 i; i < 8; ++i) emit NullifierConsumed(a.nullifiers[i],8);
        _finish(usedNonce,commitmentSeen,q,a.outputs,p.encryptedOutputs,
            firstRow,toRef,recorded);
    }

    function settleThirtyTwo(
        VantaEpochStateV1.State storage state,
        mapping(bytes32 => bool) storage usedNonce,
        mapping(uint256 => bool) storage commitmentSeen,
        VantaFamilyUnifiedPoolPreAudit.NormalEpochQuote calldata q,
        VantaFamilyUnifiedPoolPreAudit.EpochSpend32 calldata p,
        bytes32 quoteHash, uint256 batchField, Pins memory pins
    ) external returns (uint256 recorded) {
        VantaEpochStateV1.Snapshot memory source =
            state.requireSpendSource(q.sourceEpoch, q.sourceCheckpoint);
        Statement32.LegPublic calldata a = p.action;
        if (a.sourceSlotCount != source.slotCount ||
            a.checkpointX != source.x || a.checkpointY != source.y)
            revert InvalidSource();
        _checkNormal(state,commitmentSeen,q,_viewThirtyTwo(a),a.outputs,
            p.encryptedOutputs,p.feeSlots,quoteHash,batchField,pins);
        if (q.width != 32) revert InvalidNormalSpend();
        bool privateTransfer = q.mode == PRIVATE_TRANSFER;
        EpochVerifier verifier = EpochVerifier(pins.normalVerifier);
        if (!verifier.verifyEpoch32(
            a,p.gate0,p.gate1,p.link,privateTransfer,q.sourceEpoch,
            q.targetEpoch,source.slotCount,source.x,source.y
        )) revert InvalidNormalProof();
        _checkRoutedPayout(q,p.aggregateVk,p.aggregateProof,p.aggregateInputs,
            a.batchDigestField,a.saltedAmountHash,a.feeLegIndex,pins);
        // For a single public withdrawal, the combined proof now proves
        // the identical salted Gate0 amount opens to signed q.payout. The
        // standalone aggregate SNARK is redundant for this one-leg route.
        // Private transfers still prove hidden conservation in Gate0.
        _checkCombinedFeePartnerProof(q,a.outputs,p.feeSlots,p.combinedFeePartnerProof,
            quoteHash,a.saltedAmountHash,a.batchDigestField,a.feeLegIndex,pins);
        (uint256 toRef, uint256 x, uint256 y, uint64 firstRow) =
            _verifiedAppend(state,q,a.outputs,p.rowKeys,pins.kzgUpdater);
        recorded = state.recordVerifiedCrossEpochThirtyTwo(
            q.sourceEpoch,q.sourceCheckpoint,q.targetEpoch,q.targetCheckpoint,
            x,y,a.nullifiers
        );
        for (uint256 i; i < 32; ++i) emit NullifierConsumed(a.nullifiers[i],32);
        _finish(usedNonce,commitmentSeen,q,a.outputs,p.encryptedOutputs,
            firstRow,toRef,recorded);
    }
}

