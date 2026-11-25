// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {PoseidonT4} from "../libraries/PoseidonT4.sol";
import {VantaTokenHash} from "./VantaTokenHash.sol";
import {VantaDummyPolicy} from "./VantaDummyPolicy.sol";
import {VantaEpochStateV1} from "./VantaEpochStateV1.sol";
import {VantaV8PinnedEpochRolloverBase} from "./VantaV8PinnedEpochRolloverBase.sol";
import {VantaV8FiveRowKzgResearch as Kzg} from "./VantaV8FiveRowKzgResearch.sol";
import {VantaV8StatementResearch as Statement8} from "./VantaV8StatementResearch.sol";
import {VantaV8Statement32Research as Statement32} from "./VantaV8Statement32Research.sol";
import {VantaFamilyFullBundleVerifierPreAudit as Bundle} from "./VantaFamilyFullBundleVerifierPreAudit.sol";
import {VantaFamilyAggregateGroth16PreAudit as Agg} from "./VantaFamilyAggregateGroth16PreAudit.sol";

/// @dev The production verifier must be the separately keyed NO_APPEND_EXIT_V1
///      implementation. Mock implementations are for Foundry tests ONLY.
interface IVantaFamilyPreAuditExitVerifier {
    function verifyExit8(
        Statement8.LegPublic calldata action, uint64 sourceEpoch,
        uint128 protocolFee, uint128 partnerFee,
        Bundle.V8Gate0Data calldata g0, Bundle.Gate1Data calldata g1,
        Bundle.LinkData calldata link,
        uint64 row, uint256 x, uint256 y
    ) external view returns (bool);
    function verifyExit32(
        Statement32.LegPublic calldata action, uint64 sourceEpoch,
        uint128 protocolFee, uint128 partnerFee,
        Bundle.V8Gate0Data calldata g0, Bundle.Gate1Data calldata g1,
        Bundle.LinkData calldata link,
        uint64 row, uint256 x, uint256 y
    ) external view returns (bool);
    function verifyPayout(
        Agg.VerifyingKey calldata vk, Agg.Proof calldata proof,
        uint256[11] calldata input, uint256 batchDigest,
        uint256 saltedAmountHash, uint256 amount
    ) external view returns (bool);
}

/// @notice Family-bound research candidate: abstract custody core, never standalone.
/// @notice Base Sepolia research ONLY: candidate for an epoch-scoped Vanta
///         custody pool with signed or immutable fixed-fee full exits and recoverable
///         encrypted note/row logs. It is not audited and not production-safe.
/// @dev NO owner, mutable verifier, emergency fee-free selector or arbitrary
///      nullifier burner. User funds MUST NOT be deposited until reviewed
///      ceremony keys, proof integration, custody audit and wallet recovery pass.
abstract contract VantaFamilyNoAppendExitCustodyPreAudit is VantaV8PinnedEpochRolloverBase {
    using VantaEpochStateV1 for VantaEpochStateV1.State;
    using SafeERC20 for IERC20;

    uint256 private constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant MAX_VALUE = (uint256(1) << 120) - 1;
    uint256 private constant MAX_ENVELOPE_BYTES = 2048;
    bytes32 private constant EIP712_DOMAIN =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("StealthOS Vanta V8 PreAudit");
    bytes32 private constant VERSION_HASH = keccak256("1");
    bytes32 public constant EXIT_TYPEHASH = keccak256(
        "NoAppendExitQuote(uint64 chainId,address pool,address asset,uint8 width,uint64 sourceEpoch,uint256 sourceCheckpoint,address recipient,uint128 payout,uint128 protocolFee,uint128 partnerFee,uint128 protocolFeeCap,uint128 partnerFeeCap,address protocolRecipient,address partnerRecipient,address relayer,bytes32 nullifiersHash,bytes32 outputsHash,uint256 saltedAmountHash,bytes32 nonce,uint64 deadline,bytes32 feePolicyHash)"
    );
    bytes32 internal constant DEPOSIT_TYPEHASH = keccak256(
        "DepositQuote(uint64 chainId,address pool,address asset,uint64 epoch,uint256 checkpoint,address payer,uint8 count,uint128 protocolFee,uint128 partnerFee,address protocolRecipient,address partnerRecipient,bytes32 rowsHash,bytes32 nonce,uint64 deadline,bytes32 feePolicyHash)"
    );
    bytes32 public constant BATCH_DOMAIN = keccak256("STEALTHOS_VANTA_V8_NO_APPEND_EXIT_BATCH_V1");

    struct ExitQuote {
        uint64 chainId;
        address pool;
        address asset;
        uint8 width;
        uint64 sourceEpoch;
        uint256 sourceCheckpoint;
        address recipient;
        uint128 payout;
        uint128 protocolFee;
        uint128 partnerFee;
        uint128 protocolFeeCap;
        uint128 partnerFeeCap;
        address protocolRecipient;
        address partnerRecipient;
        address relayer;
        bytes32 nullifiersHash;
        bytes32 outputsHash;
        uint256 saltedAmountHash;
        bytes32 nonce;
        uint64 deadline;
        bytes32 feePolicyHash;
    }

    struct DepositQuote {
        uint64 chainId;
        address pool;
        address asset;
        uint64 epoch;
        uint256 checkpoint;
        address payer;
        uint8 count;
        uint128 protocolFee;
        uint128 partnerFee;
        address protocolRecipient;
        address partnerRecipient;
        bytes32 rowsHash;
        bytes32 nonce;
        uint64 deadline;
        bytes32 feePolicyHash;
    }

    struct DepositRow {
        uint256 npk;
        uint128 value;
        uint256 commitment;
        bytes encryptedEnvelope;
    }

    struct Exit8 {
        Statement8.LegPublic action;
        Bundle.V8Gate0Data gate0;
        Bundle.Gate1Data gate1;
        Bundle.LinkData link;
        Agg.VerifyingKey aggregateVk;
        Agg.Proof aggregateProof;
        uint256[11] aggregateInputs;
    }

    struct Exit32 {
        Statement32.LegPublic action;
        Bundle.V8Gate0Data gate0;
        Bundle.Gate1Data gate1;
        Bundle.LinkData link;
        Agg.VerifyingKey aggregateVk;
        Agg.Proof aggregateProof;
        uint256[11] aggregateInputs;
    }

    IERC20 public immutable asset;
    address public immutable feeSigner;
    address public immutable protocolFeeRecipient;
    address public immutable partnerFeeRecipient;
    uint128 public immutable minimumProtocolFee;
    /// @notice Mandatory, immutable partner fee for a signer-independent full exit.
    uint128 public immutable fixedPartnerExitFee;
    /// @notice Signer-independent exits enforce these immutable, non-client
    /// chosen percentage rates, including when deposit minimums are zero.
    uint16 public immutable exitProtocolFeeBps;
    uint16 public immutable exitPartnerFeeBps;
    bytes32 private immutable initialFeePolicyHash;
    bytes32 public immutable assetCodehash;
    bytes32 public immutable exitLogicCodehash;
    uint256 public accountedLiability;
    uint256 private entered;
    mapping(bytes32 => bool) public usedNonce;
    mapping(uint256 => bool) public commitmentSeen;

    error UnapprovedPreAuditSetup();
    error InvalidQuote();
    error InvalidSignature();
    error FeeAuthorizationRequired();
    error InvalidEncryptedNote();
    error InvalidRow();
    error InvalidProof();
    error InvalidSource();
    error Replay();
    error InsufficientEscrow();
    error AssetTransferMismatch();
    error ReentrantCall();
    error DepositCapacityReached();

    event CanonicalEncryptedNote(
        uint64 indexed epoch, uint64 indexed row, uint256 indexed commitment,
        bytes32 envelopeHash, bytes encryptedEnvelope
    );
    event CanonicalKzgRow(uint64 indexed epoch, uint64 indexed row, uint256 indexed commitment);
    event PreAuditDeposit(
        bytes32 indexed quoteNonce, uint64 indexed epoch, uint8 count,
        uint256 totalValue, uint256 checkpoint
    );
    event PreAuditFullExit(
        bytes32 indexed quoteNonce, uint64 indexed sourceEpoch,
        address indexed recipient, uint8 width, uint256 payout,
        uint256 protocolFee, uint256 partnerFee, uint256 sourceCheckpoint
    );
    event NullifierConsumed(uint256 indexed nullifier, uint8 indexed width);

    modifier noReentry() {
        if (entered != 0) revert ReentrantCall();
        entered = 1;
        _;
        entered = 0;
    }

    constructor(
        address assetAddress, address exitVerifierAddress, address kzgAddress,
        uint256 initialX, uint256 initialY, address signer,
        address protocolRecipient, address partnerRecipient,
        uint128 minFee, uint128 partnerExitFee, bytes32 policyHash,
        uint16[2] memory exitFeeRates
    ) VantaV8PinnedEpochRolloverBase(
        block.chainid, exitVerifierAddress, exitVerifierAddress.codehash,
        kzgAddress, kzgAddress.codehash, initialX, initialY
    ) {
        // Zero address is the canonical native-ETH asset, as in V1.
        if ((assetAddress != address(0) && assetAddress.code.length == 0) ||
            signer == address(0) ||
            protocolRecipient == address(0) ||
            (partnerRecipient == address(0) && (partnerExitFee != 0 || exitFeeRates[1] != 0)) ||
            protocolRecipient == address(this) || partnerRecipient == address(this) ||
            uint256(minFee) + partnerExitFee > MAX_VALUE ||
            uint256(exitFeeRates[0]) + exitFeeRates[1] >= 10_000 ||
            policyHash == 0 ||
            exitVerifierAddress.code.length == 0 || kzgAddress.code.length == 0) {
            revert UnapprovedPreAuditSetup();
        }
        asset = IERC20(assetAddress);
        assetCodehash = assetAddress == address(0) ? bytes32(0) : assetAddress.codehash;
        feeSigner = signer;
        protocolFeeRecipient = protocolRecipient;
        partnerFeeRecipient = partnerRecipient;
        minimumProtocolFee = minFee;
        fixedPartnerExitFee = partnerExitFee;
        exitProtocolFeeBps = exitFeeRates[0];
        exitPartnerFeeBps = exitFeeRates[1];
        initialFeePolicyHash = policyHash;
        exitLogicCodehash = address(VantaFamilyNoAppendExitLogicPreAudit).codehash;
        if (address(VantaFamilyNoAppendExitLogicPreAudit).code.length == 0)
            revert UnapprovedPreAuditSetup();
    }

    function _setup() internal view {
        _requirePinnedEpochSetup();
        if (address(asset) != address(0) && address(asset).codehash != assetCodehash)
            revert UnapprovedPreAuditSetup();
    }

    /// @dev The last-resort exit must NOT depend on the KZG *writer*.
    ///      This path reads a previously authenticated source checkpoint,
    ///      verifies the independently pinned no-append proof and settles
    ///      publicly without inserting rows. A broken or unavailable writer
    ///      must not block authenticated exits from historical tables.
    ///      The proof verifier and custody asset remain fail-closed.
    function _setupExit() private view {
        if (block.chainid != approvedChainId ||
            approvedThreeGate.codehash != approvedThreeGateCodehash ||
            address(VantaFamilyNoAppendExitLogicPreAudit).codehash != exitLogicCodehash)
            revert UnapprovedPreAuditSetup();
        if (address(asset) != address(0) && address(asset).codehash != assetCodehash)
            revert UnapprovedPreAuditSetup();
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(EIP712_DOMAIN, NAME_HASH, VERSION_HASH,
            block.chainid, address(this)));
    }

    function _typedDigest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domainSeparator(), structHash));
    }

    function exitQuoteDigest(ExitQuote calldata q) external view returns (bytes32) {
        return _typedDigest(keccak256(abi.encode(EXIT_TYPEHASH, q)));
    }

    /// @dev Bind the aggregation transcript before computing its salted
    /// amount commitment. Deriving this field from the completed EIP-712
    /// quote creates a circular dependency: the quote itself contains that
    /// salted amount commitment. The signed quote still binds BOTH fields.
    function _exitBatchField(ExitQuote calldata q) private pure returns (uint256) {
        return uint256(keccak256(abi.encode(
            BATCH_DOMAIN, q.chainId, q.pool, q.width,
            q.sourceEpoch, q.sourceCheckpoint, q.nonce
        ))) % FR;
    }

    function depositQuoteDigest(DepositQuote calldata q) external view returns (bytes32) {
        return _typedDigest(keccak256(abi.encode(DEPOSIT_TYPEHASH, q)));
    }

    /// @notice Public cross-language fields: the signed EIP-712 quote digest
    ///         and a nonce-scoped, pre-quote aggregation digest.
    function exitDigestFields(ExitQuote calldata q)
        external view returns (uint256 quoteField, uint256 batchField)
    {
        bytes32 typed = _typedDigest(keccak256(abi.encode(EXIT_TYPEHASH, q)));
        quoteField = uint256(typed) % FR;
        batchField = _exitBatchField(q);
    }

    function currentSource() external view returns (
        uint64 epoch, uint64 rows, uint256 x, uint256 y, uint256 checkpoint
    ) {
        epoch = epochState.currentEpoch;
        VantaEpochStateV1.Epoch storage e = epochState.epochs[epoch];
        return (epoch, e.slotCount, e.x, e.y, e.currentRef);
    }

    /// @notice Authenticated point and row-count for wallet KZG replay.
    /// @dev Read at a finalized block alongside canonical row events. This
    ///      never authorizes a spend or substitutes for a real KZG opening.
    function sourceSnapshot(uint64 id) external view returns (
        uint64 rows, uint256 x, uint256 y, uint256 checkpoint, bool closed
    ) {
        if (id > epochState.currentEpoch ||
            epochState.epochs[id].slotCount == 0)
            revert VantaEpochStateV1.UnsupportedExitSource();
        VantaEpochStateV1.Epoch storage e = epochState.epochs[id];
        return (e.slotCount, e.x, e.y,
            e.closed ? e.finalRef : e.currentRef, e.closed);
    }

    function nullifierSpent(uint256 nf) external view returns (bool) {
        return epochState.nullifierSpent[nf];
    }

    function _authorize(
        bytes32 structHash, bytes32 nonce, uint64 deadline,
        bytes calldata signature
    ) internal view returns (bytes32 typed) {
        if (nonce == 0 || usedNonce[nonce]) revert Replay();
        if (block.timestamp > deadline) revert InvalidQuote();
        typed = _typedDigest(structHash);
        if (ECDSA.recover(typed, signature) != feeSigner) revert InvalidSignature();
    }

    function _checkFee(uint128 protocolFee, uint128 partnerFee) private view {
        if (protocolFee < minimumProtocolFee ||
            (exitPartnerFeeBps == 0 && fixedPartnerExitFee == 0 && partnerFee != 0) ||
            uint256(protocolFee) + uint256(partnerFee) > MAX_VALUE)
            revert FeeAuthorizationRequired();
    }

    /// @dev For native ETH, the function's msg.value is already in custody.
    ///      For ERC20, require zero attached ETH and verify the exact token delta.
    function _receiveExact(uint256 gross) internal {
        if (address(asset) == address(0)) {
            if (msg.value != gross) revert AssetTransferMismatch();
            return;
        }
        if (msg.value != 0) revert AssetTransferMismatch();
        uint256 beforeBalance = asset.balanceOf(address(this));
        asset.safeTransferFrom(msg.sender, address(this), gross);
        if (asset.balanceOf(address(this)) - beforeBalance != gross)
            revert AssetTransferMismatch();
    }

    function _transferExact(address recipient, uint256 amount) internal {
        if (amount == 0) return;
        if (recipient == address(0) || recipient == address(this))
            revert AssetTransferMismatch();
        if (address(asset) == address(0)) {
            uint256 beforeBalance = address(this).balance;
            (bool ok,) = recipient.call{value: amount}("");
            // A recipient can forward its ETH elsewhere, as in V1. Pin only
            // the escrow delta, never the recipient's ending ETH balance.
            if (!ok || beforeBalance - address(this).balance != amount)
                revert AssetTransferMismatch();
            return;
        }
        uint256 senderBefore = asset.balanceOf(address(this));
        uint256 recipientBefore = asset.balanceOf(recipient);
        asset.safeTransfer(recipient, amount);
        if (senderBefore - asset.balanceOf(address(this)) != amount ||
            asset.balanceOf(recipient) - recipientBefore != amount)
            revert AssetTransferMismatch();
    }

    /// @dev Native ETH enters only through the explicitly quoted payable
    ///      deposit function. Forced ETH is not credited to note liability.
    receive() external payable {
        revert AssetTransferMismatch();
    }

    /// @notice Pre-audit ingress: the fee signer authorizes ALL public amounts.
    /// @dev Each emitted envelope is a canonical, on-chain recovery payload.
    ///      Wallets must decrypt and verify note openings against commitments.
    ///      No note can be inserted without the pinned KZG row update.
    function depositWithSignedFee(
        DepositQuote calldata q, DepositRow[5] calldata notes,
        Kzg.RowKey[5] calldata keys, bytes calldata signature
    ) external payable virtual noReentry returns (uint256 nextCheckpoint) {
        _setup();
        _checkFee(q.protocolFee, q.partnerFee);
        if (q.chainId != block.chainid || q.pool != address(this) ||
            q.asset != address(asset) || q.payer != msg.sender ||
            q.protocolRecipient != protocolFeeRecipient ||
            q.partnerRecipient != partnerFeeRecipient ||
            q.feePolicyHash != feePolicyHash() ||
            q.epoch != epochState.currentEpoch ||
            q.count == 0 || q.count > 5)
            revert InvalidQuote();
        VantaEpochStateV1.Epoch storage e = epochState.epochs[q.epoch];
        if (e.closed || q.checkpoint != e.currentRef) revert InvalidSource();
        if (e.slotCount >= TABLE_SIZE - 1_024 ||
            uint256(e.slotCount) + q.count > TABLE_SIZE - 5)
            revert DepositCapacityReached();

        uint256[5] memory commitments;
        uint128[5] memory values;
        bytes32[5] memory envelopeHashes;
        uint256 total;
        uint256 tokenHash = VantaTokenHash.compute(block.chainid, address(this), address(asset));
        for (uint256 i; i < 5; ++i) {
            DepositRow calldata note = notes[i];
            if (i >= q.count) {
                if (note.npk != 0 || note.value != 0 ||
                    note.commitment != 0 || note.encryptedEnvelope.length != 0)
                    revert InvalidRow();
                continue;
            }
            if (note.npk == 0 || note.npk >= FR || note.value == 0 ||
                note.value > MAX_VALUE || note.encryptedEnvelope.length < 64 ||
                note.encryptedEnvelope.length > MAX_ENVELOPE_BYTES ||
                note.encryptedEnvelope[0] != bytes1(uint8(1)))
                revert InvalidEncryptedNote();
            uint256 cm = PoseidonT4.hash([note.npk, tokenHash, uint256(note.value)]);
            if (cm != note.commitment || commitmentSeen[cm] ||
                VantaDummyPolicy.isDisallowedRealCommitment(cm))
                revert InvalidRow();
            for (uint256 j; j < i; ++j)
                if (commitments[j] == cm) revert InvalidRow();
            commitments[i] = cm;
            values[i] = note.value;
            envelopeHashes[i] = keccak256(note.encryptedEnvelope);
            total += uint256(note.value);
        }
        if (total + q.protocolFee + q.partnerFee > MAX_VALUE) revert InvalidRow();
        if (q.rowsHash != keccak256(abi.encode(commitments, values, envelopeHashes)))
            revert InvalidQuote();
        _authorize(keccak256(abi.encode(DEPOSIT_TYPEHASH, q)),
            q.nonce, q.deadline, signature);

        uint256 gross = total + q.protocolFee + q.partnerFee;
        _receiveExact(gross);
        (uint256 fromRef, uint256 toRef, uint256 x, uint256 y) =
            Kzg(approvedKzgUpdater).verifyEpochRows(
                q.epoch, e.slotCount, e.x, e.y, q.count, commitments, keys
            );
        if (fromRef != e.currentRef) revert InvalidSource();
        uint64 firstRow = e.slotCount;
        nextCheckpoint = epochState.append(q.epoch, firstRow + q.count, x, y);
        if (nextCheckpoint != toRef) revert InvalidProof();
        usedNonce[q.nonce] = true;
        for (uint256 i; i < q.count; ++i) {
            commitmentSeen[commitments[i]] = true;
            emit CanonicalKzgRow(q.epoch, firstRow + uint64(i), commitments[i]);
            emit CanonicalEncryptedNote(
                q.epoch, firstRow + uint64(i), commitments[i],
                envelopeHashes[i], notes[i].encryptedEnvelope
            );
        }
        accountedLiability += total;
        _transferExact(protocolFeeRecipient, q.protocolFee);
        _transferExact(partnerFeeRecipient, q.partnerFee);
        emit PreAuditDeposit(q.nonce, q.epoch, q.count, total, nextCheckpoint);
    }

    function feePolicyHash() public view virtual returns (bytes32) { return initialFeePolicyHash; }
    /// Emergency exits retain the deployment's original rates and hash even
    /// when new ordinary transactions use an updated protocol fee policy.
    function exitFeePolicyHash() public view returns (bytes32) { return initialFeePolicyHash; }
    function _exitPins() private view returns (VantaFamilyNoAppendExitLogicPreAudit.Pins memory) {
        return VantaFamilyNoAppendExitLogicPreAudit.Pins(
            address(asset),feeSigner,protocolFeeRecipient,partnerFeeRecipient,
            minimumProtocolFee,fixedPartnerExitFee,exitProtocolFeeBps,exitPartnerFeeBps,
            initialFeePolicyHash,approvedThreeGate,domainSeparator()
        );
    }

    /// @notice Both legacy selectors retain exactly the same no-append
    /// relation, signer-independent fee policy and one-pool settlement.
    function settleNoAppendExit8(
        ExitQuote calldata q, Exit8 calldata proof, bytes calldata feeSignature
    ) external noReentry {
        _setupExit();
        VantaFamilyNoAppendExitLogicPreAudit.settleEight(epochState,usedNonce,q,proof,feeSignature,_exitPins());
        _settle(q);
    }

    function settleNoAppendExit32(
        ExitQuote calldata q, Exit32 calldata proof, bytes calldata feeSignature
    ) external noReentry {
        _setupExit();
        VantaFamilyNoAppendExitLogicPreAudit.settleThirtyTwo(epochState,usedNonce,q,proof,feeSignature,_exitPins());
        _settle(q);
    }

    /// @dev Quote/exit consumption and all three ERC20 transfers happen in ONE
    ///      EVM transaction; a revert rolls back every global nullifier.
    function _settle(ExitQuote calldata q) private {
        if (exitPartnerFeeBps == 0 && fixedPartnerExitFee == 0 && q.partnerFee != 0)
            revert FeeAuthorizationRequired();
        uint256 consumed = uint256(q.payout) + q.protocolFee + q.partnerFee;
        if (consumed > accountedLiability) revert InsufficientEscrow();
        usedNonce[q.nonce] = true;
        accountedLiability -= consumed;
        _transferExact(q.recipient, q.payout);
        _transferExact(protocolFeeRecipient, q.protocolFee);
        _transferExact(partnerFeeRecipient, q.partnerFee);
        emit PreAuditFullExit(q.nonce, q.sourceEpoch, q.recipient,
            q.width, q.payout, q.protocolFee, q.partnerFee, q.sourceCheckpoint);
    }
}

/// @notice Immutable linked validation for the existing no-append selectors.
/// @dev Runs by delegatecall under the pool's unchanged reentrancy guard;
/// this library never transfers assets or chooses a different custody pool.
library VantaFamilyNoAppendExitLogicPreAudit {
    using VantaEpochStateV1 for VantaEpochStateV1.State;
    uint256 private constant FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant MAX_VALUE = (uint256(1) << 120) - 1;
    bytes32 private constant BATCH_DOMAIN = keccak256("STEALTHOS_VANTA_V8_NO_APPEND_EXIT_BATCH_V1");
    bytes32 private constant EXIT_TYPEHASH = keccak256(
        "NoAppendExitQuote(uint64 chainId,address pool,address asset,uint8 width,uint64 sourceEpoch,uint256 sourceCheckpoint,address recipient,uint128 payout,uint128 protocolFee,uint128 partnerFee,uint128 protocolFeeCap,uint128 partnerFeeCap,address protocolRecipient,address partnerRecipient,address relayer,bytes32 nullifiersHash,bytes32 outputsHash,uint256 saltedAmountHash,bytes32 nonce,uint64 deadline,bytes32 feePolicyHash)"
    );
    struct Pins {
        address asset;
        address feeSigner;
        address protocolFeeRecipient;
        address partnerFeeRecipient;
        uint128 minimumProtocolFee;
        uint128 fixedPartnerExitFee;
        uint16 exitProtocolFeeBps;
        uint16 exitPartnerFeeBps;
        bytes32 feePolicyHash;
        address verifier;
        bytes32 domainSeparator;
    }
    error InvalidQuote();
    error InvalidSignature();
    error FeeAuthorizationRequired();
    error InvalidProof();
    error InvalidSource();
    error Replay();
    event NullifierConsumed(uint256 indexed nullifier, uint8 indexed width);

    function _typedDigest(bytes32 structHash,bytes32 domain) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901",domain,structHash));
    }
    function _exitBatchField(VantaFamilyNoAppendExitCustodyPreAudit.ExitQuote calldata q)
        private pure returns (uint256)
    {
        return uint256(keccak256(abi.encode(BATCH_DOMAIN,q.chainId,q.pool,q.width,
            q.sourceEpoch,q.sourceCheckpoint,q.nonce))) % FR;
    }

    function _exitDue(uint256 gross, uint16 bps, uint128 floor)
        private pure returns (uint256)
    {
        // Exact integer ceil, no floating point and no modular wrapping.
        uint256 percentage = (gross * bps + 9_999) / 10_000;
        return percentage > floor ? percentage : floor;
    }

    function _checkExitQuote(
        VantaFamilyNoAppendExitCustodyPreAudit.ExitQuote calldata q, uint8 width, uint64 sourceEpoch,
        uint256 sourceCheckpoint, address recipient, uint256 saltedAmountHash,
        uint128 protocolCap, uint128 partnerCap,
        address protocolRecipient, address partnerRecipient,
        bytes32 nullifiersHash, bytes32 outputsHash,
        uint256 batchField, uint256 quoteField,
        bytes calldata signature,
        mapping(bytes32 => bool) storage usedNonce, Pins memory pins
    ) private view {
        if (q.protocolFee < pins.minimumProtocolFee ||
            uint256(q.protocolFee) + q.partnerFee > MAX_VALUE) revert FeeAuthorizationRequired();
        // A zero minimum for fee-free deposits MUST NOT waive the approved
        // withdrawal percentages on signer-independent emergency exits.
        if (q.chainId != block.chainid || q.pool != address(this) ||
            q.asset != pins.asset || q.width != width ||
            q.sourceEpoch != sourceEpoch || q.sourceCheckpoint != sourceCheckpoint ||
            q.recipient != recipient || q.recipient == address(this) ||
            q.payout == 0 ||
            q.protocolFeeCap != protocolCap || q.partnerFeeCap != partnerCap ||
            q.protocolFee > protocolCap || q.partnerFee > partnerCap ||
            q.protocolRecipient != pins.protocolFeeRecipient ||
            q.partnerRecipient != pins.partnerFeeRecipient ||
            protocolRecipient != pins.protocolFeeRecipient ||
            partnerRecipient != pins.partnerFeeRecipient ||
            q.saltedAmountHash != saltedAmountHash ||
            q.nullifiersHash != nullifiersHash || q.outputsHash != outputsHash ||
            q.feePolicyHash != pins.feePolicyHash ||
            uint256(q.payout) + q.protocolFee + q.partnerFee > MAX_VALUE)
            revert InvalidQuote();
        uint256 gross = uint256(q.payout) + q.protocolFee + q.partnerFee;
        uint256 protocolDue =
            _exitDue(gross, pins.exitProtocolFeeBps, pins.minimumProtocolFee);
        uint256 partnerDue =
            _exitDue(gross, pins.exitPartnerFeeBps, pins.fixedPartnerExitFee);
        if (uint256(q.protocolFee) < protocolDue ||
            uint256(q.partnerFee) < partnerDue)
            revert FeeAuthorizationRequired();
        // The ordinary sponsored exit stays signer-authorized and relayer-bound.
        // The same selector also permits permissionless submission with NO
        // signature or named relayer, but ONLY at immutable nonzero fee amounts.
        // Both paths still require identical fully bound cryptographic proofs,
        // global-nullifier consumption, escrow accounting and atomic payouts.
        bytes32 structHash = keccak256(abi.encode(EXIT_TYPEHASH, q));
        bytes32 typed;
        if (signature.length == 0) {
            if (q.relayer != address(0) ||
                uint256(q.protocolFee) != protocolDue ||
                uint256(q.partnerFee) != partnerDue)
                revert FeeAuthorizationRequired();
            if (q.nonce == bytes32(0) || usedNonce[q.nonce]) revert Replay();
            if (block.timestamp > q.deadline) revert InvalidQuote();
            typed = _typedDigest(structHash,pins.domainSeparator);
        } else {
            if (q.relayer != msg.sender) revert InvalidQuote();
            if (q.nonce == bytes32(0) || usedNonce[q.nonce]) revert Replay();
            if (block.timestamp > q.deadline) revert InvalidQuote();
            typed = _typedDigest(structHash,pins.domainSeparator);
            if (ECDSA.recover(typed,signature) != pins.feeSigner) revert InvalidSignature();
        }
        if (quoteField == 0 || batchField == 0 ||
            quoteField != uint256(typed) % FR ||
            batchField != _exitBatchField(q))
            revert InvalidQuote();
    }

    function settleEight(
        VantaEpochStateV1.State storage epochState, mapping(bytes32 => bool) storage usedNonce,
        VantaFamilyNoAppendExitCustodyPreAudit.ExitQuote calldata q,
        VantaFamilyNoAppendExitCustodyPreAudit.Exit8 calldata proof, bytes calldata feeSignature, Pins memory pins
    ) external {
        VantaEpochStateV1.Snapshot memory source =
            epochState.requireSpendSource(q.sourceEpoch, q.sourceCheckpoint);
        Statement8.LegPublic calldata a = proof.action;
        if (a.pool != address(this) || a.token != pins.asset ||
            a.sourceSlotCount != source.slotCount ||
            a.checkpointX != source.x || a.checkpointY != source.y)
            revert InvalidSource();
        _checkExitQuote(q, 8, q.sourceEpoch, q.sourceCheckpoint,
            a.recipient, a.saltedAmountHash,
            a.protocolFeeCap, a.partnerFeeCap,
            a.protocolFeeRecipient, a.partnerFeeRecipient,
            keccak256(abi.encode(a.nullifiers)), keccak256(abi.encode(a.outputs)),
            a.batchDigestField, a.feeQuoteDigestField, feeSignature, usedNonce, pins);
        IVantaFamilyPreAuditExitVerifier verifier =
            IVantaFamilyPreAuditExitVerifier(pins.verifier);
        if (!verifier.verifyExit8(a, q.sourceEpoch, q.protocolFee, q.partnerFee,
                proof.gate0, proof.gate1, proof.link,
                source.slotCount, source.x, source.y) ||
            !verifier.verifyPayout(
                proof.aggregateVk, proof.aggregateProof, proof.aggregateInputs,
                a.batchDigestField, a.saltedAmountHash, q.payout))
            revert InvalidProof();
        epochState.recordVerifiedNoAppendExitEight(
            q.sourceEpoch, q.sourceCheckpoint, a.nullifiers
        );
        for (uint256 i; i < 8; ++i)
            emit NullifierConsumed(a.nullifiers[i], 8);
    }

    function settleThirtyTwo(
        VantaEpochStateV1.State storage epochState, mapping(bytes32 => bool) storage usedNonce,
        VantaFamilyNoAppendExitCustodyPreAudit.ExitQuote calldata q,
        VantaFamilyNoAppendExitCustodyPreAudit.Exit32 calldata proof, bytes calldata feeSignature, Pins memory pins
    ) external {
        VantaEpochStateV1.Snapshot memory source =
            epochState.requireSpendSource(q.sourceEpoch, q.sourceCheckpoint);
        Statement32.LegPublic calldata a = proof.action;
        if (a.pool != address(this) || a.token != pins.asset ||
            a.sourceSlotCount != source.slotCount ||
            a.checkpointX != source.x || a.checkpointY != source.y)
            revert InvalidSource();
        _checkExitQuote(q, 32, q.sourceEpoch, q.sourceCheckpoint,
            a.recipient, a.saltedAmountHash,
            a.protocolFeeCap, a.partnerFeeCap,
            a.protocolFeeRecipient, a.partnerFeeRecipient,
            keccak256(abi.encode(a.nullifiers)), keccak256(abi.encode(a.outputs)),
            a.batchDigestField, a.feeQuoteDigestField, feeSignature, usedNonce, pins);
        IVantaFamilyPreAuditExitVerifier verifier =
            IVantaFamilyPreAuditExitVerifier(pins.verifier);
        if (!verifier.verifyExit32(a, q.sourceEpoch, q.protocolFee, q.partnerFee,
                proof.gate0, proof.gate1, proof.link,
                source.slotCount, source.x, source.y) ||
            !verifier.verifyPayout(
                proof.aggregateVk, proof.aggregateProof, proof.aggregateInputs,
                a.batchDigestField, a.saltedAmountHash, q.payout))
            revert InvalidProof();
        epochState.recordVerifiedNoAppendExitThirtyTwo(
            q.sourceEpoch, q.sourceCheckpoint, a.nullifiers
        );
        for (uint256 i; i < 32; ++i)
            emit NullifierConsumed(a.nullifiers[i], 32);
    }

}
