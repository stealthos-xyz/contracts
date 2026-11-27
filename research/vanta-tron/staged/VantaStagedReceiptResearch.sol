// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaFamilyGate0CcGroth16PreAudit as Gate0} from "../../../contracts/src/vanta/VantaFamilyGate0CcGroth16PreAudit.sol";
import {VantaCaulkPlusGate1Research as Caulk} from "../../../contracts/src/vanta/VantaCaulkPlusGate1Research.sol";
import {VantaCpLinkPairingResearch as Link} from "../../../contracts/src/vanta/VantaCpLinkPairingResearch.sol";
import {VantaCaulkPlusStagedResearch as StagedCaulk} from "./VantaCaulkPlusStagedResearch.sol";

/// @notice Current-state hook for a disposable, no-funds experiment.
/// @dev The implementation must authenticate the exact table and public inputs
/// against checkpoint/action, not merely return a global enabled flag. It must
/// also reject revoked configurations and stale state at finalization. This
/// interface is not an implementation of Vanta's production pool rules.
interface IVantaStagedResearchState {
    function isCurrent(
        bytes32 sessionId,
        bytes32 configurationHash,
        bytes32 actionHash,
        bytes32 checkpoint,
        bytes32 nullifier,
        bytes32 tableHash,
        bytes32 publicInputsHash
    ) external view returns (bool);
}

/// @notice Six individually verified receipts and one research finalization.
/// @dev NO FUNDS, NO TOKEN CALLS, NO POOL ADMISSION. This experiment covers only
/// family Gate0 (six inputs), four Caulk equations and CP_link. It does NOT cover
/// 40/41-input fee proofs, canonical production intent reconstruction, five-row
/// KZG transitions, authenticated production checkpoints or custody settlement.
/// The action uses a NEW research statement/context and requires proofs made
/// for that domain. A legacy proof cannot simply be relabeled as a TRON proof.
/// Configuration/code pins are immutable; deployment must use reviewed plain
/// contracts, not upgradeable proxies hidden behind unchanged proxy codehashes.
contract VantaStagedReceiptResearch {
    uint256 private constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    bytes32 public constant DOMAIN = keccak256("STEALTHOS_VANTA_TRON_STAGED_RESEARCH_V1");
    uint64 public constant MAX_SESSION_TTL = 1 days;
    uint8 public constant COMPLETE_MASK = 0x3f;

    Gate0 public immutable gate0Verifier;
    StagedCaulk public immutable gate1Verifier;
    Link public immutable linkVerifier;
    IVantaStagedResearchState public immutable stateChecker;
    bytes32 public immutable configurationHash;
    uint8 public immutable arity;
    uint256 public immutable familyTag;

    bytes32 private immutable gate0CodeHash;
    bytes32 private immutable gate1CodeHash;
    bytes32 private immutable linkCodeHash;
    bytes32 private immutable stateCodeHash;

    struct Gate0Data {
        Gate0.V8VerifyingKey vk;
        Gate0.Proof proof;
        uint256[6] publicInputs;
    }
    struct Gate1Data {
        Caulk.Table table;
        Caulk.Srs srs;
        Caulk.Proof proof;
        bytes context;
    }
    struct LinkData {
        Link.G1 pi;
        Link.G2 a2;
        Link.G2 c1;
        Link.G2 c2;
    }
    struct Bundle {
        Gate0Data g0;
        Gate1Data g1;
        LinkData link;
    }
    struct Intent {
        bytes32 actionHash;
        bytes32 checkpoint;
        // Disposable research replay key; not a complete production spent set.
        bytes32 nullifier;
        uint64 expiresAt;
    }
    struct Receipt {
        uint64 expiresAt;
        uint8 passedMask;
        bool finalized;
    }

    mapping(bytes32 => Receipt) public receipts;
    mapping(bytes32 => bool) public usedActions;
    mapping(bytes32 => bool) public usedNullifiers;

    error InvalidConfiguration();
    error InvalidBundle();
    error InvalidIntent();
    error InvalidStage();
    error AlreadyFinalized();
    error ExpiredSession();
    error VerificationFailed();
    error IncompleteSession();
    error StaleState();
    error NoExpiredSession();
    error CodeChanged();

    event StageAccepted(bytes32 indexed sessionId, bytes32 indexed actionHash, uint8 stage);
    event ResearchFinalized(
        bytes32 indexed sessionId, bytes32 indexed actionHash, bytes32 indexed nullifier
    );
    event ReceiptPruned(bytes32 indexed sessionId);

    constructor(
        address gate0,
        address gate1,
        address link,
        address state,
        bytes32 expectedConfigurationHash,
        uint8 queryArity,
        uint256 expectedFamilyTag
    ) {
        if (gate0.code.length == 0 || gate1.code.length == 0 ||
            link.code.length == 0 || state.code.length == 0 ||
            expectedConfigurationHash == bytes32(0) ||
            (queryArity != 8 && queryArity != 32) || expectedFamilyTag >= FR ||
            block.chainid >= FR) revert InvalidConfiguration();
        gate0Verifier = Gate0(gate0);
        gate1Verifier = StagedCaulk(gate1);
        linkVerifier = Link(link);
        stateChecker = IVantaStagedResearchState(state);
        gate0CodeHash = gate0.codehash;
        gate1CodeHash = gate1.codehash;
        linkCodeHash = link.codehash;
        stateCodeHash = state.codehash;
        configurationHash = expectedConfigurationHash;
        arity = queryArity;
        familyTag = expectedFamilyTag;
    }

    /// @notice Exact constructor key pin, using standard ABI encoding.
    function configurationHashFor(Bundle calldata bundle) public view returns (bytes32) {
        return keccak256(abi.encode(
            arity, familyTag, bundle.g0.vk, bundle.g1.srs,
            bundle.link.a2, bundle.link.c1, bundle.link.c2
        ));
    }

    /// @notice New disposable research statement, never a production statement.
    /// @dev Reduction is the explicit research hash-to-field definition. The
    /// full 256-bit intent is also bound without reduction in context/session.
    function statementFor(Intent calldata intent) public view returns (uint256) {
        return uint256(keccak256(abi.encode(
            DOMAIN, block.chainid, address(this), configurationHash, arity, familyTag, intent
        ))) % FR;
    }

    function contextFor(uint256[6] calldata publicInputs, Intent calldata intent)
        public view returns (bytes memory)
    {
        return abi.encode(
            DOMAIN, block.chainid, address(this), configurationHash, arity, familyTag,
            intent, keccak256(abi.encode(publicInputs))
        );
    }

    /// @notice Every key, proof point, scalar, table, context and intent is bound.
    function sessionIdFor(Bundle calldata bundle, Intent calldata intent)
        public view returns (bytes32)
    {
        return keccak256(abi.encode(
            DOMAIN, block.chainid, address(this), configurationHash, arity, familyTag,
            intent, keccak256(abi.encode(bundle))
        ));
    }

    /// @param stage 0 = Gate0, 1..4 = Caulk equations, 5 = CP_link.
    /// @dev Successful duplicate stages are idempotent. Anyone may relay a bound
    /// proof; relaying cannot alter the action or redirect a research receipt.
    function submitStage(uint8 stage, Bundle calldata bundle, Intent calldata intent)
        external returns (bytes32 sessionId)
    {
        if (stage > 5) revert InvalidStage();
        _validate(bundle, intent);
        sessionId = sessionIdFor(bundle, intent);
        Receipt storage receipt = receipts[sessionId];
        uint8 bit = uint8(1 << stage);
        if ((receipt.passedMask & bit) != 0) return sessionId;
        if (!_verifyStage(stage, bundle)) revert VerificationFailed();
        receipt.expiresAt = intent.expiresAt;
        receipt.passedMask |= bit;
        emit StageAccepted(sessionId, intent.actionHash, stage);
    }

    /// @notice Atomic one-time RESEARCH event only. No assets are moved.
    /// @dev The current-state callback runs at finalization, after all
    /// proof receipts exist. A stale or revoked snapshot cannot be finalized.
    function finalize(Bundle calldata bundle, Intent calldata intent)
        external returns (bytes32 sessionId)
    {
        _validate(bundle, intent);
        sessionId = sessionIdFor(bundle, intent);
        Receipt storage receipt = receipts[sessionId];
        if (receipt.passedMask != COMPLETE_MASK) revert IncompleteSession();
        if (receipt.finalized) revert AlreadyFinalized();
        if (!stateChecker.isCurrent(
            sessionId, configurationHash, intent.actionHash, intent.checkpoint,
            intent.nullifier, keccak256(abi.encode(bundle.g1.table)),
            keccak256(abi.encode(bundle.g0.publicInputs))
        )) revert StaleState();

        // isCurrent is a STATICCALL. It cannot mutate/reenter state before these
        // effects; there are no later external calls or custody interactions.
        receipt.finalized = true;
        usedActions[intent.actionHash] = true;
        usedNullifiers[intent.nullifier] = true;
        emit ResearchFinalized(sessionId, intent.actionHash, intent.nullifier);
    }

    /// @notice Bounded cleanup; consumed action/nullifier tombstones remain.
    function pruneExpired(bytes32 sessionId) external {
        uint64 expiry = receipts[sessionId].expiresAt;
        if (expiry == 0 || block.timestamp <= expiry) revert NoExpiredSession();
        delete receipts[sessionId];
        emit ReceiptPruned(sessionId);
    }

    function _validate(Bundle calldata bundle, Intent calldata intent) private view {
        if (address(gate0Verifier).codehash != gate0CodeHash ||
            address(gate1Verifier).codehash != gate1CodeHash ||
            address(linkVerifier).codehash != linkCodeHash ||
            address(stateChecker).codehash != stateCodeHash) revert CodeChanged();
        if (intent.actionHash == bytes32(0) || intent.checkpoint == bytes32(0) ||
            intent.nullifier == bytes32(0)) revert InvalidIntent();
        if (intent.expiresAt <= block.timestamp) revert ExpiredSession();
        if (uint256(intent.expiresAt) > block.timestamp + MAX_SESSION_TTL)
            revert InvalidIntent();
        if (usedActions[intent.actionHash] || usedNullifiers[intent.nullifier])
            revert AlreadyFinalized();
        if (bundle.g0.vk.ic.length != 7 || bundle.g1.table.n != 65_536 ||
            bundle.g1.context.length > 4096) revert InvalidBundle();
        if (configurationHashFor(bundle) != configurationHash ||
            bundle.g0.publicInputs[0] != statementFor(intent) ||
            bundle.g0.publicInputs[4] != familyTag ||
            bundle.g0.publicInputs[5] != block.chainid ||
            keccak256(bundle.g1.context) !=
                keccak256(contextFor(bundle.g0.publicInputs, intent))) revert InvalidBundle();
    }

    function _verifyStage(uint8 stage, Bundle calldata bundle) private view returns (bool) {
        if (stage == 0) return gate0Verifier.verifyFamily(
            bundle.g0.vk, bundle.g0.proof, bundle.g0.publicInputs
        );
        if (stage < 5) return gate1Verifier.verifyEquation(
            stage - 1, arity, bundle.g1.table, bundle.g1.srs,
            bundle.g1.proof, bundle.g1.context
        );
        // D and E come ONLY from the same bound Gate0/Caulk bundle.
        return linkVerifier.verifyResearch(
            bundle.link.pi,
            Link.G1(bundle.g0.proof.d.x, bundle.g0.proof.d.y),
            Link.G1(bundle.g1.table.query.x, bundle.g1.table.query.y),
            bundle.link.a2, bundle.link.c1, bundle.link.c2
        );
    }
}
