// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";
import {VantaFamilyPartnerKzgUpdatePreAudit} from "./VantaFamilyPartnerKzgUpdatePreAudit.sol";
import {PoseidonT4External} from "../libraries/PoseidonT4External.sol";
import {PoseidonT3External} from "../libraries/PoseidonExternal.sol";

interface IVantaKzgPolicyPool {
    function asset() external view returns (address);
    function releaseSetupId() external view returns (bytes32);
    function releaseGenerationId() external view returns (bytes32);
    function releaseFamilyTag() external view returns (bytes32);
    function releaseChainId() external view returns (uint256);
}

/// @notice P0.1 authenticated KZG policy-table candidate, not an active registry.
/// @dev Deploy only from the owner-proof registrar: the creating registrar is
/// the sole immutable authority. Its outer transaction authorizes all twelve
/// policies. This contract neither accepts nor exposes private receiving keys.
/// The full migration additionally requires a qualified private KZG membership
/// relation. No existing Merkle fee verifier may accept this table's checkpoint.
contract VantaFamilyPartnerKzgRegistryPreAudit is VantaFamilyReleaseBinding {
    uint256 public constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant LEAF_DOMAIN = 0x56414e54414b5a47504f4c49435901;
    uint256 public constant MAX_FEE_VALUE = (uint256(1) << 120) - 1;
    uint32 public constant TABLE_SIZE = 65_536;
    uint32 public constant FIRST_POLICY_ROW = 32;
    bytes32 public constant REGISTRY_SCHEME =
        keccak256("VANTA_FAMILY_KZG_POLICY_TABLE_V1");
    bytes32 public constant CHECKPOINT_DOMAIN =
        keccak256("VANTA_FAMILY_KZG_POLICY_CHECKPOINT_V1");

    address public immutable administrator;
    address public immutable poseidonT3;
    bytes32 public immutable poseidonT3Codehash;
    VantaFamilyPartnerKzgUpdatePreAudit public immutable updater;
    bytes32 public immutable updaterCodehash;
    bytes32 public immutable acceptedUpdateKeyRoot;

    struct Partner {
        bytes32 partnerId;
        uint64 version;
        uint256 receiverCommitment;
        uint16 feeBps;
        uint128 feeMinimum;
        uint128 feeMaximum;
        uint256 authorizationKey;
        bool active;
        uint256 leaf;
    }
    struct Pool {
        address asset;
        uint64 revision;
        uint32 nextSlot;
        bool approved;
        uint256 x;
        uint256 y;
        uint256 root;
        uint256 leafPrefix;
    }
    struct SixOperationFees {
        uint16[6] bps;
        uint128[6] minimum;
        uint128[6] maximum;
    }
    struct FeeCollector {
        bytes32 handleId;
        uint256 authorizationCommitment;
        uint256 receiverCommitment;
        uint256 proofCommitment;
        bytes32 routingCommitment;
        bool active;
    }

    mapping(address => Pool) private pools;
    mapping(address => mapping(uint16 => Partner)) private entries;
    mapping(address => mapping(bytes32 => uint32)) private partnerSlotPlusOne;
    mapping(address => mapping(uint8 => FeeCollector)) private feeCollectors;
    mapping(address => address) public activePoolForAsset;

    event PoolRegistered(address indexed pool, address indexed asset, uint256 root);
    event PolicyCommitmentChanged(address indexed pool, uint64 revision,
        uint256 x, uint256 y, uint32 nextSlot, uint256 root);
    event PartnerVersionChanged(address indexed pool, bytes32 indexed partnerId,
        uint16 slot, uint64 version, uint256 receiverCommitment, uint16 feeBps,
        uint128 feeMinimum, uint128 feeMaximum, bool active, uint256 root);
    event FeeCollectorActivated(address indexed pool, uint8 indexed role,
        bytes32 indexed handleId, uint256 receiverCommitment, uint256 proofCommitment);

    error NotAdministrator();
    error InvalidRegistrySetup();
    error InvalidPool();
    error InvalidPartner();
    error StaleCommitment();
    error PoolCapacityReached();

    modifier adminOnly() {
        if (msg.sender != administrator) revert NotAdministrator();
        if (block.chainid != releaseChainId) revert WrongFamilyNetwork();
        _requireCode();
        _;
    }

    constructor(address hasher, bytes32 updateKeyRoot, bytes32 setupId,
        bytes32 generationId, bytes32 familyTag, uint256 chainId)
        VantaFamilyReleaseBinding(setupId, generationId, familyTag, chainId)
    {
        if (hasher.code.length == 0 || updateKeyRoot == bytes32(0) ||
            chainId >= (uint256(1) << 53) || uint256(familyTag) >= FR)
            revert InvalidRegistrySetup();
        PoseidonT3External.validate(hasher);
        PoseidonT4External.validate(hasher);
        administrator = msg.sender;
        poseidonT3 = hasher;
        poseidonT3Codehash = hasher.codehash;
        acceptedUpdateKeyRoot = updateKeyRoot;
        VantaFamilyPartnerKzgUpdatePreAudit helper = new VantaFamilyPartnerKzgUpdatePreAudit(
            updateKeyRoot, setupId, generationId, familyTag, chainId
        );
        updater = helper;
        updaterCodehash = address(helper).codehash;
    }

    function _requireCode() private view {
        if (poseidonT3.codehash != poseidonT3Codehash ||
            address(updater).codehash != updaterCodehash) revert InvalidRegistrySetup();
    }

    function registerPool(address pool, address asset) external adminOnly {
        if (pool.code.length == 0 || pools[pool].approved ||
            activePoolForAsset[asset] != address(0) ||
            IVantaKzgPolicyPool(pool).asset() != asset ||
            IVantaKzgPolicyPool(pool).releaseSetupId() != releaseSetupId ||
            IVantaKzgPolicyPool(pool).releaseGenerationId() != releaseGenerationId ||
            IVantaKzgPolicyPool(pool).releaseFamilyTag() != releaseFamilyTag ||
            IVantaKzgPolicyPool(pool).releaseChainId() != releaseChainId) revert InvalidPool();
        Pool storage p = pools[pool];
        p.asset = asset;
        p.nextSlot = FIRST_POLICY_ROW;
        p.approved = true;
        // Every row starts at zero, including the reserved prefix: C=(0,0).
        // No caller may choose or import the initial table commitment.
        p.leafPrefix = _poolLeafPrefix(pool, asset);
        p.root = _checkpoint(pool, p);
        activePoolForAsset[asset] = pool;
        emit PoolRegistered(pool, asset, p.root);
        emit PolicyCommitmentChanged(pool, 0, 0, 0, p.nextSlot, p.root);
    }

    /// @notice root is a field checkpoint reference, not a policy Merkle root.
    function poolState(address pool) external view returns (
        address asset, uint256 root, uint32 nextSlot, bool approved
    ) {
        Pool storage p = pools[pool];
        return (p.asset, p.root, p.nextSlot, p.approved);
    }

    function poolCommitment(address pool) external view returns (
        uint256 x, uint256 y, uint64 revision
    ) {
        Pool storage p = pools[pool];
        return (p.x, p.y, p.revision);
    }

    /// @notice Canonical full-domain prefix for the future fee circuit.
    /// Its adapter must fetch this from the pinned registry, never a caller.
    function poolPolicyContext(address pool) external view returns (uint256) {
        _requireCode();
        if (!pools[pool].approved) revert InvalidPool();
        return pools[pool].leafPrefix;
    }

    function partnerAt(address pool, uint16 slot) external view returns (Partner memory) {
        return entries[pool][slot];
    }

    function partnerSlot(address pool, bytes32 partnerId) external view returns (
        bool found, uint16 slot
    ) {
        uint32 index = partnerSlotPlusOne[pool][partnerId];
        return (index != 0, index == 0 ? 0 : uint16(index - 1));
    }

    function operationPartnerId(uint256 basePartnerId, uint8 operation)
        public view returns (bytes32)
    {
        _requireCode();
        if (basePartnerId == 0 || basePartnerId >= FR || operation > 5)
            revert InvalidPartner();
        uint256 id = PoseidonT3External.hash(poseidonT3, [basePartnerId, uint256(operation)]);
        if (id == 0 || id >= FR) revert InvalidPartner();
        return bytes32(id);
    }

    /// @dev Full setup/generation identifiers are split into canonical limbs;
    /// no bytes32 identifier is silently truncated to one field element.
    function _poolLeafPrefix(address pool, address asset) private view returns (uint256 digest) {
        uint256[10] memory fields = [uint256(1), releaseChainId,
            uint256(uint160(address(this))), uint256(uint128(uint256(releaseSetupId))),
            uint256(releaseSetupId) >> 128, uint256(uint128(uint256(releaseGenerationId))),
            uint256(releaseGenerationId) >> 128, uint256(releaseFamilyTag),
            uint256(uint160(pool)), uint256(uint160(asset))];
        digest = LEAF_DOMAIN;
        for (uint256 i; i < fields.length; i += 2)
            digest = PoseidonT4External.hash(poseidonT3, [digest, fields[i], fields[i + 1]]);
    }

    function _validate(uint256 receiver, uint16 bps, uint128 minimum,
        uint128 maximum, uint256 authorizationKey) private pure
    {
        if (receiver == 0 || receiver >= FR || authorizationKey == 0 ||
            authorizationKey >= FR || bps > 10_000 || maximum > MAX_FEE_VALUE ||
            maximum < minimum || (bps == 0 && minimum != maximum) ||
            (bps != 0 && maximum == 0)) revert InvalidPartner();
    }

    function _leaf(uint256 prefix, bytes32 partnerId, uint8 operation,
        uint64 version, uint256 receiver, uint16 bps, uint128 minimum,
        uint128 maximum, uint256 authorizationKey) private view returns (uint256 digest)
    {
        uint256[8] memory fields = [uint256(partnerId), uint256(version), receiver,
            uint256(bps), uint256(minimum), uint256(maximum), authorizationKey, uint256(operation)];
        digest = prefix;
        for (uint256 i; i < fields.length; i += 2)
            digest = PoseidonT4External.hash(poseidonT3, [digest, fields[i], fields[i + 1]]);
        // Revoked/unallocated rows are zero and can never be a real policy.
        if (digest == 0) revert InvalidPartner();
    }

    function partnerLeaf(address pool, uint256 basePartnerId, uint8 operation,
        uint64 version, uint256 receiverCommitment, uint16 feeBps,
        uint128 minFee, uint128 maxFee, uint256 authorizationKey
    ) external view returns (uint256) {
        if (!pools[pool].approved || version == 0) revert InvalidPool();
        _validate(receiverCommitment, feeBps, minFee, maxFee, authorizationKey);
        return _leaf(pools[pool].leafPrefix, operationPartnerId(basePartnerId, operation),
            operation, version, receiverCommitment, feeBps, minFee, maxFee, authorizationKey);
    }

    function setSixOperationPolicies(
        address pool, uint256 basePartnerId, uint256 receiverCommitment,
        uint256 authorizationKey, SixOperationFees calldata fees,
        uint256 expectedCheckpoint, VantaFamilyPartnerKzgUpdatePreAudit.RowKey[6] calldata keys,
        bool registration
    ) external adminOnly returns (uint256 root) {
        Pool storage p = pools[pool];
        _requireCheckpoint(p, expectedCheckpoint);
        uint32 firstSlot = registration ? p.nextSlot : _firstSlot(pool, basePartnerId);
        if (uint256(firstSlot) + 6 > TABLE_SIZE) revert PoolCapacityReached();
        uint256[6] memory oldLeaves;
        uint256[6] memory newLeaves;
        bytes32[6] memory ids;
        uint64[6] memory versions;
        for (uint8 operation; operation < 6; ++operation) {
            uint16 slot = uint16(firstSlot + operation);
            bytes32 id = operationPartnerId(basePartnerId, operation);
            Partner storage old = entries[pool][slot];
            ids[operation] = id;
            if (registration) {
                if (partnerSlotPlusOne[pool][id] != 0 || old.version != 0)
                    revert InvalidPartner();
                versions[operation] = 1;
            } else {
                if (partnerSlotPlusOne[pool][id] != uint32(slot) + 1 || old.partnerId != id ||
                    !old.active || old.version == type(uint64).max ||
                    old.receiverCommitment != receiverCommitment || old.authorizationKey != authorizationKey)
                    revert InvalidPartner();
                versions[operation] = old.version + 1;
                oldLeaves[operation] = old.leaf;
            }
            _validate(receiverCommitment, fees.bps[operation], fees.minimum[operation],
                fees.maximum[operation], authorizationKey);
            newLeaves[operation] = _leaf(p.leafPrefix, id, operation, versions[operation],
                receiverCommitment, fees.bps[operation], fees.minimum[operation],
                fees.maximum[operation], authorizationKey);
        }
        (p.x, p.y) = updater.updateSix(firstSlot, p.x, p.y, oldLeaves, newLeaves, keys);
        if (registration) p.nextSlot += 6;
        p.revision += 1;
        root = _checkpoint(pool, p);
        p.root = root;
        for (uint8 operation; operation < 6; ++operation) {
            uint16 slot = uint16(firstSlot + operation);
            entries[pool][slot] = Partner(ids[operation], versions[operation], receiverCommitment,
                fees.bps[operation], fees.minimum[operation], fees.maximum[operation],
                authorizationKey, true, newLeaves[operation]);
            if (registration) partnerSlotPlusOne[pool][ids[operation]] = uint32(slot) + 1;
            emit PartnerVersionChanged(pool, ids[operation], slot, versions[operation],
                receiverCommitment, fees.bps[operation], fees.minimum[operation],
                fees.maximum[operation], true, root);
        }
        emit PolicyCommitmentChanged(pool, p.revision, p.x, p.y, p.nextSlot, root);
    }

    /// @notice Irreversible policy revocation, authorized by the outer owner proof.
    /// A revoked identifier/row remains reserved and cannot be registered again.
    function revokeSixOperationPolicies(address pool, uint256 basePartnerId,
        uint256 expectedCheckpoint, VantaFamilyPartnerKzgUpdatePreAudit.RowKey[6] calldata keys
    ) external adminOnly returns (uint256 root) {
        Pool storage p = pools[pool];
        _requireCheckpoint(p, expectedCheckpoint);
        uint32 firstSlot = _firstSlot(pool, basePartnerId);
        uint256[6] memory oldLeaves;
        uint256[6] memory zeroLeaves;
        for (uint8 operation; operation < 6; ++operation) {
            uint16 slot = uint16(firstSlot + operation);
            Partner storage old = entries[pool][slot];
            bytes32 id = operationPartnerId(basePartnerId, operation);
            if (partnerSlotPlusOne[pool][id] != uint32(slot) + 1 || old.partnerId != id ||
                !old.active || old.version == type(uint64).max) revert InvalidPartner();
            oldLeaves[operation] = old.leaf;
        }
        (p.x, p.y) = updater.updateSix(firstSlot, p.x, p.y, oldLeaves, zeroLeaves, keys);
        p.revision += 1;
        root = _checkpoint(pool, p);
        p.root = root;
        for (uint8 operation; operation < 6; ++operation) {
            uint16 slot = uint16(firstSlot + operation);
            Partner storage old = entries[pool][slot];
            old.version += 1;
            old.active = false;
            old.leaf = 0;
            emit PartnerVersionChanged(pool, old.partnerId, slot, old.version,
                old.receiverCommitment, old.feeBps, old.feeMinimum, old.feeMaximum, false, root);
        }
        emit PolicyCommitmentChanged(pool, p.revision, p.x, p.y, p.nextSlot, root);
    }

    function _firstSlot(address pool, uint256 basePartnerId) private view returns (uint32) {
        uint32 plusOne = partnerSlotPlusOne[pool][operationPartnerId(basePartnerId, 0)];
        if (plusOne == 0) revert InvalidPartner();
        return plusOne - 1;
    }

    function _requireCheckpoint(Pool storage p, uint256 expected) private view {
        if (!p.approved) revert InvalidPool();
        if (expected == 0 || expected != p.root || p.revision == type(uint64).max)
            revert StaleCommitment();
    }

    function _checkpoint(address pool, Pool storage p) private view returns (uint256 root) {
        root = uint256(keccak256(abi.encode(CHECKPOINT_DOMAIN, releaseChainId, address(this),
            releaseSetupId, releaseGenerationId, releaseFamilyTag, acceptedUpdateKeyRoot,
            pool, p.asset, p.revision, p.nextSlot, p.x, p.y))) % FR;
        if (root == 0) revert InvalidRegistrySetup();
    }

    function feeCollector(address pool, uint8 role) external view returns (
        bytes32 handleId, uint256 authorizationCommitment,
        uint256 receiverCommitment, bool active
    ) {
        FeeCollector storage c = feeCollectors[pool][role];
        return (c.handleId, c.authorizationCommitment, c.receiverCommitment, c.active);
    }

    function feeCollectorProofCommitment(address pool, uint8 role) external view returns (uint256) {
        return feeCollectors[pool][role].proofCommitment;
    }

    function feeCollectorRoutingCommitment(address pool, uint8 role) external view returns (bytes32) {
        return feeCollectors[pool][role].routingCommitment;
    }

    function activateFeeCollector(address pool, uint8 role, bytes32 handleId,
        uint256 authorizationCommitment, uint256 receiverCommitment,
        uint256 proofCommitment, bytes32 routingCommitment
    ) external adminOnly {
        if (!pools[pool].approved || (role != 0 && role != 2) || handleId == bytes32(0) || uint256(handleId) >= FR ||
            authorizationCommitment == 0 || authorizationCommitment >= FR ||
            receiverCommitment == 0 || receiverCommitment >= FR ||
            proofCommitment == 0 || proofCommitment >= FR || routingCommitment == bytes32(0) ||
            feeCollectors[pool][role].active) revert InvalidPartner();
        feeCollectors[pool][role] = FeeCollector(handleId, authorizationCommitment,
            receiverCommitment, proofCommitment, routingCommitment, true);
        emit FeeCollectorActivated(pool, role, handleId, receiverCommitment, proofCommitment);
    }

    function feeCollectorsActive(address pool) external view returns (bool) {
        return pools[pool].approved && feeCollectors[pool][0].active && feeCollectors[pool][2].active;
    }
}
