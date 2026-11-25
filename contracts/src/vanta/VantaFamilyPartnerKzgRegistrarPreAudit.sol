// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {PoseidonT4} from "../libraries/PoseidonT4.sol";
import {PoseidonT3External} from "../libraries/PoseidonExternal.sol";
import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";
import {VantaFamilyPublicFeeVaultPreAudit} from "./VantaFamilyPublicFeeVaultPreAudit.sol";
import {VantaFamilyPartnerKzgRegistryPreAudit} from "./VantaFamilyPartnerKzgRegistryPreAudit.sol";
import {VantaFamilyPartnerKzgUpdatePreAudit} from "./VantaFamilyPartnerKzgUpdatePreAudit.sol";

interface IVantaKzgPermanentPartnerHandle {
    function getHandleState(bytes32 handleId) external view returns (
        bytes32 recordCommitment, bytes32 ownerCommitment, uint64 epoch, bool exists
    );
    function chainId() external view returns (uint256);
}

interface IVantaKzgPartnerOwnerVerifier {
    function verifyProof(uint256[2] calldata a, uint256[2][2] calldata b,
        uint256[2] calldata c, uint256[7] calldata inputs) external view returns (bool);
}

interface IVantaKzgPartnerPool {
    function asset() external view returns (address);
    function protocolFeeRecipient() external view returns (address);
    function releaseGenesisHash() external view returns (bytes32);
}

/// @notice Pre-audit KZG registry registrar. Not an approved deployment profile.
/// @dev Reuses the family registrar's permanent-handle and genuine owner-proof
/// checks. Each owner proof authorizes six policy writes for exactly one pinned asset. The private receiver,
/// authorization and routing bindings cannot change through fee updates.
/// Registry checkpoints are additionally included in each owner action.
/// Existing owner-proven collector activation and signer-independent public
/// fee-vault claims retain their original authorization and immutable bindings.
contract VantaFamilyPartnerKzgRegistrarPreAudit is ReentrancyGuard, VantaFamilyReleaseBinding {
    uint256 private constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    bytes32 private constant RECORD_DOMAIN = keccak256("VANTA_PARTNER_HANDLE_BINDING_V3");
    bytes32 private constant REGISTER_DOMAIN = keccak256("VANTA_PARTNER_KZG_REGISTER_ASSET_PROOF_V3");
    bytes32 private constant UPDATE_DOMAIN = keccak256("VANTA_PARTNER_KZG_UPDATE_ASSET_PROOF_V3");
    bytes32 private constant REVOKE_DOMAIN = keccak256("VANTA_PARTNER_KZG_REVOKE_ASSET_PROOF_V3");
    bytes32 private constant ROLE_DOMAIN = keccak256("VANTA_FEE_COLLECTOR_ROLE_ACTIVATE_V1");
    bytes32 private constant CLAIM_DOMAIN = keccak256("VANTA_PUBLIC_EXIT_FEE_CLAIM_V1");

    struct FeePolicy {
        uint16 feeBps;
        uint128 minimumFee;
        uint128 maximumFee;
    }
    struct PartnerIdentity {
        uint256 authorizationCommitment;
        uint256 receiverCommitment;
        bytes32 routingCommitment;
        bytes32 salt;
        uint64 nextRevision;
        bool exists;
        bool revoked;
    }

    address public immutable deployer;
    address public immutable canonicalToken;
    bytes32 public immutable canonicalTokenCodehash;
    bytes32 public immutable releaseGenesisHash;
    address public immutable handleRegistry;
    bytes32 public immutable handleRegistryCodehash;
    VantaFamilyPartnerKzgRegistryPreAudit public immutable registry;
    IVantaKzgPartnerOwnerVerifier public immutable ownerVerifier;
    bytes32 public immutable ownerVerifierCodehash;
    mapping(bytes32 => PartnerIdentity) private identities;
    mapping(uint256 => bool) public usedAuthorizationNullifier;
    mapping(bytes32 => uint8) public registeredAssetMask;
    mapping(bytes32 => uint8) public revokedAssetMask;
    address[] private releaseAssets;
    mapping(address => bytes32) public approvedAssetCodehash;
    bool private additionalAssetsConfigured;
    bool private poolRegistrationStarted;

    event PartnerOnboarded(bytes32 indexed handleId, uint256 authorizationCommitment,
        bytes32 feesHash, address registry);
    event PartnerFeePolicyUpdated(bytes32 indexed handleId, uint64 revision, bytes32 feesHash);
    event PartnerRevoked(bytes32 indexed handleId, uint64 revision);
    event PartnerAssetRegistered(bytes32 indexed handleId, uint8 indexed assetIndex, uint64 revision, bytes32 feesHash);
    event PartnerAssetFeesUpdated(bytes32 indexed handleId, uint8 indexed assetIndex, uint64 revision, bytes32 feesHash);
    event PartnerAssetRevoked(bytes32 indexed handleId, uint8 indexed assetIndex, uint64 revision);
    event FeeRoleActivated(address indexed pool, uint8 indexed role, bytes32 indexed handleId);
    event PublicFeeClaimed(address indexed pool, uint8 indexed role,
        address indexed recipient, uint256 amount);

    error UnsupportedChain();
    error UnverifiedHandle();
    error InvalidAuthorization();
    error InvalidFeePolicy();
    error AlreadyRegistered();
    error UnknownPartner();
    error PoolUnavailable();

    constructor(address hasher, bytes32 acceptedUpdateKeyRoot,
        address permanentHandleRegistry, address privateOwnerVerifier, address canonicalToken_,
        bytes32 setupId, bytes32 generationId, bytes32 familyTag, uint256 chainId, bytes32 genesisHash)
        VantaFamilyReleaseBinding(setupId, generationId, familyTag, chainId)
    {
        if (chainId >= (uint256(1) << 53) || uint256(familyTag) >= FR ||
            canonicalToken_ == address(0) || canonicalToken_.code.length == 0 ||
            genesisHash == bytes32(0) || permanentHandleRegistry.code.length == 0 ||
            privateOwnerVerifier.code.length == 0 ||
            IVantaKzgPermanentPartnerHandle(permanentHandleRegistry).chainId() != chainId)
            revert UnsupportedChain();
        deployer = msg.sender;
        canonicalToken = canonicalToken_;
        canonicalTokenCodehash = canonicalToken_.codehash;
        releaseAssets.push(address(0));
        releaseAssets.push(canonicalToken_);
        approvedAssetCodehash[canonicalToken_] = canonicalToken_.codehash;
        releaseGenesisHash = genesisHash;
        handleRegistry = permanentHandleRegistry;
        handleRegistryCodehash = permanentHandleRegistry.codehash;
        ownerVerifier = IVantaKzgPartnerOwnerVerifier(privateOwnerVerifier);
        ownerVerifierCodehash = privateOwnerVerifier.codehash;
        registry = new VantaFamilyPartnerKzgRegistryPreAudit(
            hasher, acceptedUpdateKeyRoot, setupId, generationId, familyTag, chainId
        );
    }

    /// @notice Bootstrap-only asset extension. The list becomes immutable
    /// before the first pool is registered; no active partner table can be
    /// extended or silently excluded from later updates and revocation.
    function configureAdditionalAssets(address[] calldata assets, bytes32[] calldata hashes)
        external onlyReleaseChain
    {
        if (msg.sender != deployer || additionalAssetsConfigured || poolRegistrationStarted ||
            assets.length == 0 || assets.length > 6 || assets.length != hashes.length)
            revert InvalidAuthorization();
        for (uint256 i; i < assets.length; ++i) {
            address asset = assets[i];
            if (asset == address(0) || approvedAssetCodehash[asset] != bytes32(0) ||
                asset.code.length == 0 || hashes[i] == bytes32(0) || asset.codehash != hashes[i])
                revert PoolUnavailable();
            approvedAssetCodehash[asset] = hashes[i];
            releaseAssets.push(asset);
        }
        additionalAssetsConfigured = true;
    }

    function canonicalAssets() external view returns (address[] memory) { return releaseAssets; }

    /// @notice Bootstrap authority can select only code-pinned pools/assets, never partner policies.
    function registerCanonicalPool(address pool, address asset) external onlyReleaseChain {
        if (msg.sender != deployer) revert InvalidAuthorization();
        if (asset != address(0) && (approvedAssetCodehash[asset] == bytes32(0) ||
            asset.codehash != approvedAssetCodehash[asset])) revert PoolUnavailable();
        if (IVantaKzgPartnerPool(pool).releaseGenesisHash() != releaseGenesisHash) revert PoolUnavailable();
        poolRegistrationStarted = true;
        registry.registerPool(pool, asset);
    }

    /// @dev Same permanent reserved roles as the family registrar. The relayer
    /// role additionally needs deployer approval, never an alternative owner.
    function _reservedRoleHandle(uint8 role) private view returns (bytes32) {
        bytes memory name = role == 0 ? bytes("protocol.stealth") : bytes("relayer.stealth");
        return bytes32(PoseidonT3External.hash(
            registry.poseidonT3(), [uint256(keccak256(name)), block.chainid]
        ));
    }

    function roleActivationDigest(address pool, uint8 role, bytes32 handleId,
        uint256 authorizationCommitment, uint256 receiverCommitment,
        uint256 proofCommitment, bytes32 routingCommitment,
        bytes32 salt, uint64 deadline) public view returns (uint256)
    {
        return uint256(keccak256(abi.encode(ROLE_DOMAIN, block.chainid, address(this),
            releaseSetupId, releaseGenerationId, releaseGenesisHash, pool, role, handleId,
            authorizationCommitment, receiverCommitment, proofCommitment,
            routingCommitment, salt, deadline))) % FR;
    }

    function _roleVault(address pool, uint8 role) private view returns (
        VantaFamilyPublicFeeVaultPreAudit vault
    ) {
        if (role != 0) revert InvalidFeePolicy();
        address assetAddress = IVantaKzgPartnerPool(pool).asset();
        address vaultAddress = IVantaKzgPartnerPool(pool).protocolFeeRecipient();
        if (vaultAddress.code.length == 0) revert InvalidFeePolicy();
        vault = VantaFamilyPublicFeeVaultPreAudit(payable(vaultAddress));
        if (vault.registrar() != address(this) || vault.asset() != assetAddress || vault.role() != role ||
            vault.releaseSetupId() != releaseSetupId || vault.releaseGenerationId() != releaseGenerationId ||
            vault.releaseFamilyTag() != releaseFamilyTag || vault.releaseChainId() != releaseChainId ||
            vault.releaseGenesisHash() != releaseGenesisHash) revert InvalidFeePolicy();
    }

    /// @notice A sponsor may submit the reserved owner's proof. Neither a
    /// sponsor nor governance may bypass the permanent private handle owner.
    function activateFeeCollector(address pool, uint8 role, bytes32 handleId,
        uint256 authorizationCommitment, uint256 receiverCommitment,
        uint256 proofCommitment, bytes32 routingCommitment, bytes32 salt,
        uint64 deadline, uint256[8] calldata ownershipProof, uint256 authorizationNullifier)
        external nonReentrant onlyReleaseChain
    {
        if ((role != 0 && role != 2) || (role == 2 && msg.sender != deployer) ||
            proofCommitment == 0 || proofCommitment >= FR) revert InvalidAuthorization();
        _requireDeadline(deadline);
        (address assetAddress,,, bool approved) = registry.poolState(pool);
        if (!approved || registry.activePoolForAsset(assetAddress) != pool) revert PoolUnavailable();
        if (handleId != _reservedRoleHandle(role)) revert InvalidAuthorization();
        if (role == 0) {
            _roleVault(pool, role);
        }
        (,,, bool active) = registry.feeCollector(pool, role);
        if (active) revert AlreadyRegistered();
        bytes32 owner = _requireHandle(handleId, authorizationCommitment,
            receiverCommitment, routingCommitment, salt);
        _verifyOwner(handleId, owner, authorizationCommitment,
            roleActivationDigest(pool, role, handleId, authorizationCommitment,
                receiverCommitment, proofCommitment, routingCommitment, salt, deadline),
            authorizationNullifier, ownershipProof);
        registry.activateFeeCollector(pool, role, handleId, authorizationCommitment,
            receiverCommitment, proofCommitment, routingCommitment);
        emit FeeRoleActivated(pool, role, handleId);
    }

    function publicFeeClaimDigest(address pool, uint8 role, address recipient,
        uint256 amount, uint64 deadline) public view returns (uint256)
    {
        return uint256(keccak256(abi.encode(CLAIM_DOMAIN, block.chainid, address(this),
            releaseSetupId, releaseGenerationId, releaseGenesisHash,
            pool, role, recipient, amount, deadline))) % FR;
    }

    /// @notice Signer-independent recovery of public emergency-exit fees.
    /// No relayer key, KZG mutation, public owner EOA or recovery bypass is used.
    function claimPublicFee(address pool, uint8 role, address payable recipient,
        uint256 amount, bytes32 routingCommitment, bytes32 salt, uint64 deadline,
        uint256[8] calldata ownershipProof, uint256 authorizationNullifier)
        external nonReentrant onlyReleaseChain
    {
        if (role != 0 || recipient == address(0) || amount == 0) revert InvalidFeePolicy();
        _requireDeadline(deadline);
        (bytes32 handleId, uint256 auth, uint256 receiver, bool active) = registry.feeCollector(pool, role);
        if (!active) revert UnknownPartner();
        bytes32 owner = _requireHandle(handleId, auth, receiver, routingCommitment, salt);
        _verifyOwner(handleId, owner, auth,
            publicFeeClaimDigest(pool, role, recipient, amount, deadline),
            authorizationNullifier, ownershipProof);
        _roleVault(pool, role).release(recipient, amount);
        emit PublicFeeClaimed(pool, role, recipient, amount);
    }

    function partnerIdentity(bytes32 handleId) external view returns (
        uint256 authorizationCommitment, uint256 receiverCommitment,
        bytes32 routingCommitment, bytes32 salt, uint64 nextRevision, bool exists
    ) {
        PartnerIdentity storage p = identities[handleId];
        return (p.authorizationCommitment, p.receiverCommitment, p.routingCommitment,
            p.salt, p.nextRevision, p.exists);
    }

    function isPartnerHandleBound(bytes32 handleId) external view returns (bool) {
        PartnerIdentity storage p = identities[handleId];
        if (!p.exists || p.revoked) return false;
        _requireHandle(handleId, p.authorizationCommitment, p.receiverCommitment,
            p.routingCommitment, p.salt);
        return true;
    }

    function partnerFeesHash(FeePolicy[6] calldata fees) public pure returns (bytes32) {
        return keccak256(abi.encode(fees));
    }

    function handleRecordHash(bytes32 handleId, uint256 authorizationCommitment,
        uint256 receiverCommitment, bytes32 routingCommitment, bytes32 salt)
        public view returns (bytes32)
    {
        return keccak256(abi.encode(RECORD_DOMAIN, block.chainid, handleRegistry,
            handleId, authorizationCommitment, receiverCommitment, routingCommitment, salt));
    }

    function _requireHandle(bytes32 handleId, uint256 authorizationCommitment,
        uint256 receiverCommitment, bytes32 routingCommitment, bytes32 salt)
        private view returns (bytes32)
    {
        if (handleRegistry.codehash != handleRegistryCodehash ||
            handleId == bytes32(0) || uint256(handleId) >= FR ||
            authorizationCommitment == 0 || authorizationCommitment >= FR ||
            receiverCommitment == 0 || receiverCommitment >= FR ||
            routingCommitment == bytes32(0) || salt == bytes32(0)) revert UnverifiedHandle();
        (bytes32 record, bytes32 owner, uint64 epoch, bool exists) =
            IVantaKzgPermanentPartnerHandle(handleRegistry).getHandleState(handleId);
        uint256 computed = PoseidonT4.hash([
            uint256(handleRecordHash(handleId, authorizationCommitment,
                receiverCommitment, routingCommitment, salt)), uint256(1), block.chainid
        ]);
        if (!exists || epoch != 1 || owner == bytes32(0) || uint256(owner) >= FR ||
            record != bytes32(computed)) revert UnverifiedHandle();
        return owner;
    }

    function _requireDeadline(uint64 deadline) private view {
        if (deadline <= block.timestamp || deadline > block.timestamp + 1 hours)
            revert InvalidAuthorization();
    }

    function assetRegistrationVersion() external pure returns (uint8) { return 3; }

    function isPartnerAssetBound(bytes32 handleId, uint8 assetIndex) external view returns (bool) {
        PartnerIdentity storage p = identities[handleId];
        if (assetIndex >= releaseAssets.length || !p.exists || p.revoked ||
            (registeredAssetMask[handleId] & uint8(1 << assetIndex)) == 0) return false;
        _requireHandle(handleId,p.authorizationCommitment,p.receiverCommitment,p.routingCommitment,p.salt);
        return true;
    }

    function _assetPool(uint8 index) private view returns (address pool) {
        if (index >= releaseAssets.length) revert PoolUnavailable();
        address asset = releaseAssets[index];
        if (asset != address(0) && asset.codehash != approvedAssetCodehash[asset]) revert PoolUnavailable();
        pool = registry.activePoolForAsset(asset);
        if (pool == address(0) || IVantaKzgPartnerPool(pool).asset() != asset ||
            IVantaKzgPartnerPool(pool).releaseGenesisHash() != releaseGenesisHash) revert PoolUnavailable();
    }

    /// @notice Same seven-input owner relation and ceremony keys. The action
    /// commits exactly one asset/pool checkpoint, operation, revision and deadline.
    function partnerAssetActionDigest(uint8 action, bytes32 handleId, uint256 authorizationCommitment,
        uint256 receiverCommitment, bytes32 routingCommitment, bytes32 salt, bytes32 feesHash,
        uint8 assetIndex, uint256 checkpoint, uint64 revision, uint64 deadline)
        public view returns (uint256)
    {
        if (action > 2 || revision == 0) revert InvalidAuthorization();
        bytes32 domain = action == 0 ? REGISTER_DOMAIN : action == 1 ? UPDATE_DOMAIN : REVOKE_DOMAIN;
        bytes memory prefix = abi.encode(domain,block.chainid,address(this),releaseSetupId,
            releaseGenerationId,releaseFamilyTag,releaseGenesisHash,handleId,authorizationCommitment);
        bytes memory fields = action == 0 ? abi.encode(receiverCommitment,routingCommitment,salt) : bytes("");
        bytes memory policy = action == 2 ? bytes("") : abi.encode(feesHash);
        return uint256(keccak256(bytes.concat(prefix,fields,policy,
            abi.encode(assetIndex,address(registry),_assetPool(assetIndex),checkpoint,revision,deadline)))) % FR;
    }

    function _verifyOwner(bytes32 handleId, bytes32 ownerCommitment,
        uint256 authorizationCommitment, uint256 actionDigest,
        uint256 authorizationNullifier, uint256[8] calldata proof) private
    {
        if (ownerVerifierCodehash != address(ownerVerifier).codehash || actionDigest == 0 ||
            authorizationNullifier == 0 || authorizationNullifier >= FR ||
            usedAuthorizationNullifier[authorizationNullifier]) revert InvalidAuthorization();
        uint256[2] memory a = [proof[0], proof[1]];
        uint256[2][2] memory b = [[proof[2], proof[3]], [proof[4], proof[5]]];
        uint256[2] memory c = [proof[6], proof[7]];
        uint256[7] memory inputs = [uint256(releaseFamilyTag), releaseChainId,
            uint256(handleId), uint256(ownerCommitment), authorizationCommitment,
            actionDigest, authorizationNullifier];
        if (!ownerVerifier.verifyProof(a, b, c, inputs)) revert InvalidAuthorization();
        usedAuthorizationNullifier[authorizationNullifier] = true;
    }

    function _validateFees(FeePolicy[6] calldata fees) private pure {
        for (uint256 i; i < 6; ++i) {
            FeePolicy calldata f = fees[i];
            if (f.feeBps > 10_000 || f.maximumFee > (uint128(1) << 120) - 1 ||
                f.maximumFee < f.minimumFee ||
                (f.feeBps == 0 && f.minimumFee != f.maximumFee) ||
                (f.feeBps != 0 && f.maximumFee == 0)) revert InvalidFeePolicy();
        }
    }

    function registerPartnerAsset(bytes32 handleId, uint256 authorizationCommitment,
        uint256 receiverCommitment, bytes32 routingCommitment, bytes32 salt,
        uint8 assetIndex, FeePolicy[6] calldata fees, uint256 checkpoint,
        VantaFamilyPartnerKzgUpdatePreAudit.RowKey[6] calldata keys,
        uint64 revision, uint64 deadline, uint256[8] calldata ownershipProof, uint256 authorizationNullifier)
        external nonReentrant onlyReleaseChain
    {
        address pool = _assetPool(assetIndex);
        uint8 bit = uint8(1 << assetIndex);
        if (((registeredAssetMask[handleId] | revokedAssetMask[handleId]) & bit) != 0) revert AlreadyRegistered();
        PartnerIdentity storage p = identities[handleId];
        if (p.revoked || revision == type(uint64).max ||
            revision != (p.exists ? p.nextRevision : 1)) revert InvalidAuthorization();
        if (p.exists && (p.authorizationCommitment != authorizationCommitment || p.receiverCommitment != receiverCommitment ||
            p.routingCommitment != routingCommitment || p.salt != salt)) revert UnverifiedHandle();
        _validateFees(fees); _requireDeadline(deadline);
        bytes32 owner = _requireHandle(handleId,authorizationCommitment,receiverCommitment,routingCommitment,salt);
        bytes32 feesHash = partnerFeesHash(fees);
        _verifyOwner(handleId,owner,authorizationCommitment,
            partnerAssetActionDigest(0,handleId,authorizationCommitment,receiverCommitment,routingCommitment,salt,
                feesHash,assetIndex,checkpoint,revision,deadline),authorizationNullifier,ownershipProof);
        if (!p.exists) {
            identities[handleId] = PartnerIdentity(authorizationCommitment,receiverCommitment,routingCommitment,salt,revision+1,true,false);
        } else p.nextRevision = revision + 1;
        _setAssetPolicies(pool,handleId,fees,checkpoint,keys,true);
        registeredAssetMask[handleId] |= bit;
        emit PartnerAssetRegistered(handleId,assetIndex,revision,feesHash);
        emit PartnerOnboarded(handleId,authorizationCommitment,feesHash,address(registry));
    }

    function updatePartnerAssetFees(bytes32 handleId, uint8 assetIndex, FeePolicy[6] calldata fees,
        uint256 checkpoint, VantaFamilyPartnerKzgUpdatePreAudit.RowKey[6] calldata keys,
        uint64 revision, uint64 deadline, uint256[8] calldata ownershipProof, uint256 authorizationNullifier)
        external nonReentrant onlyReleaseChain
    {
        PartnerIdentity storage p = _activeAssetIdentity(handleId,assetIndex,revision);
        _validateFees(fees); _requireDeadline(deadline);
        bytes32 owner = _requireHandle(handleId,p.authorizationCommitment,p.receiverCommitment,p.routingCommitment,p.salt);
        bytes32 feesHash = partnerFeesHash(fees);
        _verifyOwner(handleId,owner,p.authorizationCommitment,
            partnerAssetActionDigest(1,handleId,p.authorizationCommitment,0,bytes32(0),bytes32(0),feesHash,
                assetIndex,checkpoint,revision,deadline),authorizationNullifier,ownershipProof);
        p.nextRevision = revision + 1;
        _setAssetPolicies(_assetPool(assetIndex),handleId,fees,checkpoint,keys,false);
        emit PartnerAssetFeesUpdated(handleId,assetIndex,revision,feesHash);
    }

    function _activeAssetIdentity(bytes32 handleId, uint8 assetIndex, uint64 revision)
        private view returns (PartnerIdentity storage p)
    {
        _assetPool(assetIndex);
        p = identities[handleId];
        if (!p.exists || p.revoked || (registeredAssetMask[handleId] & uint8(1 << assetIndex)) == 0) revert UnknownPartner();
        if (revision != p.nextRevision || revision == type(uint64).max) revert InvalidAuthorization();
    }

    function _setAssetPolicies(address pool,bytes32 handleId,FeePolicy[6] calldata fees,uint256 checkpoint,
        VantaFamilyPartnerKzgUpdatePreAudit.RowKey[6] calldata keys,bool registration) private
    {
        PartnerIdentity storage p = identities[handleId];
        VantaFamilyPartnerKzgRegistryPreAudit.SixOperationFees memory batch;
        for (uint256 i; i < 6; ++i) {
            batch.bps[i]=fees[i].feeBps; batch.minimum[i]=fees[i].minimumFee; batch.maximum[i]=fees[i].maximumFee;
        }
        registry.setSixOperationPolicies(pool,uint256(handleId),p.receiverCommitment,p.authorizationCommitment,
            batch,checkpoint,keys,registration);
    }

    /// @notice Explicit permanent on-chain revocation is separate from hiding
    /// an asset in app configuration. Existing signer-independent exits remain.
    function revokePartnerAsset(bytes32 handleId,uint8 assetIndex,uint256 checkpoint,
        VantaFamilyPartnerKzgUpdatePreAudit.RowKey[6] calldata keys,uint64 revision,uint64 deadline,
        uint256[8] calldata ownershipProof,uint256 authorizationNullifier) external nonReentrant onlyReleaseChain
    {
        PartnerIdentity storage p = _activeAssetIdentity(handleId,assetIndex,revision);
        _requireDeadline(deadline);
        bytes32 owner = _requireHandle(handleId,p.authorizationCommitment,p.receiverCommitment,p.routingCommitment,p.salt);
        _verifyOwner(handleId,owner,p.authorizationCommitment,
            partnerAssetActionDigest(2,handleId,p.authorizationCommitment,0,bytes32(0),bytes32(0),bytes32(0),
                assetIndex,checkpoint,revision,deadline),authorizationNullifier,ownershipProof);
        p.nextRevision=revision+1;
        registry.revokeSixOperationPolicies(_assetPool(assetIndex),uint256(handleId),checkpoint,keys);
        registeredAssetMask[handleId] &= ~uint8(1 << assetIndex);
        revokedAssetMask[handleId] |= uint8(1 << assetIndex);
        if (registeredAssetMask[handleId] == 0) {p.revoked=true;emit PartnerRevoked(handleId,revision);}
        emit PartnerAssetRevoked(handleId,assetIndex,revision);
    }
}
