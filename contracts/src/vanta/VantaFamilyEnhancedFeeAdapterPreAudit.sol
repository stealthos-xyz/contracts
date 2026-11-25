// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaTokenHash} from "./VantaTokenHash.sol";
import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";
import {VantaFamilyProtocolFeePolicy} from "./VantaFamilyProtocolFeePolicy.sol";
import {VantaFamilyPartnerKzgFeeVerifierPreAudit as KzgFeeVerifier} from "./VantaFamilyPartnerKzgFeeVerifierPreAudit.sol";


interface IVantaEnhancedFeePool {
    function asset() external view returns (address);
    function feePolicyHash() external view returns (bytes32);
    function minimumProtocolFee() external view returns (uint128);
    function protocolFeeRecipient() external view returns (address);
    function partnerFeeRecipient() external view returns (address);
    function releaseSetupId() external view returns (bytes32);
    function releaseGenerationId() external view returns (bytes32);
    function releaseFamilyTag() external view returns (bytes32);
    function releaseChainId() external view returns (uint256);
    function releaseGenesisHash() external view returns (bytes32);
}

interface IVantaEnhancedFeeRegistry {
    function poolState(address pool)
        external view returns (address asset, uint256 root, uint32 nextSlot, bool approved);
    function activePoolForAsset(address asset) external view returns (address);
    function poolPolicyContext(address pool) external view returns (uint256);
    function feeCollectorsActive(address pool) external view returns (bool);
    function feeCollectorProofCommitment(address pool, uint8 role) external view returns (uint256);
}

interface IVantaEnhancedFeeVault {
    function registrar() external view returns (address);
    function asset() external view returns (address);
    function role() external view returns (uint8);
}

interface IVantaEnhancedFeeRegistrar {
    function registry() external view returns (address);
}

/// @notice Canonical adapter for hidden fees and KZG policy membership.
/// @dev PRE-AUDIT ONLY. Requires a new qualified key and ceremony profile.
///      Exact protocol, partner and gas fees are private circuit witnesses.
///      No original payout, fee caps, receiving MPKs or note secrets enter this
///      ABI. The approved pool authenticates amountHash/batchDigest using its
///      Gate0 proof and constructs signedQuoteHash from the authorized header.
contract VantaFamilyEnhancedFeeAdapterPreAudit is VantaFamilyReleaseBinding {
    uint256 private constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant MAX_VALUE = (uint256(1) << 120) - 1;
    uint256 public constant ENHANCED_FEE_DOMAIN = 0x5638454645450002;
    uint256 public constant PUBLIC_SIGNAL_COUNT = 41;

    struct CanonicalQuote {
        bytes32 signedQuoteHash;
        uint256[5] outputs;
        uint8[3] feeSlots;
        uint256 feeTermsHash;
        uint8 width;
        uint8 mode;
        uint256 amountHash;
        uint256 batchDigest;
        uint256 partnerRegistryRoot;
        bytes32 signedPartnerNonce;
        // The prepaid gas-note recipient is bound by the pool's signed quote.
        // This does not restrict who may execute a subsequent delayed claim.
        address relayer;
    }

    address public immutable asset;
    address public immutable protocolRecipient;
    IVantaEnhancedFeeRegistry public immutable registry;
    KzgFeeVerifier public immutable verifier;
    bytes32 public immutable verifierCodehash;
    bytes32 public immutable registryCodehash;
    bytes32 public immutable protocolVaultCodehash;
    VantaFamilyProtocolFeePolicy public immutable protocolFeePolicy;
    bytes32 public immutable protocolFeePolicyCodehash;
    bytes32 public immutable releaseGenesisHash;
    uint128 public immutable minimumFee;
    uint256 public immutable protocolCollectorCommitment;
    uint256 public immutable relayerCollectorCommitment;

    error InvalidSetup();

    constructor(
        address asset_, address registry_, address verifier_,
        address protocolRecipient_,
        uint256 protocolCollectorCommitment_, uint256 relayerCollectorCommitment_,
        uint128 minimumFee_, uint16 protocolBps_, bytes32 policyHash_,
        bytes32 setupId, bytes32 generationId, bytes32 familyTag,
        uint256 chainId, bytes32 genesisHash, address protocolFeePolicyAddress
    ) VantaFamilyReleaseBinding(setupId, generationId, familyTag, chainId) {
        if (
            chainId >= FR || uint256(familyTag) >= FR || genesisHash == bytes32(0) ||
            registry_.code.length == 0 || verifier_.code.length == 0 ||
            protocolRecipient_.code.length == 0 ||
            policyHash_ == bytes32(0) || uint256(policyHash_) % FR == 0 ||
            protocolCollectorCommitment_ == 0 || protocolCollectorCommitment_ >= FR ||
            relayerCollectorCommitment_ == 0 || relayerCollectorCommitment_ >= FR ||
            minimumFee_ > MAX_VALUE || protocolBps_ > 10_000
        ) revert InvalidSetup();
        KzgFeeVerifier kzgFee = KzgFeeVerifier(verifier_);
        if (address(kzgFee.registry()) != registry_ || kzgFee.publicSignalCount() != 41 ||
            kzgFee.releaseSetupId() != setupId || kzgFee.releaseGenerationId() != generationId ||
            kzgFee.releaseFamilyTag() != familyTag || kzgFee.releaseChainId() != chainId)
            revert InvalidSetup();
        VantaFamilyProtocolFeePolicy policy = VantaFamilyProtocolFeePolicy(protocolFeePolicyAddress);
        if (protocolFeePolicyAddress.code.length == 0 || policy.basePolicyHash() != policyHash_ ||
            policy.releaseSetupId() != setupId || policy.releaseGenerationId() != generationId ||
            policy.releaseFamilyTag() != familyTag || policy.releaseChainId() != chainId ||
            policy.rate(0) != protocolBps_) revert InvalidSetup();
        protocolFeePolicy = policy;
        protocolFeePolicyCodehash = protocolFeePolicyAddress.codehash;
        asset = asset_;
        registry = IVantaEnhancedFeeRegistry(registry_);
        verifier = KzgFeeVerifier(verifier_);
        verifierCodehash = verifier_.codehash;
        registryCodehash = registry_.codehash;
        protocolVaultCodehash = protocolRecipient_.codehash;
        protocolRecipient = protocolRecipient_;
        protocolCollectorCommitment = protocolCollectorCommitment_;
        relayerCollectorCommitment = relayerCollectorCommitment_;
        minimumFee = minimumFee_;
        releaseGenesisHash = genesisHash;
    }

    function policyHash() public view returns (bytes32) {
        if (address(protocolFeePolicy).codehash != protocolFeePolicyCodehash) revert InvalidSetup();
        return protocolFeePolicy.policyHash();
    }

    function protocolBpsFor(uint8 operation) public view returns (uint16) {
        if (address(protocolFeePolicy).codehash != protocolFeePolicyCodehash) revert InvalidSetup();
        return protocolFeePolicy.rate(operation);
    }

    function protocolBps() external view returns (uint16) { return protocolBpsFor(0); }

    function verifyCombined(CanonicalQuote calldata q, bytes calldata proof)
        external view returns (bool)
    {
        if (!_validate(q) || !_approved(q) || proof.length != 1088) return false;
        return verifier.verifyProof(msg.sender, _publicSignals(q), proof);
    }

    function _approved(CanonicalQuote calldata q) private view returns (bool) {
        if (
            block.chainid != releaseChainId || msg.sender.code.length == 0 ||
            address(verifier).codehash != verifierCodehash ||
            address(registry).codehash != registryCodehash ||
            registry.activePoolForAsset(asset) != msg.sender ||
            !registry.feeCollectorsActive(msg.sender) ||
            registry.feeCollectorProofCommitment(msg.sender, 0) != protocolCollectorCommitment ||
            registry.feeCollectorProofCommitment(msg.sender, 2) != relayerCollectorCommitment ||
            !_vaultsBound()
        ) return false;

        IVantaEnhancedFeePool p = IVantaEnhancedFeePool(msg.sender);
        if (
            p.asset() != asset || p.feePolicyHash() != policyHash() ||
            p.minimumProtocolFee() != minimumFee ||
            p.protocolFeeRecipient() != protocolRecipient ||
            p.partnerFeeRecipient() != address(0) ||
            p.releaseSetupId() != releaseSetupId ||
            p.releaseGenerationId() != releaseGenerationId ||
            p.releaseFamilyTag() != releaseFamilyTag ||
            p.releaseChainId() != releaseChainId ||
            p.releaseGenesisHash() != releaseGenesisHash
        ) return false;
        (address registeredAsset, uint256 currentRoot,, bool approved) = registry.poolState(msg.sender);
        return approved && registeredAsset == asset && currentRoot == q.partnerRegistryRoot;
    }

    function _vaultsBound() private view returns (bool) {
        if (protocolRecipient.codehash != protocolVaultCodehash) return false;
        IVantaEnhancedFeeVault protocolVault = IVantaEnhancedFeeVault(protocolRecipient);
        address registrar = protocolVault.registrar();
        return registrar.code.length != 0 && protocolVault.asset() == asset &&
            protocolVault.role() == 0 &&
            IVantaEnhancedFeeRegistrar(registrar).registry() == address(registry);
    }

    function _validate(CanonicalQuote calldata q) private pure returns (bool) {
        if (
            uint256(q.signedQuoteHash) % FR == 0 || uint256(q.signedPartnerNonce) % FR == 0 ||
            q.feeTermsHash == 0 || q.feeTermsHash >= FR ||
            (q.width != 8 && q.width != 32) || (q.mode != 0 && q.mode != 3) ||
            q.feeSlots[0] >= q.feeSlots[1] || q.feeSlots[1] >= q.feeSlots[2] ||
            q.feeSlots[2] >= 5 || q.relayer == address(0) ||
            q.amountHash == 0 || q.amountHash >= FR ||
            q.batchDigest == 0 || q.batchDigest >= FR ||
            q.partnerRegistryRoot == 0 || q.partnerRegistryRoot >= FR
        ) return false;
        for (uint256 i; i < 5; ++i) {
            if (q.outputs[i] == 0 || q.outputs[i] >= FR) return false;
        }
        return true;
    }

    function _publicSignals(CanonicalQuote calldata q)
        private view returns (uint256[] memory s)
    {
        s = new uint256[](41);
        // fee.statement_fields()[1..30], omitting PRIVATE indices 12/13/14.
        s[0] = releaseChainId;
        s[1] = uint160(msg.sender);
        s[2] = VantaTokenHash.compute(releaseChainId, msg.sender, asset);
        s[3] = uint256(q.signedQuoteHash) % FR;
        s[4] = uint256(policyHash()) % FR;
        s[5] = q.feeTermsHash;
        s[6] = q.width;
        s[7] = q.mode;
        s[8] = 5;
        // s[9] = zero gross deposit. s[12] = private partner collector slot.
        s[10] = minimumFee;
        s[11] = protocolCollectorCommitment;
        s[13] = relayerCollectorCommitment;
        for (uint256 i; i < 3; ++i) s[14 + i] = q.feeSlots[i];
        for (uint256 i; i < 5; ++i) s[17 + i] = q.outputs[i];
        // s[22..25] = zero transfer-only context for modes 0 and 3.

        // partner.public.fields()[2,4,6,8,14,15,16].
        s[26] = uint160(address(registry));
        s[27] = uint160(asset);
        s[28] = q.partnerRegistryRoot;
        s[29] = uint256(q.signedPartnerNonce) % FR;
        s[30] = q.amountHash;
        s[31] = q.batchDigest;
        // s[32] = canonical fee-leg index zero.

        s[33] = ENHANCED_FEE_DOMAIN;
        s[34] = uint256(releaseFamilyTag);
        s[35] = uint128(uint256(releaseGenesisHash));
        s[36] = uint256(releaseGenesisHash) >> 128;
        s[37] = uint128(uint256(releaseGenerationId));
        s[38] = uint256(releaseGenerationId) >> 128;
        s[39] = protocolBpsFor(q.mode);
        s[40] = registry.poolPolicyContext(msg.sender);
    }
}
