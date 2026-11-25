// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaTokenHash} from "./VantaTokenHash.sol";
import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";
import {VantaFamilyProtocolFeePolicy} from "./VantaFamilyProtocolFeePolicy.sol";
import {VantaFamilyPartnerKzgFeeVerifierPreAudit as KzgFeeVerifier} from "./VantaFamilyPartnerKzgFeeVerifierPreAudit.sol";


interface IVantaCombinedPool {
    function asset() external view returns (address);
    function feePolicyHash() external view returns (bytes32);
    function minimumProtocolFee() external view returns (uint128);
    function protocolFeeRecipient() external view returns (address);
    function partnerFeeRecipient() external view returns (address);
}

interface IVantaCombinedRegistry {
    function poolState(address pool)
        external view returns (address asset, uint256 root, uint32 nextSlot, bool approved);
    function activePoolForAsset(address asset) external view returns (address);
    function poolPolicyContext(address pool) external view returns (uint256);
    function feeCollectorsActive(address pool) external view returns (bool);
    function feeCollectorProofCommitment(address pool, uint8 role)
        external view returns (uint256);
}

interface IVantaCombinedFeeVault {
    function registrar() external view returns (address);
    function asset() external view returns (address);
    function role() external view returns (uint8);
}

interface IVantaCombinedFeeRegistrar {
    function registry() external view returns (address);
}

/// @notice Canonical 40-input fee allocation with hidden KZG policy membership.
/// The pinned verifier composes ccGroth16, singleton Caulk+ and CP_link.
/// @dev RESEARCH ONLY. The pinned verifier key is an unaudited development key.
///      This adapter cannot be used with independently supplied fee, partner
///      or registry public signals. The authorized pool must construct the
///      signed quote and pass its canonical fields.
contract VantaFamilyCombinedFeePartnerAdapterPreAudit is VantaFamilyReleaseBinding {
    uint256 private constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant MAX_VALUE = (uint256(1) << 120) - 1;

    struct CanonicalQuote {
        bytes32 signedQuoteHash;
        uint256[5] outputs;
        uint8[3] feeSlots;
        uint8 outputCount;
        uint128 depositGross;
        uint128 protocolCap;
        uint128 partnerCap;
        uint128 relayerCap;
        uint256 feeTermsHash;
        uint8 width;
        uint8 mode;
        uint256 amountHash;
        uint256 batchDigest;
        uint8 feeLegIndex;
        uint256 partnerRegistryRoot;
        bytes32 signedPartnerNonce;
        address relayer;
        /// The signed public withdrawal amount. Must be zero otherwise.
        uint128 withdrawalPayout;
    }

    address public immutable asset;
    address public immutable protocolRecipient;
    IVantaCombinedRegistry public immutable registry;
    KzgFeeVerifier public immutable verifier;
    bytes32 public immutable verifierCodehash;
    bytes32 public immutable registryCodehash;
    bytes32 public immutable protocolVaultCodehash;
    VantaFamilyProtocolFeePolicy public immutable protocolFeePolicy;
    bytes32 public immutable protocolFeePolicyCodehash;
    uint128 public immutable minimumFee;
    // Cryptographic collector commitments only. Neither the MPKs nor salts
    // used to create them are ever disclosed on-chain.
    uint256 public immutable protocolCollectorCommitment;
    uint256 public immutable relayerCollectorCommitment;

    error InvalidSetup();

    constructor(
        address asset_, address registry_, address verifier_,
        address protocolRecipient_,
        uint256 protocolCollectorCommitment_, uint256 relayerCollectorCommitment_,
        uint128 minimumFee_, uint16 transferProtocolBps_, bytes32 policyHash_,
        bytes32 setupId, bytes32 generationId, bytes32 familyTag, uint256 chainId,
        address protocolFeePolicyAddress
    ) VantaFamilyReleaseBinding(setupId,generationId,familyTag,chainId) {
        if (block.chainid != releaseChainId ||
            uint256(familyTag) >= FR ||
            registry_.code.length == 0 || verifier_.code.length == 0 ||
            protocolRecipient_.code.length == 0 ||
            policyHash_ == bytes32(0) || protocolCollectorCommitment_ == 0 ||
            protocolCollectorCommitment_ >= FR || relayerCollectorCommitment_ == 0 ||
            relayerCollectorCommitment_ >= FR || transferProtocolBps_ > 10_000)
            revert InvalidSetup();
        KzgFeeVerifier kzgFee = KzgFeeVerifier(verifier_);
        if (address(kzgFee.registry()) != registry_ || kzgFee.publicSignalCount() != 40 ||
            kzgFee.releaseSetupId() != setupId || kzgFee.releaseGenerationId() != generationId ||
            kzgFee.releaseFamilyTag() != familyTag || kzgFee.releaseChainId() != chainId)
            revert InvalidSetup();
        VantaFamilyProtocolFeePolicy policy = VantaFamilyProtocolFeePolicy(protocolFeePolicyAddress);
        if (protocolFeePolicyAddress.code.length == 0 || policy.basePolicyHash() != policyHash_ ||
            policy.releaseSetupId() != setupId || policy.releaseGenerationId() != generationId ||
            policy.releaseFamilyTag() != familyTag || policy.releaseChainId() != chainId ||
            policy.rate(1) != transferProtocolBps_) revert InvalidSetup();
        protocolFeePolicy = policy;
        protocolFeePolicyCodehash = protocolFeePolicyAddress.codehash;
        asset = asset_;
        registry = IVantaCombinedRegistry(registry_);
        verifier = KzgFeeVerifier(verifier_);
        verifierCodehash = verifier_.codehash;
        registryCodehash = registry_.codehash;
        protocolVaultCodehash = protocolRecipient_.codehash;
        protocolRecipient = protocolRecipient_;
        protocolCollectorCommitment = protocolCollectorCommitment_;
        relayerCollectorCommitment = relayerCollectorCommitment_;
        minimumFee = minimumFee_;
    }

    function policyHash() public view returns (bytes32) {
        if (address(protocolFeePolicy).codehash != protocolFeePolicyCodehash) revert InvalidSetup();
        return protocolFeePolicy.policyHash();
    }

    function protocolBpsFor(uint8 operation) public view returns (uint16) {
        if (address(protocolFeePolicy).codehash != protocolFeePolicyCodehash) revert InvalidSetup();
        return protocolFeePolicy.rate(operation);
    }

    function transferProtocolBps() external view returns (uint16) { return protocolBpsFor(1); }

    function verifyCombined(CanonicalQuote calldata q, bytes calldata proof)
        external view returns (bool)
    {
        if (!_approved(q) || !_validate(q) || proof.length != 1088) return false;
        return verifier.verifyProof(msg.sender, _publicSignals(q), proof);
    }

    function _approved(CanonicalQuote calldata q) private view returns (bool) {
        // The partner registry permits only one active approved pool per
        // asset. Resolving it here avoids a circular constructor dependency:
        // pool pins adapter code, adapter pins immutable registry code.
        if (block.chainid != releaseChainId || msg.sender.code.length == 0 ||
            address(verifier).codehash != verifierCodehash ||
            address(registry).codehash != registryCodehash ||
            !registry.feeCollectorsActive(msg.sender) ||
            registry.feeCollectorProofCommitment(msg.sender, 0) != protocolCollectorCommitment ||
            registry.feeCollectorProofCommitment(msg.sender, 2) != relayerCollectorCommitment ||
            !_vaultsBound() ||
            (q.mode != 2 && q.protocolCap < minimumFee) ||
            q.partnerRegistryRoot == 0 || q.partnerRegistryRoot >= FR ||
            registry.activePoolForAsset(asset) != msg.sender)
            return false;
        IVantaCombinedPool p = IVantaCombinedPool(msg.sender);
        if (p.asset() != asset || p.feePolicyHash() != policyHash() ||
            p.minimumProtocolFee() != minimumFee ||
            p.protocolFeeRecipient() != protocolRecipient ||
            p.partnerFeeRecipient() != address(0))
            return false;
        (address registeredAsset, uint256 currentRoot,,bool approved) =
            registry.poolState(msg.sender);
        return approved && registeredAsset == asset && currentRoot == q.partnerRegistryRoot;
    }

    function _vaultsBound() private view returns (bool) {
        if (protocolRecipient.codehash != protocolVaultCodehash) return false;
        IVantaCombinedFeeVault protocolVault = IVantaCombinedFeeVault(protocolRecipient);
        address registrar = protocolVault.registrar();
        return registrar.code.length != 0 && protocolVault.asset() == asset &&
            protocolVault.role() == 0 &&
            IVantaCombinedFeeRegistrar(registrar).registry() == address(registry);
    }

    function _validate(CanonicalQuote calldata q) private view returns (bool) {
        if (q.signedQuoteHash == bytes32(0) || q.signedPartnerNonce == bytes32(0) ||
            q.feeTermsHash == 0 || q.feeTermsHash >= FR ||
            q.protocolCap > MAX_VALUE || q.partnerCap > MAX_VALUE ||
            q.relayerCap > MAX_VALUE || q.outputCount > 5 ||
            q.mode > 5 || q.feeSlots[0] >= q.feeSlots[1] ||
            q.feeSlots[1] >= q.feeSlots[2])
            return false;
        // A regular withdrawal must bind the publicly signed payout inside
        // the same Groth16 relation as the Gate0 amount commitment opening.
        if (q.mode == 0) {
            if (q.withdrawalPayout == 0 || q.withdrawalPayout > MAX_VALUE ||
                q.feeLegIndex != 0) return false;
            // The public payout already belongs to this 40-signal relation.
            // Enforce the configured protocol policy even if a fee signer
            // authorizes a different cap. Cast before multiplication: valid
            // 120-bit payouts times basis points can exceed uint128.
            uint256 due = (uint256(q.withdrawalPayout) * protocolBpsFor(0) + 9_999) / 10_000;
            if (due < minimumFee) due = minimumFee;
            if (uint256(q.protocolCap) != due) return false;
        } else if (q.withdrawalPayout != 0) return false;
        bool deposit = q.mode == 2;
        if (deposit) {
            if (q.width != 0 || q.outputCount < 3 ||
                q.depositGross == 0 || q.depositGross > MAX_VALUE ||
                q.protocolCap != 0 || q.partnerCap >= q.depositGross ||
                q.relayerCap != 0 || q.feeSlots[2] != 5 ||
                q.relayer != address(0) ||
                q.amountHash != 0 || q.batchDigest != 0 || q.feeLegIndex != 0)
                return false;
        } else if (
            (q.width != 8 && q.width != 32) || q.outputCount != 5 ||
            q.depositGross != 0 || q.relayer == address(0) ||
            q.feeSlots[2] >= 5 || q.amountHash == 0 || q.amountHash >= FR ||
            q.batchDigest == 0 || q.batchDigest >= FR ||
            q.feeLegIndex >= q.width
        ) return false;
        for (uint256 i; i < 5; ++i) {
            if (i < q.outputCount) {
                if (q.outputs[i] == 0 || q.outputs[i] >= FR) return false;
            } else if (q.outputs[i] != 0) return false;
        }
        return true;
    }

    function _publicSignals(CanonicalQuote calldata q)
        private view returns (uint256[] memory s)
    {
        s = new uint256[](40);
        s[0] = block.chainid;
        s[1] = uint160(msg.sender);
        s[2] = VantaTokenHash.compute(block.chainid, msg.sender, asset);
        s[3] = uint256(q.signedQuoteHash) % FR;
        s[4] = uint256(policyHash()) % FR;
        s[5] = q.feeTermsHash;
        s[6] = q.width;
        s[7] = q.mode;
        s[8] = q.outputCount;
        s[9] = q.depositGross;
        // Protocol deposits have no fee; partner deposits follow their KZG policy.
        s[10] = q.mode == 2 ? 0 : minimumFee;
        s[11] = q.protocolCap;
        s[12] = q.partnerCap;
        s[13] = q.relayerCap;
        s[14] = protocolCollectorCommitment;
        s[15] = 0;
        s[16] = q.mode == 2 ? 0 : relayerCollectorCommitment;
        for (uint256 i; i < 3; ++i) s[17 + i] = q.feeSlots[i];
        for (uint256 i; i < 5; ++i) s[20 + i] = q.outputs[i];
        if (q.mode == 1) {
            s[25] = protocolBpsFor(1);
            s[26] = q.amountHash;
            s[27] = q.batchDigest;
            s[28] = q.feeLegIndex;
        }
        s[29] = uint160(address(registry));
        s[30] = uint160(asset);
        s[31] = q.partnerRegistryRoot;
        s[32] = uint256(q.signedPartnerNonce) % FR;
        s[33] = q.amountHash;
        s[34] = q.batchDigest;
        s[35] = q.feeLegIndex;
        s[36] = q.withdrawalPayout;
        s[37] = registry.poolPolicyContext(msg.sender);
        s[38] = uint256(releaseFamilyTag);
        s[39] = releaseChainId;
    }
}

