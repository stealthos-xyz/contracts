// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";
import {VantaFamilyGate0CcGroth16PreAudit as CcGroth16} from "./VantaFamilyGate0CcGroth16PreAudit.sol";
import {VantaCaulkPlusGate1Research as Caulk} from "./VantaCaulkPlusGate1Research.sol";
import {VantaCpLinkPairingResearch as CpLink} from "./VantaCpLinkPairingResearch.sol";

interface IVantaPartnerKzgPolicyTable {
    function REGISTRY_SCHEME() external view returns (bytes32);
    function acceptedUpdateKeyRoot() external view returns (bytes32);
    function poolState(address pool) external view returns (address, uint256, uint32, bool);
    function poolCommitment(address pool) external view returns (uint256, uint256, uint64);
    function poolPolicyContext(address pool) external view returns (uint256);
    function activePoolForAsset(address asset) external view returns (address);
    function releaseSetupId() external view returns (bytes32);
    function releaseGenerationId() external view returns (bytes32);
    function releaseFamilyTag() external view returns (bytes32);
    function releaseChainId() external view returns (uint256);
}

/// @notice Pinned composition of the fee relation, one hidden policy lookup,
/// and equality of their committed private leaf. No policy identifier, row,
/// fee rate, receiver key or unblinded opening enters this proof interface.
/// @dev PRE-AUDIT. Parameters require independent final ceremony qualification.
/// This contract has no mutable key authority and cannot move funds. Canonical
/// fee adapters reconstruct all public signals before calling verifyProof.
contract VantaFamilyPartnerKzgFeeVerifierPreAudit is VantaFamilyReleaseBinding {
    uint256 private constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant PROOF_BYTES = 1088;
    bytes32 public constant REGISTRY_SCHEME = keccak256("VANTA_FAMILY_KZG_POLICY_TABLE_V1");
    bytes32 public constant MEMBERSHIP_DOMAIN = keccak256("VANTA_FAMILY_KZG_PRIVATE_POLICY_MEMBERSHIP_V1");

    struct LinkKey { CpLink.G2 a2; CpLink.G2 c1; CpLink.G2 c2; }
    struct Keys {
        CcGroth16.V8VerifyingKey fee;
        Caulk.Srs lookup;
        Caulk.G1 zH;
        LinkKey link;
    }
    struct Snapshot {
        address asset;
        uint256 checkpoint;
        uint32 nextSlot;
        uint64 revision;
        uint256 x;
        uint256 y;
        uint256 policyContext;
    }

    IVantaPartnerKzgPolicyTable public immutable registry;
    CcGroth16 public immutable feeVerifier;
    Caulk public immutable lookupVerifier;
    CpLink public immutable linkVerifier;
    uint256 public immutable publicSignalCount;
    bytes32 public immutable registryCodehash;
    bytes32 public immutable feeVerifierCodehash;
    bytes32 public immutable lookupVerifierCodehash;
    bytes32 public immutable linkVerifierCodehash;
    bytes32 public immutable acceptedUpdateKeyRoot;
    bytes32 public immutable parameterHash;
    bytes private parameters;

    error InvalidSetup();
    error InvalidCheckpoint();

    constructor(
        address registry_, address fee_, address lookup_, address link_,
        uint256 signalCount_, Keys memory keys,
        bytes32 setupId, bytes32 generationId, bytes32 familyTag, uint256 chainId
    ) VantaFamilyReleaseBinding(setupId, generationId, familyTag, chainId) {
        if (registry_.code.length == 0 || fee_.code.length == 0 ||
            lookup_.code.length == 0 || link_.code.length == 0 ||
            (signalCount_ != 40 && signalCount_ != 41) ||
            keys.fee.ic.length != signalCount_ + 1 || uint256(familyTag) >= FR)
            revert InvalidSetup();
        IVantaPartnerKzgPolicyTable r = IVantaPartnerKzgPolicyTable(registry_);
        if (r.REGISTRY_SCHEME() != REGISTRY_SCHEME ||
            r.releaseSetupId() != setupId || r.releaseGenerationId() != generationId ||
            r.releaseFamilyTag() != familyTag || r.releaseChainId() != chainId ||
            r.acceptedUpdateKeyRoot() == bytes32(0)) revert InvalidSetup();
        registry = r;
        feeVerifier = CcGroth16(fee_);
        lookupVerifier = Caulk(lookup_);
        linkVerifier = CpLink(link_);
        publicSignalCount = signalCount_;
        registryCodehash = registry_.codehash;
        feeVerifierCodehash = fee_.codehash;
        lookupVerifierCodehash = lookup_.codehash;
        linkVerifierCodehash = link_.codehash;
        acceptedUpdateKeyRoot = r.acceptedUpdateKeyRoot();
        parameters = abi.encode(keys);
        parameterHash = keccak256(parameters);
    }

    function _snapshot(address pool) private view returns (Snapshot memory s) {
        bool approved;
        (s.asset, s.checkpoint, s.nextSlot, approved) = registry.poolState(pool);
        (s.x, s.y, s.revision) = registry.poolCommitment(pool);
        if (!approved || registry.activePoolForAsset(s.asset) != pool ||
            s.checkpoint == 0 || s.checkpoint >= FR || s.nextSlot < 32 ||
            s.nextSlot > 65_536 || (s.x == 0 && s.y == 0)) revert InvalidCheckpoint();
        s.policyContext = registry.poolPolicyContext(pool);
    }

    function _context(address pool, Snapshot memory s, uint256[] calldata inputs,
        CcGroth16.G1 memory d) private view returns (bytes memory)
    {
        return abi.encode(MEMBERSHIP_DOMAIN, releaseChainId, address(this), address(registry),
            releaseSetupId, releaseGenerationId, releaseFamilyTag, acceptedUpdateKeyRoot,
            pool, s.asset, s.checkpoint, s.revision, s.nextSlot, s.x, s.y,
            s.policyContext, keccak256(abi.encode(inputs)), d.x, d.y);
    }

    /// @notice Deterministic public transcript for an independently checked
    /// current snapshot. A wallet must compare it with its own finalized data.
    function membershipContext(address pool, uint256[] calldata inputs, CcGroth16.G1 calldata d)
        external view returns (bytes memory)
    {
        if (inputs.length != publicSignalCount) revert InvalidCheckpoint();
        return _context(pool, _snapshot(pool), inputs, d);
    }

    function verifyProof(address pool, uint256[] calldata inputs, bytes calldata encoded)
        external view returns (bool)
    {
        if (block.chainid != releaseChainId || encoded.length != PROOF_BYTES ||
            inputs.length != publicSignalCount || pool.code.length == 0 ||
            address(registry).codehash != registryCodehash ||
            address(feeVerifier).codehash != feeVerifierCodehash ||
            address(lookupVerifier).codehash != lookupVerifierCodehash ||
            address(linkVerifier).codehash != linkVerifierCodehash) return false;
        Snapshot memory s = _snapshot(pool);
        bool combined = publicSignalCount == 40;
        if (inputs[0] != releaseChainId || inputs[1] != uint160(pool) ||
            inputs[combined ? 29 : 26] != uint160(address(registry)) ||
            inputs[combined ? 30 : 27] != uint160(s.asset) ||
            inputs[combined ? 31 : 28] != s.checkpoint ||
            inputs[combined ? 37 : 40] != s.policyContext ||
            inputs[combined ? 38 : 34] != uint256(releaseFamilyTag) ||
            (combined && inputs[39] != releaseChainId)) return false;
        (CcGroth16.Proof memory fee, Caulk.G1 memory query, Caulk.Proof memory lookup,
            CpLink.G1 memory pi) = abi.decode(encoded,
                (CcGroth16.Proof, Caulk.G1, Caulk.Proof, CpLink.G1));
        Keys memory keys = abi.decode(parameters, (Keys));
        if (!feeVerifier.verifyFee(keys.fee, fee, inputs)) return false;
        Caulk.Table memory table = Caulk.Table(65_536, Caulk.G1(s.x, s.y), keys.zH, query);
        if (!lookupVerifier.verifySingletonResearch(table, keys.lookup, lookup,
            _context(pool, s, inputs, fee.d))) return false;
        return linkVerifier.verifyResearch(pi, CpLink.G1(fee.d.x, fee.d.y),
            CpLink.G1(query.x, query.y), keys.link.a2, keys.link.c1, keys.link.c2);
    }
}
