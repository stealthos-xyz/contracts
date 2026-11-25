// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaFamilyFullBundleVerifierPreAudit as Bundle} from "./VantaFamilyFullBundleVerifierPreAudit.sol";
import {VantaFamilyAggregateGroth16PreAudit as Agg} from "./VantaFamilyAggregateGroth16PreAudit.sol";
import {VantaV8StatementResearch as Statement8} from "./VantaV8StatementResearch.sol";
import {VantaV8Statement32Research as Statement32} from "./VantaV8Statement32Research.sol";
import {VantaFamilyEpochDigestEightPreAudit as Digest8,
        VantaFamilyEpochDigestThirtyTwoPreAudit as Digest32}
    from "./VantaFamilyEpochDigestModulesPreAudit.sol";
import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";

/// @notice Research-only verifier for future Vanta epoch-scoped 8x5/32x5 proofs.
/// @dev No custody. This pins Gate0, Gate1, CP_link, table SRS and aggregate
/// keys but is NOT a replacement for an audited settlement contract. The
/// existing table-zero proof keys cannot authorize the new epoch statement.
contract VantaFamilyEpochProofVerifierPreAudit is VantaFamilyReleaseBinding {
    uint64 public immutable CHAIN_ID;
    bytes32 public constant EPOCH_PROFILE = keccak256("STEALTHOS_VANTA_V8_EPOCH_PROFILE_V1");
    uint256 private constant FQ =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    Bundle public immutable bundle;
    Agg public immutable aggregate;
    bytes32 public immutable bundleCodehash;
    bytes32 public immutable aggregateCodehash;
    bytes32 public immutable gate0Codehash;
    bytes32 public immutable gate1Codehash;
    bytes32 public immutable linkCodehash;
    bytes32 public immutable gate0KeyHash8;
    bytes32 public immutable gate0KeyHash32;
    bytes32 public immutable srsHash8;
    bytes32 public immutable srsHash32;
    /// @dev Each committed-witness width has a separately keyed CP_link CRS.
    ///      A single hash here silently rejects one of the two real circuits.
    bytes32 public immutable linkVkHash8;
    bytes32 public immutable linkVkHash32;
    bytes32 public immutable tableZhHash;
    bytes32 public immutable aggregateVkHash;
    Digest8 public immutable statementEight;
    Digest32 public immutable statementThirtyTwo;
    bytes32 public immutable statementEightCodehash;
    bytes32 public immutable statementThirtyTwoCodehash;

    error WrongChain();
    error InvalidResearchSetup();

    constructor(
        address bundleAddress, address aggregateAddress,
        bytes32[2] memory gate0Hashes, bytes32[2] memory srsHashes,
        bytes32[2] memory cpLinkHashes, bytes32 zHHash, bytes32 aggregateHash,
        address[2] memory statementModules,
        bytes32 setupId, bytes32 generationId, bytes32 familyTag, uint256 chainId
    ) VantaFamilyReleaseBinding(setupId,generationId,familyTag,chainId) {
        if (chainId > type(uint64).max || uint256(familyTag) >=
            21888242871839275222246405745257275088548364400416034343698204186575808495617)
            revert WrongChain();
        CHAIN_ID = uint64(chainId);
        if (bundleAddress.code.length == 0 ||
            aggregateAddress.code.length == 0 ||
            gate0Hashes[0] == 0 || gate0Hashes[1] == 0 ||
            gate0Hashes[0] == gate0Hashes[1] ||
            srsHashes[0] == 0 || srsHashes[1] == 0 ||
            cpLinkHashes[0] == 0 || cpLinkHashes[1] == 0 ||
            zHHash == 0 || aggregateHash == 0 ||
            statementModules[0] == statementModules[1] ||
            statementModules[0].code.length == 0 ||
            statementModules[1].code.length == 0)
            revert InvalidResearchSetup();
        bundle = Bundle(bundleAddress);
        aggregate = Agg(aggregateAddress);
        bundleCodehash = bundleAddress.codehash;
        aggregateCodehash = aggregateAddress.codehash;
        address g0 = address(bundle.gate0Verifier());
        address g1 = address(bundle.gate1Verifier());
        address cp = address(bundle.linkVerifier());
        if (g0.code.length == 0 || g1.code.length == 0 ||
            cp.code.length == 0) revert InvalidResearchSetup();
        gate0Codehash = g0.codehash;
        gate1Codehash = g1.codehash;
        linkCodehash = cp.codehash;
        gate0KeyHash8 = gate0Hashes[0];
        gate0KeyHash32 = gate0Hashes[1];
        srsHash8 = srsHashes[0];
        srsHash32 = srsHashes[1];
        linkVkHash8 = cpLinkHashes[0];
        linkVkHash32 = cpLinkHashes[1];
        tableZhHash = zHHash;
        aggregateVkHash = aggregateHash;
        statementEight = Digest8(statementModules[0]);
        statementThirtyTwo = Digest32(statementModules[1]);
        statementEightCodehash = statementModules[0].codehash;
        statementThirtyTwoCodehash = statementModules[1].codehash;
        if (statementEight.releaseSetupId() != releaseSetupId ||
            statementThirtyTwo.releaseSetupId() != releaseSetupId ||
            statementEight.releaseGenerationId() != releaseGenerationId ||
            statementThirtyTwo.releaseGenerationId() != releaseGenerationId ||
            statementEight.releaseFamilyTag() != releaseFamilyTag ||
            statementThirtyTwo.releaseFamilyTag() != releaseFamilyTag ||
            statementEight.releaseChainId() != releaseChainId ||
            statementThirtyTwo.releaseChainId() != releaseChainId)
            revert InvalidResearchSetup();
    }

    /// @dev Epoch-aware Gate1 context: u64BE(sourceEpoch) ||
    /// arkworks_G1_compressed(sourceKzgPoint) || u64BE(sourceRow).
    /// The source epoch must match the canonical custody ledger, never a
    /// caller-selected historical checkpoint with unrelated note ownership.
    function _expectedContext(uint64 sourceEpoch, uint64 row, uint256 x, uint256 y)
        private pure returns (bytes memory)
    {
        bytes memory point = new bytes(32);
        for (uint256 i; i < 32; ++i)
            point[i] = bytes1(uint8(x >> (i * 8)));
        if (y > FQ - y)
            point[31] = bytes1(uint8(point[31]) | uint8(0x80));
        return abi.encodePacked(sourceEpoch, point, row);
    }

    function _verify(
        uint8 width, Bundle.V8Gate0Data calldata g0,
        Bundle.Gate1Data calldata g1, Bundle.LinkData calldata link,
        uint64 sourceEpoch, uint64 sourceRow, uint256 sourceX, uint256 sourceY
    ) private view returns (bool) {
        if (block.chainid != CHAIN_ID) revert WrongChain();
        if (address(bundle).codehash != bundleCodehash ||
            address(aggregate).codehash != aggregateCodehash ||
            address(bundle.gate0Verifier()).codehash != gate0Codehash ||
            address(bundle.gate1Verifier()).codehash != gate1Codehash ||
            address(bundle.linkVerifier()).codehash != linkCodehash)
            return false;
        bytes32 g0Hash = width == 8 ? gate0KeyHash8 : gate0KeyHash32;
        bytes32 srsHash = width == 8 ? srsHash8 : srsHash32;
        bytes32 linkHash = width == 8 ? linkVkHash8 : linkVkHash32;
        if ((width != 8 && width != 32) ||
            g1.table.n != 65_536 ||
            g1.table.commitment.x != sourceX ||
            g1.table.commitment.y != sourceY ||
            keccak256(abi.encode(g0.vk)) != g0Hash ||
            keccak256(abi.encode(g1.srs)) != srsHash ||
            keccak256(abi.encode(g1.table.zH)) != tableZhHash ||
            g1.context.length != 48 ||
            keccak256(g1.context) != keccak256(_expectedContext(sourceEpoch, sourceRow, sourceX, sourceY)) ||
            keccak256(abi.encode(link.a2, link.c1, link.c2)) != linkHash)
            return false;
        return bundle.verifyV8ResearchBundle(width, g0, g1, link);
    }

    function verifyEpoch8(
        Statement8.LegPublic calldata action,
        Bundle.V8Gate0Data calldata g0, Bundle.Gate1Data calldata g1,
        Bundle.LinkData calldata link, bool privateMerge,
        uint64 sourceEpoch, uint64 targetEpoch,
        uint64 sourceRow, uint256 sourceX, uint256 sourceY
    ) external view returns (bool) {
        if (sourceEpoch > targetEpoch ||
            action.sourceSlotCount != sourceRow ||
            action.checkpointX != sourceX || action.checkpointY != sourceY)
            return false;
        if (address(statementEight).codehash != statementEightCodehash ||
            g0.publicInputs[0] != statementEight.digest(
                action, sourceEpoch, targetEpoch, privateMerge) ||
            g0.publicInputs[1] != action.protocolFeeCap ||
            g0.publicInputs[2] != action.partnerFeeCap ||
            g0.publicInputs[3] != action.saltedAmountHash ||
            g0.publicInputs[4] != uint256(releaseFamilyTag) ||
            g0.publicInputs[5] != block.chainid)
            return false;
        return _verify(8, g0, g1, link, sourceEpoch, sourceRow, sourceX, sourceY);
    }

    function verifyEpoch32(
        Statement32.LegPublic calldata action,
        Bundle.V8Gate0Data calldata g0, Bundle.Gate1Data calldata g1,
        Bundle.LinkData calldata link, bool privateMerge,
        uint64 sourceEpoch, uint64 targetEpoch,
        uint64 sourceRow, uint256 sourceX, uint256 sourceY
    ) external view returns (bool) {
        if (sourceEpoch > targetEpoch ||
            action.sourceSlotCount != sourceRow ||
            action.checkpointX != sourceX || action.checkpointY != sourceY)
            return false;
        if (address(statementThirtyTwo).codehash != statementThirtyTwoCodehash ||
            g0.publicInputs[0] != statementThirtyTwo.digest(
                action, sourceEpoch, targetEpoch, privateMerge) ||
            g0.publicInputs[1] != action.protocolFeeCap ||
            g0.publicInputs[2] != action.partnerFeeCap ||
            g0.publicInputs[3] != action.saltedAmountHash ||
            g0.publicInputs[4] != uint256(releaseFamilyTag) ||
            g0.publicInputs[5] != block.chainid)
            return false;
        return _verify(32, g0, g1, link, sourceEpoch, sourceRow, sourceX, sourceY);
    }

    /// @notice The aggregate SNARK is mandatory even for a single payout.
    /// It opens Gate0's EXACT salted hash to the one public payout amount.
    function verifyPayout(
        Agg.VerifyingKey calldata vk, Agg.Proof calldata proof,
        uint256[11] calldata input, uint256 batchDigest,
        uint256 saltedAmountHash, uint256 amount
    ) external view returns (bool) {
        if (block.chainid != CHAIN_ID) revert WrongChain();
        if (address(aggregate).codehash != aggregateCodehash ||
            keccak256(abi.encode(vk)) != aggregateVkHash ||
            input[0] != batchDigest || input[1] != 1 ||
            input[2] != amount || amount == 0 ||
            input[3] != saltedAmountHash)
            return false;
        for (uint256 i = 4; i < 11; ++i)
            if (input[i] != 0) return false;
        uint256[13] memory familyInputs;
        for (uint256 i; i < 11; ++i) familyInputs[i] = input[i];
        familyInputs[11] = uint256(releaseFamilyTag);
        familyInputs[12] = block.chainid;
        return aggregate.verifyResearch(vk, proof, familyInputs);
    }
}

