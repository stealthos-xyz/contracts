// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaEpochStateV1} from "./VantaEpochStateV1.sol";

interface IVantaEnhancedPoseidon {
    function hash(uint256[2] calldata input) external view returns (uint256);
}

interface IVantaEnhancedClaimProof {
    function verifyProof(uint256[2] calldata a, uint256[2][2] calldata b,
        uint256[2] calldata c, uint256[15] calldata signals) external view returns (bool);
}

interface IVantaEnhancedAuthorizationProof {
    function verifyProof(uint256[2] calldata a, uint256[2][2] calldata b,
        uint256[2] calldata c, uint256[19] calldata signals) external view returns (bool);
}

/// @notice Shared append-only trees for the enhanced candidate. No custody.
/// @dev Linked into the one pool. Never add an external arbitrary-leaf writer.
library VantaEnhancedTreesPreAudit {
    uint256 internal constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant ZERO_ZERO =
        0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864;
    uint256 internal constant DEPTH = 32;
    uint64 internal constant EPOCH_SECONDS = 60;
    uint64 internal constant MAX_ROOT_AGE = 10;

    struct Tree {
        uint64 count;
        uint256 root;
        uint256[32] frontier;
    }
    struct State {
        Tree reservations;
        Tree spentClaims;
        uint256[33] zeros;
        uint64 publishedEpoch;
        uint256 publishedReservationRoot;
        uint256 publishedSpentRoot;
        mapping(bytes32 => uint64) checkpointPairEpoch;
    }
    struct Domain {
        address asset;
        bytes32 genesisHash;
        bytes32 generationId;
        uint256 familyTag;
        uint256 chainId;
    }
    struct Pins {
        Domain domain;
        address hasher;
        bytes32 hasherCodehash;
        address authorizationVerifier;
        bytes32 authorizationVerifierCodehash;
        address claimVerifier;
        bytes32 claimVerifierCodehash;
        bytes32 feePolicyHash;
        uint64 maximumWindowEpochs;
        uint64 minimumDelayEpochs;
        uint64 maximumAuthorizationAgeEpochs;
    }
    struct Claim {
        uint256 reservationRoot;
        uint256 spentNullifierRoot;
        uint256 nullifier;
        address recipient;
        uint128 amount;
        uint64 executionEpoch;
        bool recovery;
    }
    error InvalidEnhancedState();
    error UnknownEnhancedRoot();
    error EnhancedTreeFull();
    error InvalidEnhancedProof();
    event EnhancedRootCheckpoint(uint64 indexed epoch, uint256 reservationRoot, uint256 spentNullifierRoot);
    event EnhancedReservation(uint64 indexed index, uint256 commitment);
    event EnhancedClaimNullifier(uint64 indexed index, uint256 nullifier);

    function hash(address hasher, uint256 left, uint256 right) internal view returns (uint256 result) {
        result = IVantaEnhancedPoseidon(hasher).hash([left, right]);
        if (result >= FR) revert InvalidEnhancedState();
    }

    function initialize(State storage self, address hasher) internal {
        if (self.spentClaims.count != 0 || hasher.code.length == 0 || hash(hasher, 0, 0) != ZERO_ZERO)
            revert InvalidEnhancedState();
        for (uint256 i; i < DEPTH; ++i) self.zeros[i + 1] = hash(hasher, self.zeros[i], self.zeros[i]);
        self.reservations.root = self.zeros[DEPTH];
        self.spentClaims.root = self.zeros[DEPTH];
        // A permanent zero sentinel supplies first-claim predecessor membership.
        append(self.spentClaims, self.zeros, hasher, 0);
    }

    function append(Tree storage tree, uint256[33] storage zeros, address hasher, uint256 leaf)
        internal returns (uint64 index)
    {
        if (tree.count >= uint64(1) << 32 || leaf >= FR) revert EnhancedTreeFull();
        index = tree.count++;
        uint64 cursor = index;
        uint256 node = leaf;
        for (uint256 i; i < DEPTH; ++i) {
            if (cursor & 1 == 0) {
                tree.frontier[i] = node;
                node = hash(hasher, node, zeros[i]);
            } else {
                node = hash(hasher, tree.frontier[i], node);
            }
            cursor >>= 1;
        }
        tree.root = node;
    }

    /// @dev One common pair per minute, before any mutation in that minute.
    /// A claimant can publish the checkpoint in its own transaction. There is
    /// no extra wallet approval or required preliminary transaction.
    function publish(State storage self) internal {
        uint64 epoch = uint64(block.timestamp / EPOCH_SECONDS);
        if (self.publishedEpoch == epoch) return;
        self.publishedEpoch = epoch;
        self.publishedReservationRoot = self.reservations.root;
        self.publishedSpentRoot = self.spentClaims.root;
        self.checkpointPairEpoch[keccak256(abi.encode(self.reservations.root,self.spentClaims.root))] = epoch;
        emit EnhancedRootCheckpoint(epoch, self.reservations.root, self.spentClaims.root);
    }

    function nextRoots(State storage self) internal view returns (uint256 reservation, uint256 spent, uint64 epoch) {
        epoch = uint64(block.timestamp / EPOCH_SECONDS);
        if (epoch > self.publishedEpoch) return (self.reservations.root, self.spentClaims.root, epoch);
        return (self.publishedReservationRoot, self.publishedSpentRoot, epoch);
    }

    function requirePins(Pins memory p) internal view {
        if (block.chainid != p.domain.chainId || p.domain.familyTag == 0 || p.domain.familyTag >= FR ||
            p.domain.genesisHash == bytes32(0) || p.domain.generationId == bytes32(0) ||
            p.hasher.codehash != p.hasherCodehash || p.hasherCodehash == bytes32(0) ||
            p.authorizationVerifier.codehash != p.authorizationVerifierCodehash ||
            p.claimVerifier.codehash != p.claimVerifierCodehash ||
            p.authorizationVerifierCodehash == bytes32(0) || p.claimVerifierCodehash == bytes32(0))
            revert InvalidEnhancedState();
    }

    function requireFreshRoots(State storage self, Claim calldata c) internal view {
        uint64 nowEpoch = uint64(block.timestamp / EPOCH_SECONDS);
        uint64 pairEpoch = self.checkpointPairEpoch[keccak256(abi.encode(c.reservationRoot,c.spentNullifierRoot))];
        // Accept only a pair actually published as one global checkpoint.
        // Independently valid roots from different epochs are not mixable.
        if (pairEpoch == 0 || pairEpoch > nowEpoch || nowEpoch - pairEpoch > MAX_ROOT_AGE)
            revert UnknownEnhancedRoot();
    }

    function claimSignals(Domain memory d, Claim calldata c) internal view returns (uint256[15] memory s) {
        s[0] = c.reservationRoot; s[1] = c.spentNullifierRoot; s[2] = c.nullifier;
        s[3] = uint160(c.recipient); s[4] = c.amount; s[5] = c.executionEpoch;
        s[6] = c.recovery ? 1 : 0; s[7] = d.familyTag; s[8] = block.chainid;
        s[9] = uint160(address(this)); s[10] = uint160(d.asset);
        s[11] = uint128(uint256(d.genesisHash)); s[12] = uint256(d.genesisHash) >> 128;
        s[13] = uint128(uint256(d.generationId)); s[14] = uint256(d.generationId) >> 128;
    }
}

/// @dev External library calls are immutable linked delegatecalls. Both note
/// spending and delayed claims consume the SAME pool nullifier registry.
library VantaEnhancedClaimLogicPreAudit {
    using VantaEpochStateV1 for VantaEpochStateV1.State;
    using VantaEnhancedTreesPreAudit for VantaEnhancedTreesPreAudit.State;

    function initialize(VantaEnhancedTreesPreAudit.State storage state, address hasher) external {
        state.initialize(hasher);
    }
    function checkpoint(VantaEnhancedTreesPreAudit.State storage state) external {
        state.publish();
    }
    function claim(
        VantaEnhancedTreesPreAudit.State storage state,
        VantaEpochStateV1.State storage epochs,
        VantaEnhancedTreesPreAudit.Pins memory pins,
        VantaEnhancedTreesPreAudit.Claim calldata c,
        bytes calldata proof
    ) external {
        VantaEnhancedTreesPreAudit.requirePins(pins);
        if (proof.length != 256 || c.recipient == address(0) || c.recipient == address(this) ||
            c.amount == 0 || c.amount >= uint256(1) << 120 || c.nullifier == 0 ||
            c.nullifier >= VantaEnhancedTreesPreAudit.FR ||
            c.executionEpoch != block.timestamp / VantaEnhancedTreesPreAudit.EPOCH_SECONDS)
            revert VantaEnhancedTreesPreAudit.InvalidEnhancedProof();
        state.publish();
        state.requireFreshRoots(c);
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory z) =
            abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));
        if (!IVantaEnhancedClaimProof(pins.claimVerifier).verifyProof(a,b,z,
            VantaEnhancedTreesPreAudit.claimSignals(pins.domain,c)))
            revert VantaEnhancedTreesPreAudit.InvalidEnhancedProof();
        epochs.consumeNullifier(c.nullifier);
        uint64 index = VantaEnhancedTreesPreAudit.append(state.spentClaims, state.zeros, pins.hasher, c.nullifier);
        emit VantaEnhancedTreesPreAudit.EnhancedClaimNullifier(index,c.nullifier);
    }
}
