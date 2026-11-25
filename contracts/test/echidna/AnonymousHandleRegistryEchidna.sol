// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AnonymousHandleRegistry} from "../../src/AnonymousHandleRegistry.sol";
import {AnonymousHandleVerifier} from "../../src/verifiers/AnonymousHandleVerifier.sol";

/// @dev The verifying key. `keyTag` is baked into runtime code so the register
///      and rotate keys carry distinct codehashes, which is what the registry's
///      distinctness check requires.
contract EchidnaHandleVerifyingKey {
    uint8 public immutable keyTag;

    constructor(uint8 keyTag_) {
        keyTag = keyTag_;
    }

    function isDevelopmentSetup() external pure returns (bool) {
        return false;
    }

    function verifyProof(
        uint256[8] calldata,
        bytes32,
        bytes32,
        bytes32,
        bytes32 nullifier,
        uint64 epoch,
        uint256 chainId,
        uint8 actionTag
    ) external pure returns (bool) {
        return nullifier != bytes32(0) && epoch != 0 && chainId != 0 && (actionTag == 1 || actionTag == 2);
    }
}

/// @dev The proof adapter, which is what the registry slots actually hold.
contract EchidnaHandleProofAdapter is AnonymousHandleVerifier {
    address public immutable override verifier;

    constructor(address verifier_) {
        verifier = verifier_;
    }

    function isDevelopmentSetup() external view override returns (bool) {
        return EchidnaHandleVerifyingKey(verifier).isDevelopmentSetup();
    }

    function verifyProof(
        uint256[8] calldata proof,
        bytes32 handleId,
        bytes32 recordCommitment,
        bytes32 ownerCommitment,
        bytes32 nullifier,
        uint64 epoch,
        uint256 chainId,
        uint8 actionTag
    ) external view override returns (bool) {
        return EchidnaHandleVerifyingKey(verifier).verifyProof(
            proof, handleId, recordCommitment, ownerCommitment, nullifier, epoch, chainId, actionTag
        );
    }
}

contract AnonymousHandleRegistryEchidna {
    AnonymousHandleRegistry public registry;
    bytes32 public lastHandleId;
    bytes32 public lastOwnerCommitment;
    bytes32 public lastUsedNullifier;
    uint64 public lastEpoch;

    constructor() {
        EchidnaHandleProofAdapter registerAdapter =
            new EchidnaHandleProofAdapter(address(new EchidnaHandleVerifyingKey(1)));
        EchidnaHandleProofAdapter rotateAdapter =
            new EchidnaHandleProofAdapter(address(new EchidnaHandleVerifyingKey(2)));
        registry = new AnonymousHandleRegistry(address(this), address(registerAdapter), address(rotateAdapter));
    }

    function register(
        bytes32 handleId,
        bytes32 recordCommitment,
        bytes32 ownerCommitment,
        bytes32 nullifier,
        uint64 epoch
    ) external {
        if (
            handleId == bytes32(0) || recordCommitment == bytes32(0) || ownerCommitment == bytes32(0)
                || nullifier == bytes32(0)
        ) return;
        if (epoch == 0) epoch = 1;

        uint256[8] memory proof;
        try registry.registerAnonymous(handleId, recordCommitment, ownerCommitment, proof, nullifier, epoch) {
            lastHandleId = handleId;
            lastOwnerCommitment = ownerCommitment;
            lastUsedNullifier = nullifier;
            lastEpoch = epoch;
        } catch {}
    }

    function rotate(bytes32 recordCommitment, bytes32 nullifier, uint64 epoch) external {
        if (lastHandleId == bytes32(0) || recordCommitment == bytes32(0) || nullifier == bytes32(0)) return;
        if (lastEpoch == type(uint64).max) return;
        if (epoch <= lastEpoch) epoch = lastEpoch + 1;

        uint256[8] memory proof;
        try registry.rotateAnonymous(lastHandleId, recordCommitment, lastOwnerCommitment, proof, nullifier, epoch) {
            lastUsedNullifier = nullifier;
            lastEpoch = epoch;
        } catch {}
    }

    function echidna_used_nullifier_cannot_register_again() external returns (bool) {
        if (lastUsedNullifier == bytes32(0)) return true;

        uint256[8] memory proof;
        try registry.registerAnonymous(
            keccak256(abi.encode("replay-register", lastHandleId, lastEpoch)),
            keccak256(abi.encode("record", lastEpoch)),
            lastOwnerCommitment,
            proof,
            lastUsedNullifier,
            lastEpoch == 0 ? 1 : lastEpoch
        ) {
            return false;
        } catch {
            return true;
        }
    }

    function echidna_used_nullifier_cannot_rotate_again() external returns (bool) {
        if (lastHandleId == bytes32(0) || lastUsedNullifier == bytes32(0)) return true;

        uint256[8] memory proof;
        try registry.rotateAnonymous(
            lastHandleId,
            keccak256(abi.encode("replay-rotate", lastEpoch)),
            lastOwnerCommitment,
            proof,
            lastUsedNullifier,
            lastEpoch == 0 ? 1 : lastEpoch
        ) {
            return false;
        } catch {
            return true;
        }
    }
}
