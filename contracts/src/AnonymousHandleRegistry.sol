// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AnonymousHandleVerifier} from "./verifiers/AnonymousHandleVerifier.sol";
import {DevelopmentChains} from "./libraries/DevelopmentChains.sol";

/**
 * @title AnonymousHandleRegistry
 * @dev The verifiers are immutable. They are the entire authorization surface —
 *      an always-true verifier lets anyone rewrite any handle's record
 *      commitment — so an owner-rotatable reference would make the owner able
 *      to seize every handle. Rotating a verifying key means deploying a new
 *      registry and migrating, which is the price of not holding that power.
 */
contract AnonymousHandleRegistry is Ownable, ReentrancyGuard {
    uint8 public constant ACTION_REGISTER = 1;
    uint8 public constant ACTION_ROTATE = 2;

    struct HandleState {
        bytes32 recordCommitment;
        bytes32 ownerCommitment;
        uint64 epoch;
        bool exists;
    }

    mapping(bytes32 => HandleState) private _handles;
    mapping(bytes32 => bool) public usedNullifier;

    AnonymousHandleVerifier public immutable registerVerifier;
    AnonymousHandleVerifier public immutable rotateVerifier;

    uint256 public immutable chainId;

    event HandleRegistered(
        bytes32 indexed handleId,
        bytes32 indexed recordCommitment,
        bytes32 indexed nullifier,
        bytes32 ownerCommitment,
        uint64 epoch
    );
    event HandleRotated(
        bytes32 indexed handleId,
        bytes32 indexed recordCommitment,
        bytes32 indexed nullifier,
        bytes32 ownerCommitment,
        uint64 epoch
    );
    event NullifierConsumed(bytes32 indexed nullifier, bytes32 indexed handleId, uint8 indexed actionTag, uint64 epoch);

    error NullifierAlreadyUsed();
    error InvalidProof();
    error HandleAlreadyExists();
    error HandleNotFound();
    error StaleEpoch();
    error InvalidActionTag();
    error InvalidVerifier();
    error DuplicateVerifier();
    error OwnerCommitmentMismatch();
    error DevelopmentVerifierOnProductionChain();

    constructor(address owner_, address registerVerifier_, address rotateVerifier_) Ownable(owner_) {
        if (
            registerVerifier_ == address(0) || rotateVerifier_ == address(0)
                || registerVerifier_.code.length == 0 || rotateVerifier_.code.length == 0
        ) revert InvalidVerifier();
        // Register and rotate are separate circuits with separate ceremonies.
        // They share an IC layout, so wiring one key into both slots is not
        // caught by any structural check and would let a register proof settle
        // a rotation under whichever key the operator actually holds.
        //
        // These slots hold ADAPTERS, and an adapter reveals nothing about the
        // key it wraps: HandleRegisterProofAdapter and HandleRotateProofAdapter
        // are byte-identical sources apart from their file paths, so their
        // deployed bytecode differs only in the trailing solc metadata hash.
        // One key behind one adapter of each type — the natural shape of the
        // misconfiguration — therefore differs in both adapter address and
        // adapter codehash. Compare the WRAPPED KEYS instead: by address, which
        // catches one deployment reused, and by codehash, which catches the
        // same verifying key deployed twice.
        address registerKey = AnonymousHandleVerifier(registerVerifier_).verifier();
        address rotateKey = AnonymousHandleVerifier(rotateVerifier_).verifier();
        if (registerKey.code.length == 0 || rotateKey.code.length == 0) revert InvalidVerifier();
        if (
            registerVerifier_ == rotateVerifier_ || registerKey == rotateKey
                || registerKey.codehash == rotateKey.codehash
        ) {
            revert DuplicateVerifier();
        }
        chainId = block.chainid;
        _requireProductionVerifier(AnonymousHandleVerifier(registerVerifier_));
        _requireProductionVerifier(AnonymousHandleVerifier(rotateVerifier_));
        registerVerifier = AnonymousHandleVerifier(registerVerifier_);
        rotateVerifier = AnonymousHandleVerifier(rotateVerifier_);
    }

    /// @dev Fail closed: a development-setup verifying key is accepted only on
    ///      an explicitly enumerated throwaway chain, never on a chain that
    ///      merely was not thought of when the guard was written.
    function _requireProductionVerifier(AnonymousHandleVerifier verifier) internal view {
        if (!DevelopmentChains.allowsDevelopmentSetup(block.chainid) && verifier.isDevelopmentSetup()) {
            revert DevelopmentVerifierOnProductionChain();
        }
    }

    function getHandleState(bytes32 handleId) external view returns (HandleState memory) {
        return _handles[handleId];
    }

    function registerAnonymous(
        bytes32 handleId,
        bytes32 initialRecordCommitment,
        bytes32 ownerCommitment,
        uint256[8] calldata proof,
        bytes32 nullifier,
        uint64 epoch
    ) external nonReentrant {
        if (usedNullifier[nullifier]) revert NullifierAlreadyUsed();
        HandleState storage state = _handles[handleId];
        if (state.exists) revert HandleAlreadyExists();
        if (epoch == 0) revert StaleEpoch();

        // Checks-effects-interactions: commit state before the external verifier
        // call. An invalid proof reverts and rolls these writes back.
        usedNullifier[nullifier] = true;
        _handles[handleId] = HandleState({
            recordCommitment: initialRecordCommitment, ownerCommitment: ownerCommitment, epoch: epoch, exists: true
        });

        bool valid = registerVerifier.verifyProof(
            proof, handleId, initialRecordCommitment, ownerCommitment, nullifier, epoch, chainId, ACTION_REGISTER
        );
        if (!valid) revert InvalidProof();

        emit NullifierConsumed(nullifier, handleId, ACTION_REGISTER, epoch);
        emit HandleRegistered(handleId, initialRecordCommitment, nullifier, ownerCommitment, epoch);
    }

    /// @notice Rotates a handle's RECORD commitment. The owner credential
    ///         (`hsk`, committed as `ownerCommitment`) is not rotatable here
    ///         and the supplied `ownerCommitment` must match the stored one:
    ///         it is the authorization input, not an update.
    /// @dev Rotating the credential itself needs `newOwnerCommitment` as an
    ///      eighth public input of `handle_rotate`, so that the current owner's
    ///      proof commits to the successor commitment. Without it, nothing in
    ///      the proof binds a successor, and any relayer holding a valid proof
    ///      could substitute a commitment of its own and take the handle.
    ///      Accepting a successor here before the circuit binds it would be
    ///      strictly worse than leaving the credential fixed.
    function rotateAnonymous(
        bytes32 handleId,
        bytes32 newRecordCommitment,
        bytes32 ownerCommitment,
        uint256[8] calldata proof,
        bytes32 nullifier,
        uint64 epoch
    ) external nonReentrant {
        if (usedNullifier[nullifier]) revert NullifierAlreadyUsed();
        HandleState storage state = _handles[handleId];
        if (!state.exists) revert HandleNotFound();
        if (epoch <= state.epoch) revert StaleEpoch();
        if (ownerCommitment != state.ownerCommitment) revert OwnerCommitmentMismatch();

        // Checks-effects-interactions: commit state before the external verifier
        // call. An invalid proof reverts and rolls these writes back.
        usedNullifier[nullifier] = true;
        state.recordCommitment = newRecordCommitment;
        state.epoch = epoch;

        bool valid = rotateVerifier.verifyProof(
            proof, handleId, newRecordCommitment, ownerCommitment, nullifier, epoch, chainId, ACTION_ROTATE
        );
        if (!valid) revert InvalidProof();

        emit NullifierConsumed(nullifier, handleId, ACTION_ROTATE, epoch);
        emit HandleRotated(handleId, newRecordCommitment, nullifier, ownerCommitment, epoch);
    }
}
