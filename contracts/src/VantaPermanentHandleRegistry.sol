// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AnonymousHandleVerifier} from "./verifiers/AnonymousHandleVerifier.sol";
import {DevelopmentChains} from "./libraries/DevelopmentChains.sol";

/**
 * @title VantaPermanentHandleRegistry
 * @notice Canonical, one-time .stealth name claims for Vanta's shared namespace.
 * @dev Deployed on ONE canonical chain. Every supported network resolves the
 *      same handle ID against this contract; other chains do not mint names.
 *      No rotation, renewal, deletion, upgrade, or owner/admin override exists.
 *
 *      The immutable initial record commitment authenticates the first Vanta
 *      receiving route. Future network-specific routes, when supported, must
 *      be authenticated as append-only signed extensions of that original
 *      on-chain record, not as another handle claim.
 */
contract VantaPermanentHandleRegistry is ReentrancyGuard {
    uint8 public constant ACTION_REGISTER = 1;
    uint64 public constant INITIAL_EPOCH = 1;

    struct HandleState {
        bytes32 recordCommitment;
        bytes32 ownerCommitment;
        uint64 epoch;
        bool exists;
    }

    mapping(bytes32 => HandleState) private _handles;
    mapping(bytes32 => bool) public usedNullifier;

    AnonymousHandleVerifier public immutable registerVerifier;
    uint256 public immutable chainId;

    event HandleRegistered(
        bytes32 indexed handleId,
        bytes32 indexed recordCommitment,
        bytes32 indexed nullifier,
        bytes32 ownerCommitment,
        uint64 epoch
    );
    event NullifierConsumed(
        bytes32 indexed nullifier, bytes32 indexed handleId, uint8 indexed actionTag, uint64 epoch
    );

    error InvalidVerifier();
    error DevelopmentVerifierOnProductionChain();
    error InvalidClaim();
    error InvalidProof();
    error NullifierAlreadyUsed();
    error HandleAlreadyExists();

    constructor(address registerAdapter) {
        if (registerAdapter == address(0) || registerAdapter.code.length == 0) revert InvalidVerifier();
        AnonymousHandleVerifier adapter = AnonymousHandleVerifier(registerAdapter);
        address verifyingKey = adapter.verifier();
        if (verifyingKey.code.length == 0) revert InvalidVerifier();
        if (!DevelopmentChains.allowsDevelopmentSetup(block.chainid) && adapter.isDevelopmentSetup()) {
            revert DevelopmentVerifierOnProductionChain();
        }
        registerVerifier = adapter;
        chainId = block.chainid;
    }

    function getHandleState(bytes32 handleId) external view returns (HandleState memory) {
        return _handles[handleId];
    }

    /// @notice This is the only state-changing entry point. A name can be claimed once, forever.
    function registerAnonymous(
        bytes32 handleId,
        bytes32 initialRecordCommitment,
        bytes32 ownerCommitment,
        uint256[8] calldata proof,
        bytes32 nullifier,
        uint64 epoch
    ) external nonReentrant {
        if (
            handleId == bytes32(0) || initialRecordCommitment == bytes32(0)
                || ownerCommitment == bytes32(0) || nullifier == bytes32(0) || epoch != INITIAL_EPOCH
        ) revert InvalidClaim();
        if (usedNullifier[nullifier]) revert NullifierAlreadyUsed();
        if (_handles[handleId].exists) revert HandleAlreadyExists();

        // A failed proof reverts both writes atomically. The reentrancy guard
        // prevents an untrusted verifier from registering a second name mid-call.
        usedNullifier[nullifier] = true;
        _handles[handleId] = HandleState({
            recordCommitment: initialRecordCommitment,
            ownerCommitment: ownerCommitment,
            epoch: epoch,
            exists: true
        });
        if (!registerVerifier.verifyProof(
            proof, handleId, initialRecordCommitment, ownerCommitment, nullifier, epoch, chainId, ACTION_REGISTER
        )) revert InvalidProof();

        emit NullifierConsumed(nullifier, handleId, ACTION_REGISTER, epoch);
        emit HandleRegistered(handleId, initialRecordCommitment, nullifier, ownerCommitment, epoch);
    }
}
