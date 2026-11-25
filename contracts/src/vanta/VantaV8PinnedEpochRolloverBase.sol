// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaEpochStateV1} from "./VantaEpochStateV1.sol";

/// @notice Reusable, permissionless *table rollover* boundary for FUTURE
///         Vanta pools. No custody, fee change, exit, or payment selector.
/// @dev A custody implementation must inherit this base and authenticate its
///      Gate0/Gate1/CP_link, KZG updates, token liability and private fee
///      notes independently. Existing immutable research pools do not use it.
///      This base is not audited or safe to custody assets on its own.
abstract contract VantaV8PinnedEpochRolloverBase {
    using VantaEpochStateV1 for VantaEpochStateV1.State;

    uint64 public constant TABLE_SIZE = 65_536;
    uint256 public immutable approvedChainId;
    address public immutable approvedThreeGate;
    address public immutable approvedKzgUpdater;
    bytes32 public immutable approvedThreeGateCodehash;
    bytes32 public immutable approvedKzgCodehash;

    VantaEpochStateV1.State internal epochState;

    error UnapprovedEpochSetup();
    error WrongEpochChain();

    constructor(
        uint256 chainId,
        address threeGate,
        bytes32 threeGateCodehash,
        address kzgUpdater,
        bytes32 kzgCodehash,
        uint256 initialX,
        uint256 initialY
    ) {
        if (chainId != block.chainid) revert WrongEpochChain();
        if (threeGate == address(0) || kzgUpdater == address(0) ||
            threeGateCodehash == bytes32(0) || kzgCodehash == bytes32(0) ||
            threeGate.codehash != threeGateCodehash ||
            kzgUpdater.codehash != kzgCodehash)
            revert UnapprovedEpochSetup();
        approvedChainId = chainId;
        approvedThreeGate = threeGate;
        approvedKzgUpdater = kzgUpdater;
        approvedThreeGateCodehash = threeGateCodehash;
        approvedKzgCodehash = kzgCodehash;
        epochState.initialize(initialX, initialY);
    }

    /// @notice Everyone calls the SAME operation after the capacity
    ///         threshold. Zero external parameters: no admin-selected
    ///         key, new initial commitment, pool, payout, or alternate fee.
    function rolloverPinned()
        external returns (uint64 nextGeneration, uint256 checkpoint)
    {
        _requirePinnedEpochSetup();
        return epochState.rolloverPinned();
    }

    /// @notice Read-only operator telemetry; not a wallet prompt.
    function nextRow() external view returns (uint64) {
        return epochState.epochs[epochState.currentEpoch].slotCount;
    }

    function activeGeneration() external view returns (
        uint64 id, uint64 rows, uint256 checkpoint
    ) {
        id = epochState.currentEpoch;
        VantaEpochStateV1.Epoch storage active = epochState.epochs[id];
        return (id, active.slotCount, active.currentRef);
    }

    function historicalCheckpoint(uint64 id)
        external view returns (uint256 checkpoint)
    {
        if (id > epochState.currentEpoch ||
            epochState.epochs[id].slotCount == 0)
            revert VantaEpochStateV1.UnsupportedExitSource();
        VantaEpochStateV1.Epoch storage source = epochState.epochs[id];
        checkpoint = source.closed ? source.finalRef : source.currentRef;
    }

    /// @dev Use the same pinned modules in the actual spend/append path.
    ///      A codehash pin alone does NOT authenticate proof setup parameters.
    function _requirePinnedEpochSetup() internal view {
        if (block.chainid != approvedChainId) revert WrongEpochChain();
        if (approvedThreeGate.codehash != approvedThreeGateCodehash ||
            approvedKzgUpdater.codehash != approvedKzgCodehash)
            revert UnapprovedEpochSetup();
    }
}
