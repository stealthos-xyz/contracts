// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaEpochCheckpointRef} from "./VantaEpochCheckpointRef.sol";

/// @notice Versioned state mechanics for a future Vanta pool with multiple KZG epochs.
/// @dev This internal library DOES NOT verify KZG row updates, the three-proof
///      bundle, asset conservation, nullifier derivation or note encryption.
///      A custody-capable pool MUST call these methods only after authenticating
///      row/update-key/proof data; never expose append() as an untrusted entrypoint.
library VantaEpochStateV1 {
    uint64 internal constant TABLE_CAPACITY = 65_536;
    uint64 internal constant INITIAL_ROWS = 32;
    uint64 internal constant MAX_APPEND_ROWS = 5;
    // Any caller may trigger a pinned rollover once an epoch approaches full. An old
    // epoch remains available as a proof *source* after this transition.
    // This reserve alone cannot guarantee access to funds: a verified
    // active output generation must remain available for ordinary exits.
    uint64 internal constant ROLLOVER_LEAD_ROWS = 1_024;
    uint256 internal constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint8 internal constant HISTORY_LENGTH = 64;

    struct Snapshot {
        uint64 epochId;
        uint64 slotCount;
        uint256 x;
        uint256 y;
    }

    struct Epoch {
        uint64 slotCount;
        uint256 x;
        uint256 y;
        uint256 currentRef;
        uint256 finalRef;
        uint8 cursor;
        bool closed;
        uint256[64] recentRefs;
    }

    struct State {
        bool initialized;
        uint64 currentEpoch;
        // Pin the canonical starting commitment for every future generation.
        // No operator-selected replacement points after initialization.
        uint256 initialX;
        uint256 initialY;
        mapping(uint64 => Epoch) epochs;
        mapping(uint256 => Snapshot) accepted;
        // Crucially global to the pool, never namespaced to the epoch.
        mapping(uint256 => bool) nullifierSpent;
    }

    error UnsupportedExitSource();
    error WrongSettlementTarget();

    error AlreadyInitialized();
    error Uninitialized();
    error WrongActiveEpoch();
    error InvalidAppendSize();
    error EpochFull();
    error EpochNotReadyForRollover();
    error EpochIdExhausted();
    error UnknownCheckpoint();
    error ZeroCheckpointRef();
    error InvalidNullifier();
    error NullifierAlreadySpent();

    event EpochOpened(uint64 indexed epochId, uint256 indexed checkpointRef, uint64 slotCount);
    event CheckpointAccepted(uint64 indexed epochId, uint256 indexed checkpointRef, uint64 slotCount);
    event EpochClosed(uint64 indexed epochId, uint256 indexed finalCheckpointRef, uint64 slotCount);

    function initialize(State storage self, uint256 initialX, uint256 initialY)
        internal returns (uint256 ref)
    {
        if (self.initialized) revert AlreadyInitialized();
        self.initialized = true;
        self.initialX = initialX;
        self.initialY = initialY;
        ref = _open(self, 0, initialX, initialY);
    }

    /// @dev Only after the caller verified the KZG update for precisely the
    ///      new rows and the three-proof settlement (if this is a spend).
    function append(
        State storage self, uint64 epochId, uint64 newSlotCount,
        uint256 newX, uint256 newY
    ) internal returns (uint256 ref) {
        if (!self.initialized) revert Uninitialized();
        if (epochId != self.currentEpoch) revert WrongActiveEpoch();
        Epoch storage epoch = self.epochs[epochId];
        if (epoch.closed) revert EpochFull();
        uint64 oldCount = epoch.slotCount;
        if (newSlotCount <= oldCount || newSlotCount - oldCount > MAX_APPEND_ROWS) {
            revert InvalidAppendSize();
        }
        if (newSlotCount > TABLE_CAPACITY) revert EpochFull();
        // Validate the curve point, new row count and versioned epoch digest.
        ref = VantaEpochCheckpointRef.compute(epochId, newSlotCount, newX, newY);
        epoch.slotCount = newSlotCount;
        epoch.x = newX;
        epoch.y = newY;
        _accept(self, epoch, epochId, ref);
    }

    /// @dev Permissionless state-only rollover after the threshold. The caller
    ///      selects NO setup, verifier, table point, fee, recipient or route.
    ///      The embedding custody pool MUST have pinned its genuine Gate0,
    ///      Gate1, CP_link and KZG parameters before exposing this operation.
    ///      The old checkpoint remains a proof source; only the active
    ///      epoch receives new five-row output commitments.
    function rolloverPinned(State storage self)
        internal returns (uint64 nextEpochId, uint256 initialRef)
    {
        if (!self.initialized) revert Uninitialized();
        uint64 oldEpochId = self.currentEpoch;
        Epoch storage oldEpoch = self.epochs[oldEpochId];
        if (oldEpoch.closed ||
            oldEpoch.slotCount < TABLE_CAPACITY - ROLLOVER_LEAD_ROWS) {
            revert EpochNotReadyForRollover();
        }
        if (oldEpochId == type(uint64).max) revert EpochIdExhausted();
        oldEpoch.closed = true;
        oldEpoch.finalRef = oldEpoch.currentRef;
        emit EpochClosed(oldEpochId, oldEpoch.finalRef, oldEpoch.slotCount);
        nextEpochId = oldEpochId + 1;
        self.currentEpoch = nextEpochId;
        initialRef = _open(self, nextEpochId, self.initialX, self.initialY);
    }

    /// @notice Internal operational readiness only; no permission to
    ///         deposit, prove or activate a new setup is granted here.
    function capacity(State storage self)
        internal view returns (uint64 remainingRows, bool rolloverDue, bool canAppendFive)
    {
        if (!self.initialized) revert Uninitialized();
        Epoch storage epoch = self.epochs[self.currentEpoch];
        remainingRows = TABLE_CAPACITY - epoch.slotCount;
        rolloverDue = remainingRows <= ROLLOVER_LEAD_ROWS;
        canAppendFive = !epoch.closed && remainingRows >= MAX_APPEND_ROWS;
    }

    /// @notice Authoritative source for the SAME authenticated 8x5/32x5
    ///         fee-enforced withdrawal path. Any checkpoint still present in
    ///         the epoch's bounded authenticated ring remains a valid source.
    ///         Every ordinary spend still writes five outputs to the active
    ///         epoch; a no-append exit writes no output rows.
    /// @dev This is a view/checkpoint gate ONLY, not a proof verifier.
    ///      The custody caller MUST authenticate Gate0, Gate1 and CP_link,
    ///      fee policy and every global nullifier before moving any funds.
    function requireSpendSource(
        State storage self, uint64 epochId, uint256 suppliedCheckpoint
    ) internal view returns (Snapshot memory result) {
        if (!self.initialized || epochId > self.currentEpoch)
            revert UnsupportedExitSource();
        Epoch storage epoch = self.epochs[epochId];
        if (epoch.slotCount == 0 || suppliedCheckpoint == 0)
            revert UnsupportedExitSource();
        result = self.accepted[suppliedCheckpoint];
        // The digest includes the epoch, but retain an explicit stored-epoch
        // check so a mapping collision or malformed test harness can never
        // authorize a checkpoint under a different generation.
        if (result.slotCount == 0 || result.epochId != epochId)
            revert UnsupportedExitSource();
    }

    /// @dev Atomic, *bookkeeping-only* cross-generation settlement. The
    ///      caller MUST authenticate the complete Gate0/Gate1/CP_link proof,
    ///      mandatory fee notes and output KZG update before calling.
    ///      The source can be a sealed/full generation; outputs are appended
    ///      exclusively to the active generation. Nullifiers stay pool-global.
    function recordVerifiedCrossEpochEight(
        State storage self,
        uint64 sourceEpoch, uint256 sourceCheckpoint,
        uint64 targetEpoch, uint256 targetCheckpoint,
        uint256 nextX, uint256 nextY,
        uint256[8] memory nullifiers
    ) internal returns (uint256 newCheckpoint) {
        _requireCrossEpochTarget(self, sourceEpoch, sourceCheckpoint,
            targetEpoch, targetCheckpoint);
        uint64 nextRow = self.epochs[targetEpoch].slotCount + MAX_APPEND_ROWS;
        newCheckpoint = append(self, targetEpoch, nextRow, nextX, nextY);
        consumeEight(self, nullifiers);
    }

    /// @dev Same atomic state transition for the 32x5 Vanta proof family.
    function recordVerifiedCrossEpochThirtyTwo(
        State storage self,
        uint64 sourceEpoch, uint256 sourceCheckpoint,
        uint64 targetEpoch, uint256 targetCheckpoint,
        uint256 nextX, uint256 nextY,
        uint256[32] memory nullifiers
    ) internal returns (uint256 newCheckpoint) {
        _requireCrossEpochTarget(self, sourceEpoch, sourceCheckpoint,
            targetEpoch, targetCheckpoint);
        uint64 nextRow = self.epochs[targetEpoch].slotCount + MAX_APPEND_ROWS;
        newCheckpoint = append(self, targetEpoch, nextRow, nextX, nextY);
        consumeThirtyTwo(self, nullifiers);
    }

    /// @notice Bookkeeping for a separately keyed NO_APPEND_EXIT_V1 full exit.
    /// @dev NO row append, active-epoch dependency, or reserve ledger.
    ///      Caller MUST first verify the complete distinct exit Gate0/Gate1/
    ///      CP_link + aggregate payout proofs and the mandatory PUBLIC fee
    ///      quote; all transfers and this state change must be atomic.
    ///      This internal helper is NEVER authorization by itself.
    function recordVerifiedNoAppendExitEight(
        State storage self, uint64 sourceEpoch, uint256 sourceCheckpoint,
        uint256[8] memory nullifiers
    ) internal {
        requireSpendSource(self, sourceEpoch, sourceCheckpoint);
        consumeEight(self, nullifiers);
    }

    /// @dev Same authenticated historical source and GLOBAL nullifier map as 8x5.
    function recordVerifiedNoAppendExitThirtyTwo(
        State storage self, uint64 sourceEpoch, uint256 sourceCheckpoint,
        uint256[32] memory nullifiers
    ) internal {
        requireSpendSource(self, sourceEpoch, sourceCheckpoint);
        consumeThirtyTwo(self, nullifiers);
    }

    function _requireCrossEpochTarget(
        State storage self,
        uint64 sourceEpoch, uint256 sourceCheckpoint,
        uint64 targetEpoch, uint256 targetCheckpoint
    ) private view {
        requireSpendSource(self, sourceEpoch, sourceCheckpoint);
        if (targetEpoch != self.currentEpoch)
            revert WrongActiveEpoch();
        Epoch storage target = self.epochs[targetEpoch];
        if (target.closed || target.currentRef == 0 ||
            target.currentRef != targetCheckpoint ||
            target.slotCount > TABLE_CAPACITY - MAX_APPEND_ROWS)
            revert WrongSettlementTarget();
    }

    /// @dev Must run within the same atomic transaction as successful full
    ///      proof verification and settlement accounting. A revert rolls back
    ///      all prior reservations and consumes no global nullifiers.
    function consumeNullifier(State storage self, uint256 nullifier) internal {
        if (!self.initialized) revert Uninitialized();
        if (nullifier == 0 || nullifier >= FR) revert InvalidNullifier();
        if (self.nullifierSpent[nullifier]) revert NullifierAlreadySpent();
        self.nullifierSpent[nullifier] = true;
    }

    /// @dev Consume exactly eight canonical nullifiers in the shared pool
    ///      registry. Caller MUST verify the pinned complete 8x5 proof bundle
    ///      first. An entire transaction reverts on any duplicate.
    function consumeEight(State storage self, uint256[8] memory nullifiers) internal {
        for (uint256 i = 0; i < 8; ++i) {
            consumeNullifier(self, nullifiers[i]);
        }
    }

    /// @dev The 32x5 verifier uses the SAME registry, not a separate mapping.
    ///      A cross-family replay or duplicate element reverts atomically.
    function consumeThirtyTwo(State storage self, uint256[32] memory nullifiers) internal {
        for (uint256 i = 0; i < 32; ++i) {
            consumeNullifier(self, nullifiers[i]);
        }
    }

    function isAccepted(State storage self, uint256 ref) internal view returns (bool) {
        return self.accepted[ref].slotCount != 0;
    }

    function snapshot(State storage self, uint256 ref)
        internal view returns (Snapshot memory result)
    {
        result = self.accepted[ref];
        if (result.slotCount == 0) revert UnknownCheckpoint();
    }

    function _open(State storage self, uint64 epochId, uint256 x, uint256 y)
        private returns (uint256 ref)
    {
        Epoch storage epoch = self.epochs[epochId];
        ref = VantaEpochCheckpointRef.compute(epochId, INITIAL_ROWS, x, y);
        epoch.slotCount = INITIAL_ROWS;
        epoch.x = x;
        epoch.y = y;
        _accept(self, epoch, epochId, ref);
        emit EpochOpened(epochId, ref, INITIAL_ROWS);
    }

    function _accept(State storage self, Epoch storage epoch, uint64 epochId, uint256 ref)
        private
    {
        // Zero is reserved as the empty-ring/unknown-snapshot sentinel.
        // A vanishingly rare Fr-reduced digest of zero must abort safely.
        if (ref == 0) revert ZeroCheckpointRef();
        uint256 overwritten = epoch.recentRefs[epoch.cursor];
        if (overwritten != 0) delete self.accepted[overwritten];
        epoch.recentRefs[epoch.cursor] = ref;
        epoch.cursor = (epoch.cursor + 1) % HISTORY_LENGTH;
        epoch.currentRef = ref;
        self.accepted[ref] = Snapshot(epochId, epoch.slotCount, epoch.x, epoch.y);
        emit CheckpointAccepted(epochId, ref, epoch.slotCount);
    }
}
