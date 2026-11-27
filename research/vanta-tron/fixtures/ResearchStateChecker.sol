// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Test-only snapshot model. No tokens, custody, or production admission.
/// @dev Owner controls fixture snapshots solely to exercise stale-state finalization.
contract ResearchStateChecker {
    address public immutable owner;
    mapping(bytes32 => bool) public current;
    constructor(address fixtureOwner) { owner = fixtureOwner; }
    function setCurrent(bytes32 snapshot, bool enabled) external {
        require(msg.sender == owner, "fixture owner only");
        current[snapshot] = enabled;
    }
    function isCurrent(
        bytes32 sessionId, bytes32 configurationHash, bytes32 actionHash,
        bytes32 checkpoint, bytes32 nullifier, bytes32 tableHash, bytes32 publicInputsHash
    ) external view returns (bool) {
        return current[keccak256(abi.encode(sessionId, configurationHash, actionHash,
            checkpoint, nullifier, tableHash, publicInputsHash))];
    }
}
