// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaPermanentHandleRegistry} from "../VantaPermanentHandleRegistry.sol";

interface IVantaBootstrapHandleHasher {
    function hash(uint256[2] calldata input) external view returns (uint256);
}

/// @notice Deploy a permanent namespace and claim its two infrastructure
/// handles atomically. There is no interval in which another wallet can claim
/// an infrastructure name, and no continuing name override or recovery power.
contract VantaFamilyHandleBootstrapFactory {
    struct Claim {
        bytes32 handleId;
        bytes32 recordCommitment;
        bytes32 ownerCommitment;
        uint256[8] proof;
        bytes32 nullifier;
    }

    VantaPermanentHandleRegistry public immutable handleRegistry;

    error InvalidInfrastructureHandle();

    constructor(address registerAdapter, address hasher, Claim[2] memory claims) {
        if (hasher.code.length == 0) revert InvalidInfrastructureHandle();
        VantaPermanentHandleRegistry created = new VantaPermanentHandleRegistry(registerAdapter);
        for (uint256 i; i < 2; ++i) {
            bytes memory label = i == 0 ? bytes("protocol.stealth") : bytes("relayer.stealth");
            bytes32 expected = bytes32(IVantaBootstrapHandleHasher(hasher).hash(
                [uint256(keccak256(label)), block.chainid]
            ));
            if (expected == bytes32(0) || claims[i].handleId != expected)
                revert InvalidInfrastructureHandle();
            Claim memory c = claims[i];
            created.registerAnonymous(c.handleId, c.recordCommitment, c.ownerCommitment,
                c.proof, c.nullifier, 1);
        }
        handleRegistry = created;
    }
}
