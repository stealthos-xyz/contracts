// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VantaPermanentHandleRegistry} from "../src/VantaPermanentHandleRegistry.sol";
import {MockHandleVerifyingKey, MockHandleProofAdapter} from "./AnonymousHandleRegistry.t.sol";

contract VantaPermanentHandleRegistryTest is Test {
    MockHandleVerifyingKey internal key;
    MockHandleProofAdapter internal adapter;
    VantaPermanentHandleRegistry internal registry;

    bytes32 internal constant HANDLE = bytes32(uint256(11));
    bytes32 internal constant RECORD = bytes32(uint256(22));
    bytes32 internal constant OWNER = bytes32(uint256(33));
    bytes32 internal constant NULLIFIER = bytes32(uint256(44));

    function setUp() public {
        key = new MockHandleVerifyingKey(1);
        adapter = new MockHandleProofAdapter(address(key), 1);
        registry = new VantaPermanentHandleRegistry(address(adapter));
    }

    function _claim(bytes32 handleId, bytes32 recordCommitment, bytes32 nullifier) internal {
        uint256[8] memory proof;
        registry.registerAnonymous(handleId, recordCommitment, OWNER, proof, nullifier, 1);
    }

    function test_onceClaimedTheNameAndRecordArePermanent() public {
        _claim(HANDLE, RECORD, NULLIFIER);
        VantaPermanentHandleRegistry.HandleState memory state = registry.getHandleState(HANDLE);
        assertTrue(state.exists);
        assertEq(state.recordCommitment, RECORD);
        assertEq(state.ownerCommitment, OWNER);
        assertEq(state.epoch, 1);
        assertTrue(registry.usedNullifier(NULLIFIER));

        vm.expectRevert(VantaPermanentHandleRegistry.HandleAlreadyExists.selector);
        _claim(HANDLE, bytes32(uint256(99)), bytes32(uint256(55)));

        state = registry.getHandleState(HANDLE);
        assertEq(state.recordCommitment, RECORD);
        assertEq(state.epoch, 1);
    }

    function test_noRotationOrRenewalEntryPointExists() public {
        _claim(HANDLE, RECORD, NULLIFIER);
        uint256[8] memory proof;
        (bool success,) = address(registry).call(abi.encodeWithSignature(
            "rotateAnonymous(bytes32,bytes32,bytes32,uint256[8],bytes32,uint64)",
            HANDLE, bytes32(uint256(55)), OWNER, proof, bytes32(uint256(66)), uint64(2)
        ));
        assertFalse(success);
        assertEq(registry.getHandleState(HANDLE).recordCommitment, RECORD);
    }

    function test_rejectsInvalidProofWithoutConsumingNameOrNullifier() public {
        key.setResult(false);
        vm.expectRevert(VantaPermanentHandleRegistry.InvalidProof.selector);
        _claim(HANDLE, RECORD, NULLIFIER);
        assertFalse(registry.getHandleState(HANDLE).exists);
        assertFalse(registry.usedNullifier(NULLIFIER));

        key.setResult(true);
        _claim(HANDLE, RECORD, NULLIFIER);
        assertTrue(registry.getHandleState(HANDLE).exists);
    }

    function test_rejectsNullifierReuseAcrossDifferentNames() public {
        _claim(HANDLE, RECORD, NULLIFIER);
        vm.expectRevert(VantaPermanentHandleRegistry.NullifierAlreadyUsed.selector);
        _claim(bytes32(uint256(99)), bytes32(uint256(100)), NULLIFIER);
    }

    function test_requiresOneInitialEpochAndNonzeroCommitments() public {
        uint256[8] memory proof;
        vm.expectRevert(VantaPermanentHandleRegistry.InvalidClaim.selector);
        registry.registerAnonymous(HANDLE, RECORD, OWNER, proof, NULLIFIER, 2);
        vm.expectRevert(VantaPermanentHandleRegistry.InvalidClaim.selector);
        registry.registerAnonymous(HANDLE, bytes32(0), OWNER, proof, NULLIFIER, 1);
        vm.expectRevert(VantaPermanentHandleRegistry.InvalidClaim.selector);
        registry.registerAnonymous(HANDLE, RECORD, bytes32(0), proof, NULLIFIER, 1);
    }

    function test_failsClosedForDevelopmentKeyOnRealChain() public {
        key.setDevelopmentSetup(true);
        vm.chainId(8453);
        vm.expectRevert(VantaPermanentHandleRegistry.DevelopmentVerifierOnProductionChain.selector);
        new VantaPermanentHandleRegistry(address(adapter));

        vm.chainId(84532);
        VantaPermanentHandleRegistry testnet = new VantaPermanentHandleRegistry(address(adapter));
        assertEq(address(testnet.registerVerifier()), address(adapter));
    }
}
