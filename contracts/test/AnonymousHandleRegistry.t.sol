// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {AnonymousHandleRegistry} from "../src/AnonymousHandleRegistry.sol";
import {HandleRegisterProofAdapter} from "../src/verifiers/HandleRegisterProofAdapter.sol";
import {HandleRotateProofAdapter} from "../src/verifiers/HandleRotateProofAdapter.sol";
import {HandleRegisterVerifier} from "../src/verifiers/HandleRegisterVerifier.sol";
import {HandleRotateVerifier} from "../src/verifiers/HandleRotateVerifier.sol";
import {AnonymousHandleVerifier} from "../src/verifiers/AnonymousHandleVerifier.sol";
import {AnonymousHandleRegistryEchidna} from "./echidna/AnonymousHandleRegistryEchidna.sol";

/// @dev Stands in for HandleRegisterVerifier/HandleRotateVerifier: the Groth16
///      verifying-key contract itself. `keyTag` is baked into runtime code, so
///      keys from different ceremonies carry distinct codehashes and two
///      deployments of one ceremony's key carry the same one.
contract MockHandleVerifyingKey {
    uint8 public immutable keyTag;

    bool public shouldPass = true;
    bool public devSetup;

    constructor(uint8 keyTag_) {
        keyTag = keyTag_;
    }

    function setResult(bool value) external {
        shouldPass = value;
    }

    function setDevelopmentSetup(bool value) external {
        devSetup = value;
    }

    function isDevelopmentSetup() external view returns (bool) {
        return devSetup;
    }

    function verifyProof(uint256[8] calldata, bytes32, bytes32, bytes32, bytes32, uint64, uint256, uint8)
        external
        view
        returns (bool)
    {
        return shouldPass;
    }
}

/// @dev Stands in for HandleRegisterProofAdapter/HandleRotateProofAdapter: a
///      thin wrapper whose own code is a function of the adapter type and never
///      of the key. `adapterTag` reproduces exactly that — two adapter types
///      differ in codehash even when they wrap one and the same key.
contract MockHandleProofAdapter is AnonymousHandleVerifier {
    address public immutable override verifier;
    uint8 public immutable adapterTag;

    constructor(address verifier_, uint8 adapterTag_) {
        verifier = verifier_;
        adapterTag = adapterTag_;
    }

    function isDevelopmentSetup() external view override returns (bool) {
        return MockHandleVerifyingKey(verifier).isDevelopmentSetup();
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
        return MockHandleVerifyingKey(verifier).verifyProof(
            proof, handleId, recordCommitment, ownerCommitment, nullifier, epoch, chainId, actionTag
        );
    }
}

contract AnonymousHandleRegistryTest is Test {
    MockHandleVerifyingKey internal registerKey;
    MockHandleVerifyingKey internal rotateKey;
    MockHandleProofAdapter internal registerVerifier;
    MockHandleProofAdapter internal rotateVerifier;
    AnonymousHandleRegistry internal registry;

    function setUp() public {
        registerKey = new MockHandleVerifyingKey(1);
        rotateKey = new MockHandleVerifyingKey(2);
        registerVerifier = new MockHandleProofAdapter(address(registerKey), 1);
        rotateVerifier = new MockHandleProofAdapter(address(rotateKey), 2);
        registry = new AnonymousHandleRegistry(address(this), address(registerVerifier), address(rotateVerifier));
    }

    function _adapter(uint8 keyTag, uint8 adapterTag) internal returns (MockHandleProofAdapter) {
        return new MockHandleProofAdapter(address(new MockHandleVerifyingKey(keyTag)), adapterTag);
    }

    function test_constructor_rejectsDevelopmentVerifierOnProductionChain() public {
        MockHandleProofAdapter devVerifier = _adapter(1, 1);
        MockHandleVerifyingKey(devVerifier.verifier()).setDevelopmentSetup(true);
        MockHandleProofAdapter prodVerifier = _adapter(2, 2);

        vm.chainId(8453);
        vm.expectRevert(AnonymousHandleRegistry.DevelopmentVerifierOnProductionChain.selector);
        new AnonymousHandleRegistry(address(this), address(devVerifier), address(prodVerifier));

        vm.expectRevert(AnonymousHandleRegistry.DevelopmentVerifierOnProductionChain.selector);
        new AnonymousHandleRegistry(address(this), address(prodVerifier), address(devVerifier));

        // A production key deploys fine on mainnet.
        MockHandleProofAdapter otherProdVerifier = _adapter(3, 3);
        AnonymousHandleRegistry mainnetRegistry =
            new AnonymousHandleRegistry(address(this), address(prodVerifier), address(otherProdVerifier));
        assertEq(address(mainnetRegistry.registerVerifier()), address(prodVerifier));
    }

    /// @notice The old gate named the two chains to reject, so a development
    ///         key deployed freely on every other value-bearing chain. Optimism
    ///         and Arbitrum are neither listed nor throwaway and must fail.
    function test_constructor_rejectsDevelopmentVerifierOnUnlistedValueChain() public {
        MockHandleProofAdapter devRegister = _adapter(1, 1);
        MockHandleProofAdapter devRotate = _adapter(2, 2);
        MockHandleVerifyingKey(devRegister.verifier()).setDevelopmentSetup(true);
        MockHandleVerifyingKey(devRotate.verifier()).setDevelopmentSetup(true);

        uint256[3] memory unlistedChains = [uint256(10), uint256(42161), uint256(137)];
        for (uint256 i = 0; i < unlistedChains.length; i++) {
            vm.chainId(unlistedChains[i]);
            vm.expectRevert(AnonymousHandleRegistry.DevelopmentVerifierOnProductionChain.selector);
            new AnonymousHandleRegistry(address(this), address(devRegister), address(devRotate));
        }

        // Base Sepolia is on the enumerated throwaway list and still deploys.
        vm.chainId(84532);
        AnonymousHandleRegistry testnetRegistry =
            new AnonymousHandleRegistry(address(this), address(devRegister), address(devRotate));
        assertEq(address(testnetRegistry.rotateVerifier()), address(devRotate));
    }

    /// @notice Register and rotate are distinct ceremonies over an identical IC
    ///         layout, so nothing structural catches one key wired into both
    ///         slots. The registry must.
    function test_constructor_rejectsSameVerifierForBothActions() public {
        MockHandleProofAdapter single = _adapter(1, 1);

        vm.expectRevert(AnonymousHandleRegistry.DuplicateVerifier.selector);
        new AnonymousHandleRegistry(address(this), address(single), address(single));
    }

    /// @notice One ceremony's verifying key deployed twice: two distinct key
    ///         addresses behind two distinct adapters, but the same key. Only
    ///         the key codehash gives it away.
    function test_constructor_rejectsOneKeyDeployedTwice() public {
        MockHandleProofAdapter registerAdapter = _adapter(7, 1);
        MockHandleProofAdapter rotateAdapter = _adapter(7, 2);
        assertTrue(registerAdapter.verifier() != rotateAdapter.verifier());
        assertEq(registerAdapter.verifier().codehash, rotateAdapter.verifier().codehash);

        vm.expectRevert(AnonymousHandleRegistry.DuplicateVerifier.selector);
        new AnonymousHandleRegistry(address(this), address(registerAdapter), address(rotateAdapter));
    }

    /// @notice The mock-level restatement of the real-adapter case below: one
    ///         key, two adapters whose codehashes differ. Independent of how
    ///         solc happens to lay out the two real adapters' metadata.
    function test_constructor_rejectsOneKeyBehindTwoDistinctAdapters() public {
        MockHandleVerifyingKey key = new MockHandleVerifyingKey(5);
        MockHandleProofAdapter registerAdapter = new MockHandleProofAdapter(address(key), 1);
        MockHandleProofAdapter rotateAdapter = new MockHandleProofAdapter(address(key), 2);
        assertTrue(address(registerAdapter).codehash != address(rotateAdapter).codehash);

        vm.expectRevert(AnonymousHandleRegistry.DuplicateVerifier.selector);
        new AnonymousHandleRegistry(address(this), address(registerAdapter), address(rotateAdapter));
    }

    /// @notice An adapter that reports a key with no code cannot be verified
    ///         against anything, so it must not be accepted merely because the
    ///         adapter itself has code.
    function test_constructor_rejectsAdapterWrappingACodelessKey() public {
        MockHandleProofAdapter hollow = new MockHandleProofAdapter(address(0xBEEF), 1);

        vm.expectRevert(AnonymousHandleRegistry.InvalidVerifier.selector);
        new AnonymousHandleRegistry(address(this), address(hollow), address(rotateVerifier));
    }

    /// @notice The registry slots hold ADAPTERS, not keys. The two adapter
    ///         types are byte-identical sources apart from their file paths, so
    ///         their deployed bytecode differs only in the trailing solc
    ///         metadata hash — a function of the path, not of the key. Two
    ///         adapters over the SAME verifying key therefore always differ in
    ///         both address and codehash, and this is the natural shape of the
    ///         misconfiguration: one key, one adapter of each type.
    function test_constructor_rejectsOneKeyBehindBothAdapterTypes() public {
        HandleRegisterVerifier key = new HandleRegisterVerifier();
        HandleRegisterProofAdapter registerAdapter = new HandleRegisterProofAdapter(address(key));
        HandleRotateProofAdapter rotateAdapter = new HandleRotateProofAdapter(address(key));

        // Precondition: nothing about the adapters themselves gives the pair
        // away, so a check that compares adapters cannot catch this.
        assertTrue(address(registerAdapter) != address(rotateAdapter));
        assertTrue(address(registerAdapter).codehash != address(rotateAdapter).codehash);
        assertEq(address(registerAdapter.verifier()), address(rotateAdapter.verifier()));

        vm.expectRevert(AnonymousHandleRegistry.DuplicateVerifier.selector);
        new AnonymousHandleRegistry(address(this), address(registerAdapter), address(rotateAdapter));
    }

    /// @notice Control for the check above: the shape
    ///         `DeployAnonymousHandleRegistry` actually produces — one key per
    ///         ceremony behind its own adapter — must still deploy. A check
    ///         that rejected this would pass every negative test and ship a
    ///         registry nobody can deploy.
    function test_constructor_acceptsTheRealDeploymentWiring() public {
        HandleRegisterProofAdapter registerAdapter =
            new HandleRegisterProofAdapter(address(new HandleRegisterVerifier()));
        HandleRotateProofAdapter rotateAdapter = new HandleRotateProofAdapter(address(new HandleRotateVerifier()));

        AnonymousHandleRegistry deployed =
            new AnonymousHandleRegistry(address(this), address(registerAdapter), address(rotateAdapter));
        assertEq(address(deployed.registerVerifier()), address(registerAdapter));
        assertEq(address(deployed.rotateVerifier()), address(rotateAdapter));
    }

    function test_constructor_rejectsCodelessVerifier() public {
        vm.expectRevert(AnonymousHandleRegistry.InvalidVerifier.selector);
        new AnonymousHandleRegistry(address(this), address(0xBEEF), address(rotateVerifier));
    }

    /// @notice The verifiers are the whole authorization surface, so the owner
    ///         must not be able to swap in an always-true one.
    /// @dev What has to be absent is the POWER, not a selector name: a call to
    ///      a signature that does not exist fails whether or not the power was
    ///      removed, so that assertion holds against the vulnerable contract
    ///      too and proves nothing. This drives the attempt AS THE OWNER — the
    ///      only actor a setter would ever have admitted — and then asserts the
    ///      outcome that a successful swap would have produced: the bound
    ///      verifier still governs, so a rejected proof stays rejected.
    function test_ownerCannotRepointVerifiersToAnAlwaysTrueKey() public {
        assertEq(registry.owner(), address(this));

        MockHandleProofAdapter alwaysTrue = _adapter(9, 9);
        // The bound key now rejects everything, so settling a handle requires
        // replacing it.
        registerKey.setResult(false);

        (bool setRegister,) =
            address(registry).call(abi.encodeWithSignature("setRegisterVerifier(address)", address(alwaysTrue)));
        assertFalse(setRegister);
        (bool setRotate,) =
            address(registry).call(abi.encodeWithSignature("setRotateVerifier(address)", address(alwaysTrue)));
        assertFalse(setRotate);
        (bool setBoth,) = address(registry).call(
            abi.encodeWithSignature("setVerifiers(address,address)", address(alwaysTrue), address(alwaysTrue))
        );
        assertFalse(setBoth);

        // The observable power: the originally bound verifiers still govern.
        assertEq(address(registry.registerVerifier()), address(registerVerifier));
        assertEq(address(registry.rotateVerifier()), address(rotateVerifier));

        uint256[8] memory proof;
        vm.expectRevert(AnonymousHandleRegistry.InvalidProof.selector);
        registry.registerAnonymous(
            keccak256("bob.stealth"), keccak256("record-v1"), keccak256("owner-bob"), proof, keccak256("n"), 1
        );
    }

    /// @notice The echidna harness is not exercised by `forge test`, so a
    ///         constructor it can no longer get through fails silently and the
    ///         fuzzing campaign quietly stops covering anything. Its stand-in
    ///         verifier has to satisfy the same interface the registry calls
    ///         during construction, on the default chain id the campaign runs
    ///         under — which is not one of the throwaway chains.
    function test_echidnaHarnessStillDeploysAndHoldsItsInvariants() public {
        vm.chainId(1);
        AnonymousHandleRegistryEchidna harness = new AnonymousHandleRegistryEchidna();

        harness.register(keccak256("h"), keccak256("r"), keccak256("o"), keccak256("n"), 1);
        assertEq(harness.lastHandleId(), keccak256("h"));
        assertTrue(harness.echidna_used_nullifier_cannot_register_again());
        assertTrue(harness.echidna_used_nullifier_cannot_rotate_again());
    }

    function test_registerAnonymous_success() public {
        bytes32 handleId = keccak256("bob.stealth");
        bytes32 commitment = keccak256("record-v1");
        bytes32 ownerCommitment = keccak256("owner-bob");
        bytes32 nullifier = keccak256("nullifier-register");
        uint256[8] memory proof;

        registry.registerAnonymous(handleId, commitment, ownerCommitment, proof, nullifier, 1);

        AnonymousHandleRegistry.HandleState memory state = registry.getHandleState(handleId);
        assertEq(state.recordCommitment, commitment);
        assertEq(state.ownerCommitment, ownerCommitment);
        assertEq(state.epoch, 1);
        assertTrue(state.exists);
        assertTrue(registry.usedNullifier(nullifier));
    }

    function test_rotateAnonymous_success() public {
        bytes32 handleId = keccak256("bob.stealth");
        bytes32 commitmentV1 = keccak256("record-v1");
        bytes32 commitmentV2 = keccak256("record-v2");
        bytes32 ownerCommitment = keccak256("owner-bob");
        bytes32 nullifierRegister = keccak256("nullifier-register");
        bytes32 nullifierRotate = keccak256("nullifier-rotate");
        uint256[8] memory proof;

        registry.registerAnonymous(handleId, commitmentV1, ownerCommitment, proof, nullifierRegister, 1);
        registry.rotateAnonymous(handleId, commitmentV2, ownerCommitment, proof, nullifierRotate, 2);

        AnonymousHandleRegistry.HandleState memory state = registry.getHandleState(handleId);
        assertEq(state.recordCommitment, commitmentV2);
        assertEq(state.ownerCommitment, ownerCommitment);
        assertEq(state.epoch, 2);
        assertTrue(state.exists);
        assertTrue(registry.usedNullifier(nullifierRotate));
    }

    function test_rotateAnonymous_rejects_wrong_owner_commitment() public {
        bytes32 handleId = keccak256("bob.stealth");
        bytes32 commitmentV1 = keccak256("record-v1");
        bytes32 commitmentV2 = keccak256("record-v2");
        bytes32 ownerCommitment = keccak256("owner-bob");
        bytes32 attackerOwnerCommitment = keccak256("owner-attacker");
        uint256[8] memory proof;

        registry.registerAnonymous(handleId, commitmentV1, ownerCommitment, proof, keccak256("n-register"), 1);

        vm.expectRevert(AnonymousHandleRegistry.OwnerCommitmentMismatch.selector);
        registry.rotateAnonymous(handleId, commitmentV2, attackerOwnerCommitment, proof, keccak256("n-attacker"), 2);
    }

    function test_reject_reused_nullifier() public {
        bytes32 handleIdA = keccak256("alice.stealth");
        bytes32 handleIdB = keccak256("bob.stealth");
        bytes32 commitment = keccak256("record-v1");
        bytes32 ownerCommitment = keccak256("owner");
        bytes32 nullifier = keccak256("same-nullifier");
        uint256[8] memory proof;

        registry.registerAnonymous(handleIdA, commitment, ownerCommitment, proof, nullifier, 1);

        vm.expectRevert(AnonymousHandleRegistry.NullifierAlreadyUsed.selector);
        registry.registerAnonymous(handleIdB, commitment, ownerCommitment, proof, nullifier, 1);
    }

    function test_reject_stale_epoch() public {
        bytes32 handleId = keccak256("bob.stealth");
        bytes32 commitment = keccak256("record-v1");
        bytes32 ownerCommitment = keccak256("owner-bob");
        uint256[8] memory proof;

        vm.expectRevert(AnonymousHandleRegistry.StaleEpoch.selector);
        registry.registerAnonymous(handleId, commitment, ownerCommitment, proof, keccak256("n1"), 0);

        registry.registerAnonymous(handleId, commitment, ownerCommitment, proof, keccak256("n2"), 1);

        vm.expectRevert(AnonymousHandleRegistry.StaleEpoch.selector);
        registry.rotateAnonymous(handleId, keccak256("record-v2"), ownerCommitment, proof, keccak256("n3"), 1);
    }

    function test_reject_invalid_proof() public {
        bytes32 handleId = keccak256("bob.stealth");
        bytes32 commitment = keccak256("record-v1");
        bytes32 ownerCommitment = keccak256("owner-bob");
        bytes32 nullifier = keccak256("n-register");
        uint256[8] memory proof;

        registerKey.setResult(false);
        vm.expectRevert(AnonymousHandleRegistry.InvalidProof.selector);
        registry.registerAnonymous(handleId, commitment, ownerCommitment, proof, nullifier, 1);
    }
}
