// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Future deployments only. Pool, registry and bootstrap contracts for a
 * family-scoped ceremony must inherit this binding and use its guard on
 * every state-changing path. Existing signed Base Sepolia pools are unchanged.
 *
 * The paired proof verifier must constrain the public FAMILY_TAG to the
 * constant compiled into its R1CS and bind the public chainId to this value.
 * Neither an RPC URL nor a mutable administrator can change this release.
 */
abstract contract VantaFamilyReleaseBinding {
    bytes32 public immutable releaseSetupId;
    bytes32 public immutable releaseGenerationId;
    bytes32 public immutable releaseFamilyTag;
    // A concrete pool already inherits approvedChainId from the pinned
    // epoch ledger. Keep this independent name to avoid shadowing it.
    uint256 public immutable releaseChainId;

    error InvalidFamilyRelease();
    error WrongFamilyNetwork();

    constructor(
        bytes32 setupId_,
        bytes32 generationId_,
        bytes32 familyTag_,
        uint256 chainId_
    ) {
        if (setupId_ == bytes32(0) || generationId_ == bytes32(0) ||
            familyTag_ == bytes32(0) || chainId_ == 0) {
            revert InvalidFamilyRelease();
        }
        if (block.chainid != chainId_) revert WrongFamilyNetwork();
        releaseSetupId = setupId_;
        releaseGenerationId = generationId_;
        releaseFamilyTag = familyTag_;
        releaseChainId = chainId_;
    }

    modifier onlyReleaseChain() {
        if (block.chainid != releaseChainId) revert WrongFamilyNetwork();
        _;
    }

    function _requireRelease(
        bytes32 setupId_,bytes32 generationId_,bytes32 familyTag_
    ) internal view {
        if (setupId_ != releaseSetupId ||
            generationId_ != releaseGenerationId ||
            familyTag_ != releaseFamilyTag) {
            revert InvalidFamilyRelease();
        }
    }
}
