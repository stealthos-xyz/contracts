// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";

interface IVantaFamilyBootstrapIdentity {
    function releaseSetupId() external view returns (bytes32);
    function releaseGenerationId() external view returns (bytes32);
    function releaseFamilyTag() external view returns (bytes32);
    function releaseChainId() external view returns (uint256);
}

interface IVantaFamilyBootstrapPool is IVantaFamilyBootstrapIdentity {
    function asset() external view returns (address);
}

interface IVantaFamilyBootstrapRegistry is IVantaFamilyBootstrapIdentity {
    function activePoolForAsset(address asset) external view returns (address);
}

/// @notice Immutable, per-generation deployment anchor. PRE-AUDIT only.
/// @dev Deploy after registering the pool in its generation-bound registry.
///      This contract never owns funds, signs operations, or controls exits.
contract VantaFamilyBootstrapPreAudit is VantaFamilyReleaseBinding {
    address public immutable pool;
    address public immutable registry;
    address public immutable asset;
    bytes32 public immutable poolCodehash;
    bytes32 public immutable registryCodehash;
    bytes32 public immutable relayerConfigSha256;

    error InvalidBootstrapGraph();

    constructor(
        address pool_,
        address registry_,
        address asset_,
        bytes32 relayerConfigSha256_,
        bytes32 setupId_,
        bytes32 generationId_,
        bytes32 familyTag_,
        uint256 chainId_
    ) VantaFamilyReleaseBinding(setupId_, generationId_, familyTag_, chainId_) {
        if (
            pool_ == registry_ || pool_.code.length == 0 || registry_.code.length == 0
                || relayerConfigSha256_ == bytes32(0)
        ) {
            revert InvalidBootstrapGraph();
        }
        pool = pool_;
        registry = registry_;
        asset = asset_;
        poolCodehash = pool_.codehash;
        registryCodehash = registry_.codehash;
        relayerConfigSha256 = relayerConfigSha256_;
        _requireGraph();
    }

    /// @notice Check the complete linked graph at its current chain state.
    /// @dev Independent reviewers must additionally compare all deployed
    ///      runtime bytecode against separately derived, signed release pins.
    function assertGraph() external view onlyReleaseChain returns (bool) {
        _requireGraph();
        return true;
    }

    function _requireGraph() private view {
        if (
            pool.codehash != poolCodehash || registry.codehash != registryCodehash
                || IVantaFamilyBootstrapPool(pool).asset() != asset
                || IVantaFamilyBootstrapRegistry(registry).activePoolForAsset(asset) != pool
        ) {
            revert InvalidBootstrapGraph();
        }
        _requireIdentity(pool);
        _requireIdentity(registry);
    }

    function _requireIdentity(address target) private view {
        IVantaFamilyBootstrapIdentity identity = IVantaFamilyBootstrapIdentity(target);
        if (
            identity.releaseSetupId() != releaseSetupId || identity.releaseGenerationId() != releaseGenerationId
                || identity.releaseFamilyTag() != releaseFamilyTag || identity.releaseChainId() != releaseChainId
        ) {
            revert InvalidBootstrapGraph();
        }
    }
}
