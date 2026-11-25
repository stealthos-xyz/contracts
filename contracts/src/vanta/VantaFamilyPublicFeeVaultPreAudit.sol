// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface IVantaFamilyVaultRegistrar {
    function releaseSetupId() external view returns (bytes32);
    function releaseGenerationId() external view returns (bytes32);
    function releaseFamilyTag() external view returns (bytes32);
    function releaseChainId() external view returns (uint256);
    function releaseGenesisHash() external view returns (bytes32);
    function canonicalToken() external view returns (address);
}

/// @notice Family-bound adaptation of the existing owner-proof public fee vault.
/// @dev Receives only public emergency-exit fees. The pinned registrar must
/// verify a genuine handle-owner proof before release. No EOA controller,
/// mutable owner, recovery bypass or new authorization is introduced.
contract VantaFamilyPublicFeeVaultPreAudit {
    using SafeERC20 for IERC20;

    address public immutable registrar;
    bytes32 public immutable registrarCodehash;
    address public immutable asset;
    bytes32 public immutable assetCodehash;
    uint8 public immutable role;
    bytes32 public immutable releaseSetupId;
    bytes32 public immutable releaseGenerationId;
    bytes32 public immutable releaseFamilyTag;
    uint256 public immutable releaseChainId;
    bytes32 public immutable releaseGenesisHash;

    error Unauthorized();
    error InvalidPayout();

    constructor(address registrar_, address asset_, uint8 role_) {
        if (registrar_.code.length == 0 || role_ != 0 ||
            (asset_ != address(0) && asset_.code.length == 0)) revert Unauthorized();
        IVantaFamilyVaultRegistrar r = IVantaFamilyVaultRegistrar(registrar_);
        uint256 chain = r.releaseChainId();
        if (chain == 0 || block.chainid != chain ||
            r.releaseSetupId() == bytes32(0) || r.releaseGenerationId() == bytes32(0) ||
            r.releaseFamilyTag() == bytes32(0) || r.releaseGenesisHash() == bytes32(0) ||
            (asset_ != address(0) && r.canonicalToken() != asset_)) revert Unauthorized();
        registrar = registrar_;
        registrarCodehash = registrar_.codehash;
        asset = asset_;
        assetCodehash = asset_ == address(0) ? bytes32(0) : asset_.codehash;
        role = role_;
        releaseSetupId = r.releaseSetupId();
        releaseGenerationId = r.releaseGenerationId();
        releaseFamilyTag = r.releaseFamilyTag();
        releaseChainId = chain;
        releaseGenesisHash = r.releaseGenesisHash();
    }

    receive() external payable {
        if (asset != address(0) || block.chainid != releaseChainId) revert InvalidPayout();
    }

    function release(address payable recipient, uint256 amount) external {
        if (msg.sender != registrar || registrar.codehash != registrarCodehash ||
            block.chainid != releaseChainId) revert Unauthorized();
        if (recipient == address(0) || recipient == address(this) || amount == 0) revert InvalidPayout();
        if (asset == address(0)) {
            (bool paid,) = recipient.call{value: amount}("");
            if (!paid) revert InvalidPayout();
        } else {
            if (asset.codehash != assetCodehash) revert InvalidPayout();
            IERC20 token = IERC20(asset);
            uint256 beforeRecipient = token.balanceOf(recipient);
            uint256 beforeVault = token.balanceOf(address(this));
            token.safeTransfer(recipient, amount);
            if (token.balanceOf(recipient) != beforeRecipient + amount ||
                token.balanceOf(address(this)) + amount != beforeVault) revert InvalidPayout();
        }
    }
}
