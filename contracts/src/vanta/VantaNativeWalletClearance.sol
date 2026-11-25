// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";

/// @notice Reusable clearance issued by StealthOS's native screening engine.
/// No transaction quote, partner credential, proof witness or funds pass here.
contract VantaNativeWalletClearance is VantaFamilyReleaseBinding {
    struct Clearance {
        address wallet;
        uint64 validAfter;
        uint64 validUntil;
        uint64 walletRevision;
        uint64 policyRevision;
    }
    bytes32 public constant CLEARANCE_TYPEHASH = keccak256(
        "NativeWalletClearance(address wallet,uint64 validAfter,uint64 validUntil,uint64 walletRevision,uint64 policyRevision,bytes32 policyHash)"
    );
    uint64 public constant MAX_VALIDITY = 3600;
    address public immutable administrator;
    bytes32 public immutable policyHash;
    address public signer;
    uint64 public policyRevision = 1;
    mapping(address => uint64) public walletRevision;
    bytes32 private immutable domainSeparator;

    error InvalidClearance();
    error Unauthorized();
    event WalletInvalidated(address indexed wallet, uint64 revision);
    event SignerChanged(address indexed signer, uint64 revision);

    constructor(address administrator_, address signer_, bytes32 policyHash_,
        bytes32 setupId, bytes32 generationId, bytes32 familyTag, uint256 chainId)
        VantaFamilyReleaseBinding(setupId, generationId, familyTag, chainId)
    {
        if (administrator_ == address(0) || signer_ == address(0) || policyHash_ == bytes32(0)) revert InvalidClearance();
        administrator = administrator_;
        signer = signer_;
        policyHash = policyHash_;
        domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("StealthOS Native Screening"), keccak256("1"), chainId, address(this)
        ));
    }

    function clearanceDigest(Clearance memory c) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator,
            keccak256(abi.encode(CLEARANCE_TYPEHASH, c.wallet, c.validAfter,
                c.validUntil, c.walletRevision, c.policyRevision, policyHash))));
    }

    function requireClearance(address payer, bytes calldata encoded) external view onlyReleaseChain {
        // Strict encoding keeps unbounded or ambiguous admission data out.
        if (encoded.length != 320) revert InvalidClearance();
        (Clearance memory c, bytes memory signature) = abi.decode(encoded, (Clearance, bytes));
        if (payer == address(0) || c.wallet != payer || c.validAfter > block.timestamp ||
            c.validUntil <= block.timestamp || c.validUntil <= c.validAfter ||
            c.validUntil - c.validAfter > MAX_VALIDITY ||
            c.walletRevision != walletRevision[payer] || c.policyRevision != policyRevision ||
            signature.length != 65 || keccak256(encoded) != keccak256(abi.encode(c, signature)) ||
            ECDSA.recover(clearanceDigest(c), signature) != signer) revert InvalidClearance();
    }

    function invalidateWallet(address wallet) external onlyReleaseChain {
        if (msg.sender != administrator) revert Unauthorized();
        if (wallet == address(0)) revert InvalidClearance();
        emit WalletInvalidated(wallet, ++walletRevision[wallet]);
    }

    function changeSigner(address next) external onlyReleaseChain {
        if (msg.sender != administrator) revert Unauthorized();
        if (next == address(0)) revert InvalidClearance();
        signer = next;
        emit SignerChanged(next, ++policyRevision);
    }
}
