// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";
import {VantaFamilyUnifiedPoolPreAudit as Pool} from "./VantaFamilyUnifiedPoolPreAudit.sol";
import {VantaFamilyDirectDepositPoolPreAudit as SwapPool} from "./VantaFamilyDirectDepositPoolPreAudit.sol";
import {VantaFamilyChikyuRouteEscrow, IFamilyMuchFiRouter, IFamilyRoutePool} from "./VantaFamilyChikyuRouteGatewayPreAudit.sol";

contract VantaFamilyPrivateSwapOutputEscrow {
    using SafeERC20 for IERC20;
    address private immutable factory = msg.sender;
    error InvalidOutputDeposit();

    receive() external payable {}

    function deposit(address pool, address asset, uint256 gross, address relayer, uint128 reimbursement, bytes calldata data) external returns (uint256 checkpoint) {
        if (msg.sender != factory) revert InvalidOutputDeposit();
        uint256 beforeBalance = asset == address(0) ? address(this).balance : IERC20(asset).balanceOf(address(this));
        if (gross == 0 || gross + reimbursement > beforeBalance) revert InvalidOutputDeposit();
        if (reimbursement != 0) {
            if (asset == address(0)) {
                (bool paid,) = payable(relayer).call{value: reimbursement}("");
                if (!paid) revert InvalidOutputDeposit();
            } else {
                uint256 beforeRelayer = IERC20(asset).balanceOf(relayer);
                IERC20(asset).safeTransfer(relayer, reimbursement);
                if (IERC20(asset).balanceOf(relayer) != beforeRelayer + reimbursement) revert InvalidOutputDeposit();
            }
        }
        if (asset != address(0)) IERC20(asset).forceApprove(pool, gross);
        (bool ok, bytes memory result) = pool.call{value: asset == address(0) ? gross : 0}(data);
        if (!ok) assembly ("memory-safe") { revert(add(result, 32), mload(result)) }
        if (asset != address(0)) IERC20(asset).forceApprove(pool, 0);
        uint256 afterBalance = asset == address(0) ? address(this).balance : IERC20(asset).balanceOf(address(this));
        if (result.length != 32 || afterBalance != beforeBalance - gross - reimbursement) revert InvalidOutputDeposit();
        checkpoint = abi.decode(result, (uint256));
    }
}

/// Exact private-source swap followed by a private output claim. The first
/// transaction pays the configured swap fees. The second cannot accept ordinary
/// deposits: only the measured DEX output of a genuine source proof is credited.
/// No EOA signature, partner authorization server or second deposit fee exists.
contract VantaFamilyPrivateSwapOutput is VantaFamilyReleaseBinding, ReentrancyGuard {
    struct Config {
        address nativePool; address usdcPool; address muchFi; address wrappedDoge; address usdc;
        bytes32 genesisHash; bytes32 setupId; bytes32 generationId; bytes32 familyTag; uint256 chainId;
    }
    struct Route {
        uint8 operation; address sourcePool; address sourceAsset; address payer; address receiver;
        uint128 amount; uint128 minimumOutput; uint64 deadline; bytes32 nonce; uint256 maximumDeliveryFee;
        address outputPool; address owner; bytes32 salt;
    }
    struct Credit {
        address pool; address owner; bytes32 salt; uint128 amount; bool claimed;
    }
    bytes32 private constant ESCROW_DOMAIN = keccak256("STEALTHOS_FAMILY_PRIVATE_SWAP_OUTPUT_V1");
    bytes32 private constant ROUTE_DOMAIN = keccak256("STEALTHOS_FAMILY_PRIVATE_SWAP_ROUTE_V1");
    bytes32 private constant CLAIM_TYPEHASH = keccak256(
        "PrivateSwapOutput(bytes32 creditId,uint256 nonce,uint64 deadline,address relayer,uint128 reimbursement,bytes32 depositHash)"
    );
    bytes32 private immutable CLAIM_DOMAIN;
    address public immutable escrowImplementation;
    bytes32 public immutable escrowCodehash;
    bytes32 public immutable releaseGenesisHash;
    address public immutable nativePool; address public immutable usdcPool;
    address public immutable muchFi; address public immutable wrappedDoge; address public immutable usdc;
    bytes32 public immutable muchFiCodehash; bytes32 public immutable wrappedDogeCodehash; bytes32 public immutable usdcCodehash;
    mapping(address => bytes32) public poolCodeHash;
    mapping(address => address) public poolAsset;
    mapping(bytes32 => Credit) public credits;
    mapping(bytes32 => mapping(uint256 => bool)) public usedNonce;
    address private activeEscrow; address private activePool; bytes32 private activeDataHash;
    error InvalidOutputDeposit();
    error InvalidRoute();
    event RoutedSettlement(bytes32 indexed quoteNonce,bytes32 indexed routeHash,address indexed sourcePool,
        uint8 operation,address receiver,uint256 inputAmount,uint256 outputAmount,bytes32 messageId,uint256 deliveryFee);
    event PrivateSwapOutputReady(bytes32 indexed creditId,address indexed pool,address indexed owner,
        bytes32 salt,address escrow,uint128 amount,bytes32 sourceNonce);
    event PrivateSwapOutputDeposited(address indexed escrow,address indexed pool,bytes32 indexed depositNonce,
        uint256 gross,uint128 reimbursement,uint256 checkpoint,bytes32 depositHash);

    constructor(Config memory c) VantaFamilyReleaseBinding(c.setupId,c.generationId,c.familyTag,c.chainId) {
        CLAIM_DOMAIN=keccak256(abi.encode(keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("StealthOS Private Swap Output"),keccak256("2"),block.chainid,address(this)));
        if (c.chainId != 6281971 || c.genesisHash == bytes32(0) || c.nativePool == c.usdcPool ||
            c.muchFi.code.length == 0 || c.wrappedDoge.code.length == 0 || c.usdc.code.length == 0 ||
            IFamilyMuchFiRouter(c.muchFi).WETH() != c.wrappedDoge) revert InvalidOutputDeposit();
        address[2] memory pools = [c.nativePool,c.usdcPool];
        address[2] memory assets = [address(0),c.usdc];
        for (uint256 i; i < 2; ++i) {
            address pool=pools[i]; IFamilyRoutePool p=IFamilyRoutePool(pool);
            if (pool.code.length == 0 || p.asset() != assets[i] || p.releaseSetupId()!=c.setupId ||
                p.releaseGenerationId()!=c.generationId || p.releaseFamilyTag()!=c.familyTag || p.releaseChainId()!=c.chainId ||
                p.releaseGenesisHash()!=c.genesisHash)
                revert InvalidOutputDeposit();
            poolCodeHash[pool]=pool.codehash; poolAsset[pool]=assets[i];
        }
        nativePool=c.nativePool; usdcPool=c.usdcPool; muchFi=c.muchFi; wrappedDoge=c.wrappedDoge; usdc=c.usdc;
        muchFiCodehash=c.muchFi.codehash; wrappedDogeCodehash=c.wrappedDoge.codehash; usdcCodehash=c.usdc.codehash;
        releaseGenesisHash=c.genesisHash;
        escrowImplementation=address(new VantaFamilyPrivateSwapOutputEscrow());
        escrowCodehash=escrowImplementation.codehash;
    }
    function predictEscrow(address pool,address owner,bytes32 salt) public view returns(address) {
        bytes32 derived=keccak256(abi.encode(ESCROW_DOMAIN,block.chainid,address(this),pool,owner,salt));
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff),address(this),derived,keccak256(_escrowInit()))))));
    }
    // EIP-1167 minimal proxy; these exact bytes are also pinned by the SDK.
    // No immutable-argument extension or Cancun-only instructions are used.
    function _escrowInit() private view returns(bytes memory) {
        return abi.encodePacked(hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",escrowImplementation,hex"5af43d82803e903d91602b57fd5bf3");
    }
    function routeHash(Route calldata r) public view returns(bytes32) {
        return keccak256(abi.encode(ROUTE_DOMAIN,block.chainid,address(this),r));
    }
    function predictFundingEscrow(Route calldata r) public view returns(address) {
        bytes32 init=keccak256(abi.encodePacked(type(VantaFamilyChikyuRouteEscrow).creationCode,
            abi.encode(r.sourcePool,r.sourceAsset,muchFi,address(0),wrappedDoge,usdc,address(0))));
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff),address(this),routeHash(r),init)))));
    }
    function _check(Pool.NormalEpochQuote calldata q,Route calldata r) private view {
        if (r.operation!=4 || r.payer!=msg.sender || r.owner==address(0) || r.salt==bytes32(0) || r.amount==0 ||
            r.minimumOutput==0 || r.deadline<block.timestamp || r.deadline>block.timestamp+3600 || r.nonce==bytes32(0) ||
            r.maximumDeliveryFee!=0 || q.chainId!=block.chainid || q.pool!=r.sourcePool || q.asset!=r.sourceAsset ||
            q.mode!=4 || q.payout!=r.amount || q.deadline!=r.deadline || q.nonce!=r.nonce || q.relayer!=address(this) ||
            q.recipient!=predictFundingEscrow(r) || q.recipient.code.length!=0 ||
            r.receiver!=predictEscrow(r.outputPool,r.owner,r.salt) || poolCodeHash[r.sourcePool]==bytes32(0) ||
            r.sourcePool.codehash!=poolCodeHash[r.sourcePool] || r.outputPool.codehash!=poolCodeHash[r.outputPool] ||
            !((r.sourcePool==nativePool && r.sourceAsset==address(0) && r.outputPool==usdcPool) ||
              (r.sourcePool==usdcPool && r.sourceAsset==usdc && r.outputPool==nativePool)) ||
            muchFi.codehash!=muchFiCodehash || wrappedDoge.codehash!=wrappedDogeCodehash || usdc.codehash!=usdcCodehash)
            revert InvalidRoute();
    }
    function _fund(Route calldata r) private returns(VantaFamilyChikyuRouteEscrow) {
        return new VantaFamilyChikyuRouteEscrow{salt:routeHash(r)}(r.sourcePool,r.sourceAsset,muchFi,address(0),wrappedDoge,usdc,address(0));
    }
    function _finish(Route calldata r,VantaFamilyChikyuRouteEscrow funding) private {
        uint256 amount=funding.swap(r.receiver,r.amount,r.minimumOutput,r.deadline);
        bytes32 creditId=routeHash(r);
        if (amount==0 || amount>type(uint128).max || credits[creditId].amount!=0) revert InvalidRoute();
        credits[creditId]=Credit(r.outputPool,r.owner,r.salt,uint128(amount),false);
        emit RoutedSettlement(r.nonce,creditId,r.sourcePool,4,r.receiver,r.amount,amount,bytes32(0),0);
        emit PrivateSwapOutputReady(creditId,r.outputPool,r.owner,r.salt,r.receiver,uint128(amount),r.nonce);
    }
    function execute8(Pool.NormalEpochQuote calldata q,Pool.EpochSpend8 calldata p,bytes calldata signature,Route calldata r)
        external nonReentrant onlyReleaseChain {
        _check(q,r); if(q.width!=8)revert InvalidRoute();
        VantaFamilyChikyuRouteEscrow funding=_fund(r);
        Pool(payable(r.sourcePool)).settleNormalEpoch8(q,p,signature); _finish(r,funding);
    }
    function execute32(Pool.NormalEpochQuote calldata q,Pool.EpochSpend32 calldata p,bytes calldata signature,Route calldata r)
        external nonReentrant onlyReleaseChain {
        _check(q,r); if(q.width!=32)revert InvalidRoute();
        VantaFamilyChikyuRouteEscrow funding=_fund(r);
        Pool(payable(r.sourcePool)).settleNormalEpoch32(q,p,signature); _finish(r,funding);
    }
    function claimDigest(bytes32 creditId,uint256 nonce,uint64 deadline,address relayer,uint128 reimbursement,bytes32 depositHash)
        public view returns(bytes32) {
        return keccak256(abi.encodePacked(hex"1901",CLAIM_DOMAIN,keccak256(abi.encode(CLAIM_TYPEHASH,creditId,nonce,deadline,relayer,reimbursement,depositHash))));
    }
    /// @notice Initial admission gate; exact calldata is independently checked by the pool.
    function isActiveIngressEscrow(address escrow,address pool) external view returns(bool) {
        return escrow==activeEscrow && pool==activePool && activeEscrow!=address(0);
    }
    function isActiveIngress(address escrow,address pool,bytes32 dataHash) external view returns(bool) {
        return escrow==activeEscrow && pool==activePool && dataHash==activeDataHash && activeEscrow!=address(0);
    }
    function claim(bytes32 creditId,uint256 nonce,uint64 deadline,address relayer,uint128 reimbursement,
        bytes calldata depositData,bytes calldata ownerSignature) external nonReentrant onlyReleaseChain returns(uint256 checkpoint) {
        Credit storage c=credits[creditId];
        if (c.amount==0 || c.claimed || relayer!=msg.sender || usedNonce[creditId][nonce] || deadline<block.timestamp ||
            deadline>block.timestamp+3600 || c.pool.codehash!=poolCodeHash[c.pool] ||
            depositData.length<4 || bytes4(depositData[:4])!=SwapPool.depositWithPrivateFeeNotes.selector ||
            ECDSA.recover(claimDigest(creditId,nonce,deadline,relayer,reimbursement,keccak256(depositData)),ownerSignature)!=c.owner)
            revert InvalidOutputDeposit();
        // The pool decodes and validates all row-key, clearance and envelope bytes.
        // The first quote tuple is static; the pool validates every dynamic field.
        Pool.PrivateFeeDepositQuote memory q=abi.decode(depositData[4:],(Pool.PrivateFeeDepositQuote));
        if (q.nonce!=creditId || q.pool!=c.pool || q.asset!=poolAsset[c.pool] || q.payer!=predictEscrow(c.pool,c.owner,c.salt) || q.count!=1 || q.protocolFeeCap!=0 || q.partnerFeeCap!=0 || q.gross==0 || uint256(q.gross)+reimbursement!=c.amount || q.deadline>deadline)
            revert InvalidOutputDeposit();
        address escrow=predictEscrow(c.pool,c.owner,c.salt);
        c.claimed=true; usedNonce[creditId][nonce]=true;
        if (escrow.code.length==0) {
            bytes memory init=_escrowInit();
            bytes32 derived=keccak256(abi.encode(ESCROW_DOMAIN,block.chainid,address(this),c.pool,c.owner,c.salt));
            address created;
            assembly("memory-safe"){created:=create2(0,add(init,32),mload(init),derived)}
            if(created!=escrow)revert InvalidOutputDeposit();
        }
        if (escrowImplementation.codehash!=escrowCodehash)revert InvalidOutputDeposit();
        activeEscrow=escrow; activePool=c.pool; activeDataHash=keccak256(depositData);
        checkpoint=VantaFamilyPrivateSwapOutputEscrow(payable(escrow)).deposit(c.pool,poolAsset[c.pool],q.gross,relayer,reimbursement,depositData);
        delete activeEscrow; delete activePool; delete activeDataHash;
        emit PrivateSwapOutputDeposited(escrow,c.pool,q.nonce,q.gross,reimbursement,checkpoint,keccak256(depositData));
    }
}
