// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";
import {VantaFamilyUnifiedPoolPreAudit as Pool} from "./VantaFamilyUnifiedPoolPreAudit.sol";

interface IFamilyMuchFiRouter {
 function WETH() external view returns(address);
 function swapExactETHForTokens(uint256,address[] calldata,address,uint256) external payable returns(uint256[] memory);
 function swapExactTokensForETH(uint256,uint256,address[] calldata,address,uint256) external returns(uint256[] memory);
}
struct FamilyCcipTokenAmount {address token;uint256 amount;}
struct FamilyCcipMessage {bytes receiver;bytes data;FamilyCcipTokenAmount[] tokenAmounts;address feeToken;bytes extraArgs;}
interface IFamilyCcipRouter {
 function isChainSupported(uint64) external view returns(bool);
 function getFee(uint64,FamilyCcipMessage calldata) external view returns(uint256);
 function ccipSend(uint64,FamilyCcipMessage calldata) external payable returns(bytes32);
}
interface IFamilyRoutePool {
 function asset() external view returns(address);
 function releaseSetupId() external view returns(bytes32);
 function releaseGenerationId() external view returns(bytes32);
 function releaseFamilyTag() external view returns(bytes32);
 function releaseChainId() external view returns(uint256);
 function releaseGenesisHash() external view returns(bytes32);
}

/// @dev Single-use immutable escrow. A venue failure reverts its creation,
/// the genuine source-pool settlement, fee notes and nullifiers atomically.
contract VantaFamilyChikyuRouteEscrow {
 using SafeERC20 for IERC20;
 address public immutable gateway;address public immutable sourcePool;address public immutable sourceAsset;
 address public immutable muchFi;address public immutable ccip;address public immutable wrappedDoge;
 address public immutable usdc;address public immutable bnm;bool public used;
 error InvalidExecution();
 constructor(address pool,address asset,address swapRouter,address bridgeRouter,address wrapped,address swapToken,address bridgeToken){
  gateway=msg.sender;sourcePool=pool;sourceAsset=asset;muchFi=swapRouter;ccip=bridgeRouter;wrappedDoge=wrapped;usdc=swapToken;bnm=bridgeToken;
 }
 receive() external payable {if(msg.sender!=sourcePool&&msg.sender!=muchFi)revert InvalidExecution();}
 modifier once(){if(msg.sender!=gateway||used)revert InvalidExecution();used=true;_;}
 function swap(address receiver,uint128 amount,uint128 minimum,uint64 deadline) external once returns(uint256 received){
  address[] memory path=new address[](2);uint256[] memory amounts;
  if(sourceAsset==address(0)){
   if(address(this).balance<amount)revert InvalidExecution();path[0]=wrappedDoge;path[1]=usdc;
   uint256 beforeBalance=IERC20(usdc).balanceOf(receiver);
   amounts=IFamilyMuchFiRouter(muchFi).swapExactETHForTokens{value:amount}(minimum,path,receiver,deadline);
   if(amounts.length!=2||IERC20(usdc).balanceOf(receiver)-beforeBalance!=amounts[1])revert InvalidExecution();
  }else{
   if(sourceAsset!=usdc||IERC20(usdc).balanceOf(address(this))<amount)revert InvalidExecution();
   path[0]=usdc;path[1]=wrappedDoge;IERC20(usdc).forceApprove(muchFi,amount);uint256 beforeBalance=receiver.balance;
   amounts=IFamilyMuchFiRouter(muchFi).swapExactTokensForETH(amount,minimum,path,receiver,deadline);
   IERC20(usdc).forceApprove(muchFi,0);
   if(amounts.length!=2||receiver.balance-beforeBalance!=amounts[1])revert InvalidExecution();
  }
  if(amounts[0]!=amount||amounts[1]<minimum)revert InvalidExecution();return amounts[1];
 }
 function bridge(address receiver,address refund,uint128 amount,uint256 maximumFee) external payable once returns(bytes32 messageId,uint256 fee){
  if(sourceAsset!=bnm||IERC20(bnm).balanceOf(address(this))<amount)revert InvalidExecution();
  FamilyCcipTokenAmount[] memory tokens=new FamilyCcipTokenAmount[](1);tokens[0]=FamilyCcipTokenAmount(bnm,amount);
  FamilyCcipMessage memory message=FamilyCcipMessage(abi.encode(receiver),"",tokens,address(0),
   abi.encodePacked(bytes4(0x181dcf10),abi.encode(uint256(0),true)));
  fee=IFamilyCcipRouter(ccip).getFee(16015286601757825753,message);
  if(fee>maximumFee||msg.value<fee)revert InvalidExecution();
  IERC20(bnm).forceApprove(ccip,amount);
  messageId=IFamilyCcipRouter(ccip).ccipSend{value:fee}(16015286601757825753,message);IERC20(bnm).forceApprove(ccip,0);
  if(messageId==bytes32(0))revert InvalidExecution();
  if(msg.value>fee){(bool ok,)=payable(refund).call{value:msg.value-fee}("");if(!ok)revert InvalidExecution();}
 }
}

/// @notice Chikyu private-source swaps and CCIP bridging to public recipients.
/// This pre-audit testnet integration reuses the existing ceremony relations.
/// There is no generic target/call executor, upgrade hook or alternate verifier.
contract VantaFamilyChikyuRouteGatewayPreAudit is ReentrancyGuard,VantaFamilyReleaseBinding {
 struct Config {
  address nativePool;address usdcPool;address bnmPool;address muchFi;address ccip;address wrappedDoge;address usdc;address bnm;
  uint256 maximumDeliveryFee;bytes32 genesisHash;bytes32 setupId;bytes32 generationId;bytes32 familyTag;uint256 chainId;
 }
 struct Route {
  uint8 operation;address sourcePool;address sourceAsset;address payer;address receiver;uint128 amount;
  uint128 minimumOutput;uint64 deadline;bytes32 nonce;uint256 maximumDeliveryFee;
 }
 address public immutable nativePool;address public immutable usdcPool;address public immutable bnmPool;
 address public immutable muchFi;address public immutable ccip;address public immutable wrappedDoge;address public immutable usdc;address public immutable bnm;
 bytes32 public immutable nativePoolCodehash;bytes32 public immutable usdcPoolCodehash;bytes32 public immutable bnmPoolCodehash;
 bytes32 public immutable muchFiCodehash;bytes32 public immutable ccipCodehash;bytes32 public immutable wrappedDogeCodehash;bytes32 public immutable usdcCodehash;bytes32 public immutable bnmCodehash;
 bytes32 public immutable releaseGenesisHash;
 uint256 public immutable maximumDeliveryFee;
 bytes32 private constant ROUTE_DOMAIN=keccak256("STEALTHOS_FAMILY_CHIKYU_PUBLIC_ROUTE_V1");
 event RoutedSettlement(bytes32 indexed quoteNonce,bytes32 indexed routeHash,address indexed sourcePool,uint8 operation,address receiver,uint256 inputAmount,uint256 outputAmount,bytes32 messageId,uint256 deliveryFee);
 error InvalidRoute();error InvalidSetup();
 constructor(Config memory c) VantaFamilyReleaseBinding(c.setupId,c.generationId,c.familyTag,c.chainId){
  if(c.chainId!=6281971||c.maximumDeliveryFee==0||c.maximumDeliveryFee>100 ether||c.genesisHash==bytes32(0)||
   c.muchFi.code.length==0||c.ccip.code.length==0||c.wrappedDoge.code.length==0||c.usdc.code.length==0||c.bnm.code.length==0||
   c.usdc==c.bnm||c.nativePool==c.usdcPool||c.nativePool==c.bnmPool||c.usdcPool==c.bnmPool||
   IFamilyMuchFiRouter(c.muchFi).WETH()!=c.wrappedDoge||!IFamilyCcipRouter(c.ccip).isChainSupported(16015286601757825753))revert InvalidSetup();
  address[3] memory pools=[c.nativePool,c.usdcPool,c.bnmPool];address[3] memory assets=[address(0),c.usdc,c.bnm];
  for(uint256 i;i<3;i++){
   IFamilyRoutePool p=IFamilyRoutePool(pools[i]);if(pools[i].code.length==0||p.asset()!=assets[i]||p.releaseSetupId()!=c.setupId||
    p.releaseGenerationId()!=c.generationId||p.releaseFamilyTag()!=c.familyTag||p.releaseChainId()!=c.chainId||p.releaseGenesisHash()!=c.genesisHash)revert InvalidSetup();
  }
  nativePool=c.nativePool;usdcPool=c.usdcPool;bnmPool=c.bnmPool;muchFi=c.muchFi;ccip=c.ccip;wrappedDoge=c.wrappedDoge;usdc=c.usdc;bnm=c.bnm;
  maximumDeliveryFee=c.maximumDeliveryFee;releaseGenesisHash=c.genesisHash;nativePoolCodehash=c.nativePool.codehash;usdcPoolCodehash=c.usdcPool.codehash;bnmPoolCodehash=c.bnmPool.codehash;
  muchFiCodehash=c.muchFi.codehash;ccipCodehash=c.ccip.codehash;wrappedDogeCodehash=c.wrappedDoge.codehash;usdcCodehash=c.usdc.codehash;bnmCodehash=c.bnm.codehash;
 }
 function routeHash(Route calldata r) public view returns(bytes32){return keccak256(abi.encode(ROUTE_DOMAIN,block.chainid,address(this),r));}
 function _init(Route calldata r) private view returns(bytes memory){return abi.encodePacked(type(VantaFamilyChikyuRouteEscrow).creationCode,
  abi.encode(r.sourcePool,r.sourceAsset,muchFi,ccip,wrappedDoge,usdc,bnm));}
 function predictEscrow(Route calldata r) public view returns(address){return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff),address(this),routeHash(r),keccak256(_init(r)))))));}
 function _check(Pool.NormalEpochQuote calldata q,Route calldata r) private view {
  if(r.payer!=msg.sender||r.receiver==address(0)||r.receiver==r.sourcePool||r.receiver==address(this)||r.receiver==q.recipient||
   r.amount==0||r.minimumOutput==0||r.deadline<block.timestamp||r.deadline>block.timestamp+3600||r.nonce==bytes32(0)||
   q.chainId!=block.chainid||q.pool!=r.sourcePool||q.asset!=r.sourceAsset||q.mode!=r.operation||q.payout!=r.amount||
   q.deadline!=r.deadline||q.nonce!=r.nonce||q.relayer!=address(this)||q.recipient!=predictEscrow(r)||
   q.recipient.code.length!=0||muchFi.codehash!=muchFiCodehash||ccip.codehash!=ccipCodehash||wrappedDoge.codehash!=wrappedDogeCodehash||usdc.codehash!=usdcCodehash||bnm.codehash!=bnmCodehash)revert InvalidRoute();
  if(r.operation==4){
   if(msg.value!=0||r.maximumDeliveryFee!=0||!((r.sourcePool==nativePool&&r.sourceAsset==address(0)&&nativePool.codehash==nativePoolCodehash)||
    (r.sourcePool==usdcPool&&r.sourceAsset==usdc&&usdcPool.codehash==usdcPoolCodehash)))revert InvalidRoute();
  }else if(r.operation==5){
   if(r.sourcePool!=bnmPool||r.sourceAsset!=bnm||bnmPool.codehash!=bnmPoolCodehash||r.minimumOutput!=r.amount||
    r.maximumDeliveryFee==0||r.maximumDeliveryFee>maximumDeliveryFee||msg.value>r.maximumDeliveryFee)revert InvalidRoute();
  }else revert InvalidRoute();
 }
 function _finish(Route calldata r,VantaFamilyChikyuRouteEscrow escrow) private {
  uint256 output;uint256 fee;bytes32 messageId;
  if(r.operation==4)output=escrow.swap(r.receiver,r.amount,r.minimumOutput,r.deadline);
  else{(messageId,fee)=escrow.bridge{value:msg.value}(r.receiver,r.payer,r.amount,r.maximumDeliveryFee);output=r.amount;}
  emit RoutedSettlement(r.nonce,routeHash(r),r.sourcePool,r.operation,r.receiver,r.amount,output,messageId,fee);
 }
 function execute8(Pool.NormalEpochQuote calldata q,Pool.EpochSpend8 calldata p,bytes calldata signature,Route calldata r) external payable nonReentrant onlyReleaseChain {
  _check(q,r);if(q.width!=8)revert InvalidRoute();
  VantaFamilyChikyuRouteEscrow escrow=new VantaFamilyChikyuRouteEscrow{salt:routeHash(r)}(r.sourcePool,r.sourceAsset,muchFi,ccip,wrappedDoge,usdc,bnm);
  Pool(payable(r.sourcePool)).settleNormalEpoch8(q,p,signature);_finish(r,escrow);
 }
 function execute32(Pool.NormalEpochQuote calldata q,Pool.EpochSpend32 calldata p,bytes calldata signature,Route calldata r) external payable nonReentrant onlyReleaseChain {
  _check(q,r);if(q.width!=32)revert InvalidRoute();
  VantaFamilyChikyuRouteEscrow escrow=new VantaFamilyChikyuRouteEscrow{salt:routeHash(r)}(r.sourcePool,r.sourceAsset,muchFi,ccip,wrappedDoge,usdc,bnm);
  Pool(payable(r.sourcePool)).settleNormalEpoch32(q,p,signature);_finish(r,escrow);
 }
}
