// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {VantaFamilyReleaseBinding} from "../src/vanta/VantaFamilyReleaseBinding.sol";
import {VantaFamilyUnifiedPoolPreAudit as Pool} from "../src/vanta/VantaFamilyUnifiedPoolPreAudit.sol";
import {VantaFamilyChikyuRouteGatewayPreAudit as Gateway, VantaFamilyChikyuRouteEscrow as Escrow,
 FamilyCcipMessage} from "../src/vanta/VantaFamilyChikyuRouteGatewayPreAudit.sol";

// These venue and source-pool mocks isolate routing/rollback, not proof validity.
// Genuine proof and fee admission are tested separately in RoutedSettlement.
contract RouteToken is ERC20 {
 constructor() ERC20("Route fixture", "FIX") {}
 function mint(address to,uint256 n) external {_mint(to,n);}
}
contract RoutePoolMock is VantaFamilyReleaseBinding {
 address public immutable asset; bool public consumed;
 constructor(address a) VantaFamilyReleaseBinding(bytes32(uint256(1)),bytes32(uint256(2)),bytes32(uint256(3)),block.chainid){asset=a;}
 function releaseGenesisHash() external pure returns(bytes32){return bytes32(uint256(4));}
 function settleNormalEpoch8(Pool.NormalEpochQuote calldata q,Pool.EpochSpend8 calldata,bytes calldata) external {settle(q);}
 function settleNormalEpoch32(Pool.NormalEpochQuote calldata q,Pool.EpochSpend32 calldata,bytes calldata) external {settle(q);}
 function settle(Pool.NormalEpochQuote calldata q) private {
  require(!consumed);consumed=true;
  if(asset==address(0)){(bool ok,)=payable(q.recipient).call{value:q.payout}("");require(ok);}
  else require(RouteToken(asset).transfer(q.recipient,q.payout));
 }
}
contract MuchFiRouteMock {
 address public immutable WETH; RouteToken public immutable token; bool public fail;
 constructor(address w,RouteToken t){WETH=w;token=t;}
 receive() external payable {}
 function setFail(bool value) external {fail=value;}
 function swapExactETHForTokens(uint256 minimum,address[] calldata path,address to,uint256 deadline) external payable returns(uint256[] memory out){
  require(!fail&&path[0]==WETH&&path[1]==address(token)&&deadline>=block.timestamp);
  out=new uint256[](2);out[0]=msg.value;out[1]=msg.value*2;require(out[1]>=minimum);token.mint(to,out[1]);
 }
 function swapExactTokensForETH(uint256 n,uint256 minimum,address[] calldata path,address to,uint256 deadline) external returns(uint256[] memory out){
  require(!fail&&path[0]==address(token)&&path[1]==WETH&&deadline>=block.timestamp);
  out=new uint256[](2);out[0]=n;out[1]=n/2;require(out[1]>=minimum&&token.transferFrom(msg.sender,address(this),n));
  (bool ok,)=payable(to).call{value:out[1]}("");require(ok);
 }
}
contract CcipRouteMock {
 uint256 public fee=1 ether; bool public fail; bytes32 public lastMessage;
 function setFee(uint256 n) external {fee=n;}
 function setFail(bool value) external {fail=value;}
 function isChainSupported(uint64 selector) external pure returns(bool){return selector==16015286601757825753;}
 function getFee(uint64,FamilyCcipMessage calldata) external view returns(uint256){return fee;}
 function ccipSend(uint64 selector,FamilyCcipMessage calldata message) external payable returns(bytes32){
  require(!fail&&selector==16015286601757825753&&msg.value==fee&&message.data.length==0&&message.feeToken==address(0));
  require(message.tokenAmounts.length==1&&keccak256(message.extraArgs)==keccak256(abi.encodePacked(bytes4(0x181dcf10),abi.encode(uint256(0),true))));
  require(RouteToken(message.tokenAmounts[0].token).transferFrom(msg.sender,address(this),message.tokenAmounts[0].amount));
  lastMessage=keccak256(abi.encode(selector,message));return lastMessage;
 }
}
contract VantaFamilyChikyuRouteGatewayTest is Test {
 address constant RECEIVER=address(0x1234);
 RouteToken usdc;RouteToken bnm;RouteToken wrapped;RoutePoolMock nativePool;RoutePoolMock usdcPool;RoutePoolMock bnmPool;
 MuchFiRouteMock much;CcipRouteMock ccip;Gateway gateway;
 receive() external payable {}
 function setUp() public {
  vm.chainId(6281971);vm.warp(1000);vm.deal(address(this),100 ether);
  usdc=new RouteToken();bnm=new RouteToken();wrapped=new RouteToken();much=new MuchFiRouteMock(address(wrapped),usdc);ccip=new CcipRouteMock();
  nativePool=new RoutePoolMock(address(0));usdcPool=new RoutePoolMock(address(usdc));bnmPool=new RoutePoolMock(address(bnm));
  vm.deal(address(nativePool),100 ether);vm.deal(address(much),100 ether);usdc.mint(address(usdcPool),100 ether);bnm.mint(address(bnmPool),100 ether);
  gateway=new Gateway(Gateway.Config(address(nativePool),address(usdcPool),address(bnmPool),address(much),address(ccip),address(wrapped),
   address(usdc),address(bnm),30 ether,bytes32(uint256(4)),bytes32(uint256(1)),bytes32(uint256(2)),bytes32(uint256(3)),block.chainid));
 }
 function prepare(uint8 op,bool token) private view returns(Pool.NormalEpochQuote memory q,Gateway.Route memory r){
  address pool=op==5?address(bnmPool):(token?address(usdcPool):address(nativePool));
  address asset=op==5?address(bnm):(token?address(usdc):address(0));
  r=Gateway.Route(op,pool,asset,address(this),RECEIVER,2 ether,op==5?2 ether:(token?1 ether:4 ether),uint64(block.timestamp+600),bytes32(uint256(123)),op==5?2 ether:0);
  q.chainId=uint64(block.chainid);q.pool=pool;q.asset=asset;q.width=8;q.mode=op;q.payout=r.amount;q.deadline=r.deadline;
  q.nonce=r.nonce;q.relayer=address(gateway);q.recipient=gateway.predictEscrow(r);
 }
 function execute(Pool.NormalEpochQuote memory q,Gateway.Route memory r,uint256 value) private {Pool.EpochSpend8 memory proof;gateway.execute8{value:value}(q,proof,"",r);}
 function assertRolledBack(Pool.NormalEpochQuote memory q) private view {assertFalse(RoutePoolMock(payable(q.pool)).consumed());assertEq(q.recipient.code.length,0);}
 function testNativeSwapPaysOnlyBoundReceiver() public {
  (Pool.NormalEpochQuote memory q,Gateway.Route memory r)=prepare(4,false);execute(q,r,0);
  assertEq(usdc.balanceOf(RECEIVER),4 ether);assertTrue(nativePool.consumed());assertTrue(Escrow(payable(q.recipient)).used());
 }
 function testTokenSwapClearsAllowance() public {
  (Pool.NormalEpochQuote memory q,Gateway.Route memory r)=prepare(4,true);execute(q,r,0);
  assertEq(RECEIVER.balance,1 ether);assertEq(usdc.allowance(q.recipient,address(much)),0);assertTrue(usdcPool.consumed());
 }
 function testThirtyTwoUsesSameAtomicRoute() public {
  (Pool.NormalEpochQuote memory q,Gateway.Route memory r)=prepare(4,false);q.width=32;Pool.EpochSpend32 memory proof;
  gateway.execute32(q,proof,"",r);assertEq(usdc.balanceOf(RECEIVER),4 ether);
 }
 function testSlippageRevertsSourceAndEscrow() public {
  (Pool.NormalEpochQuote memory q,Gateway.Route memory r)=prepare(4,false);r.minimumOutput=5 ether;q.recipient=gateway.predictEscrow(r);
  vm.expectRevert();execute(q,r,0);assertRolledBack(q);assertEq(address(nativePool).balance,100 ether);assertEq(usdc.balanceOf(RECEIVER),0);
 }
 function testVenueFailureRevertsSourceAndEscrow() public {
  (Pool.NormalEpochQuote memory q,Gateway.Route memory r)=prepare(4,true);much.setFail(true);
  vm.expectRevert();execute(q,r,0);assertRolledBack(q);assertEq(usdc.balanceOf(address(usdcPool)),100 ether);
 }
 function testBridgeUsesExactTokenAndRefundsUnusedFee() public {
  (Pool.NormalEpochQuote memory q,Gateway.Route memory r)=prepare(5,false);uint256 beforeBalance=address(this).balance;
  execute(q,r,2 ether);assertEq(address(this).balance,beforeBalance-1 ether);assertEq(bnm.balanceOf(address(ccip)),2 ether);
  assertEq(bnm.allowance(q.recipient,address(ccip)),0);assertTrue(ccip.lastMessage()!=bytes32(0));assertTrue(bnmPool.consumed());
 }
 function testBridgeFeeIncreaseRevertsEverything() public {
  (Pool.NormalEpochQuote memory q,Gateway.Route memory r)=prepare(5,false);ccip.setFee(3 ether);
  vm.expectRevert();execute(q,r,2 ether);assertRolledBack(q);assertEq(bnm.balanceOf(address(bnmPool)),100 ether);
 }
 function testBridgeFailureRevertsEverything() public {
  (Pool.NormalEpochQuote memory q,Gateway.Route memory r)=prepare(5,false);ccip.setFail(true);
  vm.expectRevert();execute(q,r,2 ether);assertRolledBack(q);assertEq(bnm.balanceOf(address(bnmPool)),100 ether);
 }
 function testChangedReceiverCannotUseSignedEscrow() public {
  (Pool.NormalEpochQuote memory q,Gateway.Route memory r)=prepare(4,false);r.receiver=address(0x9999);
  vm.expectRevert(Gateway.InvalidRoute.selector);execute(q,r,0);assertRolledBack(q);
 }
 function testChangedPayerCannotUseSignedEscrow() public {
  (Pool.NormalEpochQuote memory q,Gateway.Route memory r)=prepare(4,false);r.payer=address(0x9999);
  vm.expectRevert(Gateway.InvalidRoute.selector);execute(q,r,0);assertRolledBack(q);
 }
 function testWrongAssetOrOperationRejected() public {
  (Pool.NormalEpochQuote memory q,Gateway.Route memory r)=prepare(5,false);r.sourceAsset=address(usdc);q.asset=r.sourceAsset;q.recipient=gateway.predictEscrow(r);
  vm.expectRevert(Gateway.InvalidRoute.selector);execute(q,r,1 ether);assertRolledBack(q);
  (q,r)=prepare(4,false);r.operation=1;q.mode=1;q.recipient=gateway.predictEscrow(r);
  vm.expectRevert(Gateway.InvalidRoute.selector);execute(q,r,0);assertRolledBack(q);
 }
 function testChangedVenueCodeRejected() public {
  (Pool.NormalEpochQuote memory q,Gateway.Route memory r)=prepare(4,false);vm.etch(address(much),hex"6000");
  vm.expectRevert(Gateway.InvalidRoute.selector);execute(q,r,0);assertRolledBack(q);
 }
 function testSameRouteCannotExecuteTwice() public {
  (Pool.NormalEpochQuote memory q,Gateway.Route memory r)=prepare(4,false);execute(q,r,0);
  vm.expectRevert(Gateway.InvalidRoute.selector);execute(q,r,0);assertEq(usdc.balanceOf(RECEIVER),4 ether);
 }
}
