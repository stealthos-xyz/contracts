// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {VantaFamilyReleaseBinding} from "../src/vanta/VantaFamilyReleaseBinding.sol";
import {VantaFamilyUnifiedPoolPreAudit as Pool} from "../src/vanta/VantaFamilyUnifiedPoolPreAudit.sol";
import {VantaFamilyDirectDepositPoolPreAudit as DepositPool} from "../src/vanta/VantaFamilyDirectDepositPoolPreAudit.sol";
import {VantaV8FiveRowKzgResearch as Kzg} from "../src/vanta/VantaV8FiveRowKzgResearch.sol";
import {VantaFamilyPrivateSwapOutput as Gateway} from "../src/vanta/VantaFamilyPrivateSwapOutput.sol";
contract SwapToken is ERC20 {
 constructor()ERC20("Fixture","FIX"){} function mint(address a,uint256 n)external{_mint(a,n);}
}
/// Boundary fixtures isolate source-credit provenance and exact forwarding.
/// They are not cryptographic proof fixtures or evidence of live readiness.
contract SwapPoolFixture is VantaFamilyReleaseBinding {
 address public immutable asset;bytes32 public constant releaseGenesisHash=bytes32(uint256(4));
 mapping(bytes32=>bool)public usedNonce;bool public reject;address private gateway;
 function setGateway(address g)external{gateway=g;}
 constructor(address a)VantaFamilyReleaseBinding(bytes32(uint256(1)),bytes32(uint256(2)),bytes32(uint256(3)),block.chainid){asset=a;}
 receive()external payable{}
 function setReject(bool v)external{reject=v;}
 function settleNormalEpoch8(Pool.NormalEpochQuote calldata q,Pool.EpochSpend8 calldata,bytes calldata)external{
  require(!reject&&!usedNonce[q.nonce],"proof rejected");usedNonce[q.nonce]=true;
  if(asset==address(0)){(bool ok,)=payable(q.recipient).call{value:q.payout}("");require(ok);}
  else SwapToken(asset).transfer(q.recipient,q.payout);
 }
 function depositWithPrivateFeeNotes(Pool.PrivateFeeDepositQuote calldata q,uint256[5] calldata,bytes[5] calldata,
  Kzg.RowKey[5] calldata,uint8[2] calldata,bytes calldata,bytes calldata)external payable returns(uint256){
  require(!reject,"proof rejected");require(q.count==1&&q.protocolFeeCap==0&&q.partnerFeeCap==0&&q.payer==msg.sender&&!usedNonce[q.nonce]);
  require(Gateway(gateway).isActiveIngress(msg.sender,address(this),keccak256(msg.data)));
  usedNonce[q.nonce]=true;
  if(asset==address(0))require(msg.value==q.gross);else require(SwapToken(asset).transferFrom(msg.sender,address(this),q.gross));return 77;
 }
}
interface SwapEscrowView{function factoryAddress()external view returns(address);}
contract SwapRouterFixture {
 address public immutable WETH;SwapToken public immutable token;
 constructor(address w,SwapToken t){WETH=w;token=t;}
 receive()external payable{}
 function swapExactETHForTokens(uint256 minimum,address[] calldata,address receiver,uint256)external payable returns(uint256[]memory a){
  a=new uint256[](2);a[0]=msg.value;a[1]=msg.value*2;require(a[1]>=minimum);token.mint(receiver,a[1]);
 }
 function swapExactTokensForETH(uint256 n,uint256 minimum,address[] calldata,address receiver,uint256)external returns(uint256[]memory a){
  require(token.transferFrom(msg.sender,address(this),n));a=new uint256[](2);a[0]=n;a[1]=n/2;require(a[1]>=minimum);
  (bool ok,)=payable(receiver).call{value:a[1]}("");require(ok);
 }
}
contract VantaFamilyPrivateSwapOutputTest is Test {
 Gateway g;SwapToken token;SwapPoolFixture nativePool;SwapPoolFixture tokenPool;SwapRouterFixture router;
 uint256 constant KEY=1234567;address owner;address constant RELAYER=address(0x7777);bytes32 constant SALT=bytes32(uint256(99));
 function setUp()public{vm.chainId(6281971);vm.warp(1000);owner=vm.addr(KEY);token=new SwapToken();SwapToken wrapped=new SwapToken();
  nativePool=new SwapPoolFixture(address(0));tokenPool=new SwapPoolFixture(address(token));router=new SwapRouterFixture(address(wrapped),token);
  g=new Gateway(Gateway.Config(address(nativePool),address(tokenPool),address(router),address(wrapped),address(token),bytes32(uint256(4)),bytes32(uint256(1)),bytes32(uint256(2)),bytes32(uint256(3)),block.chainid));
  nativePool.setGateway(address(g));tokenPool.setGateway(address(g));
  vm.deal(address(nativePool),100 ether);vm.deal(address(router),100 ether);token.mint(address(tokenPool),100 ether);
 }
 function _route(bool reverse)internal view returns(Gateway.Route memory r,Pool.NormalEpochQuote memory q){
  r=Gateway.Route(4,reverse?address(tokenPool):address(nativePool),reverse?address(token):address(0),RELAYER,address(0),10 ether,1,1500,bytes32(uint256(55)),0,reverse?address(nativePool):address(tokenPool),owner,SALT);
  r.receiver=g.predictEscrow(r.outputPool,owner,SALT);q.chainId=uint64(block.chainid);q.pool=r.sourcePool;q.asset=r.sourceAsset;q.width=8;q.mode=4;q.payout=r.amount;
  q.deadline=r.deadline;q.nonce=r.nonce;q.relayer=address(g);q.recipient=g.predictFundingEscrow(r);
 }
 function _execute(bool reverse)internal returns(bytes32 id,Gateway.Route memory r){Pool.NormalEpochQuote memory q;(r,q)=_route(reverse);Pool.EpochSpend8 memory proof;
  vm.prank(RELAYER);g.execute8(q,proof,"fixture",r);return(g.routeHash(r),r);
 }
 function _data(bytes32 creditId,Gateway.Route memory r,uint128 gross)internal pure returns(bytes memory){
  Pool.PrivateFeeDepositQuote memory q;q.chainId=6281971;q.pool=r.outputPool;q.asset=r.sourceAsset==address(0)?address(0):address(0);
  q.payer=r.receiver;q.count=1;q.gross=gross;q.nonce=creditId;q.deadline=1500;
  uint256[5] memory outputs;bytes[5]memory envelopes;Kzg.RowKey[5]memory keys;uint8[2]memory slots;
  return abi.encodeCall(DepositPool.depositWithPrivateFeeNotes,(q,outputs,envelopes,keys,slots,hex"01",hex"02"));
 }
 function _packet(bytes32 creditId,Gateway.Route memory r,uint128 gross)internal view returns(bytes memory data,bytes memory sig){
  Pool.PrivateFeeDepositQuote memory q;q.chainId=6281971;q.pool=r.outputPool;q.asset=r.outputPool==address(tokenPool)?address(token):address(0);
  q.payer=r.receiver;q.count=1;q.gross=gross;q.nonce=creditId;q.deadline=1500;
  uint256[5]memory outputs;bytes[5]memory env;Kzg.RowKey[5]memory keys;uint8[2]memory slots;
  data=abi.encodeCall(DepositPool.depositWithPrivateFeeNotes,(q,outputs,env,keys,slots,hex"01",hex"02"));
  (uint8 v,bytes32 a,bytes32 b)=vm.sign(KEY,g.claimDigest(creditId,0,1500,RELAYER,0,keccak256(data)));sig=abi.encodePacked(a,b,v);
 }
 function _claim(bytes32 id,bytes memory data,bytes memory sig)internal returns(uint256){vm.prank(RELAYER);return g.claim(id,0,1500,RELAYER,0,data,sig);}
 function testMeasuredTokenOutputReshieldsWithoutDepositFee()public{(bytes32 id,Gateway.Route memory r)=_execute(false);
  (bytes memory data,bytes memory sig)=_packet(id,r,20 ether);assertEq(_claim(id,data,sig),77);assertEq(token.balanceOf(r.receiver),0);assertTrue(tokenPool.usedNonce(id));
 }
 function testNativeOutputReshieldsWithoutDepositFee()public{(bytes32 id,Gateway.Route memory r)=_execute(true);
  (bytes memory data,bytes memory sig)=_packet(id,r,5 ether);assertEq(_claim(id,data,sig),77);assertEq(r.receiver.balance,0);
 }
 function testDonationsDoNotCreateFeeFreeDepositCredits()public{(bytes32 id,Gateway.Route memory r)=_execute(false);token.mint(r.receiver,2 ether);
  (bytes memory data,bytes memory sig)=_packet(id,r,22 ether);vm.expectRevert();_claim(id,data,sig);
  (data,sig)=_packet(id,r,20 ether);_claim(id,data,sig);assertEq(token.balanceOf(r.receiver),2 ether);
  vm.expectRevert();_claim(id,data,sig);
 }
 function testCannotClaimArbitraryPrefunding()public{(Gateway.Route memory r,)=_route(false);token.mint(r.receiver,20 ether);bytes32 id=g.routeHash(r);
  (bytes memory data,bytes memory sig)=_packet(id,r,20 ether);vm.expectRevert();_claim(id,data,sig);
 }
 function testOutputProofRejectionRollsBackClaimAndEscrow()public{(bytes32 id,Gateway.Route memory r)=_execute(false);tokenPool.setReject(true);
  (bytes memory data,bytes memory sig)=_packet(id,r,20 ether);vm.expectRevert(bytes("proof rejected"));_claim(id,data,sig);
  (,,,,bool claimed)=g.credits(id);assertFalse(claimed);assertEq(r.receiver.code.length,0);assertFalse(g.usedNonce(id,0));assertEq(token.balanceOf(r.receiver),20 ether);
  tokenPool.setReject(false);_claim(id,data,sig);
 }
 function testCannotRedirectClaimOrReplay()public{(bytes32 id,Gateway.Route memory r)=_execute(false);(bytes memory data,bytes memory sig)=_packet(id,r,20 ether);
  vm.expectRevert();vm.prank(address(1));g.claim(id,0,1500,RELAYER,0,data,sig);
  vm.expectRevert();_claim(id,bytes.concat(data,hex"00"),sig);
  _claim(id,data,sig);vm.expectRevert();_claim(id,data,sig);
  assertFalse(g.isActiveIngress(r.receiver,r.outputPool,keccak256(data)));
 }
 function testCannotRedirectSourceToEOAOrDifferentPool()public{(Gateway.Route memory r,Pool.NormalEpochQuote memory q)=_route(false);r.receiver=owner;Pool.EpochSpend8 memory proof;
  vm.expectRevert();vm.prank(RELAYER);g.execute8(q,proof,"fixture",r);
 }
 function testSourceProofFailureCreatesNoCreditOrEscrow()public{(Gateway.Route memory r,Pool.NormalEpochQuote memory q)=_route(false);nativePool.setReject(true);Pool.EpochSpend8 memory proof;
  vm.expectRevert(bytes("proof rejected"));vm.prank(RELAYER);g.execute8(q,proof,"fixture",r);(,,,uint128 amount,)=g.credits(g.routeHash(r));assertEq(amount,0);assertEq(q.recipient.code.length,0);
 }
}
