// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {VantaFamilyAdditionalAssetFeeVaultPreAudit as Vault} from "../src/vanta/VantaFamilyAdditionalAssetFeeVaultPreAudit.sol";
import {VantaFamilyPublicFeeVaultPreAudit as OriginalVault} from "../src/vanta/VantaFamilyPublicFeeVaultPreAudit.sol";

// Only registrar identity and ERC-20 accounting fixtures; no owner-proof claims.
contract AdditionalVaultRegistrarFixture {
 bytes32 public releaseSetupId=bytes32(uint256(1));
 bytes32 public releaseGenerationId=bytes32(uint256(2));
 bytes32 public releaseFamilyTag=bytes32(uint256(3));
 bytes32 public releaseGenesisHash=bytes32(uint256(4));
 uint256 public releaseChainId=6281971;
 address public canonicalToken;
 mapping(address=>bytes32) public approvedAssetCodehash;
 constructor(address canonical){canonicalToken=canonical;approvedAssetCodehash[canonical]=canonical.codehash;}
 function approve(address token,bytes32 codehash) external{approvedAssetCodehash[token]=codehash;}
 function emptySetup() external{releaseSetupId=bytes32(0);}
 function pay(Vault vault,address payable recipient,uint256 amount) external{vault.release(recipient,amount);}
}
contract AdditionalVaultTokenFixture is ERC20 {
 constructor() ERC20("Fixture token","FIX"){}
 function mint(address to,uint256 value) external{_mint(to,value);}
}
contract VantaFamilyAdditionalAssetFeeVaultTest is Test {
 AdditionalVaultRegistrarFixture reg;AdditionalVaultTokenFixture canonical;AdditionalVaultTokenFixture usdc;AdditionalVaultTokenFixture bnm;
 function setUp() public{vm.chainId(6281971);canonical=new AdditionalVaultTokenFixture();usdc=new AdditionalVaultTokenFixture();bnm=new AdditionalVaultTokenFixture();
  reg=new AdditionalVaultRegistrarFixture(address(canonical));reg.approve(address(usdc),address(usdc).codehash);reg.approve(address(bnm),address(bnm).codehash);}
 function testBothAdditionalAssetsUsePinnedRegistrarAndOwnerOnlyPayout() public{
  address payable recipient=payable(address(0xBEEF));
  for(uint256 i;i<2;i++){AdditionalVaultTokenFixture token=i==0?usdc:bnm;Vault v=new Vault(address(reg),address(token),0);
   assertEq(v.registrar(),address(reg));assertEq(v.assetCodehash(),address(token).codehash);assertEq(v.releaseGenerationId(),reg.releaseGenerationId());
   token.mint(address(v),100);vm.expectRevert(Vault.Unauthorized.selector);v.release(recipient,10);
   reg.pay(v,recipient,10);assertEq(token.balanceOf(recipient),10);assertEq(token.balanceOf(address(v)),90);}
 }
 function testExistingNativeAndCanonicalConstructorsRemainCompatible() public{
  OriginalVault nativeVault=new OriginalVault(address(reg),address(0),0);
  OriginalVault tokenVault=new OriginalVault(address(reg),address(canonical),0);
  assertEq(nativeVault.asset(),address(0));assertEq(tokenVault.asset(),address(canonical));
  vm.expectRevert(OriginalVault.Unauthorized.selector);new OriginalVault(address(reg),address(usdc),0);
 }
 function testRejectUnapprovedToken() public{AdditionalVaultTokenFixture token=new AdditionalVaultTokenFixture();vm.expectRevert(Vault.Unauthorized.selector);new Vault(address(reg),address(token),0);}
 function testRejectWrongAssetCodehash() public{reg.approve(address(usdc),bytes32(uint256(99)));vm.expectRevert(Vault.Unauthorized.selector);new Vault(address(reg),address(usdc),0);}
 function testRejectNativeCanonicalPartnerRoleAndNoncontracts() public{
  vm.expectRevert(Vault.Unauthorized.selector);new Vault(address(reg),address(0),0);
  vm.expectRevert(Vault.Unauthorized.selector);new Vault(address(reg),address(canonical),0);
  vm.expectRevert(Vault.Unauthorized.selector);new Vault(address(reg),address(usdc),1);
  vm.expectRevert(Vault.Unauthorized.selector);new Vault(address(0x123),address(usdc),0);
  vm.expectRevert(Vault.Unauthorized.selector);new Vault(address(reg),address(0x123),0);
 }
 function testRejectWrongChainAndEmptyRelease() public{vm.chainId(1);vm.expectRevert(Vault.Unauthorized.selector);new Vault(address(reg),address(usdc),0);
  vm.chainId(6281971);reg.emptySetup();vm.expectRevert(Vault.Unauthorized.selector);new Vault(address(reg),address(usdc),0);}
 function testRejectChangedTokenAndRegistrarCodeBeforeRelease() public{
  Vault v=new Vault(address(reg),address(usdc),0);usdc.mint(address(v),100);vm.etch(address(usdc),hex"00");
  vm.expectRevert(Vault.InvalidPayout.selector);reg.pay(v,payable(address(0xBEEF)),10);
  vm.etch(address(reg),hex"00");vm.prank(address(reg));vm.expectRevert(Vault.Unauthorized.selector);v.release(payable(address(0xBEEF)),10);
 }
 function testRejectInvalidPayouts() public{Vault v=new Vault(address(reg),address(usdc),0);usdc.mint(address(v),100);
  vm.expectRevert(Vault.InvalidPayout.selector);reg.pay(v,payable(address(0)),10);
  vm.expectRevert(Vault.InvalidPayout.selector);reg.pay(v,payable(address(v)),10);
  vm.expectRevert(Vault.InvalidPayout.selector);reg.pay(v,payable(address(0xBEEF)),0);
 }
}
