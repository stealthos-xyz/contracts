// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {VantaKzgUpdateKeyResearch} from "../src/vanta/VantaKzgUpdateKeyResearch.sol";
import {VantaCpLinkPairingResearch} from "../src/vanta/VantaCpLinkPairingResearch.sol";

contract ArkworksCompressionHarness is VantaKzgUpdateKeyResearch {
    function matches(G1Point calldata point, bytes32 compressed) external pure returns (bool) {
        return _matchesArkCompressed(point, compressed);
    }
}

contract VantaFyeoCryptographicRegressionTest is Test {
    uint256 constant FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    function testArkworksLittleEndianAndSignFlags() public {
        ArkworksCompressionHarness h = new ArkworksCompressionHarness();
        VantaKzgUpdateKeyResearch.G1Point memory g = VantaKzgUpdateKeyResearch.G1Point(1, 2);
        bytes32 canonical = bytes32(uint256(1) << 248);
        assertTrue(h.matches(g, canonical));
        assertFalse(h.matches(g, bytes32(uint256(1))));
        assertFalse(h.matches(g, canonical | bytes32(uint256(0x40))));
        assertFalse(h.matches(g, canonical | bytes32(uint256(0x80))));
        g.y = FQ - 2;
        assertTrue(h.matches(g, canonical | bytes32(uint256(0x80))));
        assertFalse(h.matches(g, canonical));
    }

    function testPairingRejectsOffCurveG2() public {
        VantaCpLinkPairingResearch v = new VantaCpLinkPairingResearch();
        VantaCpLinkPairingResearch.G1 memory g = VantaCpLinkPairingResearch.G1(1, 2);
        (bool ok, bytes memory ret) = address(0x07).staticcall(abi.encode(uint256(1), uint256(2), uint256(2)));
        assertTrue(ok);
        (uint256 x, uint256 y) = abi.decode(ret, (uint256,uint256));
        VantaCpLinkPairingResearch.G1 memory twice = VantaCpLinkPairingResearch.G1(x,y);
        VantaCpLinkPairingResearch.G2 memory h = VantaCpLinkPairingResearch.G2(
            11559732032986387107991004021392285783925812861821192530917403151452391805634,
            10857046999023057135944570762232829481370756359578518086990519993285655852781,
            4082367875863433681332203403145435568316851327593401208105741076214120093531,
            8495653923123431417604973247489272438418190587263600148770280649306958101930
        );
        assertTrue(v.verifyResearch(twice,g,g,h,h,h));
        h.yRe += 1;
        assertFalse(v.verifyResearch(twice,g,g,h,h,h));
    }
}
