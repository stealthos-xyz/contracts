// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Isolated CP_link pairing relation research (NOT a pool verifier).
/// @dev This checks e(pi, A2) = e(D, C1) * e(E, C2) using the real BN254
///      EIP-197 precompile in one call. Crucially, ALL key elements are
///      caller-provided here: this adapter is only a wiring/gas test.
///      A funds-moving verifier MUST pin a reviewed immutable CP_link VK
///      and check Gate 0 + Gate 1 + CP_link under the same full statement.
contract VantaCpLinkPairingResearch {
    uint256 internal constant FQ =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1 {
        uint256 x;
        uint256 y;
    }

    /// @dev EVM precompile order: imaginary coefficient FIRST, then real.
    struct G2 {
        uint256 xIm;
        uint256 xRe;
        uint256 yIm;
        uint256 yRe;
    }

    function verifyResearch(
        G1 calldata pi, G1 calldata d, G1 calldata e,
        G2 calldata a2, G2 calldata c1, G2 calldata c2
    ) external view returns (bool) {
        if (!_validG1(pi) || !_validG1(d) || !_validG1(e)) return false;
        if (!_validG2(a2) || !_validG2(c1) || !_validG2(c2)) return false;

        bytes memory pairs = abi.encodePacked(
            pi.x, pi.y, a2.xIm, a2.xRe, a2.yIm, a2.yRe,
            d.x, FQ - d.y, c1.xIm, c1.xRe, c1.yIm, c1.yRe,
            e.x, FQ - e.y, c2.xIm, c2.xRe, c2.yIm, c2.yRe
        );
        (bool success, bytes memory response) = address(0x08).staticcall(pairs);
        return success && response.length == 32 && abi.decode(response, (uint256)) == 1;
    }

    function _validG1(G1 calldata p) private pure returns (bool) {
        if ((p.x == 0 && p.y == 0) || p.x >= FQ || p.y >= FQ) return false;
        return mulmod(p.y, p.y, FQ) ==
            addmod(mulmod(mulmod(p.x, p.x, FQ), p.x, FQ), 3, FQ);
    }

    function _validG2(G2 calldata p) private pure returns (bool) {
        if (p.xIm >= FQ || p.xRe >= FQ || p.yIm >= FQ || p.yRe >= FQ) return false;
        return (p.xIm | p.xRe | p.yIm | p.yRe) != 0;
    }
}
