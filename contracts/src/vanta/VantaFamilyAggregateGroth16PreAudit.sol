// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Genuine BN254 Groth16 verifier for V8's 13-public-input
/// salted-hidden-share aggregate relation (research only).
/// @dev Exactly [batchDigest,legCount,publicPayout,H0..H7,familyTag,chainId], with fourteen
/// Groth16 IC points. This is only an EIP-196/197 arithmetic adapter.
/// The key is still caller supplied. Pinned independent setup, strict
/// batch/source/hash admission, atomic KZG state updates and actual payout
/// remain mandatory before funds can move.
contract VantaFamilyAggregateGroth16PreAudit {
    uint256 internal constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant FQ =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1 { uint256 x; uint256 y; }
    struct G2 { uint256 xIm; uint256 xRe; uint256 yIm; uint256 yRe; }

    struct VerifyingKey {
        G1 alpha;
        G2 beta;
        G2 gamma;
        G2 delta;
        G1[] ic;
    }
    struct Proof {
        G1 a;
        G2 b;
        G1 c;
    }

    function verifyResearch(
        VerifyingKey calldata vk, Proof calldata proof,
        uint256[13] calldata publicInputs
    ) external view returns (bool) {
        if (vk.ic.length != 14 ||
            !_validG1(proof.a) || !_validG1(proof.c) ||
            !_validG1(vk.alpha) ||
            !_validG2(proof.b) || !_validG2(vk.beta) ||
            !_validG2(vk.gamma) || !_validG2(vk.delta))
            return false;

        G1 memory prepared = vk.ic[0];
        if (!_validG1(prepared)) return false;
        for (uint256 i; i < 13; ++i) {
            if (publicInputs[i] >= FR || !_validG1(vk.ic[i + 1]))
                return false;
            (bool ok, G1 memory scaled) = _ecMul(
                vk.ic[i + 1], publicInputs[i]
            );
            if (!ok) return false;
            (ok, prepared) = _ecAdd(prepared, scaled);
            if (!ok) return false;
        }

        // Four BN254 six-word pairs. Never inline 24 scalars into one
        // abi.encodePacked call: solc 0.8.26 via-IR Yul stack overflows.
        bytes memory pairInput = bytes.concat(
            abi.encodePacked(
                proof.a.x, proof.a.y,
                proof.b.xIm, proof.b.xRe, proof.b.yIm, proof.b.yRe
            ),
            abi.encodePacked(
                vk.alpha.x, _neg(vk.alpha.y),
                vk.beta.xIm, vk.beta.xRe, vk.beta.yIm, vk.beta.yRe
            ),
            abi.encodePacked(
                prepared.x, _neg(prepared.y),
                vk.gamma.xIm, vk.gamma.xRe, vk.gamma.yIm, vk.gamma.yRe
            ),
            abi.encodePacked(
                proof.c.x, _neg(proof.c.y),
                vk.delta.xIm, vk.delta.xRe, vk.delta.yIm, vk.delta.yRe
            )
        );
        (bool okPair, bytes memory response) =
            address(0x08).staticcall(pairInput);
        return okPair && response.length == 32 &&
            abi.decode(response, (uint256)) == 1;
    }

    function _ecMul(G1 calldata p, uint256 scalar)
        private view returns (bool ok, G1 memory result)
    {
        (bool success, bytes memory response) = address(0x07).staticcall(
            abi.encode(p.x, p.y, scalar)
        );
        if (!success || response.length != 64) return (false, result);
        (result.x,result.y) = abi.decode(response,(uint256,uint256));
        return (true,result);
    }

    function _ecAdd(G1 memory a, G1 memory b)
        private view returns (bool ok, G1 memory result)
    {
        (bool success, bytes memory response) = address(0x06).staticcall(
            abi.encode(a.x,a.y,b.x,b.y)
        );
        if (!success || response.length != 64) return (false,result);
        (result.x,result.y) = abi.decode(response,(uint256,uint256));
        return (true,result);
    }

    function _neg(uint256 y) private pure returns (uint256) {
        return y == 0 ? 0 : FQ - y;
    }

    function _validG1(G1 memory p) private pure returns (bool) {
        if (p.x >= FQ || p.y >= FQ) return false;
        if (p.x == 0 && p.y == 0) return true;
        return mulmod(p.y,p.y,FQ) ==
            addmod(mulmod(mulmod(p.x,p.x,FQ),p.x,FQ),3,FQ);
    }

    function _validG2(G2 memory p) private pure returns (bool) {
        return p.xIm < FQ && p.xRe < FQ &&
            p.yIm < FQ && p.yRe < FQ &&
            (p.xIm | p.xRe | p.yIm | p.yRe) != 0;
    }
}

