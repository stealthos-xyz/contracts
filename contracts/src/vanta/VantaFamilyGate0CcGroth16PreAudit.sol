// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Isolated EVM arithmetic parity for Vanta's 32-commitment ccGroth16.
/// @dev This is NOT a funds-moving verifier. The caller controls verification
///      keys; production MUST pin a reviewed setup hash/keys and independently
///      verify Gate 1 and CP_link in the same canonical transaction context.
///      ccGroth16 verification: e(A,B) = e(alpha,beta) *
///      e(IC_0 + statement*IC_1 + D,gamma) * e(C,delta).
contract VantaFamilyGate0CcGroth16PreAudit {
    uint256 internal constant FQ =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    struct G1 {
        uint256 x;
        uint256 y;
    }

    struct G2 {
        uint256 xIm;
        uint256 xRe;
        uint256 yIm;
        uint256 yRe;
    }

    struct VerifyingKey {
        G1 alpha;
        G2 beta;
        G2 gamma;
        G2 delta;
        G1 ic0;
        G1 ic1;
    }

    struct Proof {
        G1 a;
        G2 b;
        G1 c;
        G1 d;
    }

    /// @dev Arkworks V8 8x5 and 32x5 relations expose six Groth16
    /// public inputs, in order: [statement, protocolFeeCap, partnerFeeCap,
    /// saltedAmountHash, familyTag, chainId]. IC[0] is the constant term; IC[1..6] bind inputs.
    /// This cannot be verified by the historical 2-point V4 IC.
    struct V8VerifyingKey {
        G1 alpha;
        G2 beta;
        G2 gamma;
        G2 delta;
        // Dynamic calldata container avoids a deeply flattened 24-word ABI
        // decode; verifyV8Research still requires EXACTLY seven IC points.
        G1[] ic;
    }



    /// @notice EIP-196 scalar multiplication and addition + EIP-197 4-pair check.
    function verifyResearch(VerifyingKey calldata vk, Proof calldata proof, uint256 statement)
        external view returns (bool)
    {
        if (statement >= FR || !_g1Valid(proof.a) || !_g1Valid(proof.c)
            || !_g1Valid(proof.d) || !_g1Valid(vk.alpha)
            || !_g1Valid(vk.ic0) || !_g1Valid(vk.ic1)
            || !_g2Valid(proof.b) || !_g2Valid(vk.beta)
            || !_g2Valid(vk.gamma) || !_g2Valid(vk.delta)
        ) return false;

        (bool mulOk, G1 memory contribution) = _ecMul(vk.ic1, statement);
        if (!mulOk) return false;
        (bool addOk, G1 memory publicInputs) = _ecAdd(vk.ic0, contribution);
        if (!addOk) return false;
        (addOk, publicInputs) = _ecAdd(publicInputs, proof.d);
        if (!addOk) return false;

        // Each BN254 pairing consists of exactly six 32-byte limbs.
        // Encoding a single 24-limb tuple hits a solc 0.8.26 via-IR Yul
        // stack limit. Concatenating four 192-byte pairs is byte-identical
        // to the EIP-197 input and leaves the four-pair equation unchanged.
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
                publicInputs.x, _neg(publicInputs.y),
                vk.gamma.xIm, vk.gamma.xRe, vk.gamma.yIm, vk.gamma.yRe
            ),
            abi.encodePacked(
                proof.c.x, _neg(proof.c.y),
                vk.delta.xIm, vk.delta.xRe, vk.delta.yIm, vk.delta.yRe
            )
        );
        (bool ok, bytes memory result) = address(0x08).staticcall(pairInput);
        return ok && result.length == 32 && abi.decode(result, (uint256)) == 1;
    }

    /// @notice Genuine 6-public-input V8 ccGroth16 pairing equation.
    /// @dev RESEARCH ONLY: verification key comes from calldata, so this
    /// proves no production authority. The pool must pin the accepted V8
    /// VK and recompute all six public values from its canonical intent.
    function verifyFamily(
        V8VerifyingKey calldata vk,
        Proof calldata proof,
        uint256[6] calldata inputs
    ) external view returns (bool) {
        uint256[] memory canonical = new uint256[](6);
        for (uint256 i; i < 6; ++i) canonical[i] = inputs[i];
        return _verifyVector(vk, proof, canonical);
    }

    /// @notice The same ccGroth16 equation for the two KZG fee relations.
    /// @dev Arithmetic only. The fee adapter pins this key and reconstructs
    /// all 40/41 inputs, then verifies singleton Caulk+ and CP_link as well.
    function verifyFee(
        V8VerifyingKey calldata vk,
        Proof calldata proof,
        uint256[] calldata inputs
    ) external view returns (bool) {
        if (inputs.length != 40 && inputs.length != 41) return false;
        return _verifyVector(vk, proof, inputs);
    }

    function _verifyVector(
        V8VerifyingKey calldata vk,
        Proof calldata proof,
        uint256[] memory inputs
    ) private view returns (bool) {
        if (vk.ic.length != inputs.length + 1) return false;
        if (!_g1Valid(proof.a) || !_g1Valid(proof.c) || !_g1Valid(proof.d) ||
            !_g1Valid(vk.alpha) || !_g2Valid(proof.b) ||
            !_g2Valid(vk.beta) || !_g2Valid(vk.gamma) || !_g2Valid(vk.delta))
            return false;

        for (uint256 i = 0; i < vk.ic.length; ++i) {
            if (!_g1Valid(vk.ic[i])) return false;
        }
        G1 memory prepared = vk.ic[0];
        for (uint256 i = 0; i < inputs.length; ++i) {
            if (inputs[i] >= FR) return false;
            (bool okMul, G1 memory scaled) = _ecMul(vk.ic[i+1], inputs[i]);
            if (!okMul) return false;
            (bool okAdd, G1 memory next) = _ecAdd(prepared, scaled);
            if (!okAdd) return false;
            prepared = next;
        }
        (bool finalOk, G1 memory finalInputs) = _ecAdd(prepared, proof.d);
        if (!finalOk) return false;
        // e(A,B) = e(alpha,beta) * e(IC(public)+D,gamma) * e(C,delta).
        // Each BN254 pairing consists of exactly six 32-byte limbs.
        // Encoding a single 24-limb tuple hits a solc 0.8.26 via-IR Yul
        // stack limit. Concatenating four 192-byte pairs is byte-identical
        // to the EIP-197 input and leaves the four-pair equation unchanged.
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
                finalInputs.x, _neg(finalInputs.y),
                vk.gamma.xIm, vk.gamma.xRe, vk.gamma.yIm, vk.gamma.yRe
            ),
            abi.encodePacked(
                proof.c.x, _neg(proof.c.y),
                vk.delta.xIm, vk.delta.xRe, vk.delta.yIm, vk.delta.yRe
            )
        );
        (bool ok, bytes memory response) = address(0x08).staticcall(pairInput);
        return ok && response.length == 32 &&
            abi.decode(response, (uint256)) == 1;
    }

    function _ecMul(G1 calldata a, uint256 b)
        private view returns (bool ok, G1 memory result)
    {
        (bool success, bytes memory answer) = address(0x07).staticcall(
            abi.encodePacked(a.x, a.y, b)
        );
        if (!success || answer.length != 64) return (false, result);
        (result.x, result.y) = abi.decode(answer, (uint256, uint256));
        return (true, result);
    }

    function _ecAdd(G1 memory a, G1 memory b)
        private view returns (bool ok, G1 memory result)
    {
        (bool success, bytes memory answer) = address(0x06).staticcall(
            abi.encodePacked(a.x, a.y, b.x, b.y)
        );
        if (!success || answer.length != 64) return (false, result);
        (result.x, result.y) = abi.decode(answer, (uint256, uint256));
        return (true, result);
    }

    function _neg(uint256 y) private pure returns (uint256) {
        return y == 0 ? 0 : FQ - y;
    }

    function _g1Valid(G1 calldata p) private pure returns (bool) {
        if (p.x >= FQ || p.y >= FQ) return false;
        // EIP-196 point-at-infinity representation is (0,0).
        if (p.x == 0 && p.y == 0) return true;
        return mulmod(p.y, p.y, FQ)
            == addmod(mulmod(mulmod(p.x, p.x, FQ), p.x, FQ), 3, FQ);
    }

    function _g2Valid(G2 calldata p) private pure returns (bool) {
        if (p.xIm >= FQ || p.xRe >= FQ || p.yIm >= FQ || p.yRe >= FQ) return false;
        // Reject G2 infinity. The pairing precompile checks curve/subgroup.
        return (p.xIm | p.xRe | p.yIm | p.yRe) != 0;
    }
}

