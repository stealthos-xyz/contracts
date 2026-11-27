// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaCaulkPlusGate1Research as Caulk} from "../../../contracts/src/vanta/VantaCaulkPlusGate1Research.sol";

/// @notice Checks ONE of the four original Caulk+ identities per call.
/// @dev RESEARCH ONLY. This contract grants no checkpoint or custody authority.
/// The transcript is derived by the unmodified, runtime-pinned Caulk contract.
/// Arithmetic and validation helpers are copied from source git blob
/// db550e581713cb63fc196442877b98028d2e4a80; check-source-pins.mjs guards drift.
/// Splitting identities does not split an individual pairing product and does
/// not introduce batching coefficients or alter the existing proof protocol.
contract VantaCaulkPlusStagedResearch {
    uint256 private constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant FQ =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    Caulk public immutable transcriptVerifier;
    bytes32 public immutable transcriptCodeHash;

    constructor(address transcript) {
        require(transcript.code.length != 0, "Vanta research transcript missing");
        transcriptVerifier = Caulk(transcript);
        transcriptCodeHash = transcript.codehash;
    }

    /// @param equation Zero-based equation index: 0, 1, 2 or 3.
    /// @param arity Exact native query arity: 1 for policy, 8 or 32 for family.
    /// @dev All original point/scalar checks run for each stage. G2 curve and
    /// subgroup validation remains in the pairing precompile for points used by
    /// that equation. A caller must require ALL four stages for one bound proof.
    function verifyEquation(
        uint8 equation,
        uint8 arity,
        Caulk.Table calldata t,
        Caulk.Srs calldata s,
        Caulk.Proof calldata p,
        bytes calldata context
    ) external view returns (bool) {
        if (address(transcriptVerifier).codehash != transcriptCodeHash || equation > 3)
            return false;
        if ((arity != 1 && arity != 8 && arity != 32) || t.n != 65_536 ||
            context.length > 4096 || p.v1 >= FR || p.v2 >= FR) return false;
        if (s.g1.x != 1 || s.g1.y != 2) return false;
        if (!_validG1(t.commitment) || !_validG1(t.zH) || !_validG1(t.query) ||
            !_validG1(p.zI) || !_validG1(p.cI) || !_validG1(p.u) ||
            !_validG1(p.h) || !_validG1(p.pi1) || !_validG1(p.pi2) ||
            !_validG1(p.pi3) || !_validG2(s.g20) || !_validG2(s.g21) ||
            !_validG2(p.w)) return false;
        if (_isInfinity(t.commitment) || _isInfinity(t.query)) return false;

        uint256 chi1;
        uint256 chi2;
        uint256 alpha;
        if (arity == 1) {
            (chi1, chi2, alpha) = transcriptVerifier.deriveSingletonChallenges(t, p, context);
        } else {
            (chi1, chi2, alpha) =
                transcriptVerifier.deriveChallengesForArity(arity, t, p, context);
        }

        // (1) e(U-v1*G1, G20) = e(pi1, G21-alpha*G20).
        if (equation == 0) return _kzg(s, p.u, alpha, p.v1, p.pi1);

        // (2) e((Zi+chi1*Ci)-v2*G1, G20) = e(pi2, G21-v1*G20).
        if (equation == 1) {
            (bool ok, Caulk.G1 memory left) = _mul(p.cI, chi1);
            if (!ok) return false;
            (ok, left) = _add(p.zI, left);
            return ok && _kzg(s, left, p.v1, p.v2, p.pi2);
        }

        // (3) e(v2*G1-chi1*E-(alpha^m-1)*H, G20)
        //       = e(pi3, G21-alpha*G20).
        if (equation == 2) {
            (bool ok, Caulk.G1 memory left) = _mul(s.g1, p.v2);
            if (!ok) return false;
            (bool mulOk, Caulk.G1 memory scaled) = _mul(t.query, chi1);
            if (!mulOk) return false;
            (ok, left) = _add(left, _neg(scaled));
            if (!ok) return false;
            (mulOk, scaled) = _mul(p.h, addmod(_powerForArity(alpha, arity), FR - 1, FR));
            if (!mulOk) return false;
            (ok, left) = _add(left, _neg(scaled));
            return ok && _kzg(s, left, alpha, 0, p.pi3);
        }

        // (4) e(C-Ci+chi2*ZH, G20) = e(Zi,W).
        {
            (bool ok, Caulk.G1 memory left) = _add(t.commitment, _neg(p.cI));
            if (!ok) return false;
            (bool mulOk, Caulk.G1 memory scaled) = _mul(t.zH, chi2);
            if (!mulOk) return false;
            (ok, left) = _add(left, scaled);
            return ok && _pairEq(left, s.g20, p.zI, p.w);
        }
    }

    function _kzg(
        Caulk.Srs calldata s, Caulk.G1 memory commitment,
        uint256 point, uint256 value, Caulk.G1 memory pi
    ) private view returns (bool) {
        (bool ok, Caulk.G1 memory scaled) = _mul(s.g1, value);
        if (!ok) return false;
        (bool addOk, Caulk.G1 memory left) = _add(commitment, _neg(scaled));
        if (!addOk) return false;
        (addOk, scaled) = _mul(pi, point);
        if (!addOk) return false;
        (addOk, left) = _add(left, scaled);
        return addOk && _pairEq(left, s.g20, pi, s.g21);
    }

    function _pairEq(
        Caulk.G1 memory left, Caulk.G2 memory leftG2,
        Caulk.G1 memory right, Caulk.G2 memory rightG2
    ) private view returns (bool) {
        Caulk.G1 memory negRight = _neg(right);
        bytes memory pairs = abi.encodePacked(
            left.x, left.y, leftG2.xIm, leftG2.xRe, leftG2.yIm, leftG2.yRe,
            negRight.x, negRight.y, rightG2.xIm, rightG2.xRe, rightG2.yIm, rightG2.yRe
        );
        (bool ok, bytes memory response) = address(0x08).staticcall(pairs);
        return ok && response.length == 32 && abi.decode(response, (uint256)) == 1;
    }

    function _add(Caulk.G1 memory a, Caulk.G1 memory b)
        private view returns (bool ok, Caulk.G1 memory result)
    {
        (bool success, bytes memory response) = address(0x06).staticcall(
            abi.encodePacked(a.x, a.y, b.x, b.y)
        );
        if (!success || response.length != 64) return (false, result);
        (result.x, result.y) = abi.decode(response, (uint256, uint256));
        return (true, result);
    }

    function _mul(Caulk.G1 memory a, uint256 scalar)
        private view returns (bool ok, Caulk.G1 memory result)
    {
        (bool success, bytes memory response) = address(0x07).staticcall(
            abi.encodePacked(a.x, a.y, scalar)
        );
        if (!success || response.length != 64) return (false, result);
        (result.x, result.y) = abi.decode(response, (uint256, uint256));
        return (true, result);
    }

    function _neg(Caulk.G1 memory p) private pure returns (Caulk.G1 memory) {
        if (p.y != 0) p.y = FQ - p.y;
        return p;
    }

    function _isInfinity(Caulk.G1 memory p) private pure returns (bool) {
        return p.x == 0 && p.y == 0;
    }

    function _validG1(Caulk.G1 memory p) private pure returns (bool) {
        if (p.x >= FQ || p.y >= FQ) return false;
        if (_isInfinity(p)) return true;
        return mulmod(p.y, p.y, FQ) ==
            addmod(mulmod(mulmod(p.x, p.x, FQ), p.x, FQ), 3, FQ);
    }

    function _validG2(Caulk.G2 memory p) private pure returns (bool) {
        return p.xIm < FQ && p.xRe < FQ && p.yIm < FQ && p.yRe < FQ &&
            (p.xIm | p.xRe | p.yIm | p.yRe) != 0;
    }

    function _powerForArity(uint256 value, uint8 arity) private pure returns (uint256) {
        if (arity == 1) return value;
        for (uint256 i; i < (arity == 8 ? 3 : 5); ++i) value = mulmod(value, value, FR);
        return value;
    }
}
