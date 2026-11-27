# Vanta TRON feasibility (research only)

2026-11-27. Branch: vanta-tron. No broadcast, public testnet deployment, signing, production credentials, activation, ceremony contribution, SDK publication, PR or merge. No changes to existing DogeOS/Base/Solana runtime. All conclusions are provisional until TVM execution. Keep research files outside production paths.

Central work: https://github.com/stealthos-xyz/privacy-protocol/tree/vanta-tron/research/vanta-tron

## Source-level review
Gate0 ccGroth16, Caulk+ Gate1 and CP_link use BN254 0x06/07/08 and strict result lengths. The TVM supports those addresses and imaginary-first G2 ordering (see java-tron PrecompiledContracts.java). The six-input research bundle uses 17 multiplications, 18 additions and 15 pairs across six calls, giving 884,700 Energy precompile-only under Istanbul pricing; actual TVM execution and fees remain unmeasured. Fee Gate0 has 40/41 inputs. The source manifest and exact compiler configuration (0.8.26/Cancun/via-IR) remain untouched. Research compiler/opcode feature gates, CREATE2 address derivation, native TRX six-decimal amounts, TRC20 return/balance behavior, account activation, code hash, full settlement and revert/rollback parity. Run synthetic non-custodial fixtures on isolated local TVM only; both 8x5 and 32x5 plus actual fee/KZG paths must pass. No production verifier changes or funds-moving research verifier.
