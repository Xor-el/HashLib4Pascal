// PMULL implementation of CRC folding (PMULL/PMULL2 + TBL byte-reverse) +
// Barrett reduction for non-reflected (MSB-first) CRCs with width 8..64.
// ABI (after HlpSimdProc4Begin_aarch64.inc): x0 = AData, w1 = ALength (>= 16,
//   multiple of 16), x2 = AState, x3 = AConstants (PCRCFoldRuntimeCtx;
//   FoldConstants at +0).
//   AState: pointer to the initial CRC pre-shifted left by (64 - Width) as
//   one UInt64. Returns the final CRC in x0.
//   AConstants: [+0] Fold_4x128, [+16] Fold_1x128, [+32] Barrett,
//               [+64] BswapMask, [+80] CrcBits, [+88] BarrettShift.
// Register map:
//   v0-v3    = fold accumulators (xmm0-3)
//   v4       = pmull-hi temp (xmm4)
//   v5       = loaded 16-byte block (xmm5)
//   v6       = BswapMask then Barrett consts [G : mu_lo] (xmm6)
//   v7       = Fold_8x128 / Fold_4x128 then Fold_1x128 (xmm7)
//   v17      = dup staging for clmul hi*lo ($01) Barrett mix
//   v19-v22  = fold-by-8 upper accumulators (xmm8-11)
// Saves: none (leaf nostackframe; caller-saved GPR/vector only: v0-v7, v17,
//   v19-v22).
// AArch64 vector instructions are .long-encoded for broad assembler compatibility.
// Reference: Linux kernel crc-pclmul-template.S (Eric Biggers), HashLib
//   CRCFoldForwardPclmul_x86_64.inc.

  .long 0x3dc01066                    // ldr q6, [x3, #64]
  .long 0x7102003f                    // cmp w1, #128
  b.lo .Lcrc_fwd_check64
  .long 0x3dc00c67                    // ldr q7, [x3, #48]
  .long 0x3dc00000                    // ldr q0, [x0, #0]
  .long 0x4e060000                    // tbl v0.16b, {v0.16b}, v6.16b
  .long 0x3dc00401                    // ldr q1, [x0, #16]
  .long 0x4e060021                    // tbl v1.16b, {v1.16b}, v6.16b
  .long 0x3dc00802                    // ldr q2, [x0, #32]
  .long 0x4e060042                    // tbl v2.16b, {v2.16b}, v6.16b
  .long 0x3dc00c03                    // ldr q3, [x0, #48]
  .long 0x4e060063                    // tbl v3.16b, {v3.16b}, v6.16b
  .long 0x3dc01013                    // ldr q19, [x0, #64]
  .long 0x4e060273                    // tbl v19.16b, {v19.16b}, v6.16b
  .long 0x3dc01414                    // ldr q20, [x0, #80]
  .long 0x4e060294                    // tbl v20.16b, {v20.16b}, v6.16b
  .long 0x3dc01815                    // ldr q21, [x0, #96]
  .long 0x4e0602b5                    // tbl v21.16b, {v21.16b}, v6.16b
  .long 0x3dc01c16                    // ldr q22, [x0, #112]
  .long 0x4e0602d6                    // tbl v22.16b, {v22.16b}, v6.16b
  .long 0xf9400044                    // ldr x4, [x2]
  .long 0x6e241c84                    // eor v4.16b, v4.16b, v4.16b
  .long 0x4e181c84                    // ins v4.d[1], x4
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x91020000                    // add x0, x0, #128
  .long 0x51020021                    // sub w1, w1, #128
  .long 0x7102003f                    // cmp w1, #128
  b.lo .Lcrc_fwd_fold8_reduce
.Lcrc_fwd_fold8_loop:
  .long 0x4ea01c04                    // orr v4.16b, v0.16b, v0.16b
  .long 0x0ee7e000                    // pmull v0.1q, v0.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x3dc00005                    // ldr q5, [x0, #0]
  .long 0x4e0600a5                    // tbl v5.16b, {v5.16b}, v6.16b
  .long 0x6e251c00                    // eor v0.16b, v0.16b, v5.16b
  .long 0x4ea11c24                    // orr v4.16b, v1.16b, v1.16b
  .long 0x0ee7e021                    // pmull v1.1q, v1.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241c21                    // eor v1.16b, v1.16b, v4.16b
  .long 0x3dc00405                    // ldr q5, [x0, #16]
  .long 0x4e0600a5                    // tbl v5.16b, {v5.16b}, v6.16b
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x4ea21c44                    // orr v4.16b, v2.16b, v2.16b
  .long 0x0ee7e042                    // pmull v2.1q, v2.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x3dc00805                    // ldr q5, [x0, #32]
  .long 0x4e0600a5                    // tbl v5.16b, {v5.16b}, v6.16b
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x4ea31c64                    // orr v4.16b, v3.16b, v3.16b
  .long 0x0ee7e063                    // pmull v3.1q, v3.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241c63                    // eor v3.16b, v3.16b, v4.16b
  .long 0x3dc00c05                    // ldr q5, [x0, #48]
  .long 0x4e0600a5                    // tbl v5.16b, {v5.16b}, v6.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x4eb31e64                    // orr v4.16b, v19.16b, v19.16b
  .long 0x0ee7e273                    // pmull v19.1q, v19.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241e73                    // eor v19.16b, v19.16b, v4.16b
  .long 0x3dc01005                    // ldr q5, [x0, #64]
  .long 0x4e0600a5                    // tbl v5.16b, {v5.16b}, v6.16b
  .long 0x6e251e73                    // eor v19.16b, v19.16b, v5.16b
  .long 0x4eb41e84                    // orr v4.16b, v20.16b, v20.16b
  .long 0x0ee7e294                    // pmull v20.1q, v20.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241e94                    // eor v20.16b, v20.16b, v4.16b
  .long 0x3dc01405                    // ldr q5, [x0, #80]
  .long 0x4e0600a5                    // tbl v5.16b, {v5.16b}, v6.16b
  .long 0x6e251e94                    // eor v20.16b, v20.16b, v5.16b
  .long 0x4eb51ea4                    // orr v4.16b, v21.16b, v21.16b
  .long 0x0ee7e2b5                    // pmull v21.1q, v21.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x3dc01805                    // ldr q5, [x0, #96]
  .long 0x4e0600a5                    // tbl v5.16b, {v5.16b}, v6.16b
  .long 0x6e251eb5                    // eor v21.16b, v21.16b, v5.16b
  .long 0x4eb61ec4                    // orr v4.16b, v22.16b, v22.16b
  .long 0x0ee7e2d6                    // pmull v22.1q, v22.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241ed6                    // eor v22.16b, v22.16b, v4.16b
  .long 0x3dc01c05                    // ldr q5, [x0, #112]
  .long 0x4e0600a5                    // tbl v5.16b, {v5.16b}, v6.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x91020000                    // add x0, x0, #128
  .long 0x51020021                    // sub w1, w1, #128
  .long 0x7102003f                    // cmp w1, #128
  b.hs .Lcrc_fwd_fold8_loop
.Lcrc_fwd_fold8_reduce:
  .long 0x3dc00067                    // ldr q7, [x3]
  .long 0x4ea01c04                    // orr v4.16b, v0.16b, v0.16b
  .long 0x0ee7e000                    // pmull v0.1q, v0.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x6e331c00                    // eor v0.16b, v0.16b, v19.16b
  .long 0x4ea11c24                    // orr v4.16b, v1.16b, v1.16b
  .long 0x0ee7e021                    // pmull v1.1q, v1.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241c21                    // eor v1.16b, v1.16b, v4.16b
  .long 0x6e341c21                    // eor v1.16b, v1.16b, v20.16b
  .long 0x4ea21c44                    // orr v4.16b, v2.16b, v2.16b
  .long 0x0ee7e042                    // pmull v2.1q, v2.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e351c42                    // eor v2.16b, v2.16b, v21.16b
  .long 0x4ea31c64                    // orr v4.16b, v3.16b, v3.16b
  .long 0x0ee7e063                    // pmull v3.1q, v3.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241c63                    // eor v3.16b, v3.16b, v4.16b
  .long 0x6e361c63                    // eor v3.16b, v3.16b, v22.16b
  b .Lcrc_fwd_fold4_done
.Lcrc_fwd_check64:
  .long 0x7101003f                    // cmp w1, #64
  b.hs .Lcrc_fwd_large
  .long 0x3dc00467                    // ldr q7, [x3, #16]
  .long 0x3dc00000                    // ldr q0, [x0]
  .long 0x4e060000                    // tbl v0.16b, {v0.16b}, v6.16b
  .long 0xf9400044                    // ldr x4, [x2]
  .long 0x6e241c84                    // eor v4.16b, v4.16b, v4.16b
  .long 0x4e181c84                    // ins v4.d[1], x4
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x91004000                    // add x0, x0, #16
  .long 0x51004021                    // sub w1, w1, #16
  b .Lcrc_fwd_fold1_check
.Lcrc_fwd_large:
  .long 0x3dc00067                    // ldr q7, [x3]
  .long 0x3dc00000                    // ldr q0, [x0, #0]
  .long 0x4e060000                    // tbl v0.16b, {v0.16b}, v6.16b
  .long 0x3dc00401                    // ldr q1, [x0, #16]
  .long 0x4e060021                    // tbl v1.16b, {v1.16b}, v6.16b
  .long 0x3dc00802                    // ldr q2, [x0, #32]
  .long 0x4e060042                    // tbl v2.16b, {v2.16b}, v6.16b
  .long 0x3dc00c03                    // ldr q3, [x0, #48]
  .long 0x4e060063                    // tbl v3.16b, {v3.16b}, v6.16b
  .long 0xf9400044                    // ldr x4, [x2]
  .long 0x6e241c84                    // eor v4.16b, v4.16b, v4.16b
  .long 0x4e181c84                    // ins v4.d[1], x4
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x91010000                    // add x0, x0, #64
  .long 0x51010021                    // sub w1, w1, #64
  .long 0x7101003f                    // cmp w1, #64
  b.lo .Lcrc_fwd_fold4_done
.Lcrc_fwd_fold4_loop:
  .long 0x4ea01c04                    // orr v4.16b, v0.16b, v0.16b
  .long 0x0ee7e000                    // pmull v0.1q, v0.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x3dc00005                    // ldr q5, [x0, #0]
  .long 0x4e0600a5                    // tbl v5.16b, {v5.16b}, v6.16b
  .long 0x6e251c00                    // eor v0.16b, v0.16b, v5.16b
  .long 0x4ea11c24                    // orr v4.16b, v1.16b, v1.16b
  .long 0x0ee7e021                    // pmull v1.1q, v1.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241c21                    // eor v1.16b, v1.16b, v4.16b
  .long 0x3dc00405                    // ldr q5, [x0, #16]
  .long 0x4e0600a5                    // tbl v5.16b, {v5.16b}, v6.16b
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x4ea21c44                    // orr v4.16b, v2.16b, v2.16b
  .long 0x0ee7e042                    // pmull v2.1q, v2.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x3dc00805                    // ldr q5, [x0, #32]
  .long 0x4e0600a5                    // tbl v5.16b, {v5.16b}, v6.16b
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x4ea31c64                    // orr v4.16b, v3.16b, v3.16b
  .long 0x0ee7e063                    // pmull v3.1q, v3.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241c63                    // eor v3.16b, v3.16b, v4.16b
  .long 0x3dc00c05                    // ldr q5, [x0, #48]
  .long 0x4e0600a5                    // tbl v5.16b, {v5.16b}, v6.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x91010000                    // add x0, x0, #64
  .long 0x51010021                    // sub w1, w1, #64
  .long 0x7101003f                    // cmp w1, #64
  b.hs .Lcrc_fwd_fold4_loop
.Lcrc_fwd_fold4_done:
  .long 0x3dc00467                    // ldr q7, [x3, #16]
  .long 0x4ea01c04                    // orr v4.16b, v0.16b, v0.16b
  .long 0x0ee7e000                    // pmull v0.1q, v0.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x4ea01c04                    // orr v4.16b, v0.16b, v0.16b
  .long 0x0ee7e000                    // pmull v0.1q, v0.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x4ea01c04                    // orr v4.16b, v0.16b, v0.16b
  .long 0x0ee7e000                    // pmull v0.1q, v0.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
.Lcrc_fwd_fold1_check:
  .long 0x7100403f                    // cmp w1, #16
  b.lo .Lcrc_fwd_fold1_done
.Lcrc_fwd_fold1_loop:
  .long 0x4ea01c04                    // orr v4.16b, v0.16b, v0.16b
  .long 0x0ee7e000                    // pmull v0.1q, v0.1d, v7.1d
  .long 0x4ee7e084                    // pmull2 v4.1q, v4.2d, v7.2d
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x3dc00005                    // ldr q5, [x0, #0]
  .long 0x4e0600a5                    // tbl v5.16b, {v5.16b}, v6.16b
  .long 0x6e251c00                    // eor v0.16b, v0.16b, v5.16b
  .long 0x91004000                    // add x0, x0, #16
  .long 0x51004021                    // sub w1, w1, #16
  .long 0x7100403f                    // cmp w1, #16
  b.hs .Lcrc_fwd_fold1_loop
.Lcrc_fwd_fold1_done:
  .long 0x3dc00866                    // ldr q6, [x3, #32]
  .long 0x4e180411                    // dup v17.2d, v0.d[1]
  .long 0x0ee6e221                    // pmull v1.1q, v17.1d, v6.1d
  .long 0x6e201c21                    // eor v1.16b, v1.16b, v0.16b
  .long 0x4ee6e021                    // pmull2 v1.1q, v1.2d, v6.2d
  .long 0xfd402c62                    // ldr d2, [x3, #88]
  .long 0x4e080442                    // dup v2.2d, v2.d[0]
  .long 0x6ee24421                    // ushl v1.2d, v1.2d, v2.2d
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x0ee6e001                    // pmull v1.1q, v0.1d, v6.1d
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x4ee6e000                    // pmull2 v0.1q, v0.2d, v6.2d
  .long 0x4e083c00                    // umov x0, v0.d[0]
  ret
