// BLAKE2b compress AArch64 NEON implementation.
// Expects AAPCS64: x0 = state ptr (8 x UInt64), x1 = message ptr (128 bytes),
//   x2 = counter+flags ptr (32 bytes: t[0..1], f[0..1]), x3 = IV ptr (8 x UInt64).
// Leaf nostackframe; uses v8-v15 for message block (d8-d15 lanes; no save/restore).
// Reference: BLAKE2/BLAKE2 neon/blake2b-neon.c, HashLib Blake2BCompressSse2_x86_64.inc.
// AArch64 vector instructions are .long-encoded for broad assembler compatibility.
// Register map:
//   v0, v1   = row1l, row1h (h[0..3] working, 2 x u64 each)
//   v2, v3   = row2l, row2h (h[4..7] working)
//   v4, v5   = row3l, row3h (IV[0..3])
//   v6, v7   = row4l, row4h (IV[4..7] XOR counter+flags)
//   v8-v15   = message block (16 x UInt64)
//   v16-v19  = saved initial row1l/h, row2l/h for the final feed-forward XOR
//   v20      = message gather temp b0 (G function)
//   v21-v23  = rotate / diagonalize temps (2-op insert rotates rename the
//     rotated row halves through v21/v22; b1 gather uses v23)
//   u64 ror-by-32 uses rev64.4s (vrev64q_u32), not rev64.16b.

  {$I ..\..\Include\Simd\Common\HlpSimdNonVolatileSave_aarch64.inc}

  .long 0xad400400                    // ldp q0, q1, [x0]
  .long 0xad410c02                    // ldp q2, q3, [x0, #32]
  .long 0x4ea01c10                    // orr v16.16b, v0.16b, v0.16b
  .long 0x4ea11c31                    // orr v17.16b, v1.16b, v1.16b
  .long 0x4ea21c52                    // orr v18.16b, v2.16b, v2.16b
  .long 0x4ea31c73                    // orr v19.16b, v3.16b, v3.16b
  .long 0xad401464                    // ldp q4, q5, [x3]
  .long 0xad411c66                    // ldp q6, q7, [x3, #32]
  .long 0xad405855                    // ldp q21, q22, [x2]
  .long 0x6e351cc6                    // eor v6.16b, v6.16b, v21.16b
  .long 0x6e361ce7                    // eor v7.16b, v7.16b, v22.16b
  .long 0xad402428                    // ldp q8, q9, [x1]
  .long 0xad412c2a                    // ldp q10, q11, [x1, #32]
  .long 0xad42342c                    // ldp q12, q13, [x1, #64]
  .long 0xad433c2e                    // ldp q14, q15, [x1, #96]
  .long 0x6e080514                    // ins v20.d[0], v8.d[0]
  .long 0x6e180534                    // ins v20.d[1], v9.d[0]
  .long 0x6e080557                    // ins v23.d[0], v10.d[0]
  .long 0x6e180577                    // ins v23.d[1], v11.d[0]
  .long 0x4ee28694                    // add v20.2d, v20.2d, v2.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee386f7                    // add v23.2d, v23.2d, v3.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x4ea008c6                    // rev64 v6.4s, v6.4s
  .long 0x4ea008e7                    // rev64 v7.4s, v7.4s
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6f680455                    // ushr v21.2d, v2.2d, #24
  .long 0x6f685455                    // sli v21.2d, v2.2d, #40
  .long 0x6f680476                    // ushr v22.2d, v3.2d, #24
  .long 0x6f685476                    // sli v22.2d, v3.2d, #40
  .long 0x6e084514                    // ins v20.d[0], v8.d[1]
  .long 0x6e184534                    // ins v20.d[1], v9.d[1]
  .long 0x6e084557                    // ins v23.d[0], v10.d[1]
  .long 0x6e184577                    // ins v23.d[1], v11.d[1]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004c2                    // ushr v2.2d, v6.2d, #16
  .long 0x6f7054c2                    // sli v2.2d, v6.2d, #48
  .long 0x6f7004e3                    // ushr v3.2d, v7.2d, #16
  .long 0x6f7054e3                    // sli v3.2d, v7.2d, #48
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a6                    // add v6.2d, v21.2d, v21.2d
  .long 0x6f4146a6                    // sri v6.2d, v21.2d, #63
  .long 0x4ef686c7                    // add v7.2d, v22.2d, v22.2d
  .long 0x6f4146c7                    // sri v7.2d, v22.2d, #63
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x6e080594                    // ins v20.d[0], v12.d[0]
  .long 0x6e1805b4                    // ins v20.d[1], v13.d[0]
  .long 0x6e0805d7                    // ins v23.d[0], v14.d[0]
  .long 0x6e1805f7                    // ins v23.d[1], v15.d[0]
  .long 0x4ee68694                    // add v20.2d, v20.2d, v6.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee786f7                    // add v23.2d, v23.2d, v7.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x4ea00842                    // rev64 v2.4s, v2.4s
  .long 0x4ea00863                    // rev64 v3.4s, v3.4s
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241cc6                    // eor v6.16b, v6.16b, v4.16b
  .long 0x6e251ce7                    // eor v7.16b, v7.16b, v5.16b
  .long 0x6f6804d5                    // ushr v21.2d, v6.2d, #24
  .long 0x6f6854d5                    // sli v21.2d, v6.2d, #40
  .long 0x6f6804f6                    // ushr v22.2d, v7.2d, #24
  .long 0x6f6854f6                    // sli v22.2d, v7.2d, #40
  .long 0x6e084594                    // ins v20.d[0], v12.d[1]
  .long 0x6e1845b4                    // ins v20.d[1], v13.d[1]
  .long 0x6e0845d7                    // ins v23.d[0], v14.d[1]
  .long 0x6e1845f7                    // ins v23.d[1], v15.d[1]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x6f700446                    // ushr v6.2d, v2.2d, #16
  .long 0x6f705446                    // sli v6.2d, v2.2d, #48
  .long 0x6f700467                    // ushr v7.2d, v3.2d, #16
  .long 0x6f705467                    // sli v7.2d, v3.2d, #48
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a2                    // add v2.2d, v21.2d, v21.2d
  .long 0x6f4146a2                    // sri v2.2d, v21.2d, #63
  .long 0x4ef686c3                    // add v3.2d, v22.2d, v22.2d
  .long 0x6f4146c3                    // sri v3.2d, v22.2d, #63
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x6e0805f4                    // ins v20.d[0], v15.d[0]
  .long 0x6e180554                    // ins v20.d[1], v10.d[0]
  .long 0x6e084597                    // ins v23.d[0], v12.d[1]
  .long 0x6e1845d7                    // ins v23.d[1], v14.d[1]
  .long 0x4ee28694                    // add v20.2d, v20.2d, v2.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee386f7                    // add v23.2d, v23.2d, v3.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x4ea008c6                    // rev64 v6.4s, v6.4s
  .long 0x4ea008e7                    // rev64 v7.4s, v7.4s
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6f680455                    // ushr v21.2d, v2.2d, #24
  .long 0x6f685455                    // sli v21.2d, v2.2d, #40
  .long 0x6f680476                    // ushr v22.2d, v3.2d, #24
  .long 0x6f685476                    // sli v22.2d, v3.2d, #40
  .long 0x6e0805b4                    // ins v20.d[0], v13.d[0]
  .long 0x6e180594                    // ins v20.d[1], v12.d[0]
  .long 0x6e0b41f7                    // ext v23.16b, v15.16b, v11.16b, #8
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004c2                    // ushr v2.2d, v6.2d, #16
  .long 0x6f7054c2                    // sli v2.2d, v6.2d, #48
  .long 0x6f7004e3                    // ushr v3.2d, v7.2d, #16
  .long 0x6f7054e3                    // sli v3.2d, v7.2d, #48
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a6                    // add v6.2d, v21.2d, v21.2d
  .long 0x6f4146a6                    // sri v6.2d, v21.2d, #63
  .long 0x4ef686c7                    // add v7.2d, v22.2d, v22.2d
  .long 0x6f4146c7                    // sri v7.2d, v22.2d, #63
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x6e084114                    // ext v20.16b, v8.16b, v8.16b, #8
  .long 0x6e0845b7                    // ins v23.d[0], v13.d[1]
  .long 0x6e184557                    // ins v23.d[1], v10.d[1]
  .long 0x4ee68694                    // add v20.2d, v20.2d, v6.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee786f7                    // add v23.2d, v23.2d, v7.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x4ea00842                    // rev64 v2.4s, v2.4s
  .long 0x4ea00863                    // rev64 v3.4s, v3.4s
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241cc6                    // eor v6.16b, v6.16b, v4.16b
  .long 0x6e251ce7                    // eor v7.16b, v7.16b, v5.16b
  .long 0x6f6804d5                    // ushr v21.2d, v6.2d, #24
  .long 0x6f6854d5                    // sli v21.2d, v6.2d, #40
  .long 0x6f6804f6                    // ushr v22.2d, v7.2d, #24
  .long 0x6f6854f6                    // sli v22.2d, v7.2d, #40
  .long 0x6e0805d4                    // ins v20.d[0], v14.d[0]
  .long 0x6e180534                    // ins v20.d[1], v9.d[0]
  .long 0x6e084577                    // ins v23.d[0], v11.d[1]
  .long 0x6e184537                    // ins v23.d[1], v9.d[1]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x6f700446                    // ushr v6.2d, v2.2d, #16
  .long 0x6f705446                    // sli v6.2d, v2.2d, #48
  .long 0x6f700467                    // ushr v7.2d, v3.2d, #16
  .long 0x6f705467                    // sli v7.2d, v3.2d, #48
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a2                    // add v2.2d, v21.2d, v21.2d
  .long 0x6f4146a2                    // sri v2.2d, v21.2d, #63
  .long 0x4ef686c3                    // add v3.2d, v22.2d, v22.2d
  .long 0x6f4146c3                    // sri v3.2d, v22.2d, #63
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x6e0e41b4                    // ext v20.16b, v13.16b, v14.16b, #8
  .long 0x6e084557                    // ins v23.d[0], v10.d[1]
  .long 0x6e1845f7                    // ins v23.d[1], v15.d[1]
  .long 0x4ee28694                    // add v20.2d, v20.2d, v2.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee386f7                    // add v23.2d, v23.2d, v3.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x4ea008c6                    // rev64 v6.4s, v6.4s
  .long 0x4ea008e7                    // rev64 v7.4s, v7.4s
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6f680455                    // ushr v21.2d, v2.2d, #24
  .long 0x6f685455                    // sli v21.2d, v2.2d, #40
  .long 0x6f680476                    // ushr v22.2d, v3.2d, #24
  .long 0x6f685476                    // sli v22.2d, v3.2d, #40
  .long 0x6e080594                    // ins v20.d[0], v12.d[0]
  .long 0x6e180514                    // ins v20.d[1], v8.d[0]
  .long 0x6e080537                    // ins v23.d[0], v9.d[0]
  .long 0x6e1845d7                    // ins v23.d[1], v14.d[1]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004c2                    // ushr v2.2d, v6.2d, #16
  .long 0x6f7054c2                    // sli v2.2d, v6.2d, #48
  .long 0x6f7004e3                    // ushr v3.2d, v7.2d, #16
  .long 0x6f7054e3                    // sli v3.2d, v7.2d, #48
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a6                    // add v6.2d, v21.2d, v21.2d
  .long 0x6f4146a6                    // sri v6.2d, v21.2d, #63
  .long 0x4ef686c7                    // add v7.2d, v22.2d, v22.2d
  .long 0x6f4146c7                    // sri v7.2d, v22.2d, #63
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x6e0805b4                    // ins v20.d[0], v13.d[0]
  .long 0x6e184534                    // ins v20.d[1], v9.d[1]
  .long 0x6e084577                    // ins v23.d[0], v11.d[1]
  .long 0x6e184597                    // ins v23.d[1], v12.d[1]
  .long 0x4ee68694                    // add v20.2d, v20.2d, v6.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee786f7                    // add v23.2d, v23.2d, v7.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x4ea00842                    // rev64 v2.4s, v2.4s
  .long 0x4ea00863                    // rev64 v3.4s, v3.4s
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241cc6                    // eor v6.16b, v6.16b, v4.16b
  .long 0x6e251ce7                    // eor v7.16b, v7.16b, v5.16b
  .long 0x6f6804d5                    // ushr v21.2d, v6.2d, #24
  .long 0x6f6854d5                    // sli v21.2d, v6.2d, #40
  .long 0x6f6804f6                    // ushr v22.2d, v7.2d, #24
  .long 0x6f6854f6                    // sli v22.2d, v7.2d, #40
  .long 0x6e0805f4                    // ins v20.d[0], v15.d[0]
  .long 0x6e180574                    // ins v20.d[1], v11.d[0]
  .long 0x6e0a4117                    // ext v23.16b, v8.16b, v10.16b, #8
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x6f700446                    // ushr v6.2d, v2.2d, #16
  .long 0x6f705446                    // sli v6.2d, v2.2d, #48
  .long 0x6f700467                    // ushr v7.2d, v3.2d, #16
  .long 0x6f705467                    // sli v7.2d, v3.2d, #48
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a2                    // add v2.2d, v21.2d, v21.2d
  .long 0x6f4146a2                    // sri v2.2d, v21.2d, #63
  .long 0x4ef686c3                    // add v3.2d, v22.2d, v22.2d
  .long 0x6f4146c3                    // sri v3.2d, v22.2d, #63
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x6e084574                    // ins v20.d[0], v11.d[1]
  .long 0x6e184534                    // ins v20.d[1], v9.d[1]
  .long 0x6e0845d7                    // ins v23.d[0], v14.d[1]
  .long 0x6e1845b7                    // ins v23.d[1], v13.d[1]
  .long 0x4ee28694                    // add v20.2d, v20.2d, v2.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee386f7                    // add v23.2d, v23.2d, v3.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x4ea008c6                    // rev64 v6.4s, v6.4s
  .long 0x4ea008e7                    // rev64 v7.4s, v7.4s
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6f680455                    // ushr v21.2d, v2.2d, #24
  .long 0x6f685455                    // sli v21.2d, v2.2d, #40
  .long 0x6f680476                    // ushr v22.2d, v3.2d, #24
  .long 0x6f685476                    // sli v22.2d, v3.2d, #40
  .long 0x6e084594                    // ins v20.d[0], v12.d[1]
  .long 0x6e184514                    // ins v20.d[1], v8.d[1]
  .long 0x6e0805d7                    // ins v23.d[0], v14.d[0]
  .long 0x6e1805f7                    // ins v23.d[1], v15.d[0]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004c2                    // ushr v2.2d, v6.2d, #16
  .long 0x6f7054c2                    // sli v2.2d, v6.2d, #48
  .long 0x6f7004e3                    // ushr v3.2d, v7.2d, #16
  .long 0x6f7054e3                    // sli v3.2d, v7.2d, #48
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a6                    // add v6.2d, v21.2d, v21.2d
  .long 0x6f4146a6                    // sri v6.2d, v21.2d, #63
  .long 0x4ef686c7                    // add v7.2d, v22.2d, v22.2d
  .long 0x6f4146c7                    // sri v7.2d, v22.2d, #63
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x6e080534                    // ins v20.d[0], v9.d[0]
  .long 0x6e184554                    // ins v20.d[1], v10.d[1]
  .long 0x6e080557                    // ins v23.d[0], v10.d[0]
  .long 0x6e1845f7                    // ins v23.d[1], v15.d[1]
  .long 0x4ee68694                    // add v20.2d, v20.2d, v6.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee786f7                    // add v23.2d, v23.2d, v7.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x4ea00842                    // rev64 v2.4s, v2.4s
  .long 0x4ea00863                    // rev64 v3.4s, v3.4s
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241cc6                    // eor v6.16b, v6.16b, v4.16b
  .long 0x6e251ce7                    // eor v7.16b, v7.16b, v5.16b
  .long 0x6f6804d5                    // ushr v21.2d, v6.2d, #24
  .long 0x6f6854d5                    // sli v21.2d, v6.2d, #40
  .long 0x6f6804f6                    // ushr v22.2d, v7.2d, #24
  .long 0x6f6854f6                    // sli v22.2d, v7.2d, #40
  .long 0x6e080574                    // ins v20.d[0], v11.d[0]
  .long 0x6e1805b4                    // ins v20.d[1], v13.d[0]
  .long 0x6e080517                    // ins v23.d[0], v8.d[0]
  .long 0x6e180597                    // ins v23.d[1], v12.d[0]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x6f700446                    // ushr v6.2d, v2.2d, #16
  .long 0x6f705446                    // sli v6.2d, v2.2d, #48
  .long 0x6f700467                    // ushr v7.2d, v3.2d, #16
  .long 0x6f705467                    // sli v7.2d, v3.2d, #48
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a2                    // add v2.2d, v21.2d, v21.2d
  .long 0x6f4146a2                    // sri v2.2d, v21.2d, #63
  .long 0x4ef686c3                    // add v3.2d, v22.2d, v22.2d
  .long 0x6f4146c3                    // sri v3.2d, v22.2d, #63
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x6e084594                    // ins v20.d[0], v12.d[1]
  .long 0x6e184554                    // ins v20.d[1], v10.d[1]
  .long 0x6e080537                    // ins v23.d[0], v9.d[0]
  .long 0x6e1805b7                    // ins v23.d[1], v13.d[0]
  .long 0x4ee28694                    // add v20.2d, v20.2d, v2.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee386f7                    // add v23.2d, v23.2d, v3.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x4ea008c6                    // rev64 v6.4s, v6.4s
  .long 0x4ea008e7                    // rev64 v7.4s, v7.4s
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6f680455                    // ushr v21.2d, v2.2d, #24
  .long 0x6f685455                    // sli v21.2d, v2.2d, #40
  .long 0x6f680476                    // ushr v22.2d, v3.2d, #24
  .long 0x6f685476                    // sli v22.2d, v3.2d, #40
  .long 0x6e080514                    // ins v20.d[0], v8.d[0]
  .long 0x6e184574                    // ins v20.d[1], v11.d[1]
  .long 0x6e080557                    // ins v23.d[0], v10.d[0]
  .long 0x6e1845f7                    // ins v23.d[1], v15.d[1]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004c2                    // ushr v2.2d, v6.2d, #16
  .long 0x6f7054c2                    // sli v2.2d, v6.2d, #48
  .long 0x6f7004e3                    // ushr v3.2d, v7.2d, #16
  .long 0x6f7054e3                    // sli v3.2d, v7.2d, #48
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a6                    // add v6.2d, v21.2d, v21.2d
  .long 0x6f4146a6                    // sri v6.2d, v21.2d, #63
  .long 0x4ef686c7                    // add v7.2d, v22.2d, v22.2d
  .long 0x6f4146c7                    // sri v7.2d, v22.2d, #63
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x6e0805f4                    // ins v20.d[0], v15.d[0]
  .long 0x6e1845b4                    // ins v20.d[1], v13.d[1]
  .long 0x6e080577                    // ins v23.d[0], v11.d[0]
  .long 0x6e184537                    // ins v23.d[1], v9.d[1]
  .long 0x4ee68694                    // add v20.2d, v20.2d, v6.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee786f7                    // add v23.2d, v23.2d, v7.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x4ea00842                    // rev64 v2.4s, v2.4s
  .long 0x4ea00863                    // rev64 v3.4s, v3.4s
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241cc6                    // eor v6.16b, v6.16b, v4.16b
  .long 0x6e251ce7                    // eor v7.16b, v7.16b, v5.16b
  .long 0x6f6804d5                    // ushr v21.2d, v6.2d, #24
  .long 0x6f6854d5                    // sli v21.2d, v6.2d, #40
  .long 0x6f6804f6                    // ushr v22.2d, v7.2d, #24
  .long 0x6f6854f6                    // sli v22.2d, v7.2d, #40
  .long 0x6e0e4114                    // ext v20.16b, v8.16b, v14.16b, #8
  .long 0x6e080597                    // ins v23.d[0], v12.d[0]
  .long 0x6e1845d7                    // ins v23.d[1], v14.d[1]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x6f700446                    // ushr v6.2d, v2.2d, #16
  .long 0x6f705446                    // sli v6.2d, v2.2d, #48
  .long 0x6f700467                    // ushr v7.2d, v3.2d, #16
  .long 0x6f705467                    // sli v7.2d, v3.2d, #48
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a2                    // add v2.2d, v21.2d, v21.2d
  .long 0x6f4146a2                    // sri v2.2d, v21.2d, #63
  .long 0x4ef686c3                    // add v3.2d, v22.2d, v22.2d
  .long 0x6f4146c3                    // sri v3.2d, v22.2d, #63
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x6e080534                    // ins v20.d[0], v9.d[0]
  .long 0x6e180574                    // ins v20.d[1], v11.d[0]
  .long 0x6e080517                    // ins v23.d[0], v8.d[0]
  .long 0x6e180597                    // ins v23.d[1], v12.d[0]
  .long 0x4ee28694                    // add v20.2d, v20.2d, v2.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee386f7                    // add v23.2d, v23.2d, v3.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x4ea008c6                    // rev64 v6.4s, v6.4s
  .long 0x4ea008e7                    // rev64 v7.4s, v7.4s
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6f680455                    // ushr v21.2d, v2.2d, #24
  .long 0x6f685455                    // sli v21.2d, v2.2d, #40
  .long 0x6f680476                    // ushr v22.2d, v3.2d, #24
  .long 0x6f685476                    // sli v22.2d, v3.2d, #40
  .long 0x6e0805d4                    // ins v20.d[0], v14.d[0]
  .long 0x6e1805b4                    // ins v20.d[1], v13.d[0]
  .long 0x6e0845b7                    // ins v23.d[0], v13.d[1]
  .long 0x6e184537                    // ins v23.d[1], v9.d[1]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004c2                    // ushr v2.2d, v6.2d, #16
  .long 0x6f7054c2                    // sli v2.2d, v6.2d, #48
  .long 0x6f7004e3                    // ushr v3.2d, v7.2d, #16
  .long 0x6f7054e3                    // sli v3.2d, v7.2d, #48
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a6                    // add v6.2d, v21.2d, v21.2d
  .long 0x6f4146a6                    // sri v6.2d, v21.2d, #63
  .long 0x4ef686c7                    // add v7.2d, v22.2d, v22.2d
  .long 0x6f4146c7                    // sri v7.2d, v22.2d, #63
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x6e080554                    // ins v20.d[0], v10.d[0]
  .long 0x6e184574                    // ins v20.d[1], v11.d[1]
  .long 0x6e0845f7                    // ins v23.d[0], v15.d[1]
  .long 0x6e184517                    // ins v23.d[1], v8.d[1]
  .long 0x4ee68694                    // add v20.2d, v20.2d, v6.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee786f7                    // add v23.2d, v23.2d, v7.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x4ea00842                    // rev64 v2.4s, v2.4s
  .long 0x4ea00863                    // rev64 v3.4s, v3.4s
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241cc6                    // eor v6.16b, v6.16b, v4.16b
  .long 0x6e251ce7                    // eor v7.16b, v7.16b, v5.16b
  .long 0x6f6804d5                    // ushr v21.2d, v6.2d, #24
  .long 0x6f6854d5                    // sli v21.2d, v6.2d, #40
  .long 0x6f6804f6                    // ushr v22.2d, v7.2d, #24
  .long 0x6f6854f6                    // sli v22.2d, v7.2d, #40
  .long 0x6e0845d4                    // ins v20.d[0], v14.d[1]
  .long 0x6e184554                    // ins v20.d[1], v10.d[1]
  .long 0x6e0805f7                    // ins v23.d[0], v15.d[0]
  .long 0x6e184597                    // ins v23.d[1], v12.d[1]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x6f700446                    // ushr v6.2d, v2.2d, #16
  .long 0x6f705446                    // sli v6.2d, v2.2d, #48
  .long 0x6f700467                    // ushr v7.2d, v3.2d, #16
  .long 0x6f705467                    // sli v7.2d, v3.2d, #48
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a2                    // add v2.2d, v21.2d, v21.2d
  .long 0x6f4146a2                    // sri v2.2d, v21.2d, #63
  .long 0x4ef686c3                    // add v3.2d, v22.2d, v22.2d
  .long 0x6f4146c3                    // sri v3.2d, v22.2d, #63
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x6e0805d4                    // ins v20.d[0], v14.d[0]
  .long 0x6e184514                    // ins v20.d[1], v8.d[1]
  .long 0x6e0805f7                    // ins v23.d[0], v15.d[0]
  .long 0x6e180557                    // ins v23.d[1], v10.d[0]
  .long 0x4ee28694                    // add v20.2d, v20.2d, v2.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee386f7                    // add v23.2d, v23.2d, v3.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x4ea008c6                    // rev64 v6.4s, v6.4s
  .long 0x4ea008e7                    // rev64 v7.4s, v7.4s
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6f680455                    // ushr v21.2d, v2.2d, #24
  .long 0x6f685455                    // sli v21.2d, v2.2d, #40
  .long 0x6f680476                    // ushr v22.2d, v3.2d, #24
  .long 0x6f685476                    // sli v22.2d, v3.2d, #40
  .long 0x6e084554                    // ins v20.d[0], v10.d[1]
  .long 0x6e1845f4                    // ins v20.d[1], v15.d[1]
  .long 0x6e0d41d7                    // ext v23.16b, v14.16b, v13.16b, #8
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004c2                    // ushr v2.2d, v6.2d, #16
  .long 0x6f7054c2                    // sli v2.2d, v6.2d, #48
  .long 0x6f7004e3                    // ushr v3.2d, v7.2d, #16
  .long 0x6f7054e3                    // sli v3.2d, v7.2d, #48
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a6                    // add v6.2d, v21.2d, v21.2d
  .long 0x6f4146a6                    // sri v6.2d, v21.2d, #63
  .long 0x4ef686c7                    // add v7.2d, v22.2d, v22.2d
  .long 0x6f4146c7                    // sri v7.2d, v22.2d, #63
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x6e080514                    // ins v20.d[0], v8.d[0]
  .long 0x6e180574                    // ins v20.d[1], v11.d[0]
  .long 0x6e0c4197                    // ext v23.16b, v12.16b, v12.16b, #8
  .long 0x4ee68694                    // add v20.2d, v20.2d, v6.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee786f7                    // add v23.2d, v23.2d, v7.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x4ea00842                    // rev64 v2.4s, v2.4s
  .long 0x4ea00863                    // rev64 v3.4s, v3.4s
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241cc6                    // eor v6.16b, v6.16b, v4.16b
  .long 0x6e251ce7                    // eor v7.16b, v7.16b, v5.16b
  .long 0x6f6804d5                    // ushr v21.2d, v6.2d, #24
  .long 0x6f6854d5                    // sli v21.2d, v6.2d, #40
  .long 0x6f6804f6                    // ushr v22.2d, v7.2d, #24
  .long 0x6f6854f6                    // sli v22.2d, v7.2d, #40
  .long 0x6e084574                    // ins v20.d[0], v11.d[1]
  .long 0x6e184534                    // ins v20.d[1], v9.d[1]
  .long 0x6e080537                    // ins v23.d[0], v9.d[0]
  .long 0x6e1845b7                    // ins v23.d[1], v13.d[1]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x6f700446                    // ushr v6.2d, v2.2d, #16
  .long 0x6f705446                    // sli v6.2d, v2.2d, #48
  .long 0x6f700467                    // ushr v7.2d, v3.2d, #16
  .long 0x6f705467                    // sli v7.2d, v3.2d, #48
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a2                    // add v2.2d, v21.2d, v21.2d
  .long 0x6f4146a2                    // sri v2.2d, v21.2d, #63
  .long 0x4ef686c3                    // add v3.2d, v22.2d, v22.2d
  .long 0x6f4146c3                    // sri v3.2d, v22.2d, #63
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x6e0845d4                    // ins v20.d[0], v14.d[1]
  .long 0x6e184574                    // ins v20.d[1], v11.d[1]
  .long 0x6e0805d7                    // ins v23.d[0], v14.d[0]
  .long 0x6e184537                    // ins v23.d[1], v9.d[1]
  .long 0x4ee28694                    // add v20.2d, v20.2d, v2.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee386f7                    // add v23.2d, v23.2d, v3.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x4ea008c6                    // rev64 v6.4s, v6.4s
  .long 0x4ea008e7                    // rev64 v7.4s, v7.4s
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6f680455                    // ushr v21.2d, v2.2d, #24
  .long 0x6f685455                    // sli v21.2d, v2.2d, #40
  .long 0x6f680476                    // ushr v22.2d, v3.2d, #24
  .long 0x6f685476                    // sli v22.2d, v3.2d, #40
  .long 0x6e0f41b4                    // ext v20.16b, v13.16b, v15.16b, #8
  .long 0x6e084517                    // ins v23.d[0], v8.d[1]
  .long 0x6e184597                    // ins v23.d[1], v12.d[1]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004c2                    // ushr v2.2d, v6.2d, #16
  .long 0x6f7054c2                    // sli v2.2d, v6.2d, #48
  .long 0x6f7004e3                    // ushr v3.2d, v7.2d, #16
  .long 0x6f7054e3                    // sli v3.2d, v7.2d, #48
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a6                    // add v6.2d, v21.2d, v21.2d
  .long 0x6f4146a6                    // sri v6.2d, v21.2d, #63
  .long 0x4ef686c7                    // add v7.2d, v22.2d, v22.2d
  .long 0x6f4146c7                    // sri v7.2d, v22.2d, #63
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x6e084554                    // ins v20.d[0], v10.d[1]
  .long 0x6e1845f4                    // ins v20.d[1], v15.d[1]
  .long 0x6e080597                    // ins v23.d[0], v12.d[0]
  .long 0x6e180537                    // ins v23.d[1], v9.d[0]
  .long 0x4ee68694                    // add v20.2d, v20.2d, v6.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee786f7                    // add v23.2d, v23.2d, v7.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x4ea00842                    // rev64 v2.4s, v2.4s
  .long 0x4ea00863                    // rev64 v3.4s, v3.4s
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241cc6                    // eor v6.16b, v6.16b, v4.16b
  .long 0x6e251ce7                    // eor v7.16b, v7.16b, v5.16b
  .long 0x6f6804d5                    // ushr v21.2d, v6.2d, #24
  .long 0x6f6854d5                    // sli v21.2d, v6.2d, #40
  .long 0x6f6804f6                    // ushr v22.2d, v7.2d, #24
  .long 0x6f6854f6                    // sli v22.2d, v7.2d, #40
  .long 0x6e080514                    // ins v20.d[0], v8.d[0]
  .long 0x6e180554                    // ins v20.d[1], v10.d[0]
  .long 0x6e080577                    // ins v23.d[0], v11.d[0]
  .long 0x6e1805b7                    // ins v23.d[1], v13.d[0]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x6f700446                    // ushr v6.2d, v2.2d, #16
  .long 0x6f705446                    // sli v6.2d, v2.2d, #48
  .long 0x6f700467                    // ushr v7.2d, v3.2d, #16
  .long 0x6f705467                    // sli v7.2d, v3.2d, #48
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a2                    // add v2.2d, v21.2d, v21.2d
  .long 0x6f4146a2                    // sri v2.2d, v21.2d, #63
  .long 0x4ef686c3                    // add v3.2d, v22.2d, v22.2d
  .long 0x6f4146c3                    // sri v3.2d, v22.2d, #63
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x6e080574                    // ins v20.d[0], v11.d[0]
  .long 0x6e1805f4                    // ins v20.d[1], v15.d[0]
  .long 0x6e0841b7                    // ext v23.16b, v13.16b, v8.16b, #8
  .long 0x4ee28694                    // add v20.2d, v20.2d, v2.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee386f7                    // add v23.2d, v23.2d, v3.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x4ea008c6                    // rev64 v6.4s, v6.4s
  .long 0x4ea008e7                    // rev64 v7.4s, v7.4s
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6f680455                    // ushr v21.2d, v2.2d, #24
  .long 0x6f685455                    // sli v21.2d, v2.2d, #40
  .long 0x6f680476                    // ushr v22.2d, v3.2d, #24
  .long 0x6f685476                    // sli v22.2d, v3.2d, #40
  .long 0x6e0845f4                    // ins v20.d[0], v15.d[1]
  .long 0x6e184594                    // ins v20.d[1], v12.d[1]
  .long 0x6e0c4137                    // ext v23.16b, v9.16b, v12.16b, #8
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004c2                    // ushr v2.2d, v6.2d, #16
  .long 0x6f7054c2                    // sli v2.2d, v6.2d, #48
  .long 0x6f7004e3                    // ushr v3.2d, v7.2d, #16
  .long 0x6f7054e3                    // sli v3.2d, v7.2d, #48
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a6                    // add v6.2d, v21.2d, v21.2d
  .long 0x6f4146a6                    // sri v6.2d, v21.2d, #63
  .long 0x4ef686c7                    // add v7.2d, v22.2d, v22.2d
  .long 0x6f4146c7                    // sri v7.2d, v22.2d, #63
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x4eae1dd4                    // orr v20.16b, v14.16b, v14.16b
  .long 0x6e0d4117                    // ext v23.16b, v8.16b, v13.16b, #8
  .long 0x4ee68694                    // add v20.2d, v20.2d, v6.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee786f7                    // add v23.2d, v23.2d, v7.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x4ea00842                    // rev64 v2.4s, v2.4s
  .long 0x4ea00863                    // rev64 v3.4s, v3.4s
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241cc6                    // eor v6.16b, v6.16b, v4.16b
  .long 0x6e251ce7                    // eor v7.16b, v7.16b, v5.16b
  .long 0x6f6804d5                    // ushr v21.2d, v6.2d, #24
  .long 0x6f6854d5                    // sli v21.2d, v6.2d, #40
  .long 0x6f6804f6                    // ushr v22.2d, v7.2d, #24
  .long 0x6f6854f6                    // sli v22.2d, v7.2d, #40
  .long 0x6e080534                    // ins v20.d[0], v9.d[0]
  .long 0x6e184574                    // ins v20.d[1], v11.d[1]
  .long 0x4eaa1d57                    // orr v23.16b, v10.16b, v10.16b
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x6f700446                    // ushr v6.2d, v2.2d, #16
  .long 0x6f705446                    // sli v6.2d, v2.2d, #48
  .long 0x6f700467                    // ushr v7.2d, v3.2d, #16
  .long 0x6f705467                    // sli v7.2d, v3.2d, #48
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a2                    // add v2.2d, v21.2d, v21.2d
  .long 0x6f4146a2                    // sri v2.2d, v21.2d, #63
  .long 0x4ef686c3                    // add v3.2d, v22.2d, v22.2d
  .long 0x6f4146c3                    // sri v3.2d, v22.2d, #63
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x6e0805b4                    // ins v20.d[0], v13.d[0]
  .long 0x6e180594                    // ins v20.d[1], v12.d[0]
  .long 0x6e084577                    // ins v23.d[0], v11.d[1]
  .long 0x6e184517                    // ins v23.d[1], v8.d[1]
  .long 0x4ee28694                    // add v20.2d, v20.2d, v2.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee386f7                    // add v23.2d, v23.2d, v3.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x4ea008c6                    // rev64 v6.4s, v6.4s
  .long 0x4ea008e7                    // rev64 v7.4s, v7.4s
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6f680455                    // ushr v21.2d, v2.2d, #24
  .long 0x6f685455                    // sli v21.2d, v2.2d, #40
  .long 0x6f680476                    // ushr v22.2d, v3.2d, #24
  .long 0x6f685476                    // sli v22.2d, v3.2d, #40
  .long 0x6e080534                    // ins v20.d[0], v9.d[0]
  .long 0x6e180554                    // ins v20.d[1], v10.d[0]
  .long 0x6e080577                    // ins v23.d[0], v11.d[0]
  .long 0x6e184557                    // ins v23.d[1], v10.d[1]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004c2                    // ushr v2.2d, v6.2d, #16
  .long 0x6f7054c2                    // sli v2.2d, v6.2d, #48
  .long 0x6f7004e3                    // ushr v3.2d, v7.2d, #16
  .long 0x6f7054e3                    // sli v3.2d, v7.2d, #48
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a6                    // add v6.2d, v21.2d, v21.2d
  .long 0x6f4146a6                    // sri v6.2d, v21.2d, #63
  .long 0x4ef686c7                    // add v7.2d, v22.2d, v22.2d
  .long 0x6f4146c7                    // sri v7.2d, v22.2d, #63
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x6e0845f4                    // ins v20.d[0], v15.d[1]
  .long 0x6e184594                    // ins v20.d[1], v12.d[1]
  .long 0x6e084537                    // ins v23.d[0], v9.d[1]
  .long 0x6e1845d7                    // ins v23.d[1], v14.d[1]
  .long 0x4ee68694                    // add v20.2d, v20.2d, v6.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee786f7                    // add v23.2d, v23.2d, v7.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x4ea00842                    // rev64 v2.4s, v2.4s
  .long 0x4ea00863                    // rev64 v3.4s, v3.4s
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241cc6                    // eor v6.16b, v6.16b, v4.16b
  .long 0x6e251ce7                    // eor v7.16b, v7.16b, v5.16b
  .long 0x6f6804d5                    // ushr v21.2d, v6.2d, #24
  .long 0x6f6854d5                    // sli v21.2d, v6.2d, #40
  .long 0x6f6804f6                    // ushr v22.2d, v7.2d, #24
  .long 0x6f6854f6                    // sli v22.2d, v7.2d, #40
  .long 0x6e0f41b4                    // ext v20.16b, v13.16b, v15.16b, #8
  .long 0x6e0805d7                    // ins v23.d[0], v14.d[0]
  .long 0x6e180517                    // ins v23.d[1], v8.d[0]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x6f700446                    // ushr v6.2d, v2.2d, #16
  .long 0x6f705446                    // sli v6.2d, v2.2d, #48
  .long 0x6f700467                    // ushr v7.2d, v3.2d, #16
  .long 0x6f705467                    // sli v7.2d, v3.2d, #48
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a2                    // add v2.2d, v21.2d, v21.2d
  .long 0x6f4146a2                    // sri v2.2d, v21.2d, #63
  .long 0x4ef686c3                    // add v3.2d, v22.2d, v22.2d
  .long 0x6f4146c3                    // sri v3.2d, v22.2d, #63
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x6e080514                    // ins v20.d[0], v8.d[0]
  .long 0x6e180534                    // ins v20.d[1], v9.d[0]
  .long 0x6e080557                    // ins v23.d[0], v10.d[0]
  .long 0x6e180577                    // ins v23.d[1], v11.d[0]
  .long 0x4ee28694                    // add v20.2d, v20.2d, v2.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee386f7                    // add v23.2d, v23.2d, v3.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x4ea008c6                    // rev64 v6.4s, v6.4s
  .long 0x4ea008e7                    // rev64 v7.4s, v7.4s
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6f680455                    // ushr v21.2d, v2.2d, #24
  .long 0x6f685455                    // sli v21.2d, v2.2d, #40
  .long 0x6f680476                    // ushr v22.2d, v3.2d, #24
  .long 0x6f685476                    // sli v22.2d, v3.2d, #40
  .long 0x6e084514                    // ins v20.d[0], v8.d[1]
  .long 0x6e184534                    // ins v20.d[1], v9.d[1]
  .long 0x6e084557                    // ins v23.d[0], v10.d[1]
  .long 0x6e184577                    // ins v23.d[1], v11.d[1]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004c2                    // ushr v2.2d, v6.2d, #16
  .long 0x6f7054c2                    // sli v2.2d, v6.2d, #48
  .long 0x6f7004e3                    // ushr v3.2d, v7.2d, #16
  .long 0x6f7054e3                    // sli v3.2d, v7.2d, #48
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a6                    // add v6.2d, v21.2d, v21.2d
  .long 0x6f4146a6                    // sri v6.2d, v21.2d, #63
  .long 0x4ef686c7                    // add v7.2d, v22.2d, v22.2d
  .long 0x6f4146c7                    // sri v7.2d, v22.2d, #63
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x6e080594                    // ins v20.d[0], v12.d[0]
  .long 0x6e1805b4                    // ins v20.d[1], v13.d[0]
  .long 0x6e0805d7                    // ins v23.d[0], v14.d[0]
  .long 0x6e1805f7                    // ins v23.d[1], v15.d[0]
  .long 0x4ee68694                    // add v20.2d, v20.2d, v6.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee786f7                    // add v23.2d, v23.2d, v7.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x4ea00842                    // rev64 v2.4s, v2.4s
  .long 0x4ea00863                    // rev64 v3.4s, v3.4s
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241cc6                    // eor v6.16b, v6.16b, v4.16b
  .long 0x6e251ce7                    // eor v7.16b, v7.16b, v5.16b
  .long 0x6f6804d5                    // ushr v21.2d, v6.2d, #24
  .long 0x6f6854d5                    // sli v21.2d, v6.2d, #40
  .long 0x6f6804f6                    // ushr v22.2d, v7.2d, #24
  .long 0x6f6854f6                    // sli v22.2d, v7.2d, #40
  .long 0x6e084594                    // ins v20.d[0], v12.d[1]
  .long 0x6e1845b4                    // ins v20.d[1], v13.d[1]
  .long 0x6e0845d7                    // ins v23.d[0], v14.d[1]
  .long 0x6e1845f7                    // ins v23.d[1], v15.d[1]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x6f700446                    // ushr v6.2d, v2.2d, #16
  .long 0x6f705446                    // sli v6.2d, v2.2d, #48
  .long 0x6f700467                    // ushr v7.2d, v3.2d, #16
  .long 0x6f705467                    // sli v7.2d, v3.2d, #48
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a2                    // add v2.2d, v21.2d, v21.2d
  .long 0x6f4146a2                    // sri v2.2d, v21.2d, #63
  .long 0x4ef686c3                    // add v3.2d, v22.2d, v22.2d
  .long 0x6f4146c3                    // sri v3.2d, v22.2d, #63
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x6e0805f4                    // ins v20.d[0], v15.d[0]
  .long 0x6e180554                    // ins v20.d[1], v10.d[0]
  .long 0x6e084597                    // ins v23.d[0], v12.d[1]
  .long 0x6e1845d7                    // ins v23.d[1], v14.d[1]
  .long 0x4ee28694                    // add v20.2d, v20.2d, v2.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee386f7                    // add v23.2d, v23.2d, v3.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x4ea008c6                    // rev64 v6.4s, v6.4s
  .long 0x4ea008e7                    // rev64 v7.4s, v7.4s
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6f680455                    // ushr v21.2d, v2.2d, #24
  .long 0x6f685455                    // sli v21.2d, v2.2d, #40
  .long 0x6f680476                    // ushr v22.2d, v3.2d, #24
  .long 0x6f685476                    // sli v22.2d, v3.2d, #40
  .long 0x6e0805b4                    // ins v20.d[0], v13.d[0]
  .long 0x6e180594                    // ins v20.d[1], v12.d[0]
  .long 0x6e0b41f7                    // ext v23.16b, v15.16b, v11.16b, #8
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004c2                    // ushr v2.2d, v6.2d, #16
  .long 0x6f7054c2                    // sli v2.2d, v6.2d, #48
  .long 0x6f7004e3                    // ushr v3.2d, v7.2d, #16
  .long 0x6f7054e3                    // sli v3.2d, v7.2d, #48
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a6                    // add v6.2d, v21.2d, v21.2d
  .long 0x6f4146a6                    // sri v6.2d, v21.2d, #63
  .long 0x4ef686c7                    // add v7.2d, v22.2d, v22.2d
  .long 0x6f4146c7                    // sri v7.2d, v22.2d, #63
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x6e084114                    // ext v20.16b, v8.16b, v8.16b, #8
  .long 0x6e0845b7                    // ins v23.d[0], v13.d[1]
  .long 0x6e184557                    // ins v23.d[1], v10.d[1]
  .long 0x4ee68694                    // add v20.2d, v20.2d, v6.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ee786f7                    // add v23.2d, v23.2d, v7.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x4ea00842                    // rev64 v2.4s, v2.4s
  .long 0x4ea00863                    // rev64 v3.4s, v3.4s
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x6e241cc6                    // eor v6.16b, v6.16b, v4.16b
  .long 0x6e251ce7                    // eor v7.16b, v7.16b, v5.16b
  .long 0x6f6804d5                    // ushr v21.2d, v6.2d, #24
  .long 0x6f6854d5                    // sli v21.2d, v6.2d, #40
  .long 0x6f6804f6                    // ushr v22.2d, v7.2d, #24
  .long 0x6f6854f6                    // sli v22.2d, v7.2d, #40
  .long 0x6e0805d4                    // ins v20.d[0], v14.d[0]
  .long 0x6e180534                    // ins v20.d[1], v9.d[0]
  .long 0x6e084577                    // ins v23.d[0], v11.d[1]
  .long 0x6e184537                    // ins v23.d[1], v9.d[1]
  .long 0x4ef58694                    // add v20.2d, v20.2d, v21.2d
  .long 0x4ef48400                    // add v0.2d, v0.2d, v20.2d
  .long 0x4ef686f7                    // add v23.2d, v23.2d, v22.2d
  .long 0x4ef78421                    // add v1.2d, v1.2d, v23.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x6f700446                    // ushr v6.2d, v2.2d, #16
  .long 0x6f705446                    // sli v6.2d, v2.2d, #48
  .long 0x6f700467                    // ushr v7.2d, v3.2d, #16
  .long 0x6f705467                    // sli v7.2d, v3.2d, #48
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x6e241eb5                    // eor v21.16b, v21.16b, v4.16b
  .long 0x6e251ed6                    // eor v22.16b, v22.16b, v5.16b
  .long 0x4ef586a2                    // add v2.2d, v21.2d, v21.2d
  .long 0x6f4146a2                    // sri v2.2d, v21.2d, #63
  .long 0x4ef686c3                    // add v3.2d, v22.2d, v22.2d
  .long 0x6f4146c3                    // sri v3.2d, v22.2d, #63
  .long 0x6e024075                    // ext v21.16b, v3.16b, v2.16b, #8
  .long 0x6e034043                    // ext v3.16b, v2.16b, v3.16b, #8
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x4ea41c95                    // orr v21.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x6e0740d5                    // ext v21.16b, v6.16b, v7.16b, #8
  .long 0x6e0640e7                    // ext v7.16b, v7.16b, v6.16b, #8
  .long 0x4eb51ea6                    // orr v6.16b, v21.16b, v21.16b
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x6e201e00                    // eor v0.16b, v16.16b, v0.16b
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x6e211e21                    // eor v1.16b, v17.16b, v1.16b
  .long 0x6e261c42                    // eor v2.16b, v2.16b, v6.16b
  .long 0x6e221e42                    // eor v2.16b, v18.16b, v2.16b
  .long 0x6e271c63                    // eor v3.16b, v3.16b, v7.16b
  .long 0x6e231e63                    // eor v3.16b, v19.16b, v3.16b
  .long 0xad000400                    // stp q0, q1, [x0]
  .long 0xad010c02                    // stp q2, q3, [x0, #32]

  {$I ..\..\Include\Simd\Common\HlpSimdNonVolatileRestore_aarch64.inc}
  ret
