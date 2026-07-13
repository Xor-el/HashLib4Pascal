// NEON implementation of Adler-32 block processing (num_blocks x 32-byte blocks).
// Does NOT apply mod 65521 (the caller does).
// ABI (after HlpSimdProc4Begin_aarch64.inc): x0 = data ptr, w1 = num_blocks,
//   x2 = sums ptr, x3 = constants ptr.
//   Sums layout: [SumA: UInt32, SumB: UInt32].
//   Constants layout matches Adler32Constants: bytes [32..1] at offsets 0..31.
// Register map:
//   w9       = block counter (from w1)
//   w10      = SumA in / SumA out
//   w11      = SumB in / SumB out
//   w12      = SumA * num_blocks (v_ps lane 0 seed)
//   w13      = horizontal-reduce scratch
//   v0       = v_s1 (uint32x4 byte-sum accumulators)
//   v1       = v_s2 (uint32x4 s2 partial, SumB seeded in lane 0)
//   v4-v5    = 32 input bytes per block
//   v6-v8    = uaddlp / horizontal-reduce temps
//   v16-v19  = column sums (uint16x8)
//   v20      = v_ps (SumA*blocks + per-block v_s1), lane 0 used before <<5 add
//   v24-v27  = widened weight vectors for vmlal
//   v28-v29  = weight byte loads from AConstants
//   v30      = ext scratch for weight / reduce halves
// Saves: none (leaf nostackframe; caller-saved GPR/vector only).
// AArch64 vector instructions are .long-encoded for broad assembler compatibility.
// Reference: Chromium zlib adler32_simd.c, HashLib Adler32BlocksSsse3_x86_64.inc.

  .long 0xb940004a                    // ldr w10, [x2]
  .long 0xb940044b                    // ldr w11, [x2, #4]
  .long 0x1b017d4c                    // mul w12, w10, w1
  .long 0x2a0103e9                    // mov w9, w1
  .long 0x6e341e94                    // eor v20.16b, v20.16b, v20.16b
  .long 0x4e041d94                    // ins v20.s[0], w12
  .long 0x6e211c21                    // eor v1.16b, v1.16b, v1.16b
  .long 0x4e041d61                    // ins v1.s[0], w11
  .long 0x6e201c00                    // eor v0.16b, v0.16b, v0.16b
  .long 0x6e301e10                    // eor v16.16b, v16.16b, v16.16b
  .long 0x6e311e31                    // eor v17.16b, v17.16b, v17.16b
  .long 0x6e321e52                    // eor v18.16b, v18.16b, v18.16b
  .long 0x6e331e73                    // eor v19.16b, v19.16b, v19.16b
  .long 0x3dc0007c                    // ldr q28, [x3, #0x0]
  .long 0x3dc0047d                    // ldr q29, [x3, #0x10]
.Ladler_blocks_loop:
  .long 0x4ea08694                    // add v20.4s, v20.4s, v0.4s
  .long 0x3dc00004                    // ldr q4, [x0, #0x0]
  .long 0x3dc00405                    // ldr q5, [x0, #0x10]
  .long 0x6e202886                    // uaddlp v6.8h, v4.16b
  .long 0x6e6068c0                    // uadalp v0.4s, v6.8h
  .long 0x6e2028a7                    // uaddlp v7.8h, v5.16b
  .long 0x6e6068e0                    // uadalp v0.4s, v7.8h
  .long 0x2e241210                    // uaddw v16.8h, v16.8h, v4.8b
  .long 0x6e241231                    // uaddw2 v17.8h, v17.8h, v4.16b
  .long 0x2e251252                    // uaddw v18.8h, v18.8h, v5.8b
  .long 0x6e251273                    // uaddw2 v19.8h, v19.8h, v5.16b
  .long 0x91008000                    // add x0, x0, #32
  .long 0x71000529                    // subs w9, w9, #1
  b.ne .Ladler_blocks_loop
  .long 0x4f255694                    // shl v20.4s, v20.4s, #5
  .long 0x4eb48421                    // add v1.4s, v1.4s, v20.4s
  .long 0x2f08a798                    // ushll v24.8h, v28.8b, #0
  .long 0x6e1c439e                    // ext v30.16b, v28.16b, v28.16b, #8
  .long 0x2f08a7d9                    // ushll v25.8h, v30.8b, #0
  .long 0x2f08a7ba                    // ushll v26.8h, v29.8b, #0
  .long 0x6e1d43be                    // ext v30.16b, v29.16b, v29.16b, #8
  .long 0x2f08a7db                    // ushll v27.8h, v30.8b, #0
  .long 0x2e788201                    // umlal v1.4s, v16.4h, v24.4h
  .long 0x6e788201                    // umlal2 v1.4s, v16.8h, v24.8h
  .long 0x2e798221                    // umlal v1.4s, v17.4h, v25.4h
  .long 0x6e798221                    // umlal2 v1.4s, v17.8h, v25.8h
  .long 0x2e7a8241                    // umlal v1.4s, v18.4h, v26.4h
  .long 0x6e7a8241                    // umlal2 v1.4s, v18.8h, v26.8h
  .long 0x2e7b8261                    // umlal v1.4s, v19.4h, v27.4h
  .long 0x6e7b8261                    // umlal2 v1.4s, v19.8h, v27.8h
  .long 0x4ea0bc06                    // addp v6.4s, v0.4s, v0.4s
  .long 0x0ea6bcc6                    // addp v6.2s, v6.2s, v6.2s
  .long 0x0e043ccd                    // umov w13, v6.s[0]
  .long 0x0b0d014a                    // add w10, w10, w13
  .long 0x4ea1bc26                    // addp v6.4s, v1.4s, v1.4s
  .long 0x0ea6bcc6                    // addp v6.2s, v6.2s, v6.2s
  .long 0x0e043ccb                    // umov w11, v6.s[0]
  .long 0xb900004a                    // str w10, [x2]
  .long 0xb900044b                    // str w11, [x2, #4]
  ret
