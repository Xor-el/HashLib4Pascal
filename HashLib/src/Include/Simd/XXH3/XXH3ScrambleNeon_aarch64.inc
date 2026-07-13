// XXH3 scrambleAcc AArch64 NEON implementation (64-byte secret slice).
// Expects AAPCS64: x0 = acc ptr (8 x UInt64, 16-byte aligned), x1 = secret ptr.
// Leaf nostackframe; caller-saved GPR/vector only.
// Reference: Cyan4973/xxHash xxhash.h XXH3_scrambleAcc_neon, HashLib XXH3ScrambleSse2_x86_64.inc.
// AArch64 vector instructions are .long-encoded for broad assembler compatibility.
// Register map:
//   w10      = XXH_PRIME32_1 constant loader
//   v4       = kPrimeHi ({0, PRIME32_1, 0, PRIME32_1} as u32x4)
//   v5       = kPrimeLo (PRIME32_1 broadcast to u32x2)
//   v3       = prod_hi (vmul u32) / final chunk result
//   v1       = shifted acc, secret key, or data_key_lo (xtn)
  .long 0x528f362a                    // movz w10, #0x79b1, lsl #0
  .long 0x72b3c6ea                    // movk w10, #0x9e37, lsl #16
  .long 0x0e040d45                    // dup v5.2s, w10
  .long 0x6e241c84                    // eor v4.16b, v4.16b, v4.16b
  .long 0x4e0c1d44                    // ins v4.s[1], w10
  .long 0x4e1c1d44                    // ins v4.s[3], w10
  // --- chunk 0: acc[0..1], secret[0x0..] ---
  .long 0x3dc00000                    // ldr q0, [x0, #0x0]
  .long 0x6f510401                    // ushr v1.2d, v0.2d, #47
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x3dc00021                    // ldr q1, [x1, #0x0]
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x4ea49c03                    // mul v3.4s, v0.4s, v4.4s
  .long 0x0ea12801                    // xtn v1.2s, v0.2d
  .long 0x2ea58023                    // umlal v3.2d, v1.2s, v5.2s
  .long 0x3d800003                    // str q3, [x0, #0x0]
  // --- chunk 1: acc[2..3], secret[0x10..] ---
  .long 0x3dc00400                    // ldr q0, [x0, #0x10]
  .long 0x6f510401                    // ushr v1.2d, v0.2d, #47
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x3dc00421                    // ldr q1, [x1, #0x10]
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x4ea49c03                    // mul v3.4s, v0.4s, v4.4s
  .long 0x0ea12801                    // xtn v1.2s, v0.2d
  .long 0x2ea58023                    // umlal v3.2d, v1.2s, v5.2s
  .long 0x3d800403                    // str q3, [x0, #0x10]
  // --- chunk 2: acc[4..5], secret[0x20..] ---
  .long 0x3dc00800                    // ldr q0, [x0, #0x20]
  .long 0x6f510401                    // ushr v1.2d, v0.2d, #47
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x3dc00821                    // ldr q1, [x1, #0x20]
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x4ea49c03                    // mul v3.4s, v0.4s, v4.4s
  .long 0x0ea12801                    // xtn v1.2s, v0.2d
  .long 0x2ea58023                    // umlal v3.2d, v1.2s, v5.2s
  .long 0x3d800803                    // str q3, [x0, #0x20]
  // --- chunk 3: acc[6..7], secret[0x30..] ---
  .long 0x3dc00c00                    // ldr q0, [x0, #0x30]
  .long 0x6f510401                    // ushr v1.2d, v0.2d, #47
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x3dc00c21                    // ldr q1, [x1, #0x30]
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x4ea49c03                    // mul v3.4s, v0.4s, v4.4s
  .long 0x0ea12801                    // xtn v1.2s, v0.2d
  .long 0x2ea58023                    // umlal v3.2d, v1.2s, v5.2s
  .long 0x3d800c03                    // str q3, [x0, #0x30]
  ret
