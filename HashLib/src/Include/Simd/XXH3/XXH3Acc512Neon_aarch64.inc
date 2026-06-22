// XXH3 accumulate_512 AArch64 NEON implementation (one 64-byte stripe).
// Expects AAPCS64: x0 = acc ptr (8 x UInt64, 16-byte aligned), x1 = input ptr,
//   x2 = secret ptr.
// Touches only caller-saved registers (x0-x2, v0-v7, v16-v19); no AAPCS64
//   callee-saved register is used, so the 'nostackframe' leaf needs no prologue.
// Reference (golden): HashLib XXH3Acc512Sse2_x86_64.inc (semantic parity);
//   Cyan4973/xxHash xxhash.h XXH3_accumulate_512_neon with XXH3_NEON_LANES=8
//   (2 batch iterations, no scalar tail).
//
// Instruction encodings (for assembler compatibility):
//   FPC 3.2.2's inline assembler cannot encode AArch64 vector mnemonics
//   (subscripted vector regs require FPC 3.3+, and ldr/str/ldp with qN crash the
//   3.2.2 assembler). Each such instruction is therefore emitted as its raw 32-bit
//   '.long' opcode, with the equivalent mnemonic in the trailing comment; only
//   neg/ret stay as text.
//
// Register map:
//   v0-v3    = acc[0..3] (4 x uint64x2)
//   v4-v5    = data_vec_1/2 (input)
//   v6-v7    = key_vec / uzp temps (data_key_lo, data_key_hi)
//   v16-v17  = data_swap_1/2 (vext input by 8 bytes)
//   v18-v19  = sum_1/sum_2 (umlal / umlal2 widen-multiply-add into swap)
  // --- batch i=0: acc[0..1], input[0x0..], secret[0x0..] ---
  .long 0x3dc00024                    // ldr q4, [x1, #0x0]
  .long 0x3dc00425                    // ldr q5, [x1, #0x10]
  .long 0x3dc00046                    // ldr q6, [x2, #0x0]
  .long 0x3dc00447                    // ldr q7, [x2, #0x10]
  .long 0x6e044090                    // ext v16.16b, v4.16b, v4.16b, #8
  .long 0x6e0540b1                    // ext v17.16b, v5.16b, v5.16b, #8
  .long 0x6e261c84                    // eor v4.16b, v4.16b, v6.16b
  .long 0x6e271ca5                    // eor v5.16b, v5.16b, v7.16b
  .long 0x4e871886                    // uzp1 v6.4s, v4.4s, v5.4s
  .long 0x4e875887                    // uzp2 v7.4s, v4.4s, v5.4s
  .long 0x2ea780d0                    // umlal v16.2d, v6.2s, v7.2s
  .long 0x6ea780d1                    // umlal2 v17.2d, v6.4s, v7.4s
  .long 0x3dc00000                    // ldr q0, [x0, #0x0]
  .long 0x3dc00401                    // ldr q1, [x0, #0x10]
  .long 0x4ef08400                    // add v0.2d, v0.2d, v16.2d
  .long 0x4ef18421                    // add v1.2d, v1.2d, v17.2d
  .long 0x3d800000                    // str q0, [x0, #0x0]
  .long 0x3d800401                    // str q1, [x0, #0x10]
  // --- batch i=2: acc[2..3], input[0x20..], secret[0x20..] ---
  .long 0x3dc00824                    // ldr q4, [x1, #0x20]
  .long 0x3dc00c25                    // ldr q5, [x1, #0x30]
  .long 0x3dc00846                    // ldr q6, [x2, #0x20]
  .long 0x3dc00c47                    // ldr q7, [x2, #0x30]
  .long 0x6e044090                    // ext v16.16b, v4.16b, v4.16b, #8
  .long 0x6e0540b1                    // ext v17.16b, v5.16b, v5.16b, #8
  .long 0x6e261c84                    // eor v4.16b, v4.16b, v6.16b
  .long 0x6e271ca5                    // eor v5.16b, v5.16b, v7.16b
  .long 0x4e871886                    // uzp1 v6.4s, v4.4s, v5.4s
  .long 0x4e875887                    // uzp2 v7.4s, v4.4s, v5.4s
  .long 0x2ea780d0                    // umlal v16.2d, v6.2s, v7.2s
  .long 0x6ea780d1                    // umlal2 v17.2d, v6.4s, v7.4s
  .long 0x3dc00802                    // ldr q2, [x0, #0x20]
  .long 0x3dc00c03                    // ldr q3, [x0, #0x30]
  .long 0x4ef08442                    // add v2.2d, v2.2d, v16.2d
  .long 0x4ef18463                    // add v3.2d, v3.2d, v17.2d
  .long 0x3d800802                    // str q2, [x0, #0x20]
  .long 0x3d800c03                    // str q3, [x0, #0x30]
  ret
