// SHA-1 ARMv8 Crypto Extension (FEAT_SHA1) implementation.
// Expects AAPCS64: x0 = state ptr (5 x UInt32), x1 = data ptr,
//   w2 = numblocks, x3 = K_SHA1 ptr (16 UInt32: each of the four round
//   constants replicated across 4 lanes).
// Touches only caller-saved registers (x0-x3, w2, v0-v7, v16-v22); no AAPCS64
//   callee-saved register (x19-x28, or the low 64 bits of v8-v15) is used, so
//   the 'nostackframe' leaf needs neither prologue nor epilogue.
// Reference: OpenSSL CRYPTOGAMS sha1-armv8.S (sha1_block_armv8).
//
// Instruction encodings (for assembler compatibility):
//   FPC 3.2.2's inline assembler cannot encode AArch64 vector/crypto mnemonics
//   (subscripted vector regs and the FEAT_SHA1 ops require FPC 3.3+, and
//   ldr/str/ldp with qN/sN crash the 3.2.2 assembler). Each such instruction is
//   therefore emitted as its raw 32-bit '.long' opcode, with the equivalent
//   mnemonic in the trailing comment; only cbz/cbnz/sub/ret stay as text.
//
// Register map:
//   v0       = ABCD working state
//   v1.s[0]  = E working state (single lane; sha1c/p/m consume it as a scalar)
//   v2, v3   = sha1h ping-pong (E rotated by the round)
//   v4-v7    = message schedule (W)
//   v16-v19  = K round constants (K_00_19, K_20_39, K_40_59, K_60_79)
//   v20, v21 = W+K per round
//   v22      = saved ABCD for the final add

  cbz w2, .Lcryptoext_sha1_done
  .long 0x6e211c21                    // eor v1.16b, v1.16b, v1.16b
  .long 0x3dc00000                    // ldr q0, [x0]
  .long 0xbd401001                    // ldr s1, [x0, #16]
  .long 0x4c402870                    // ld1 {v16.4s-v19.4s}, [x3]
.Lcryptoext_sha1_block_loop:
  .long 0xacc11424                    // ldp q4, q5, [x1], #32
  .long 0xacc11c26                    // ldp q6, q7, [x1], #32
  sub w2, w2, #1
  .long 0x6e200884                    // rev32 v4.16b, v4.16b
  .long 0x6e2008a5                    // rev32 v5.16b, v5.16b
  .long 0x4ea48614                    // add v20.4s, v16.4s, v4.4s
  .long 0x6e2008c6                    // rev32 v6.16b, v6.16b
  .long 0x4ea01c16                    // orr v22.16b, v0.16b, v0.16b
  .long 0x4ea58615                    // add v21.4s, v16.4s, v5.4s
  .long 0x6e2008e7                    // rev32 v7.16b, v7.16b
  .long 0x5e280803                    // sha1h s3, s0
  .long 0x5e140020                    // sha1c q0, s1, v20.4s
  .long 0x4ea68614                    // add v20.4s, v16.4s, v6.4s
  .long 0x5e0630a4                    // sha1su0 v4.4s, v5.4s, v6.4s
  .long 0x5e280802                    // sha1h s2, s0
  .long 0x5e150060                    // sha1c q0, s3, v21.4s
  .long 0x4ea78615                    // add v21.4s, v16.4s, v7.4s
  .long 0x5e2818e4                    // sha1su1 v4.4s, v7.4s
  .long 0x5e0730c5                    // sha1su0 v5.4s, v6.4s, v7.4s
  .long 0x5e280803                    // sha1h s3, s0
  .long 0x5e140040                    // sha1c q0, s2, v20.4s
  .long 0x4ea48614                    // add v20.4s, v16.4s, v4.4s
  .long 0x5e281885                    // sha1su1 v5.4s, v4.4s
  .long 0x5e0430e6                    // sha1su0 v6.4s, v7.4s, v4.4s
  .long 0x5e280802                    // sha1h s2, s0
  .long 0x5e150060                    // sha1c q0, s3, v21.4s
  .long 0x4ea58635                    // add v21.4s, v17.4s, v5.4s
  .long 0x5e2818a6                    // sha1su1 v6.4s, v5.4s
  .long 0x5e053087                    // sha1su0 v7.4s, v4.4s, v5.4s
  .long 0x5e280803                    // sha1h s3, s0
  .long 0x5e140040                    // sha1c q0, s2, v20.4s
  .long 0x4ea68634                    // add v20.4s, v17.4s, v6.4s
  .long 0x5e2818c7                    // sha1su1 v7.4s, v6.4s
  .long 0x5e0630a4                    // sha1su0 v4.4s, v5.4s, v6.4s
  .long 0x5e280802                    // sha1h s2, s0
  .long 0x5e151060                    // sha1p q0, s3, v21.4s
  .long 0x4ea78635                    // add v21.4s, v17.4s, v7.4s
  .long 0x5e2818e4                    // sha1su1 v4.4s, v7.4s
  .long 0x5e0730c5                    // sha1su0 v5.4s, v6.4s, v7.4s
  .long 0x5e280803                    // sha1h s3, s0
  .long 0x5e141040                    // sha1p q0, s2, v20.4s
  .long 0x4ea48634                    // add v20.4s, v17.4s, v4.4s
  .long 0x5e281885                    // sha1su1 v5.4s, v4.4s
  .long 0x5e0430e6                    // sha1su0 v6.4s, v7.4s, v4.4s
  .long 0x5e280802                    // sha1h s2, s0
  .long 0x5e151060                    // sha1p q0, s3, v21.4s
  .long 0x4ea58635                    // add v21.4s, v17.4s, v5.4s
  .long 0x5e2818a6                    // sha1su1 v6.4s, v5.4s
  .long 0x5e053087                    // sha1su0 v7.4s, v4.4s, v5.4s
  .long 0x5e280803                    // sha1h s3, s0
  .long 0x5e141040                    // sha1p q0, s2, v20.4s
  .long 0x4ea68654                    // add v20.4s, v18.4s, v6.4s
  .long 0x5e2818c7                    // sha1su1 v7.4s, v6.4s
  .long 0x5e0630a4                    // sha1su0 v4.4s, v5.4s, v6.4s
  .long 0x5e280802                    // sha1h s2, s0
  .long 0x5e151060                    // sha1p q0, s3, v21.4s
  .long 0x4ea78655                    // add v21.4s, v18.4s, v7.4s
  .long 0x5e2818e4                    // sha1su1 v4.4s, v7.4s
  .long 0x5e0730c5                    // sha1su0 v5.4s, v6.4s, v7.4s
  .long 0x5e280803                    // sha1h s3, s0
  .long 0x5e142040                    // sha1m q0, s2, v20.4s
  .long 0x4ea48654                    // add v20.4s, v18.4s, v4.4s
  .long 0x5e281885                    // sha1su1 v5.4s, v4.4s
  .long 0x5e0430e6                    // sha1su0 v6.4s, v7.4s, v4.4s
  .long 0x5e280802                    // sha1h s2, s0
  .long 0x5e152060                    // sha1m q0, s3, v21.4s
  .long 0x4ea58655                    // add v21.4s, v18.4s, v5.4s
  .long 0x5e2818a6                    // sha1su1 v6.4s, v5.4s
  .long 0x5e053087                    // sha1su0 v7.4s, v4.4s, v5.4s
  .long 0x5e280803                    // sha1h s3, s0
  .long 0x5e142040                    // sha1m q0, s2, v20.4s
  .long 0x4ea68654                    // add v20.4s, v18.4s, v6.4s
  .long 0x5e2818c7                    // sha1su1 v7.4s, v6.4s
  .long 0x5e0630a4                    // sha1su0 v4.4s, v5.4s, v6.4s
  .long 0x5e280802                    // sha1h s2, s0
  .long 0x5e152060                    // sha1m q0, s3, v21.4s
  .long 0x4ea78675                    // add v21.4s, v19.4s, v7.4s
  .long 0x5e2818e4                    // sha1su1 v4.4s, v7.4s
  .long 0x5e0730c5                    // sha1su0 v5.4s, v6.4s, v7.4s
  .long 0x5e280803                    // sha1h s3, s0
  .long 0x5e142040                    // sha1m q0, s2, v20.4s
  .long 0x4ea48674                    // add v20.4s, v19.4s, v4.4s
  .long 0x5e281885                    // sha1su1 v5.4s, v4.4s
  .long 0x5e0430e6                    // sha1su0 v6.4s, v7.4s, v4.4s
  .long 0x5e280802                    // sha1h s2, s0
  .long 0x5e151060                    // sha1p q0, s3, v21.4s
  .long 0x4ea58675                    // add v21.4s, v19.4s, v5.4s
  .long 0x5e2818a6                    // sha1su1 v6.4s, v5.4s
  .long 0x5e053087                    // sha1su0 v7.4s, v4.4s, v5.4s
  .long 0x5e280803                    // sha1h s3, s0
  .long 0x5e141040                    // sha1p q0, s2, v20.4s
  .long 0x4ea68674                    // add v20.4s, v19.4s, v6.4s
  .long 0x5e2818c7                    // sha1su1 v7.4s, v6.4s
  .long 0x5e280802                    // sha1h s2, s0
  .long 0x5e151060                    // sha1p q0, s3, v21.4s
  .long 0x4ea78675                    // add v21.4s, v19.4s, v7.4s
  .long 0x5e280803                    // sha1h s3, s0
  .long 0x5e141040                    // sha1p q0, s2, v20.4s
  .long 0x5e280802                    // sha1h s2, s0
  .long 0x5e151060                    // sha1p q0, s3, v21.4s
  .long 0x4ea28421                    // add v1.4s, v1.4s, v2.4s
  .long 0x4eb68400                    // add v0.4s, v0.4s, v22.4s
  cbnz w2, .Lcryptoext_sha1_block_loop
  .long 0x3d800000                    // str q0, [x0]
  .long 0xbd001001                    // str s1, [x0, #16]
.Lcryptoext_sha1_done:
  ret
