// Scrypt Salsa20/8 XOR AArch64 NEON implementation (Percival-permuted data).
// Expects AAPCS64: x0 = State ptr, x1 = Input ptr.
// Each pointer addresses 16 UInt32 (64 bytes) in permuted order:
//   v0 = {w0,w5,w10,w15}, v1 = {w4,w9,w14,w3}, v2 = {w8,w13,w2,w7}, v3 = {w12,w1,w6,w11}.
// Leaf nostackframe; caller-saved GPR/vector only.
// Column/row quarter-rounds via lane-parallel ext-based diagonalize (see Tarsnap scrypt-sse.c).
// Reference: Tarsnap crypto_scrypt-sse.c, HashLib ScryptSalsa8Sse2_x86_64.inc.
// AArch64 vector instructions are .long-encoded for broad assembler compatibility.
// Register map:
//   w9       = double-round counter (4 iterations)
//   v0       = A
//   v1       = B
//   v2       = C
//   v3       = D
//   v4-v5    = quarter-round temps (add + shl + sri)
//   v16-v19  = saved XOR'd state (A,B,C,D) for the final addition
  .long 0x3dc00000                    // ldr q0, [x0, #0x0]
  .long 0x3dc00024                    // ldr q4, [x1, #0x0]
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x4ea01c10                    // mov v16.16b, v0.16b
  .long 0x3dc00401                    // ldr q1, [x0, #0x10]
  .long 0x3dc00424                    // ldr q4, [x1, #0x10]
  .long 0x6e241c21                    // eor v1.16b, v1.16b, v4.16b
  .long 0x4ea11c31                    // mov v17.16b, v1.16b
  .long 0x3dc00802                    // ldr q2, [x0, #0x20]
  .long 0x3dc00824                    // ldr q4, [x1, #0x20]
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x4ea21c52                    // mov v18.16b, v2.16b
  .long 0x3dc00c03                    // ldr q3, [x0, #0x30]
  .long 0x3dc00c24                    // ldr q4, [x1, #0x30]
  .long 0x6e241c63                    // eor v3.16b, v3.16b, v4.16b
  .long 0x4ea31c73                    // mov v19.16b, v3.16b
  mov w9, #4
.Lscrypt_double_round:
  .long 0x4ea38404                    // add v4.4s, v0.4s, v3.4s
  .long 0x4f275485                    // shl v5.4s, v4.4s, #7
  .long 0x6f274485                    // sri v5.4s, v4.4s, #25
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x4ea08424                    // add v4.4s, v1.4s, v0.4s
  .long 0x4f295485                    // shl v5.4s, v4.4s, #9
  .long 0x6f294485                    // sri v5.4s, v4.4s, #23
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x4ea18444                    // add v4.4s, v2.4s, v1.4s
  .long 0x4f2d5485                    // shl v5.4s, v4.4s, #13
  .long 0x6f2d4485                    // sri v5.4s, v4.4s, #19
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x4ea28464                    // add v4.4s, v3.4s, v2.4s
  .long 0x4f325485                    // shl v5.4s, v4.4s, #18
  .long 0x6f324485                    // sri v5.4s, v4.4s, #14
  .long 0x6e251c00                    // eor v0.16b, v0.16b, v5.16b
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e032063                    // ext v3.16b, v3.16b, v3.16b, #4
  .long 0x4ea18404                    // add v4.4s, v0.4s, v1.4s
  .long 0x4f275485                    // shl v5.4s, v4.4s, #7
  .long 0x6f274485                    // sri v5.4s, v4.4s, #25
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x4ea08464                    // add v4.4s, v3.4s, v0.4s
  .long 0x4f295485                    // shl v5.4s, v4.4s, #9
  .long 0x6f294485                    // sri v5.4s, v4.4s, #23
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x4ea38444                    // add v4.4s, v2.4s, v3.4s
  .long 0x4f2d5485                    // shl v5.4s, v4.4s, #13
  .long 0x6f2d4485                    // sri v5.4s, v4.4s, #19
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x4ea28424                    // add v4.4s, v1.4s, v2.4s
  .long 0x4f325485                    // shl v5.4s, v4.4s, #18
  .long 0x6f324485                    // sri v5.4s, v4.4s, #14
  .long 0x6e251c00                    // eor v0.16b, v0.16b, v5.16b
  .long 0x6e012021                    // ext v1.16b, v1.16b, v1.16b, #4
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e036063                    // ext v3.16b, v3.16b, v3.16b, #12
  subs w9, w9, #1
  b.ne .Lscrypt_double_round
  .long 0x4eb08400                    // add v0.4s, v0.4s, v16.4s
  .long 0x3d800000                    // str q0, [x0, #0x0]
  .long 0x4eb18421                    // add v1.4s, v1.4s, v17.4s
  .long 0x3d800401                    // str q1, [x0, #0x10]
  .long 0x4eb28442                    // add v2.4s, v2.4s, v18.4s
  .long 0x3d800802                    // str q2, [x0, #0x20]
  .long 0x4eb38463                    // add v3.4s, v3.4s, v19.4s
  .long 0x3d800c03                    // str q3, [x0, #0x30]
  ret
