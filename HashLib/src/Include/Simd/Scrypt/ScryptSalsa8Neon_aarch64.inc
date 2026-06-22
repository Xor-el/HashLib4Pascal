// AArch64 NEON implementation of fused XOR + Salsa20/8 on Percival-permuted data.
//
// Reference: Colin Percival, "Stronger Key Derivation via Sequential
// Memory-Hard Functions" (2009); Tarsnap scrypt crypto_scrypt_smix_sse2.c;
// HashLib ScryptSalsa8Sse2_x86_64.inc. The (i*5 mod 16) data permutation
// arranges each 16-word Salsa20 state into role-based diagonal order,
// enabling lane-parallel SIMD processing of column and row quarter-rounds
// with pshufd-based diagonalize/undiagonalize between them.
//
// Expects AAPCS64: x0 = State ptr, x1 = Input ptr.
// Each pointer addresses 16 UInt32 (64 bytes) in permuted order:
//   v0 = A = {w0,w5,w10,w15}, v1 = B = {w4,w9,w14,w3},
//   v2 = C = {w8,w13,w2,w7},  v3 = D = {w12,w1,w6,w11}.
// Operation: State = Salsa20/8(State XOR Input)
// Uses v0-v5, v16 (pshufd scratch); caller-saved only, leaf nostackframe.
// Stack: 80 bytes (64 for saved XOR'd state + 16 for AAPCS64 alignment).
//
// Column QR (lane-parallel):
//   B ^= rotl(A+D,7); C ^= rotl(B+A,9); D ^= rotl(C+B,13); A ^= rotl(D+C,18)
// Diag:   ins/pshufd B,$93; C,$4E; D,$39
// Row QR (lane-parallel, swapped B/D roles):
//   D ^= rotl(A+B,7); C ^= rotl(D+A,9); B ^= rotl(C+D,13); A ^= rotl(B+C,18)
// Undiag: ins/pshufd B,$39; C,$4E; D,$93
//
// Instruction encodings (for assembler compatibility):
//   FPC 3.2.2's inline assembler cannot encode AArch64 vector mnemonics
//   (subscripted vector regs require FPC 3.3+, and ldr/str/ldp with qN crash the
//   3.2.2 assembler). Each such instruction is therefore emitted as its raw 32-bit
//   '.long' opcode, with the equivalent mnemonic in the trailing comment; only
//   stack/loop/ret mnemonics stay as text.
//
// Register map:
//   w9       = double-round counter (4 iterations)
//   v0       = A
//   v1       = B
//   v2       = C
//   v3       = D
//   v4-v5    = quarter-round temps (add + rotl)
//   v16      = pshufd/ins scratch when permuting in-place
  sub sp, sp, #80
  .long 0x3dc00000                    // ldr q0, [x0, #0x0]
  .long 0x3dc00024                    // ldr q4, [x1, #0x0]
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x3d8003e0                    // str q0, [sp, #0x0]
  .long 0x3dc00401                    // ldr q1, [x0, #0x10]
  .long 0x3dc00424                    // ldr q4, [x1, #0x10]
  .long 0x6e241c21                    // eor v1.16b, v1.16b, v4.16b
  .long 0x3d8007e1                    // str q1, [sp, #0x10]
  .long 0x3dc00802                    // ldr q2, [x0, #0x20]
  .long 0x3dc00824                    // ldr q4, [x1, #0x20]
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x3d800be2                    // str q2, [sp, #0x20]
  .long 0x3dc00c03                    // ldr q3, [x0, #0x30]
  .long 0x3dc00c24                    // ldr q4, [x1, #0x30]
  .long 0x6e241c63                    // eor v3.16b, v3.16b, v4.16b
  .long 0x3d800fe3                    // str q3, [sp, #0x30]
  mov w9, #4
.Lscrypt_double_round:
  .long 0x4ea38404                    // add v4.4s, v0.4s, v3.4s
  .long 0x4f275485                    // shl v5.4s, v4.4s, #7
  .long 0x6f270484                    // ushr v4.4s, v4.4s, #25
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x6e241c21                    // eor v1.16b, v1.16b, v4.16b
  .long 0x4ea08424                    // add v4.4s, v1.4s, v0.4s
  .long 0x4f295485                    // shl v5.4s, v4.4s, #9
  .long 0x6f290484                    // ushr v4.4s, v4.4s, #23
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x4ea18444                    // add v4.4s, v2.4s, v1.4s
  .long 0x4f2d5485                    // shl v5.4s, v4.4s, #13
  .long 0x6f2d0484                    // ushr v4.4s, v4.4s, #19
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6e241c63                    // eor v3.16b, v3.16b, v4.16b
  .long 0x4ea28464                    // add v4.4s, v3.4s, v2.4s
  .long 0x4f325485                    // shl v5.4s, v4.4s, #18
  .long 0x6f320484                    // ushr v4.4s, v4.4s, #14
  .long 0x6e251c00                    // eor v0.16b, v0.16b, v5.16b
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x6e046430                    // ins v16.s[0], v1.s[3]
  .long 0x6e0c0430                    // ins v16.s[1], v1.s[0]
  .long 0x6e142430                    // ins v16.s[2], v1.s[1]
  .long 0x6e1c4430                    // ins v16.s[3], v1.s[2]
  .long 0x4eb01e01                    // orr v1.16b, v16.16b, v16.16b
  .long 0x6e044450                    // ins v16.s[0], v2.s[2]
  .long 0x6e0c6450                    // ins v16.s[1], v2.s[3]
  .long 0x6e140450                    // ins v16.s[2], v2.s[0]
  .long 0x6e1c2450                    // ins v16.s[3], v2.s[1]
  .long 0x4eb01e02                    // orr v2.16b, v16.16b, v16.16b
  .long 0x6e042470                    // ins v16.s[0], v3.s[1]
  .long 0x6e0c4470                    // ins v16.s[1], v3.s[2]
  .long 0x6e146470                    // ins v16.s[2], v3.s[3]
  .long 0x6e1c0470                    // ins v16.s[3], v3.s[0]
  .long 0x4eb01e03                    // orr v3.16b, v16.16b, v16.16b
  .long 0x4ea18404                    // add v4.4s, v0.4s, v1.4s
  .long 0x4f275485                    // shl v5.4s, v4.4s, #7
  .long 0x6f270484                    // ushr v4.4s, v4.4s, #25
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6e241c63                    // eor v3.16b, v3.16b, v4.16b
  .long 0x4ea08464                    // add v4.4s, v3.4s, v0.4s
  .long 0x4f295485                    // shl v5.4s, v4.4s, #9
  .long 0x6f290484                    // ushr v4.4s, v4.4s, #23
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x4ea38444                    // add v4.4s, v2.4s, v3.4s
  .long 0x4f2d5485                    // shl v5.4s, v4.4s, #13
  .long 0x6f2d0484                    // ushr v4.4s, v4.4s, #19
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x6e241c21                    // eor v1.16b, v1.16b, v4.16b
  .long 0x4ea28424                    // add v4.4s, v1.4s, v2.4s
  .long 0x4f325485                    // shl v5.4s, v4.4s, #18
  .long 0x6f320484                    // ushr v4.4s, v4.4s, #14
  .long 0x6e251c00                    // eor v0.16b, v0.16b, v5.16b
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x6e042430                    // ins v16.s[0], v1.s[1]
  .long 0x6e0c4430                    // ins v16.s[1], v1.s[2]
  .long 0x6e146430                    // ins v16.s[2], v1.s[3]
  .long 0x6e1c0430                    // ins v16.s[3], v1.s[0]
  .long 0x4eb01e01                    // orr v1.16b, v16.16b, v16.16b
  .long 0x6e044450                    // ins v16.s[0], v2.s[2]
  .long 0x6e0c6450                    // ins v16.s[1], v2.s[3]
  .long 0x6e140450                    // ins v16.s[2], v2.s[0]
  .long 0x6e1c2450                    // ins v16.s[3], v2.s[1]
  .long 0x4eb01e02                    // orr v2.16b, v16.16b, v16.16b
  .long 0x6e046470                    // ins v16.s[0], v3.s[3]
  .long 0x6e0c0470                    // ins v16.s[1], v3.s[0]
  .long 0x6e142470                    // ins v16.s[2], v3.s[1]
  .long 0x6e1c4470                    // ins v16.s[3], v3.s[2]
  .long 0x4eb01e03                    // orr v3.16b, v16.16b, v16.16b
  subs w9, w9, #1
  b.ne .Lscrypt_double_round
  .long 0x3dc003e4                    // ldr q4, [sp, #0x0]
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x3d800000                    // str q0, [x0, #0x0]
  .long 0x3dc007e4                    // ldr q4, [sp, #0x10]
  .long 0x4ea48421                    // add v1.4s, v1.4s, v4.4s
  .long 0x3d800401                    // str q1, [x0, #0x10]
  .long 0x3dc00be4                    // ldr q4, [sp, #0x20]
  .long 0x4ea48442                    // add v2.4s, v2.4s, v4.4s
  .long 0x3d800802                    // str q2, [x0, #0x20]
  .long 0x3dc00fe4                    // ldr q4, [sp, #0x30]
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x3d800c03                    // str q3, [x0, #0x30]
  add sp, sp, #80
  ret
