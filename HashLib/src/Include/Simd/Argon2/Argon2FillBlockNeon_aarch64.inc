// AArch64 NEON implementation of Argon2 FillBlock (BlaMka round function).
//
// Reference: jedisct1/libsodium crypto_pwhash/argon2/argon2-fill-block-neon.c,
//   crypto_pwhash/argon2/blamka-round-neon.h; HashLib Argon2FillBlockSse2_x86_64.inc.
//
// Expects AAPCS64: x0 = Left ptr, x1 = Right ptr, x2 = Current ptr, w3 = WithXor.
// Each pointer addresses 128 UInt64 (1024 bytes).
// Uses v0-v7 (A/B/C/D pairs), v16-v18 temps; caller-saved only, leaf nostackframe.
// Stack: 2128 bytes — R_buf at [sp+64], Z_buf at [sp+1088], plus 16-byte SP pad.
// x9 = R_buf, x11 = Z_buf during rounds; x2/w3 survive all loops.
//
// Steps (same semantics as SSE2):
//   1. R_buf = Left XOR Right
//   2. Z_buf = copy(R_buf)
//   3. Eight column rounds on Z_buf (128-byte slices)
//   4. Eight row rounds on Z_buf (stride-16 qword access)
//   5. Current = R_buf XOR Z_buf [XOR Current if WithXor <> 0]
// Indexed loads/stores in steps 1/2/5: ldr/str qN, [xBase, x10].
// Column/row slices: x12 = x11 + x10, then ldr/str qN, [x12, #imm].
// Diagonalize uses vext #8 (blamka-round-neon.h), not SSE2 shufpd.
//
// Instruction encodings (for assembler compatibility):
//   FPC 3.2.2's inline assembler cannot encode AArch64 vector mnemonics
//   (subscripted vector regs require FPC 3.3+, and ldr/str/ldp with qN crash the
//   3.2.2 assembler). Each such instruction is therefore emitted as its raw 32-bit
//   '.long' opcode, with the equivalent mnemonic in the trailing comment; only
//   add/mov/cmp/sub/cbz/b.lo/b/ret stay as text (never ldr/str/ldp with qN).
//
// Register map:
//   v0-v1    = A0, A1
//   v2-v3    = B0, B1
//   v4-v5    = C0, C1
//   v6-v7    = D0, D1
//   v16-v18  = fBlaMka / rotr temps
//   x9       = R_buf base ([sp+64])
//   x10      = loop byte offset (steps 1-5)
//   x11      = Z_buf base ([sp+1088])
//   x12      = Z slice pointer (column/row load/store)
//   w3       = WithXor (0 or 1)
  sub sp, sp, #2128
  add x9, sp, #64
  mov x10, #0
.Largon2_xor_loop:
  .long 0x3cea6800                    // ldr q0, [x0, x10]
  .long 0x3cea6821                    // ldr q1, [x1, x10]
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x3caa6920                    // str q0, [x9, x10]
  add x10, x10, #16
  cmp x10, #1024
  b.lo .Largon2_xor_loop
  add x11, sp, #1088
  mov x10, #0
.Largon2_copy_loop:
  .long 0x3cea6920                    // ldr q0, [x9, x10]
  .long 0x3caa6960                    // str q0, [x11, x10]
  add x10, x10, #16
  cmp x10, #1024
  b.lo .Largon2_copy_loop
  mov x10, #0
.Largon2_col_loop:
  add x12, x11, x10
  .long 0x3dc00180                    // ldr q0, [x12, #0]
  .long 0x3dc00581                    // ldr q1, [x12, #16]
  .long 0x3dc00982                    // ldr q2, [x12, #32]
  .long 0x3dc00d83                    // ldr q3, [x12, #48]
  .long 0x3dc01184                    // ldr q4, [x12, #64]
  .long 0x3dc01585                    // ldr q5, [x12, #80]
  .long 0x3dc01986                    // ldr q6, [x12, #96]
  .long 0x3dc01d87                    // ldr q7, [x12, #112]
  .long 0x0ea12810                    // xtn v16.2s, v0.2d
  .long 0x0ea12851                    // xtn v17.2s, v2.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee28400                    // add v0.2d, v0.2d, v2.2d
  .long 0x4ef28400                    // add v0.2d, v0.2d, v18.2d
  .long 0x0ea12830                    // xtn v16.2s, v1.2d
  .long 0x0ea12871                    // xtn v17.2s, v3.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee38421                    // add v1.2d, v1.2d, v3.2d
  .long 0x4ef28421                    // add v1.2d, v1.2d, v18.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x4ea008c6                    // rev64 v6.4s, v6.4s
  .long 0x4ea008e7                    // rev64 v7.4s, v7.4s
  .long 0x0ea12890                    // xtn v16.2s, v4.2d
  .long 0x0ea128d1                    // xtn v17.2s, v6.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ef28484                    // add v4.2d, v4.2d, v18.2d
  .long 0x0ea128b0                    // xtn v16.2s, v5.2d
  .long 0x0ea128f1                    // xtn v17.2s, v7.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x4ef284a5                    // add v5.2d, v5.2d, v18.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6f680450                    // ushr v16.2d, v2.2d, #24
  .long 0x4f685451                    // shl v17.2d, v2.2d, #40
  .long 0x4eb11e02                    // orr v2.16b, v16.16b, v17.16b
  .long 0x6f680470                    // ushr v16.2d, v3.2d, #24
  .long 0x4f685471                    // shl v17.2d, v3.2d, #40
  .long 0x4eb11e03                    // orr v3.16b, v16.16b, v17.16b
  .long 0x0ea12810                    // xtn v16.2s, v0.2d
  .long 0x0ea12851                    // xtn v17.2s, v2.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee28400                    // add v0.2d, v0.2d, v2.2d
  .long 0x4ef28400                    // add v0.2d, v0.2d, v18.2d
  .long 0x0ea12830                    // xtn v16.2s, v1.2d
  .long 0x0ea12871                    // xtn v17.2s, v3.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee38421                    // add v1.2d, v1.2d, v3.2d
  .long 0x4ef28421                    // add v1.2d, v1.2d, v18.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004d0                    // ushr v16.2d, v6.2d, #16
  .long 0x4f7054d1                    // shl v17.2d, v6.2d, #48
  .long 0x4eb11e06                    // orr v6.16b, v16.16b, v17.16b
  .long 0x6f7004f0                    // ushr v16.2d, v7.2d, #16
  .long 0x4f7054f1                    // shl v17.2d, v7.2d, #48
  .long 0x4eb11e07                    // orr v7.16b, v16.16b, v17.16b
  .long 0x0ea12890                    // xtn v16.2s, v4.2d
  .long 0x0ea128d1                    // xtn v17.2s, v6.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ef28484                    // add v4.2d, v4.2d, v18.2d
  .long 0x0ea128b0                    // xtn v16.2s, v5.2d
  .long 0x0ea128f1                    // xtn v17.2s, v7.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x4ef284a5                    // add v5.2d, v5.2d, v18.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x4ee28450                    // add v16.2d, v2.2d, v2.2d
  .long 0x6f410451                    // ushr v17.2d, v2.2d, #63
  .long 0x4eb11e02                    // orr v2.16b, v16.16b, v17.16b
  .long 0x4ee38470                    // add v16.2d, v3.2d, v3.2d
  .long 0x6f410471                    // ushr v17.2d, v3.2d, #63
  .long 0x4eb11e03                    // orr v3.16b, v16.16b, v17.16b
  .long 0x6e034050                    // ext v16.16b, v2.16b, v3.16b, #8
  .long 0x6e024071                    // ext v17.16b, v3.16b, v2.16b, #8
  .long 0x4eb01e02                    // orr v2.16b, v16.16b, v16.16b
  .long 0x4eb11e23                    // orr v3.16b, v17.16b, v17.16b
  .long 0x4ea41c90                    // orr v16.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb01e05                    // orr v5.16b, v16.16b, v16.16b
  .long 0x6e0740d0                    // ext v16.16b, v6.16b, v7.16b, #8
  .long 0x6e0640f1                    // ext v17.16b, v7.16b, v6.16b, #8
  .long 0x4eb11e26                    // orr v6.16b, v17.16b, v17.16b
  .long 0x4eb01e07                    // orr v7.16b, v16.16b, v16.16b
  .long 0x0ea12810                    // xtn v16.2s, v0.2d
  .long 0x0ea12851                    // xtn v17.2s, v2.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee28400                    // add v0.2d, v0.2d, v2.2d
  .long 0x4ef28400                    // add v0.2d, v0.2d, v18.2d
  .long 0x0ea12830                    // xtn v16.2s, v1.2d
  .long 0x0ea12871                    // xtn v17.2s, v3.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee38421                    // add v1.2d, v1.2d, v3.2d
  .long 0x4ef28421                    // add v1.2d, v1.2d, v18.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x4ea008c6                    // rev64 v6.4s, v6.4s
  .long 0x4ea008e7                    // rev64 v7.4s, v7.4s
  .long 0x0ea12890                    // xtn v16.2s, v4.2d
  .long 0x0ea128d1                    // xtn v17.2s, v6.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ef28484                    // add v4.2d, v4.2d, v18.2d
  .long 0x0ea128b0                    // xtn v16.2s, v5.2d
  .long 0x0ea128f1                    // xtn v17.2s, v7.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x4ef284a5                    // add v5.2d, v5.2d, v18.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6f680450                    // ushr v16.2d, v2.2d, #24
  .long 0x4f685451                    // shl v17.2d, v2.2d, #40
  .long 0x4eb11e02                    // orr v2.16b, v16.16b, v17.16b
  .long 0x6f680470                    // ushr v16.2d, v3.2d, #24
  .long 0x4f685471                    // shl v17.2d, v3.2d, #40
  .long 0x4eb11e03                    // orr v3.16b, v16.16b, v17.16b
  .long 0x0ea12810                    // xtn v16.2s, v0.2d
  .long 0x0ea12851                    // xtn v17.2s, v2.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee28400                    // add v0.2d, v0.2d, v2.2d
  .long 0x4ef28400                    // add v0.2d, v0.2d, v18.2d
  .long 0x0ea12830                    // xtn v16.2s, v1.2d
  .long 0x0ea12871                    // xtn v17.2s, v3.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee38421                    // add v1.2d, v1.2d, v3.2d
  .long 0x4ef28421                    // add v1.2d, v1.2d, v18.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004d0                    // ushr v16.2d, v6.2d, #16
  .long 0x4f7054d1                    // shl v17.2d, v6.2d, #48
  .long 0x4eb11e06                    // orr v6.16b, v16.16b, v17.16b
  .long 0x6f7004f0                    // ushr v16.2d, v7.2d, #16
  .long 0x4f7054f1                    // shl v17.2d, v7.2d, #48
  .long 0x4eb11e07                    // orr v7.16b, v16.16b, v17.16b
  .long 0x0ea12890                    // xtn v16.2s, v4.2d
  .long 0x0ea128d1                    // xtn v17.2s, v6.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ef28484                    // add v4.2d, v4.2d, v18.2d
  .long 0x0ea128b0                    // xtn v16.2s, v5.2d
  .long 0x0ea128f1                    // xtn v17.2s, v7.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x4ef284a5                    // add v5.2d, v5.2d, v18.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x4ee28450                    // add v16.2d, v2.2d, v2.2d
  .long 0x6f410451                    // ushr v17.2d, v2.2d, #63
  .long 0x4eb11e02                    // orr v2.16b, v16.16b, v17.16b
  .long 0x4ee38470                    // add v16.2d, v3.2d, v3.2d
  .long 0x6f410471                    // ushr v17.2d, v3.2d, #63
  .long 0x4eb11e03                    // orr v3.16b, v16.16b, v17.16b
  .long 0x6e024070                    // ext v16.16b, v3.16b, v2.16b, #8
  .long 0x6e034051                    // ext v17.16b, v2.16b, v3.16b, #8
  .long 0x4eb01e02                    // orr v2.16b, v16.16b, v16.16b
  .long 0x4eb11e23                    // orr v3.16b, v17.16b, v17.16b
  .long 0x4ea41c90                    // orr v16.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb01e05                    // orr v5.16b, v16.16b, v16.16b
  .long 0x6e0640f0                    // ext v16.16b, v7.16b, v6.16b, #8
  .long 0x6e0740d1                    // ext v17.16b, v6.16b, v7.16b, #8
  .long 0x4eb11e26                    // orr v6.16b, v17.16b, v17.16b
  .long 0x4eb01e07                    // orr v7.16b, v16.16b, v16.16b
  add x12, x11, x10
  .long 0x3d800180                    // str q0, [x12, #0]
  .long 0x3d800581                    // str q1, [x12, #16]
  .long 0x3d800982                    // str q2, [x12, #32]
  .long 0x3d800d83                    // str q3, [x12, #48]
  .long 0x3d801184                    // str q4, [x12, #64]
  .long 0x3d801585                    // str q5, [x12, #80]
  .long 0x3d801986                    // str q6, [x12, #96]
  .long 0x3d801d87                    // str q7, [x12, #112]
  add x10, x10, #128
  cmp x10, #1024
  b.lo .Largon2_col_loop
  mov x10, #0
.Largon2_row_loop:
  add x12, x11, x10
  .long 0x3dc00180                    // ldr q0, [x12, #0]
  .long 0x3dc02181                    // ldr q1, [x12, #128]
  .long 0x3dc04182                    // ldr q2, [x12, #256]
  .long 0x3dc06183                    // ldr q3, [x12, #384]
  .long 0x3dc08184                    // ldr q4, [x12, #512]
  .long 0x3dc0a185                    // ldr q5, [x12, #640]
  .long 0x3dc0c186                    // ldr q6, [x12, #768]
  .long 0x3dc0e187                    // ldr q7, [x12, #896]
  .long 0x0ea12810                    // xtn v16.2s, v0.2d
  .long 0x0ea12851                    // xtn v17.2s, v2.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee28400                    // add v0.2d, v0.2d, v2.2d
  .long 0x4ef28400                    // add v0.2d, v0.2d, v18.2d
  .long 0x0ea12830                    // xtn v16.2s, v1.2d
  .long 0x0ea12871                    // xtn v17.2s, v3.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee38421                    // add v1.2d, v1.2d, v3.2d
  .long 0x4ef28421                    // add v1.2d, v1.2d, v18.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x4ea008c6                    // rev64 v6.4s, v6.4s
  .long 0x4ea008e7                    // rev64 v7.4s, v7.4s
  .long 0x0ea12890                    // xtn v16.2s, v4.2d
  .long 0x0ea128d1                    // xtn v17.2s, v6.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ef28484                    // add v4.2d, v4.2d, v18.2d
  .long 0x0ea128b0                    // xtn v16.2s, v5.2d
  .long 0x0ea128f1                    // xtn v17.2s, v7.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x4ef284a5                    // add v5.2d, v5.2d, v18.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6f680450                    // ushr v16.2d, v2.2d, #24
  .long 0x4f685451                    // shl v17.2d, v2.2d, #40
  .long 0x4eb11e02                    // orr v2.16b, v16.16b, v17.16b
  .long 0x6f680470                    // ushr v16.2d, v3.2d, #24
  .long 0x4f685471                    // shl v17.2d, v3.2d, #40
  .long 0x4eb11e03                    // orr v3.16b, v16.16b, v17.16b
  .long 0x0ea12810                    // xtn v16.2s, v0.2d
  .long 0x0ea12851                    // xtn v17.2s, v2.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee28400                    // add v0.2d, v0.2d, v2.2d
  .long 0x4ef28400                    // add v0.2d, v0.2d, v18.2d
  .long 0x0ea12830                    // xtn v16.2s, v1.2d
  .long 0x0ea12871                    // xtn v17.2s, v3.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee38421                    // add v1.2d, v1.2d, v3.2d
  .long 0x4ef28421                    // add v1.2d, v1.2d, v18.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004d0                    // ushr v16.2d, v6.2d, #16
  .long 0x4f7054d1                    // shl v17.2d, v6.2d, #48
  .long 0x4eb11e06                    // orr v6.16b, v16.16b, v17.16b
  .long 0x6f7004f0                    // ushr v16.2d, v7.2d, #16
  .long 0x4f7054f1                    // shl v17.2d, v7.2d, #48
  .long 0x4eb11e07                    // orr v7.16b, v16.16b, v17.16b
  .long 0x0ea12890                    // xtn v16.2s, v4.2d
  .long 0x0ea128d1                    // xtn v17.2s, v6.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ef28484                    // add v4.2d, v4.2d, v18.2d
  .long 0x0ea128b0                    // xtn v16.2s, v5.2d
  .long 0x0ea128f1                    // xtn v17.2s, v7.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x4ef284a5                    // add v5.2d, v5.2d, v18.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x4ee28450                    // add v16.2d, v2.2d, v2.2d
  .long 0x6f410451                    // ushr v17.2d, v2.2d, #63
  .long 0x4eb11e02                    // orr v2.16b, v16.16b, v17.16b
  .long 0x4ee38470                    // add v16.2d, v3.2d, v3.2d
  .long 0x6f410471                    // ushr v17.2d, v3.2d, #63
  .long 0x4eb11e03                    // orr v3.16b, v16.16b, v17.16b
  .long 0x6e034050                    // ext v16.16b, v2.16b, v3.16b, #8
  .long 0x6e024071                    // ext v17.16b, v3.16b, v2.16b, #8
  .long 0x4eb01e02                    // orr v2.16b, v16.16b, v16.16b
  .long 0x4eb11e23                    // orr v3.16b, v17.16b, v17.16b
  .long 0x4ea41c90                    // orr v16.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb01e05                    // orr v5.16b, v16.16b, v16.16b
  .long 0x6e0740d0                    // ext v16.16b, v6.16b, v7.16b, #8
  .long 0x6e0640f1                    // ext v17.16b, v7.16b, v6.16b, #8
  .long 0x4eb11e26                    // orr v6.16b, v17.16b, v17.16b
  .long 0x4eb01e07                    // orr v7.16b, v16.16b, v16.16b
  .long 0x0ea12810                    // xtn v16.2s, v0.2d
  .long 0x0ea12851                    // xtn v17.2s, v2.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee28400                    // add v0.2d, v0.2d, v2.2d
  .long 0x4ef28400                    // add v0.2d, v0.2d, v18.2d
  .long 0x0ea12830                    // xtn v16.2s, v1.2d
  .long 0x0ea12871                    // xtn v17.2s, v3.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee38421                    // add v1.2d, v1.2d, v3.2d
  .long 0x4ef28421                    // add v1.2d, v1.2d, v18.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x4ea008c6                    // rev64 v6.4s, v6.4s
  .long 0x4ea008e7                    // rev64 v7.4s, v7.4s
  .long 0x0ea12890                    // xtn v16.2s, v4.2d
  .long 0x0ea128d1                    // xtn v17.2s, v6.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ef28484                    // add v4.2d, v4.2d, v18.2d
  .long 0x0ea128b0                    // xtn v16.2s, v5.2d
  .long 0x0ea128f1                    // xtn v17.2s, v7.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x4ef284a5                    // add v5.2d, v5.2d, v18.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x6f680450                    // ushr v16.2d, v2.2d, #24
  .long 0x4f685451                    // shl v17.2d, v2.2d, #40
  .long 0x4eb11e02                    // orr v2.16b, v16.16b, v17.16b
  .long 0x6f680470                    // ushr v16.2d, v3.2d, #24
  .long 0x4f685471                    // shl v17.2d, v3.2d, #40
  .long 0x4eb11e03                    // orr v3.16b, v16.16b, v17.16b
  .long 0x0ea12810                    // xtn v16.2s, v0.2d
  .long 0x0ea12851                    // xtn v17.2s, v2.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee28400                    // add v0.2d, v0.2d, v2.2d
  .long 0x4ef28400                    // add v0.2d, v0.2d, v18.2d
  .long 0x0ea12830                    // xtn v16.2s, v1.2d
  .long 0x0ea12871                    // xtn v17.2s, v3.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee38421                    // add v1.2d, v1.2d, v3.2d
  .long 0x4ef28421                    // add v1.2d, v1.2d, v18.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004d0                    // ushr v16.2d, v6.2d, #16
  .long 0x4f7054d1                    // shl v17.2d, v6.2d, #48
  .long 0x4eb11e06                    // orr v6.16b, v16.16b, v17.16b
  .long 0x6f7004f0                    // ushr v16.2d, v7.2d, #16
  .long 0x4f7054f1                    // shl v17.2d, v7.2d, #48
  .long 0x4eb11e07                    // orr v7.16b, v16.16b, v17.16b
  .long 0x0ea12890                    // xtn v16.2s, v4.2d
  .long 0x0ea128d1                    // xtn v17.2s, v6.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ef28484                    // add v4.2d, v4.2d, v18.2d
  .long 0x0ea128b0                    // xtn v16.2s, v5.2d
  .long 0x0ea128f1                    // xtn v17.2s, v7.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x4ef284a5                    // add v5.2d, v5.2d, v18.2d
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x4ee28450                    // add v16.2d, v2.2d, v2.2d
  .long 0x6f410451                    // ushr v17.2d, v2.2d, #63
  .long 0x4eb11e02                    // orr v2.16b, v16.16b, v17.16b
  .long 0x4ee38470                    // add v16.2d, v3.2d, v3.2d
  .long 0x6f410471                    // ushr v17.2d, v3.2d, #63
  .long 0x4eb11e03                    // orr v3.16b, v16.16b, v17.16b
  .long 0x6e024070                    // ext v16.16b, v3.16b, v2.16b, #8
  .long 0x6e034051                    // ext v17.16b, v2.16b, v3.16b, #8
  .long 0x4eb01e02                    // orr v2.16b, v16.16b, v16.16b
  .long 0x4eb11e23                    // orr v3.16b, v17.16b, v17.16b
  .long 0x4ea41c90                    // orr v16.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb01e05                    // orr v5.16b, v16.16b, v16.16b
  .long 0x6e0640f0                    // ext v16.16b, v7.16b, v6.16b, #8
  .long 0x6e0740d1                    // ext v17.16b, v6.16b, v7.16b, #8
  .long 0x4eb11e26                    // orr v6.16b, v17.16b, v17.16b
  .long 0x4eb01e07                    // orr v7.16b, v16.16b, v16.16b
  add x12, x11, x10
  .long 0x3d800180                    // str q0, [x12, #0]
  .long 0x3d802181                    // str q1, [x12, #128]
  .long 0x3d804182                    // str q2, [x12, #256]
  .long 0x3d806183                    // str q3, [x12, #384]
  .long 0x3d808184                    // str q4, [x12, #512]
  .long 0x3d80a185                    // str q5, [x12, #640]
  .long 0x3d80c186                    // str q6, [x12, #768]
  .long 0x3d80e187                    // str q7, [x12, #896]
  add x10, x10, #16
  cmp x10, #128
  b.lo .Largon2_row_loop
  cbz w3, .Largon2_final_noxor
  mov x10, #0
.Largon2_final_xor_loop:
  .long 0x3cea6920                    // ldr q0, [x9, x10]
  .long 0x3cea6961                    // ldr q1, [x11, x10]
  .long 0x3cea6842                    // ldr q2, [x2, x10]
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3caa6840                    // str q0, [x2, x10]
  add x10, x10, #16
  cmp x10, #1024
  b.lo .Largon2_final_xor_loop
  b .Largon2_epilogue
.Largon2_final_noxor:
  mov x10, #0
.Largon2_final_noxor_loop:
  .long 0x3cea6920                    // ldr q0, [x9, x10]
  .long 0x3cea6961                    // ldr q1, [x11, x10]
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x3caa6840                    // str q0, [x2, x10]
  add x10, x10, #16
  cmp x10, #1024
  b.lo .Largon2_final_noxor_loop
.Largon2_epilogue:
  add sp, sp, #2128
  ret
