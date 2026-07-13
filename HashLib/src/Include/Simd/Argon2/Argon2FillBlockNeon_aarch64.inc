// Argon2 FillBlock AArch64 NEON implementation (BlaMka round function).
// Expects AAPCS64: x0 = Left ptr, x1 = Right ptr, x2 = Current ptr, w3 = WithXor.
// Each pointer addresses 128 UInt64 (1024 bytes).
// Stack frame 2128 bytes; see register map.
// Steps: R=Left XOR Right; Z=copy(R); 8 column + 8 row BlaMka rounds on Z;
//   Current = R XOR Z [XOR Current if WithXor]. Diagonalize via vext #8.
// Reference: jedisct1/libsodium argon2-fill-block-neon.c, HashLib Argon2FillBlockSse2_x86_64.inc.
// AArch64 vector instructions are .long-encoded for broad assembler compatibility.
// Register map:
//   v0-v1    = A0, A1
//   v2-v3    = B0, B1
//   v4-v5    = C0, C1
//   v6-v7    = D0, D1
//   v16-v18  = fBlaMka / rotate temps (2-op insert rotates rename B/D rows
//     through v16/v17; rows return home before each slice store)
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
  .long 0x6f685450                    // sli v16.2d, v2.2d, #40
  .long 0x6f680471                    // ushr v17.2d, v3.2d, #24
  .long 0x6f685471                    // sli v17.2d, v3.2d, #40
  .long 0x0ea12802                    // xtn v2.2s, v0.2d
  .long 0x0ea12a03                    // xtn v3.2s, v16.2d
  .long 0x2ea3c052                    // umull v18.2d, v2.2s, v3.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ef08400                    // add v0.2d, v0.2d, v16.2d
  .long 0x4ef28400                    // add v0.2d, v0.2d, v18.2d
  .long 0x0ea12822                    // xtn v2.2s, v1.2d
  .long 0x0ea12a23                    // xtn v3.2s, v17.2d
  .long 0x2ea3c052                    // umull v18.2d, v2.2s, v3.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ef18421                    // add v1.2d, v1.2d, v17.2d
  .long 0x4ef28421                    // add v1.2d, v1.2d, v18.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004c2                    // ushr v2.2d, v6.2d, #16
  .long 0x6f7054c2                    // sli v2.2d, v6.2d, #48
  .long 0x6f7004e3                    // ushr v3.2d, v7.2d, #16
  .long 0x6f7054e3                    // sli v3.2d, v7.2d, #48
  .long 0x0ea12886                    // xtn v6.2s, v4.2d
  .long 0x0ea12847                    // xtn v7.2s, v2.2d
  .long 0x2ea7c0d2                    // umull v18.2d, v6.2s, v7.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ef28484                    // add v4.2d, v4.2d, v18.2d
  .long 0x0ea128a6                    // xtn v6.2s, v5.2d
  .long 0x0ea12867                    // xtn v7.2s, v3.2d
  .long 0x2ea7c0d2                    // umull v18.2d, v6.2s, v7.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x4ef284a5                    // add v5.2d, v5.2d, v18.2d
  .long 0x6e241e10                    // eor v16.16b, v16.16b, v4.16b
  .long 0x6e251e31                    // eor v17.16b, v17.16b, v5.16b
  .long 0x4ef08606                    // add v6.2d, v16.2d, v16.2d
  .long 0x6f414606                    // sri v6.2d, v16.2d, #63
  .long 0x4ef18627                    // add v7.2d, v17.2d, v17.2d
  .long 0x6f414627                    // sri v7.2d, v17.2d, #63
  .long 0x6e0740d0                    // ext v16.16b, v6.16b, v7.16b, #8
  .long 0x6e0640f1                    // ext v17.16b, v7.16b, v6.16b, #8
  .long 0x4eb01e06                    // orr v6.16b, v16.16b, v16.16b
  .long 0x4eb11e27                    // orr v7.16b, v17.16b, v17.16b
  .long 0x4ea41c90                    // orr v16.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb01e05                    // orr v5.16b, v16.16b, v16.16b
  .long 0x6e034050                    // ext v16.16b, v2.16b, v3.16b, #8
  .long 0x6e024071                    // ext v17.16b, v3.16b, v2.16b, #8
  .long 0x4eb11e22                    // orr v2.16b, v17.16b, v17.16b
  .long 0x4eb01e03                    // orr v3.16b, v16.16b, v16.16b
  .long 0x0ea12810                    // xtn v16.2s, v0.2d
  .long 0x0ea128d1                    // xtn v17.2s, v6.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee68400                    // add v0.2d, v0.2d, v6.2d
  .long 0x4ef28400                    // add v0.2d, v0.2d, v18.2d
  .long 0x0ea12830                    // xtn v16.2s, v1.2d
  .long 0x0ea128f1                    // xtn v17.2s, v7.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee78421                    // add v1.2d, v1.2d, v7.2d
  .long 0x4ef28421                    // add v1.2d, v1.2d, v18.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x4ea00842                    // rev64 v2.4s, v2.4s
  .long 0x4ea00863                    // rev64 v3.4s, v3.4s
  .long 0x0ea12890                    // xtn v16.2s, v4.2d
  .long 0x0ea12851                    // xtn v17.2s, v2.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ef28484                    // add v4.2d, v4.2d, v18.2d
  .long 0x0ea128b0                    // xtn v16.2s, v5.2d
  .long 0x0ea12871                    // xtn v17.2s, v3.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x4ef284a5                    // add v5.2d, v5.2d, v18.2d
  .long 0x6e241cc6                    // eor v6.16b, v6.16b, v4.16b
  .long 0x6e251ce7                    // eor v7.16b, v7.16b, v5.16b
  .long 0x6f6804d0                    // ushr v16.2d, v6.2d, #24
  .long 0x6f6854d0                    // sli v16.2d, v6.2d, #40
  .long 0x6f6804f1                    // ushr v17.2d, v7.2d, #24
  .long 0x6f6854f1                    // sli v17.2d, v7.2d, #40
  .long 0x0ea12806                    // xtn v6.2s, v0.2d
  .long 0x0ea12a07                    // xtn v7.2s, v16.2d
  .long 0x2ea7c0d2                    // umull v18.2d, v6.2s, v7.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ef08400                    // add v0.2d, v0.2d, v16.2d
  .long 0x4ef28400                    // add v0.2d, v0.2d, v18.2d
  .long 0x0ea12826                    // xtn v6.2s, v1.2d
  .long 0x0ea12a27                    // xtn v7.2s, v17.2d
  .long 0x2ea7c0d2                    // umull v18.2d, v6.2s, v7.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ef18421                    // add v1.2d, v1.2d, v17.2d
  .long 0x4ef28421                    // add v1.2d, v1.2d, v18.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x6f700446                    // ushr v6.2d, v2.2d, #16
  .long 0x6f705446                    // sli v6.2d, v2.2d, #48
  .long 0x6f700467                    // ushr v7.2d, v3.2d, #16
  .long 0x6f705467                    // sli v7.2d, v3.2d, #48
  .long 0x0ea12882                    // xtn v2.2s, v4.2d
  .long 0x0ea128c3                    // xtn v3.2s, v6.2d
  .long 0x2ea3c052                    // umull v18.2d, v2.2s, v3.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ef28484                    // add v4.2d, v4.2d, v18.2d
  .long 0x0ea128a2                    // xtn v2.2s, v5.2d
  .long 0x0ea128e3                    // xtn v3.2s, v7.2d
  .long 0x2ea3c052                    // umull v18.2d, v2.2s, v3.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x4ef284a5                    // add v5.2d, v5.2d, v18.2d
  .long 0x6e241e10                    // eor v16.16b, v16.16b, v4.16b
  .long 0x6e251e31                    // eor v17.16b, v17.16b, v5.16b
  .long 0x4ef08602                    // add v2.2d, v16.2d, v16.2d
  .long 0x6f414602                    // sri v2.2d, v16.2d, #63
  .long 0x4ef18623                    // add v3.2d, v17.2d, v17.2d
  .long 0x6f414623                    // sri v3.2d, v17.2d, #63
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
  .long 0x6f685450                    // sli v16.2d, v2.2d, #40
  .long 0x6f680471                    // ushr v17.2d, v3.2d, #24
  .long 0x6f685471                    // sli v17.2d, v3.2d, #40
  .long 0x0ea12802                    // xtn v2.2s, v0.2d
  .long 0x0ea12a03                    // xtn v3.2s, v16.2d
  .long 0x2ea3c052                    // umull v18.2d, v2.2s, v3.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ef08400                    // add v0.2d, v0.2d, v16.2d
  .long 0x4ef28400                    // add v0.2d, v0.2d, v18.2d
  .long 0x0ea12822                    // xtn v2.2s, v1.2d
  .long 0x0ea12a23                    // xtn v3.2s, v17.2d
  .long 0x2ea3c052                    // umull v18.2d, v2.2s, v3.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ef18421                    // add v1.2d, v1.2d, v17.2d
  .long 0x4ef28421                    // add v1.2d, v1.2d, v18.2d
  .long 0x6e201cc6                    // eor v6.16b, v6.16b, v0.16b
  .long 0x6e211ce7                    // eor v7.16b, v7.16b, v1.16b
  .long 0x6f7004c2                    // ushr v2.2d, v6.2d, #16
  .long 0x6f7054c2                    // sli v2.2d, v6.2d, #48
  .long 0x6f7004e3                    // ushr v3.2d, v7.2d, #16
  .long 0x6f7054e3                    // sli v3.2d, v7.2d, #48
  .long 0x0ea12886                    // xtn v6.2s, v4.2d
  .long 0x0ea12847                    // xtn v7.2s, v2.2d
  .long 0x2ea7c0d2                    // umull v18.2d, v6.2s, v7.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ef28484                    // add v4.2d, v4.2d, v18.2d
  .long 0x0ea128a6                    // xtn v6.2s, v5.2d
  .long 0x0ea12867                    // xtn v7.2s, v3.2d
  .long 0x2ea7c0d2                    // umull v18.2d, v6.2s, v7.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x4ef284a5                    // add v5.2d, v5.2d, v18.2d
  .long 0x6e241e10                    // eor v16.16b, v16.16b, v4.16b
  .long 0x6e251e31                    // eor v17.16b, v17.16b, v5.16b
  .long 0x4ef08606                    // add v6.2d, v16.2d, v16.2d
  .long 0x6f414606                    // sri v6.2d, v16.2d, #63
  .long 0x4ef18627                    // add v7.2d, v17.2d, v17.2d
  .long 0x6f414627                    // sri v7.2d, v17.2d, #63
  .long 0x6e0740d0                    // ext v16.16b, v6.16b, v7.16b, #8
  .long 0x6e0640f1                    // ext v17.16b, v7.16b, v6.16b, #8
  .long 0x4eb01e06                    // orr v6.16b, v16.16b, v16.16b
  .long 0x4eb11e27                    // orr v7.16b, v17.16b, v17.16b
  .long 0x4ea41c90                    // orr v16.16b, v4.16b, v4.16b
  .long 0x4ea51ca4                    // orr v4.16b, v5.16b, v5.16b
  .long 0x4eb01e05                    // orr v5.16b, v16.16b, v16.16b
  .long 0x6e034050                    // ext v16.16b, v2.16b, v3.16b, #8
  .long 0x6e024071                    // ext v17.16b, v3.16b, v2.16b, #8
  .long 0x4eb11e22                    // orr v2.16b, v17.16b, v17.16b
  .long 0x4eb01e03                    // orr v3.16b, v16.16b, v16.16b
  .long 0x0ea12810                    // xtn v16.2s, v0.2d
  .long 0x0ea128d1                    // xtn v17.2s, v6.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee68400                    // add v0.2d, v0.2d, v6.2d
  .long 0x4ef28400                    // add v0.2d, v0.2d, v18.2d
  .long 0x0ea12830                    // xtn v16.2s, v1.2d
  .long 0x0ea128f1                    // xtn v17.2s, v7.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee78421                    // add v1.2d, v1.2d, v7.2d
  .long 0x4ef28421                    // add v1.2d, v1.2d, v18.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x4ea00842                    // rev64 v2.4s, v2.4s
  .long 0x4ea00863                    // rev64 v3.4s, v3.4s
  .long 0x0ea12890                    // xtn v16.2s, v4.2d
  .long 0x0ea12851                    // xtn v17.2s, v2.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee28484                    // add v4.2d, v4.2d, v2.2d
  .long 0x4ef28484                    // add v4.2d, v4.2d, v18.2d
  .long 0x0ea128b0                    // xtn v16.2s, v5.2d
  .long 0x0ea12871                    // xtn v17.2s, v3.2d
  .long 0x2eb1c212                    // umull v18.2d, v16.2s, v17.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee384a5                    // add v5.2d, v5.2d, v3.2d
  .long 0x4ef284a5                    // add v5.2d, v5.2d, v18.2d
  .long 0x6e241cc6                    // eor v6.16b, v6.16b, v4.16b
  .long 0x6e251ce7                    // eor v7.16b, v7.16b, v5.16b
  .long 0x6f6804d0                    // ushr v16.2d, v6.2d, #24
  .long 0x6f6854d0                    // sli v16.2d, v6.2d, #40
  .long 0x6f6804f1                    // ushr v17.2d, v7.2d, #24
  .long 0x6f6854f1                    // sli v17.2d, v7.2d, #40
  .long 0x0ea12806                    // xtn v6.2s, v0.2d
  .long 0x0ea12a07                    // xtn v7.2s, v16.2d
  .long 0x2ea7c0d2                    // umull v18.2d, v6.2s, v7.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ef08400                    // add v0.2d, v0.2d, v16.2d
  .long 0x4ef28400                    // add v0.2d, v0.2d, v18.2d
  .long 0x0ea12826                    // xtn v6.2s, v1.2d
  .long 0x0ea12a27                    // xtn v7.2s, v17.2d
  .long 0x2ea7c0d2                    // umull v18.2d, v6.2s, v7.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ef18421                    // add v1.2d, v1.2d, v17.2d
  .long 0x4ef28421                    // add v1.2d, v1.2d, v18.2d
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x6f700446                    // ushr v6.2d, v2.2d, #16
  .long 0x6f705446                    // sli v6.2d, v2.2d, #48
  .long 0x6f700467                    // ushr v7.2d, v3.2d, #16
  .long 0x6f705467                    // sli v7.2d, v3.2d, #48
  .long 0x0ea12882                    // xtn v2.2s, v4.2d
  .long 0x0ea128c3                    // xtn v3.2s, v6.2d
  .long 0x2ea3c052                    // umull v18.2d, v2.2s, v3.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee68484                    // add v4.2d, v4.2d, v6.2d
  .long 0x4ef28484                    // add v4.2d, v4.2d, v18.2d
  .long 0x0ea128a2                    // xtn v2.2s, v5.2d
  .long 0x0ea128e3                    // xtn v3.2s, v7.2d
  .long 0x2ea3c052                    // umull v18.2d, v2.2s, v3.2s
  .long 0x4ef28652                    // add v18.2d, v18.2d, v18.2d
  .long 0x4ee784a5                    // add v5.2d, v5.2d, v7.2d
  .long 0x4ef284a5                    // add v5.2d, v5.2d, v18.2d
  .long 0x6e241e10                    // eor v16.16b, v16.16b, v4.16b
  .long 0x6e251e31                    // eor v17.16b, v17.16b, v5.16b
  .long 0x4ef08602                    // add v2.2d, v16.2d, v16.2d
  .long 0x6f414602                    // sri v2.2d, v16.2d, #63
  .long 0x4ef18623                    // add v3.2d, v17.2d, v17.2d
  .long 0x6f414623                    // sri v3.2d, v17.2d, #63
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
