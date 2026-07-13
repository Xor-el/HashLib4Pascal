// Gpr implementation of SHA-1 compress (AArch64) for cores without the
// SHA-1 crypto extension; the Gpr name states the ISA requirement: none
// beyond base AArch64. Serial SHA maps better onto the 31 GPRs than onto
// NEON lanes (single dependency chain, 1-op ror, rotate-folded eor
// operands). The four round constants are materialized as movz/movk
// immediates - no K table is read.
// ABI (after HlpSimdProc3Begin_aarch64.inc): x0 = state ptr (5 x UInt32),
//   x1 = data ptr, w2 = numblocks.
// Frame: 96-byte AAPCS64 frame (x29/x30 + x19-x28 callee-saved).
// AArch64 instructions are .long-encoded for broad assembler compatibility.
// Reference: OpenSSL CRYPTOGAMS sha1-armv8.pl (sha1_block_data_order, the
// plain path).

  .long 0x2a0203e2                  // mov w2,w2  // zero-extend ANumBlocks (AAPCS64 leaves x2's top half undefined)

  .long 0xa9ba7bfd                  // stp x29,x30,[sp,#-96]!
  .long 0x910003fd                  // add x29,sp,#0
  .long 0xa90153f3                  // stp x19,x20,[sp,#16]
  .long 0xa9025bf5                  // stp x21,x22,[sp,#32]
  .long 0xa90363f7                  // stp x23,x24,[sp,#48]
  .long 0xa9046bf9                  // stp x25,x26,[sp,#64]
  .long 0xa90573fb                  // stp x27,x28,[sp,#80]

  .long 0x29405414                  // ldp w20,w21,[x0]
  .long 0x29415c16                  // ldp w22,w23,[x0,#8]
  .long 0xb9401018                  // ldr w24,[x0,#16]


.Lsha1_gpr_loop:
  .long 0xf8440423                  // ldr x3,[x1],#64
  .long 0x528f333c                  // movz w28,#0x7999
  .long 0xd1000442                  // sub x2,x2,#1
  .long 0x72ab505c                  // movk w28,#0x5a82, lsl #16
  .long 0xdac00863                  // rev32 x3,x3
  .long 0x0b1c0318                  // add w24,w24,w28  // warm it up
  .long 0x0b030318                  // add w24,w24,w3
  .long 0xd360fc64                  // lsr x4,x3,#32
  .long 0xf85c8025                  // ldr x5,[x1,#-56]
  .long 0x0a3502f9                  // bic w25,w23,w21
  .long 0x0a1502da                  // and w26,w22,w21
  .long 0x13946e9b                  // ror w27,w20,#27
  .long 0x0b1c02f7                  // add w23,w23,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b0318                  // add w24,w24,w27  // e+=rot(a,5)
  .long 0x13950ab5                  // ror w21,w21,#2
  .long 0x0b0402f7                  // add w23,w23,w4  // future e+=X[i]
  .long 0x0b190318                  // add w24,w24,w25  // e+=F(b,c,d)
  .long 0xdac008a5                  // rev32 x5,x5
  .long 0x0a3402d9                  // bic w25,w22,w20
  .long 0x0a1402ba                  // and w26,w21,w20
  .long 0x13986f1b                  // ror w27,w24,#27
  .long 0x0b1c02d6                  // add w22,w22,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b02f7                  // add w23,w23,w27  // e+=rot(a,5)
  .long 0x13940a94                  // ror w20,w20,#2
  .long 0x0b0502d6                  // add w22,w22,w5  // future e+=X[i]
  .long 0x0b1902f7                  // add w23,w23,w25  // e+=F(b,c,d)
  .long 0xd360fca6                  // lsr x6,x5,#32
  .long 0xf85d0027                  // ldr x7,[x1,#-48]
  .long 0x0a3802b9                  // bic w25,w21,w24
  .long 0x0a18029a                  // and w26,w20,w24
  .long 0x13976efb                  // ror w27,w23,#27
  .long 0x0b1c02b5                  // add w21,w21,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b02d6                  // add w22,w22,w27  // e+=rot(a,5)
  .long 0x13980b18                  // ror w24,w24,#2
  .long 0x0b0602b5                  // add w21,w21,w6  // future e+=X[i]
  .long 0x0b1902d6                  // add w22,w22,w25  // e+=F(b,c,d)
  .long 0xdac008e7                  // rev32 x7,x7
  .long 0x0a370299                  // bic w25,w20,w23
  .long 0x0a17031a                  // and w26,w24,w23
  .long 0x13966edb                  // ror w27,w22,#27
  .long 0x0b1c0294                  // add w20,w20,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b02b5                  // add w21,w21,w27  // e+=rot(a,5)
  .long 0x13970af7                  // ror w23,w23,#2
  .long 0x0b070294                  // add w20,w20,w7  // future e+=X[i]
  .long 0x0b1902b5                  // add w21,w21,w25  // e+=F(b,c,d)
  .long 0xd360fce8                  // lsr x8,x7,#32
  .long 0xf85d8029                  // ldr x9,[x1,#-40]
  .long 0x0a360319                  // bic w25,w24,w22
  .long 0x0a1602fa                  // and w26,w23,w22
  .long 0x13956ebb                  // ror w27,w21,#27
  .long 0x0b1c0318                  // add w24,w24,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b0294                  // add w20,w20,w27  // e+=rot(a,5)
  .long 0x13960ad6                  // ror w22,w22,#2
  .long 0x0b080318                  // add w24,w24,w8  // future e+=X[i]
  .long 0x0b190294                  // add w20,w20,w25  // e+=F(b,c,d)
  .long 0xdac00929                  // rev32 x9,x9
  .long 0x0a3502f9                  // bic w25,w23,w21
  .long 0x0a1502da                  // and w26,w22,w21
  .long 0x13946e9b                  // ror w27,w20,#27
  .long 0x0b1c02f7                  // add w23,w23,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b0318                  // add w24,w24,w27  // e+=rot(a,5)
  .long 0x13950ab5                  // ror w21,w21,#2
  .long 0x0b0902f7                  // add w23,w23,w9  // future e+=X[i]
  .long 0x0b190318                  // add w24,w24,w25  // e+=F(b,c,d)
  .long 0xd360fd2a                  // lsr x10,x9,#32
  .long 0xf85e002b                  // ldr x11,[x1,#-32]
  .long 0x0a3402d9                  // bic w25,w22,w20
  .long 0x0a1402ba                  // and w26,w21,w20
  .long 0x13986f1b                  // ror w27,w24,#27
  .long 0x0b1c02d6                  // add w22,w22,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b02f7                  // add w23,w23,w27  // e+=rot(a,5)
  .long 0x13940a94                  // ror w20,w20,#2
  .long 0x0b0a02d6                  // add w22,w22,w10  // future e+=X[i]
  .long 0x0b1902f7                  // add w23,w23,w25  // e+=F(b,c,d)
  .long 0xdac0096b                  // rev32 x11,x11
  .long 0x0a3802b9                  // bic w25,w21,w24
  .long 0x0a18029a                  // and w26,w20,w24
  .long 0x13976efb                  // ror w27,w23,#27
  .long 0x0b1c02b5                  // add w21,w21,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b02d6                  // add w22,w22,w27  // e+=rot(a,5)
  .long 0x13980b18                  // ror w24,w24,#2
  .long 0x0b0b02b5                  // add w21,w21,w11  // future e+=X[i]
  .long 0x0b1902d6                  // add w22,w22,w25  // e+=F(b,c,d)
  .long 0xd360fd6c                  // lsr x12,x11,#32
  .long 0xf85e802d                  // ldr x13,[x1,#-24]
  .long 0x0a370299                  // bic w25,w20,w23
  .long 0x0a17031a                  // and w26,w24,w23
  .long 0x13966edb                  // ror w27,w22,#27
  .long 0x0b1c0294                  // add w20,w20,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b02b5                  // add w21,w21,w27  // e+=rot(a,5)
  .long 0x13970af7                  // ror w23,w23,#2
  .long 0x0b0c0294                  // add w20,w20,w12  // future e+=X[i]
  .long 0x0b1902b5                  // add w21,w21,w25  // e+=F(b,c,d)
  .long 0xdac009ad                  // rev32 x13,x13
  .long 0x0a360319                  // bic w25,w24,w22
  .long 0x0a1602fa                  // and w26,w23,w22
  .long 0x13956ebb                  // ror w27,w21,#27
  .long 0x0b1c0318                  // add w24,w24,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b0294                  // add w20,w20,w27  // e+=rot(a,5)
  .long 0x13960ad6                  // ror w22,w22,#2
  .long 0x0b0d0318                  // add w24,w24,w13  // future e+=X[i]
  .long 0x0b190294                  // add w20,w20,w25  // e+=F(b,c,d)
  .long 0xd360fdae                  // lsr x14,x13,#32
  .long 0xf85f002f                  // ldr x15,[x1,#-16]
  .long 0x0a3502f9                  // bic w25,w23,w21
  .long 0x0a1502da                  // and w26,w22,w21
  .long 0x13946e9b                  // ror w27,w20,#27
  .long 0x0b1c02f7                  // add w23,w23,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b0318                  // add w24,w24,w27  // e+=rot(a,5)
  .long 0x13950ab5                  // ror w21,w21,#2
  .long 0x0b0e02f7                  // add w23,w23,w14  // future e+=X[i]
  .long 0x0b190318                  // add w24,w24,w25  // e+=F(b,c,d)
  .long 0xdac009ef                  // rev32 x15,x15
  .long 0x0a3402d9                  // bic w25,w22,w20
  .long 0x0a1402ba                  // and w26,w21,w20
  .long 0x13986f1b                  // ror w27,w24,#27
  .long 0x0b1c02d6                  // add w22,w22,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b02f7                  // add w23,w23,w27  // e+=rot(a,5)
  .long 0x13940a94                  // ror w20,w20,#2
  .long 0x0b0f02d6                  // add w22,w22,w15  // future e+=X[i]
  .long 0x0b1902f7                  // add w23,w23,w25  // e+=F(b,c,d)
  .long 0xd360fdf0                  // lsr x16,x15,#32
  .long 0xf85f8031                  // ldr x17,[x1,#-8]
  .long 0x0a3802b9                  // bic w25,w21,w24
  .long 0x0a18029a                  // and w26,w20,w24
  .long 0x13976efb                  // ror w27,w23,#27
  .long 0x0b1c02b5                  // add w21,w21,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b02d6                  // add w22,w22,w27  // e+=rot(a,5)
  .long 0x13980b18                  // ror w24,w24,#2
  .long 0x0b1002b5                  // add w21,w21,w16  // future e+=X[i]
  .long 0x0b1902d6                  // add w22,w22,w25  // e+=F(b,c,d)
  .long 0xdac00a31                  // rev32 x17,x17
  .long 0x0a370299                  // bic w25,w20,w23
  .long 0x0a17031a                  // and w26,w24,w23
  .long 0x13966edb                  // ror w27,w22,#27
  .long 0x0b1c0294                  // add w20,w20,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b02b5                  // add w21,w21,w27  // e+=rot(a,5)
  .long 0x13970af7                  // ror w23,w23,#2
  .long 0x0b110294                  // add w20,w20,w17  // future e+=X[i]
  .long 0x0b1902b5                  // add w21,w21,w25  // e+=F(b,c,d)
  .long 0xd360fe33                  // lsr x19,x17,#32
  .long 0x4a050063                  // eor w3,w3,w5
  .long 0x0a360319                  // bic w25,w24,w22
  .long 0x0a1602fa                  // and w26,w23,w22
  .long 0x13956ebb                  // ror w27,w21,#27
  .long 0x4a0b0063                  // eor w3,w3,w11
  .long 0x0b1c0318                  // add w24,w24,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b0294                  // add w20,w20,w27  // e+=rot(a,5)
  .long 0x4a100063                  // eor w3,w3,w16
  .long 0x13960ad6                  // ror w22,w22,#2
  .long 0x0b130318                  // add w24,w24,w19  // future e+=X[i]
  .long 0x0b190294                  // add w20,w20,w25  // e+=F(b,c,d)
  .long 0x13837c63                  // ror w3,w3,#31
  .long 0x4a060084                  // eor w4,w4,w6
  .long 0x0a3502f9                  // bic w25,w23,w21
  .long 0x0a1502da                  // and w26,w22,w21
  .long 0x13946e9b                  // ror w27,w20,#27
  .long 0x4a0c0084                  // eor w4,w4,w12
  .long 0x0b1c02f7                  // add w23,w23,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b0318                  // add w24,w24,w27  // e+=rot(a,5)
  .long 0x4a110084                  // eor w4,w4,w17
  .long 0x13950ab5                  // ror w21,w21,#2
  .long 0x0b0302f7                  // add w23,w23,w3  // future e+=X[i]
  .long 0x0b190318                  // add w24,w24,w25  // e+=F(b,c,d)
  .long 0x13847c84                  // ror w4,w4,#31
  .long 0x4a0700a5                  // eor w5,w5,w7
  .long 0x0a3402d9                  // bic w25,w22,w20
  .long 0x0a1402ba                  // and w26,w21,w20
  .long 0x13986f1b                  // ror w27,w24,#27
  .long 0x4a0d00a5                  // eor w5,w5,w13
  .long 0x0b1c02d6                  // add w22,w22,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b02f7                  // add w23,w23,w27  // e+=rot(a,5)
  .long 0x4a1300a5                  // eor w5,w5,w19
  .long 0x13940a94                  // ror w20,w20,#2
  .long 0x0b0402d6                  // add w22,w22,w4  // future e+=X[i]
  .long 0x0b1902f7                  // add w23,w23,w25  // e+=F(b,c,d)
  .long 0x13857ca5                  // ror w5,w5,#31
  .long 0x4a0800c6                  // eor w6,w6,w8
  .long 0x0a3802b9                  // bic w25,w21,w24
  .long 0x0a18029a                  // and w26,w20,w24
  .long 0x13976efb                  // ror w27,w23,#27
  .long 0x4a0e00c6                  // eor w6,w6,w14
  .long 0x0b1c02b5                  // add w21,w21,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b02d6                  // add w22,w22,w27  // e+=rot(a,5)
  .long 0x4a0300c6                  // eor w6,w6,w3
  .long 0x13980b18                  // ror w24,w24,#2
  .long 0x0b0502b5                  // add w21,w21,w5  // future e+=X[i]
  .long 0x0b1902d6                  // add w22,w22,w25  // e+=F(b,c,d)
  .long 0x13867cc6                  // ror w6,w6,#31
  .long 0x4a0900e7                  // eor w7,w7,w9
  .long 0x0a370299                  // bic w25,w20,w23
  .long 0x0a17031a                  // and w26,w24,w23
  .long 0x13966edb                  // ror w27,w22,#27
  .long 0x4a0f00e7                  // eor w7,w7,w15
  .long 0x0b1c0294                  // add w20,w20,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b02b5                  // add w21,w21,w27  // e+=rot(a,5)
  .long 0x4a0400e7                  // eor w7,w7,w4
  .long 0x13970af7                  // ror w23,w23,#2
  .long 0x0b060294                  // add w20,w20,w6  // future e+=X[i]
  .long 0x0b1902b5                  // add w21,w21,w25  // e+=F(b,c,d)
  .long 0x13877ce7                  // ror w7,w7,#31
  .long 0x529d743c                  // movz w28,#0xeba1
  .long 0x72addb3c                  // movk w28,#0x6ed9, lsl #16
  .long 0x4a0a0108                  // eor w8,w8,w10
  .long 0x0a360319                  // bic w25,w24,w22
  .long 0x0a1602fa                  // and w26,w23,w22
  .long 0x13956ebb                  // ror w27,w21,#27
  .long 0x4a100108                  // eor w8,w8,w16
  .long 0x0b1c0318                  // add w24,w24,w28  // future e+=K
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x0b1b0294                  // add w20,w20,w27  // e+=rot(a,5)
  .long 0x4a050108                  // eor w8,w8,w5
  .long 0x13960ad6                  // ror w22,w22,#2
  .long 0x0b070318                  // add w24,w24,w7  // future e+=X[i]
  .long 0x0b190294                  // add w20,w20,w25  // e+=F(b,c,d)
  .long 0x13887d08                  // ror w8,w8,#31
  .long 0x4a0b0129                  // eor w9,w9,w11
  .long 0x4a1502f9                  // eor w25,w23,w21
  .long 0x13946e9b                  // ror w27,w20,#27
  .long 0x0b1c02f7                  // add w23,w23,w28  // future e+=K
  .long 0x4a110129                  // eor w9,w9,w17
  .long 0x4a160339                  // eor w25,w25,w22
  .long 0x0b1b0318                  // add w24,w24,w27  // e+=rot(a,5)
  .long 0x13950ab5                  // ror w21,w21,#2
  .long 0x4a060129                  // eor w9,w9,w6
  .long 0x0b0802f7                  // add w23,w23,w8  // future e+=X[i]
  .long 0x0b190318                  // add w24,w24,w25  // e+=F(b,c,d)
  .long 0x13897d29                  // ror w9,w9,#31
  .long 0x4a0c014a                  // eor w10,w10,w12
  .long 0x4a1402d9                  // eor w25,w22,w20
  .long 0x13986f1b                  // ror w27,w24,#27
  .long 0x0b1c02d6                  // add w22,w22,w28  // future e+=K
  .long 0x4a13014a                  // eor w10,w10,w19
  .long 0x4a150339                  // eor w25,w25,w21
  .long 0x0b1b02f7                  // add w23,w23,w27  // e+=rot(a,5)
  .long 0x13940a94                  // ror w20,w20,#2
  .long 0x4a07014a                  // eor w10,w10,w7
  .long 0x0b0902d6                  // add w22,w22,w9  // future e+=X[i]
  .long 0x0b1902f7                  // add w23,w23,w25  // e+=F(b,c,d)
  .long 0x138a7d4a                  // ror w10,w10,#31
  .long 0x4a0d016b                  // eor w11,w11,w13
  .long 0x4a1802b9                  // eor w25,w21,w24
  .long 0x13976efb                  // ror w27,w23,#27
  .long 0x0b1c02b5                  // add w21,w21,w28  // future e+=K
  .long 0x4a03016b                  // eor w11,w11,w3
  .long 0x4a140339                  // eor w25,w25,w20
  .long 0x0b1b02d6                  // add w22,w22,w27  // e+=rot(a,5)
  .long 0x13980b18                  // ror w24,w24,#2
  .long 0x4a08016b                  // eor w11,w11,w8
  .long 0x0b0a02b5                  // add w21,w21,w10  // future e+=X[i]
  .long 0x0b1902d6                  // add w22,w22,w25  // e+=F(b,c,d)
  .long 0x138b7d6b                  // ror w11,w11,#31
  .long 0x4a0e018c                  // eor w12,w12,w14
  .long 0x4a170299                  // eor w25,w20,w23
  .long 0x13966edb                  // ror w27,w22,#27
  .long 0x0b1c0294                  // add w20,w20,w28  // future e+=K
  .long 0x4a04018c                  // eor w12,w12,w4
  .long 0x4a180339                  // eor w25,w25,w24
  .long 0x0b1b02b5                  // add w21,w21,w27  // e+=rot(a,5)
  .long 0x13970af7                  // ror w23,w23,#2
  .long 0x4a09018c                  // eor w12,w12,w9
  .long 0x0b0b0294                  // add w20,w20,w11  // future e+=X[i]
  .long 0x0b1902b5                  // add w21,w21,w25  // e+=F(b,c,d)
  .long 0x138c7d8c                  // ror w12,w12,#31
  .long 0x4a0f01ad                  // eor w13,w13,w15
  .long 0x4a160319                  // eor w25,w24,w22
  .long 0x13956ebb                  // ror w27,w21,#27
  .long 0x0b1c0318                  // add w24,w24,w28  // future e+=K
  .long 0x4a0501ad                  // eor w13,w13,w5
  .long 0x4a170339                  // eor w25,w25,w23
  .long 0x0b1b0294                  // add w20,w20,w27  // e+=rot(a,5)
  .long 0x13960ad6                  // ror w22,w22,#2
  .long 0x4a0a01ad                  // eor w13,w13,w10
  .long 0x0b0c0318                  // add w24,w24,w12  // future e+=X[i]
  .long 0x0b190294                  // add w20,w20,w25  // e+=F(b,c,d)
  .long 0x138d7dad                  // ror w13,w13,#31
  .long 0x4a1001ce                  // eor w14,w14,w16
  .long 0x4a1502f9                  // eor w25,w23,w21
  .long 0x13946e9b                  // ror w27,w20,#27
  .long 0x0b1c02f7                  // add w23,w23,w28  // future e+=K
  .long 0x4a0601ce                  // eor w14,w14,w6
  .long 0x4a160339                  // eor w25,w25,w22
  .long 0x0b1b0318                  // add w24,w24,w27  // e+=rot(a,5)
  .long 0x13950ab5                  // ror w21,w21,#2
  .long 0x4a0b01ce                  // eor w14,w14,w11
  .long 0x0b0d02f7                  // add w23,w23,w13  // future e+=X[i]
  .long 0x0b190318                  // add w24,w24,w25  // e+=F(b,c,d)
  .long 0x138e7dce                  // ror w14,w14,#31
  .long 0x4a1101ef                  // eor w15,w15,w17
  .long 0x4a1402d9                  // eor w25,w22,w20
  .long 0x13986f1b                  // ror w27,w24,#27
  .long 0x0b1c02d6                  // add w22,w22,w28  // future e+=K
  .long 0x4a0701ef                  // eor w15,w15,w7
  .long 0x4a150339                  // eor w25,w25,w21
  .long 0x0b1b02f7                  // add w23,w23,w27  // e+=rot(a,5)
  .long 0x13940a94                  // ror w20,w20,#2
  .long 0x4a0c01ef                  // eor w15,w15,w12
  .long 0x0b0e02d6                  // add w22,w22,w14  // future e+=X[i]
  .long 0x0b1902f7                  // add w23,w23,w25  // e+=F(b,c,d)
  .long 0x138f7def                  // ror w15,w15,#31
  .long 0x4a130210                  // eor w16,w16,w19
  .long 0x4a1802b9                  // eor w25,w21,w24
  .long 0x13976efb                  // ror w27,w23,#27
  .long 0x0b1c02b5                  // add w21,w21,w28  // future e+=K
  .long 0x4a080210                  // eor w16,w16,w8
  .long 0x4a140339                  // eor w25,w25,w20
  .long 0x0b1b02d6                  // add w22,w22,w27  // e+=rot(a,5)
  .long 0x13980b18                  // ror w24,w24,#2
  .long 0x4a0d0210                  // eor w16,w16,w13
  .long 0x0b0f02b5                  // add w21,w21,w15  // future e+=X[i]
  .long 0x0b1902d6                  // add w22,w22,w25  // e+=F(b,c,d)
  .long 0x13907e10                  // ror w16,w16,#31
  .long 0x4a030231                  // eor w17,w17,w3
  .long 0x4a170299                  // eor w25,w20,w23
  .long 0x13966edb                  // ror w27,w22,#27
  .long 0x0b1c0294                  // add w20,w20,w28  // future e+=K
  .long 0x4a090231                  // eor w17,w17,w9
  .long 0x4a180339                  // eor w25,w25,w24
  .long 0x0b1b02b5                  // add w21,w21,w27  // e+=rot(a,5)
  .long 0x13970af7                  // ror w23,w23,#2
  .long 0x4a0e0231                  // eor w17,w17,w14
  .long 0x0b100294                  // add w20,w20,w16  // future e+=X[i]
  .long 0x0b1902b5                  // add w21,w21,w25  // e+=F(b,c,d)
  .long 0x13917e31                  // ror w17,w17,#31
  .long 0x4a040273                  // eor w19,w19,w4
  .long 0x4a160319                  // eor w25,w24,w22
  .long 0x13956ebb                  // ror w27,w21,#27
  .long 0x0b1c0318                  // add w24,w24,w28  // future e+=K
  .long 0x4a0a0273                  // eor w19,w19,w10
  .long 0x4a170339                  // eor w25,w25,w23
  .long 0x0b1b0294                  // add w20,w20,w27  // e+=rot(a,5)
  .long 0x13960ad6                  // ror w22,w22,#2
  .long 0x4a0f0273                  // eor w19,w19,w15
  .long 0x0b110318                  // add w24,w24,w17  // future e+=X[i]
  .long 0x0b190294                  // add w20,w20,w25  // e+=F(b,c,d)
  .long 0x13937e73                  // ror w19,w19,#31
  .long 0x4a050063                  // eor w3,w3,w5
  .long 0x4a1502f9                  // eor w25,w23,w21
  .long 0x13946e9b                  // ror w27,w20,#27
  .long 0x0b1c02f7                  // add w23,w23,w28  // future e+=K
  .long 0x4a0b0063                  // eor w3,w3,w11
  .long 0x4a160339                  // eor w25,w25,w22
  .long 0x0b1b0318                  // add w24,w24,w27  // e+=rot(a,5)
  .long 0x13950ab5                  // ror w21,w21,#2
  .long 0x4a100063                  // eor w3,w3,w16
  .long 0x0b1302f7                  // add w23,w23,w19  // future e+=X[i]
  .long 0x0b190318                  // add w24,w24,w25  // e+=F(b,c,d)
  .long 0x13837c63                  // ror w3,w3,#31
  .long 0x4a060084                  // eor w4,w4,w6
  .long 0x4a1402d9                  // eor w25,w22,w20
  .long 0x13986f1b                  // ror w27,w24,#27
  .long 0x0b1c02d6                  // add w22,w22,w28  // future e+=K
  .long 0x4a0c0084                  // eor w4,w4,w12
  .long 0x4a150339                  // eor w25,w25,w21
  .long 0x0b1b02f7                  // add w23,w23,w27  // e+=rot(a,5)
  .long 0x13940a94                  // ror w20,w20,#2
  .long 0x4a110084                  // eor w4,w4,w17
  .long 0x0b0302d6                  // add w22,w22,w3  // future e+=X[i]
  .long 0x0b1902f7                  // add w23,w23,w25  // e+=F(b,c,d)
  .long 0x13847c84                  // ror w4,w4,#31
  .long 0x4a0700a5                  // eor w5,w5,w7
  .long 0x4a1802b9                  // eor w25,w21,w24
  .long 0x13976efb                  // ror w27,w23,#27
  .long 0x0b1c02b5                  // add w21,w21,w28  // future e+=K
  .long 0x4a0d00a5                  // eor w5,w5,w13
  .long 0x4a140339                  // eor w25,w25,w20
  .long 0x0b1b02d6                  // add w22,w22,w27  // e+=rot(a,5)
  .long 0x13980b18                  // ror w24,w24,#2
  .long 0x4a1300a5                  // eor w5,w5,w19
  .long 0x0b0402b5                  // add w21,w21,w4  // future e+=X[i]
  .long 0x0b1902d6                  // add w22,w22,w25  // e+=F(b,c,d)
  .long 0x13857ca5                  // ror w5,w5,#31
  .long 0x4a0800c6                  // eor w6,w6,w8
  .long 0x4a170299                  // eor w25,w20,w23
  .long 0x13966edb                  // ror w27,w22,#27
  .long 0x0b1c0294                  // add w20,w20,w28  // future e+=K
  .long 0x4a0e00c6                  // eor w6,w6,w14
  .long 0x4a180339                  // eor w25,w25,w24
  .long 0x0b1b02b5                  // add w21,w21,w27  // e+=rot(a,5)
  .long 0x13970af7                  // ror w23,w23,#2
  .long 0x4a0300c6                  // eor w6,w6,w3
  .long 0x0b050294                  // add w20,w20,w5  // future e+=X[i]
  .long 0x0b1902b5                  // add w21,w21,w25  // e+=F(b,c,d)
  .long 0x13867cc6                  // ror w6,w6,#31
  .long 0x4a0900e7                  // eor w7,w7,w9
  .long 0x4a160319                  // eor w25,w24,w22
  .long 0x13956ebb                  // ror w27,w21,#27
  .long 0x0b1c0318                  // add w24,w24,w28  // future e+=K
  .long 0x4a0f00e7                  // eor w7,w7,w15
  .long 0x4a170339                  // eor w25,w25,w23
  .long 0x0b1b0294                  // add w20,w20,w27  // e+=rot(a,5)
  .long 0x13960ad6                  // ror w22,w22,#2
  .long 0x4a0400e7                  // eor w7,w7,w4
  .long 0x0b060318                  // add w24,w24,w6  // future e+=X[i]
  .long 0x0b190294                  // add w20,w20,w25  // e+=F(b,c,d)
  .long 0x13877ce7                  // ror w7,w7,#31
  .long 0x4a0a0108                  // eor w8,w8,w10
  .long 0x4a1502f9                  // eor w25,w23,w21
  .long 0x13946e9b                  // ror w27,w20,#27
  .long 0x0b1c02f7                  // add w23,w23,w28  // future e+=K
  .long 0x4a100108                  // eor w8,w8,w16
  .long 0x4a160339                  // eor w25,w25,w22
  .long 0x0b1b0318                  // add w24,w24,w27  // e+=rot(a,5)
  .long 0x13950ab5                  // ror w21,w21,#2
  .long 0x4a050108                  // eor w8,w8,w5
  .long 0x0b0702f7                  // add w23,w23,w7  // future e+=X[i]
  .long 0x0b190318                  // add w24,w24,w25  // e+=F(b,c,d)
  .long 0x13887d08                  // ror w8,w8,#31
  .long 0x4a0b0129                  // eor w9,w9,w11
  .long 0x4a1402d9                  // eor w25,w22,w20
  .long 0x13986f1b                  // ror w27,w24,#27
  .long 0x0b1c02d6                  // add w22,w22,w28  // future e+=K
  .long 0x4a110129                  // eor w9,w9,w17
  .long 0x4a150339                  // eor w25,w25,w21
  .long 0x0b1b02f7                  // add w23,w23,w27  // e+=rot(a,5)
  .long 0x13940a94                  // ror w20,w20,#2
  .long 0x4a060129                  // eor w9,w9,w6
  .long 0x0b0802d6                  // add w22,w22,w8  // future e+=X[i]
  .long 0x0b1902f7                  // add w23,w23,w25  // e+=F(b,c,d)
  .long 0x13897d29                  // ror w9,w9,#31
  .long 0x4a0c014a                  // eor w10,w10,w12
  .long 0x4a1802b9                  // eor w25,w21,w24
  .long 0x13976efb                  // ror w27,w23,#27
  .long 0x0b1c02b5                  // add w21,w21,w28  // future e+=K
  .long 0x4a13014a                  // eor w10,w10,w19
  .long 0x4a140339                  // eor w25,w25,w20
  .long 0x0b1b02d6                  // add w22,w22,w27  // e+=rot(a,5)
  .long 0x13980b18                  // ror w24,w24,#2
  .long 0x4a07014a                  // eor w10,w10,w7
  .long 0x0b0902b5                  // add w21,w21,w9  // future e+=X[i]
  .long 0x0b1902d6                  // add w22,w22,w25  // e+=F(b,c,d)
  .long 0x138a7d4a                  // ror w10,w10,#31
  .long 0x4a0d016b                  // eor w11,w11,w13
  .long 0x4a170299                  // eor w25,w20,w23
  .long 0x13966edb                  // ror w27,w22,#27
  .long 0x0b1c0294                  // add w20,w20,w28  // future e+=K
  .long 0x4a03016b                  // eor w11,w11,w3
  .long 0x4a180339                  // eor w25,w25,w24
  .long 0x0b1b02b5                  // add w21,w21,w27  // e+=rot(a,5)
  .long 0x13970af7                  // ror w23,w23,#2
  .long 0x4a08016b                  // eor w11,w11,w8
  .long 0x0b0a0294                  // add w20,w20,w10  // future e+=X[i]
  .long 0x0b1902b5                  // add w21,w21,w25  // e+=F(b,c,d)
  .long 0x138b7d6b                  // ror w11,w11,#31
  .long 0x52979b9c                  // movz w28,#0xbcdc
  .long 0x72b1e37c                  // movk w28,#0x8f1b, lsl #16
  .long 0x4a0e018c                  // eor w12,w12,w14
  .long 0x4a160319                  // eor w25,w24,w22
  .long 0x13956ebb                  // ror w27,w21,#27
  .long 0x0b1c0318                  // add w24,w24,w28  // future e+=K
  .long 0x4a04018c                  // eor w12,w12,w4
  .long 0x4a170339                  // eor w25,w25,w23
  .long 0x0b1b0294                  // add w20,w20,w27  // e+=rot(a,5)
  .long 0x13960ad6                  // ror w22,w22,#2
  .long 0x4a09018c                  // eor w12,w12,w9
  .long 0x0b0b0318                  // add w24,w24,w11  // future e+=X[i]
  .long 0x0b190294                  // add w20,w20,w25  // e+=F(b,c,d)
  .long 0x138c7d8c                  // ror w12,w12,#31
  .long 0x2a1602b9                  // orr w25,w21,w22
  .long 0x0a1602ba                  // and w26,w21,w22
  .long 0x4a0f01ad                  // eor w13,w13,w15
  .long 0x13946e9b                  // ror w27,w20,#27
  .long 0x0a170339                  // and w25,w25,w23
  .long 0x0b1c02f7                  // add w23,w23,w28  // future e+=K
  .long 0x4a0501ad                  // eor w13,w13,w5
  .long 0x0b1b0318                  // add w24,w24,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13950ab5                  // ror w21,w21,#2
  .long 0x4a0a01ad                  // eor w13,w13,w10
  .long 0x0b0c02f7                  // add w23,w23,w12  // future e+=X[i]
  .long 0x0b190318                  // add w24,w24,w25  // e+=F(b,c,d)
  .long 0x138d7dad                  // ror w13,w13,#31
  .long 0x2a150299                  // orr w25,w20,w21
  .long 0x0a15029a                  // and w26,w20,w21
  .long 0x4a1001ce                  // eor w14,w14,w16
  .long 0x13986f1b                  // ror w27,w24,#27
  .long 0x0a160339                  // and w25,w25,w22
  .long 0x0b1c02d6                  // add w22,w22,w28  // future e+=K
  .long 0x4a0601ce                  // eor w14,w14,w6
  .long 0x0b1b02f7                  // add w23,w23,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13940a94                  // ror w20,w20,#2
  .long 0x4a0b01ce                  // eor w14,w14,w11
  .long 0x0b0d02d6                  // add w22,w22,w13  // future e+=X[i]
  .long 0x0b1902f7                  // add w23,w23,w25  // e+=F(b,c,d)
  .long 0x138e7dce                  // ror w14,w14,#31
  .long 0x2a140319                  // orr w25,w24,w20
  .long 0x0a14031a                  // and w26,w24,w20
  .long 0x4a1101ef                  // eor w15,w15,w17
  .long 0x13976efb                  // ror w27,w23,#27
  .long 0x0a150339                  // and w25,w25,w21
  .long 0x0b1c02b5                  // add w21,w21,w28  // future e+=K
  .long 0x4a0701ef                  // eor w15,w15,w7
  .long 0x0b1b02d6                  // add w22,w22,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13980b18                  // ror w24,w24,#2
  .long 0x4a0c01ef                  // eor w15,w15,w12
  .long 0x0b0e02b5                  // add w21,w21,w14  // future e+=X[i]
  .long 0x0b1902d6                  // add w22,w22,w25  // e+=F(b,c,d)
  .long 0x138f7def                  // ror w15,w15,#31
  .long 0x2a1802f9                  // orr w25,w23,w24
  .long 0x0a1802fa                  // and w26,w23,w24
  .long 0x4a130210                  // eor w16,w16,w19
  .long 0x13966edb                  // ror w27,w22,#27
  .long 0x0a140339                  // and w25,w25,w20
  .long 0x0b1c0294                  // add w20,w20,w28  // future e+=K
  .long 0x4a080210                  // eor w16,w16,w8
  .long 0x0b1b02b5                  // add w21,w21,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13970af7                  // ror w23,w23,#2
  .long 0x4a0d0210                  // eor w16,w16,w13
  .long 0x0b0f0294                  // add w20,w20,w15  // future e+=X[i]
  .long 0x0b1902b5                  // add w21,w21,w25  // e+=F(b,c,d)
  .long 0x13907e10                  // ror w16,w16,#31
  .long 0x2a1702d9                  // orr w25,w22,w23
  .long 0x0a1702da                  // and w26,w22,w23
  .long 0x4a030231                  // eor w17,w17,w3
  .long 0x13956ebb                  // ror w27,w21,#27
  .long 0x0a180339                  // and w25,w25,w24
  .long 0x0b1c0318                  // add w24,w24,w28  // future e+=K
  .long 0x4a090231                  // eor w17,w17,w9
  .long 0x0b1b0294                  // add w20,w20,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13960ad6                  // ror w22,w22,#2
  .long 0x4a0e0231                  // eor w17,w17,w14
  .long 0x0b100318                  // add w24,w24,w16  // future e+=X[i]
  .long 0x0b190294                  // add w20,w20,w25  // e+=F(b,c,d)
  .long 0x13917e31                  // ror w17,w17,#31
  .long 0x2a1602b9                  // orr w25,w21,w22
  .long 0x0a1602ba                  // and w26,w21,w22
  .long 0x4a040273                  // eor w19,w19,w4
  .long 0x13946e9b                  // ror w27,w20,#27
  .long 0x0a170339                  // and w25,w25,w23
  .long 0x0b1c02f7                  // add w23,w23,w28  // future e+=K
  .long 0x4a0a0273                  // eor w19,w19,w10
  .long 0x0b1b0318                  // add w24,w24,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13950ab5                  // ror w21,w21,#2
  .long 0x4a0f0273                  // eor w19,w19,w15
  .long 0x0b1102f7                  // add w23,w23,w17  // future e+=X[i]
  .long 0x0b190318                  // add w24,w24,w25  // e+=F(b,c,d)
  .long 0x13937e73                  // ror w19,w19,#31
  .long 0x2a150299                  // orr w25,w20,w21
  .long 0x0a15029a                  // and w26,w20,w21
  .long 0x4a050063                  // eor w3,w3,w5
  .long 0x13986f1b                  // ror w27,w24,#27
  .long 0x0a160339                  // and w25,w25,w22
  .long 0x0b1c02d6                  // add w22,w22,w28  // future e+=K
  .long 0x4a0b0063                  // eor w3,w3,w11
  .long 0x0b1b02f7                  // add w23,w23,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13940a94                  // ror w20,w20,#2
  .long 0x4a100063                  // eor w3,w3,w16
  .long 0x0b1302d6                  // add w22,w22,w19  // future e+=X[i]
  .long 0x0b1902f7                  // add w23,w23,w25  // e+=F(b,c,d)
  .long 0x13837c63                  // ror w3,w3,#31
  .long 0x2a140319                  // orr w25,w24,w20
  .long 0x0a14031a                  // and w26,w24,w20
  .long 0x4a060084                  // eor w4,w4,w6
  .long 0x13976efb                  // ror w27,w23,#27
  .long 0x0a150339                  // and w25,w25,w21
  .long 0x0b1c02b5                  // add w21,w21,w28  // future e+=K
  .long 0x4a0c0084                  // eor w4,w4,w12
  .long 0x0b1b02d6                  // add w22,w22,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13980b18                  // ror w24,w24,#2
  .long 0x4a110084                  // eor w4,w4,w17
  .long 0x0b0302b5                  // add w21,w21,w3  // future e+=X[i]
  .long 0x0b1902d6                  // add w22,w22,w25  // e+=F(b,c,d)
  .long 0x13847c84                  // ror w4,w4,#31
  .long 0x2a1802f9                  // orr w25,w23,w24
  .long 0x0a1802fa                  // and w26,w23,w24
  .long 0x4a0700a5                  // eor w5,w5,w7
  .long 0x13966edb                  // ror w27,w22,#27
  .long 0x0a140339                  // and w25,w25,w20
  .long 0x0b1c0294                  // add w20,w20,w28  // future e+=K
  .long 0x4a0d00a5                  // eor w5,w5,w13
  .long 0x0b1b02b5                  // add w21,w21,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13970af7                  // ror w23,w23,#2
  .long 0x4a1300a5                  // eor w5,w5,w19
  .long 0x0b040294                  // add w20,w20,w4  // future e+=X[i]
  .long 0x0b1902b5                  // add w21,w21,w25  // e+=F(b,c,d)
  .long 0x13857ca5                  // ror w5,w5,#31
  .long 0x2a1702d9                  // orr w25,w22,w23
  .long 0x0a1702da                  // and w26,w22,w23
  .long 0x4a0800c6                  // eor w6,w6,w8
  .long 0x13956ebb                  // ror w27,w21,#27
  .long 0x0a180339                  // and w25,w25,w24
  .long 0x0b1c0318                  // add w24,w24,w28  // future e+=K
  .long 0x4a0e00c6                  // eor w6,w6,w14
  .long 0x0b1b0294                  // add w20,w20,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13960ad6                  // ror w22,w22,#2
  .long 0x4a0300c6                  // eor w6,w6,w3
  .long 0x0b050318                  // add w24,w24,w5  // future e+=X[i]
  .long 0x0b190294                  // add w20,w20,w25  // e+=F(b,c,d)
  .long 0x13867cc6                  // ror w6,w6,#31
  .long 0x2a1602b9                  // orr w25,w21,w22
  .long 0x0a1602ba                  // and w26,w21,w22
  .long 0x4a0900e7                  // eor w7,w7,w9
  .long 0x13946e9b                  // ror w27,w20,#27
  .long 0x0a170339                  // and w25,w25,w23
  .long 0x0b1c02f7                  // add w23,w23,w28  // future e+=K
  .long 0x4a0f00e7                  // eor w7,w7,w15
  .long 0x0b1b0318                  // add w24,w24,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13950ab5                  // ror w21,w21,#2
  .long 0x4a0400e7                  // eor w7,w7,w4
  .long 0x0b0602f7                  // add w23,w23,w6  // future e+=X[i]
  .long 0x0b190318                  // add w24,w24,w25  // e+=F(b,c,d)
  .long 0x13877ce7                  // ror w7,w7,#31
  .long 0x2a150299                  // orr w25,w20,w21
  .long 0x0a15029a                  // and w26,w20,w21
  .long 0x4a0a0108                  // eor w8,w8,w10
  .long 0x13986f1b                  // ror w27,w24,#27
  .long 0x0a160339                  // and w25,w25,w22
  .long 0x0b1c02d6                  // add w22,w22,w28  // future e+=K
  .long 0x4a100108                  // eor w8,w8,w16
  .long 0x0b1b02f7                  // add w23,w23,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13940a94                  // ror w20,w20,#2
  .long 0x4a050108                  // eor w8,w8,w5
  .long 0x0b0702d6                  // add w22,w22,w7  // future e+=X[i]
  .long 0x0b1902f7                  // add w23,w23,w25  // e+=F(b,c,d)
  .long 0x13887d08                  // ror w8,w8,#31
  .long 0x2a140319                  // orr w25,w24,w20
  .long 0x0a14031a                  // and w26,w24,w20
  .long 0x4a0b0129                  // eor w9,w9,w11
  .long 0x13976efb                  // ror w27,w23,#27
  .long 0x0a150339                  // and w25,w25,w21
  .long 0x0b1c02b5                  // add w21,w21,w28  // future e+=K
  .long 0x4a110129                  // eor w9,w9,w17
  .long 0x0b1b02d6                  // add w22,w22,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13980b18                  // ror w24,w24,#2
  .long 0x4a060129                  // eor w9,w9,w6
  .long 0x0b0802b5                  // add w21,w21,w8  // future e+=X[i]
  .long 0x0b1902d6                  // add w22,w22,w25  // e+=F(b,c,d)
  .long 0x13897d29                  // ror w9,w9,#31
  .long 0x2a1802f9                  // orr w25,w23,w24
  .long 0x0a1802fa                  // and w26,w23,w24
  .long 0x4a0c014a                  // eor w10,w10,w12
  .long 0x13966edb                  // ror w27,w22,#27
  .long 0x0a140339                  // and w25,w25,w20
  .long 0x0b1c0294                  // add w20,w20,w28  // future e+=K
  .long 0x4a13014a                  // eor w10,w10,w19
  .long 0x0b1b02b5                  // add w21,w21,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13970af7                  // ror w23,w23,#2
  .long 0x4a07014a                  // eor w10,w10,w7
  .long 0x0b090294                  // add w20,w20,w9  // future e+=X[i]
  .long 0x0b1902b5                  // add w21,w21,w25  // e+=F(b,c,d)
  .long 0x138a7d4a                  // ror w10,w10,#31
  .long 0x2a1702d9                  // orr w25,w22,w23
  .long 0x0a1702da                  // and w26,w22,w23
  .long 0x4a0d016b                  // eor w11,w11,w13
  .long 0x13956ebb                  // ror w27,w21,#27
  .long 0x0a180339                  // and w25,w25,w24
  .long 0x0b1c0318                  // add w24,w24,w28  // future e+=K
  .long 0x4a03016b                  // eor w11,w11,w3
  .long 0x0b1b0294                  // add w20,w20,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13960ad6                  // ror w22,w22,#2
  .long 0x4a08016b                  // eor w11,w11,w8
  .long 0x0b0a0318                  // add w24,w24,w10  // future e+=X[i]
  .long 0x0b190294                  // add w20,w20,w25  // e+=F(b,c,d)
  .long 0x138b7d6b                  // ror w11,w11,#31
  .long 0x2a1602b9                  // orr w25,w21,w22
  .long 0x0a1602ba                  // and w26,w21,w22
  .long 0x4a0e018c                  // eor w12,w12,w14
  .long 0x13946e9b                  // ror w27,w20,#27
  .long 0x0a170339                  // and w25,w25,w23
  .long 0x0b1c02f7                  // add w23,w23,w28  // future e+=K
  .long 0x4a04018c                  // eor w12,w12,w4
  .long 0x0b1b0318                  // add w24,w24,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13950ab5                  // ror w21,w21,#2
  .long 0x4a09018c                  // eor w12,w12,w9
  .long 0x0b0b02f7                  // add w23,w23,w11  // future e+=X[i]
  .long 0x0b190318                  // add w24,w24,w25  // e+=F(b,c,d)
  .long 0x138c7d8c                  // ror w12,w12,#31
  .long 0x2a150299                  // orr w25,w20,w21
  .long 0x0a15029a                  // and w26,w20,w21
  .long 0x4a0f01ad                  // eor w13,w13,w15
  .long 0x13986f1b                  // ror w27,w24,#27
  .long 0x0a160339                  // and w25,w25,w22
  .long 0x0b1c02d6                  // add w22,w22,w28  // future e+=K
  .long 0x4a0501ad                  // eor w13,w13,w5
  .long 0x0b1b02f7                  // add w23,w23,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13940a94                  // ror w20,w20,#2
  .long 0x4a0a01ad                  // eor w13,w13,w10
  .long 0x0b0c02d6                  // add w22,w22,w12  // future e+=X[i]
  .long 0x0b1902f7                  // add w23,w23,w25  // e+=F(b,c,d)
  .long 0x138d7dad                  // ror w13,w13,#31
  .long 0x2a140319                  // orr w25,w24,w20
  .long 0x0a14031a                  // and w26,w24,w20
  .long 0x4a1001ce                  // eor w14,w14,w16
  .long 0x13976efb                  // ror w27,w23,#27
  .long 0x0a150339                  // and w25,w25,w21
  .long 0x0b1c02b5                  // add w21,w21,w28  // future e+=K
  .long 0x4a0601ce                  // eor w14,w14,w6
  .long 0x0b1b02d6                  // add w22,w22,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13980b18                  // ror w24,w24,#2
  .long 0x4a0b01ce                  // eor w14,w14,w11
  .long 0x0b0d02b5                  // add w21,w21,w13  // future e+=X[i]
  .long 0x0b1902d6                  // add w22,w22,w25  // e+=F(b,c,d)
  .long 0x138e7dce                  // ror w14,w14,#31
  .long 0x2a1802f9                  // orr w25,w23,w24
  .long 0x0a1802fa                  // and w26,w23,w24
  .long 0x4a1101ef                  // eor w15,w15,w17
  .long 0x13966edb                  // ror w27,w22,#27
  .long 0x0a140339                  // and w25,w25,w20
  .long 0x0b1c0294                  // add w20,w20,w28  // future e+=K
  .long 0x4a0701ef                  // eor w15,w15,w7
  .long 0x0b1b02b5                  // add w21,w21,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13970af7                  // ror w23,w23,#2
  .long 0x4a0c01ef                  // eor w15,w15,w12
  .long 0x0b0e0294                  // add w20,w20,w14  // future e+=X[i]
  .long 0x0b1902b5                  // add w21,w21,w25  // e+=F(b,c,d)
  .long 0x138f7def                  // ror w15,w15,#31
  .long 0x52983adc                  // movz w28,#0xc1d6
  .long 0x72b94c5c                  // movk w28,#0xca62, lsl #16
  .long 0x2a1702d9                  // orr w25,w22,w23
  .long 0x0a1702da                  // and w26,w22,w23
  .long 0x4a130210                  // eor w16,w16,w19
  .long 0x13956ebb                  // ror w27,w21,#27
  .long 0x0a180339                  // and w25,w25,w24
  .long 0x0b1c0318                  // add w24,w24,w28  // future e+=K
  .long 0x4a080210                  // eor w16,w16,w8
  .long 0x0b1b0294                  // add w20,w20,w27  // e+=rot(a,5)
  .long 0x2a1a0339                  // orr w25,w25,w26
  .long 0x13960ad6                  // ror w22,w22,#2
  .long 0x4a0d0210                  // eor w16,w16,w13
  .long 0x0b0f0318                  // add w24,w24,w15  // future e+=X[i]
  .long 0x0b190294                  // add w20,w20,w25  // e+=F(b,c,d)
  .long 0x13907e10                  // ror w16,w16,#31
  .long 0x4a030231                  // eor w17,w17,w3
  .long 0x4a1502f9                  // eor w25,w23,w21
  .long 0x13946e9b                  // ror w27,w20,#27
  .long 0x0b1c02f7                  // add w23,w23,w28  // future e+=K
  .long 0x4a090231                  // eor w17,w17,w9
  .long 0x4a160339                  // eor w25,w25,w22
  .long 0x0b1b0318                  // add w24,w24,w27  // e+=rot(a,5)
  .long 0x13950ab5                  // ror w21,w21,#2
  .long 0x4a0e0231                  // eor w17,w17,w14
  .long 0x0b1002f7                  // add w23,w23,w16  // future e+=X[i]
  .long 0x0b190318                  // add w24,w24,w25  // e+=F(b,c,d)
  .long 0x13917e31                  // ror w17,w17,#31
  .long 0x4a040273                  // eor w19,w19,w4
  .long 0x4a1402d9                  // eor w25,w22,w20
  .long 0x13986f1b                  // ror w27,w24,#27
  .long 0x0b1c02d6                  // add w22,w22,w28  // future e+=K
  .long 0x4a0a0273                  // eor w19,w19,w10
  .long 0x4a150339                  // eor w25,w25,w21
  .long 0x0b1b02f7                  // add w23,w23,w27  // e+=rot(a,5)
  .long 0x13940a94                  // ror w20,w20,#2
  .long 0x4a0f0273                  // eor w19,w19,w15
  .long 0x0b1102d6                  // add w22,w22,w17  // future e+=X[i]
  .long 0x0b1902f7                  // add w23,w23,w25  // e+=F(b,c,d)
  .long 0x13937e73                  // ror w19,w19,#31
  .long 0x4a050063                  // eor w3,w3,w5
  .long 0x4a1802b9                  // eor w25,w21,w24
  .long 0x13976efb                  // ror w27,w23,#27
  .long 0x0b1c02b5                  // add w21,w21,w28  // future e+=K
  .long 0x4a0b0063                  // eor w3,w3,w11
  .long 0x4a140339                  // eor w25,w25,w20
  .long 0x0b1b02d6                  // add w22,w22,w27  // e+=rot(a,5)
  .long 0x13980b18                  // ror w24,w24,#2
  .long 0x4a100063                  // eor w3,w3,w16
  .long 0x0b1302b5                  // add w21,w21,w19  // future e+=X[i]
  .long 0x0b1902d6                  // add w22,w22,w25  // e+=F(b,c,d)
  .long 0x13837c63                  // ror w3,w3,#31
  .long 0x4a060084                  // eor w4,w4,w6
  .long 0x4a170299                  // eor w25,w20,w23
  .long 0x13966edb                  // ror w27,w22,#27
  .long 0x0b1c0294                  // add w20,w20,w28  // future e+=K
  .long 0x4a0c0084                  // eor w4,w4,w12
  .long 0x4a180339                  // eor w25,w25,w24
  .long 0x0b1b02b5                  // add w21,w21,w27  // e+=rot(a,5)
  .long 0x13970af7                  // ror w23,w23,#2
  .long 0x4a110084                  // eor w4,w4,w17
  .long 0x0b030294                  // add w20,w20,w3  // future e+=X[i]
  .long 0x0b1902b5                  // add w21,w21,w25  // e+=F(b,c,d)
  .long 0x13847c84                  // ror w4,w4,#31
  .long 0x4a0700a5                  // eor w5,w5,w7
  .long 0x4a160319                  // eor w25,w24,w22
  .long 0x13956ebb                  // ror w27,w21,#27
  .long 0x0b1c0318                  // add w24,w24,w28  // future e+=K
  .long 0x4a0d00a5                  // eor w5,w5,w13
  .long 0x4a170339                  // eor w25,w25,w23
  .long 0x0b1b0294                  // add w20,w20,w27  // e+=rot(a,5)
  .long 0x13960ad6                  // ror w22,w22,#2
  .long 0x4a1300a5                  // eor w5,w5,w19
  .long 0x0b040318                  // add w24,w24,w4  // future e+=X[i]
  .long 0x0b190294                  // add w20,w20,w25  // e+=F(b,c,d)
  .long 0x13857ca5                  // ror w5,w5,#31
  .long 0x4a0800c6                  // eor w6,w6,w8
  .long 0x4a1502f9                  // eor w25,w23,w21
  .long 0x13946e9b                  // ror w27,w20,#27
  .long 0x0b1c02f7                  // add w23,w23,w28  // future e+=K
  .long 0x4a0e00c6                  // eor w6,w6,w14
  .long 0x4a160339                  // eor w25,w25,w22
  .long 0x0b1b0318                  // add w24,w24,w27  // e+=rot(a,5)
  .long 0x13950ab5                  // ror w21,w21,#2
  .long 0x4a0300c6                  // eor w6,w6,w3
  .long 0x0b0502f7                  // add w23,w23,w5  // future e+=X[i]
  .long 0x0b190318                  // add w24,w24,w25  // e+=F(b,c,d)
  .long 0x13867cc6                  // ror w6,w6,#31
  .long 0x4a0900e7                  // eor w7,w7,w9
  .long 0x4a1402d9                  // eor w25,w22,w20
  .long 0x13986f1b                  // ror w27,w24,#27
  .long 0x0b1c02d6                  // add w22,w22,w28  // future e+=K
  .long 0x4a0f00e7                  // eor w7,w7,w15
  .long 0x4a150339                  // eor w25,w25,w21
  .long 0x0b1b02f7                  // add w23,w23,w27  // e+=rot(a,5)
  .long 0x13940a94                  // ror w20,w20,#2
  .long 0x4a0400e7                  // eor w7,w7,w4
  .long 0x0b0602d6                  // add w22,w22,w6  // future e+=X[i]
  .long 0x0b1902f7                  // add w23,w23,w25  // e+=F(b,c,d)
  .long 0x13877ce7                  // ror w7,w7,#31
  .long 0x4a0a0108                  // eor w8,w8,w10
  .long 0x4a1802b9                  // eor w25,w21,w24
  .long 0x13976efb                  // ror w27,w23,#27
  .long 0x0b1c02b5                  // add w21,w21,w28  // future e+=K
  .long 0x4a100108                  // eor w8,w8,w16
  .long 0x4a140339                  // eor w25,w25,w20
  .long 0x0b1b02d6                  // add w22,w22,w27  // e+=rot(a,5)
  .long 0x13980b18                  // ror w24,w24,#2
  .long 0x4a050108                  // eor w8,w8,w5
  .long 0x0b0702b5                  // add w21,w21,w7  // future e+=X[i]
  .long 0x0b1902d6                  // add w22,w22,w25  // e+=F(b,c,d)
  .long 0x13887d08                  // ror w8,w8,#31
  .long 0x4a0b0129                  // eor w9,w9,w11
  .long 0x4a170299                  // eor w25,w20,w23
  .long 0x13966edb                  // ror w27,w22,#27
  .long 0x0b1c0294                  // add w20,w20,w28  // future e+=K
  .long 0x4a110129                  // eor w9,w9,w17
  .long 0x4a180339                  // eor w25,w25,w24
  .long 0x0b1b02b5                  // add w21,w21,w27  // e+=rot(a,5)
  .long 0x13970af7                  // ror w23,w23,#2
  .long 0x4a060129                  // eor w9,w9,w6
  .long 0x0b080294                  // add w20,w20,w8  // future e+=X[i]
  .long 0x0b1902b5                  // add w21,w21,w25  // e+=F(b,c,d)
  .long 0x13897d29                  // ror w9,w9,#31
  .long 0x4a0c014a                  // eor w10,w10,w12
  .long 0x4a160319                  // eor w25,w24,w22
  .long 0x13956ebb                  // ror w27,w21,#27
  .long 0x0b1c0318                  // add w24,w24,w28  // future e+=K
  .long 0x4a13014a                  // eor w10,w10,w19
  .long 0x4a170339                  // eor w25,w25,w23
  .long 0x0b1b0294                  // add w20,w20,w27  // e+=rot(a,5)
  .long 0x13960ad6                  // ror w22,w22,#2
  .long 0x4a07014a                  // eor w10,w10,w7
  .long 0x0b090318                  // add w24,w24,w9  // future e+=X[i]
  .long 0x0b190294                  // add w20,w20,w25  // e+=F(b,c,d)
  .long 0x138a7d4a                  // ror w10,w10,#31
  .long 0x4a0d016b                  // eor w11,w11,w13
  .long 0x4a1502f9                  // eor w25,w23,w21
  .long 0x13946e9b                  // ror w27,w20,#27
  .long 0x0b1c02f7                  // add w23,w23,w28  // future e+=K
  .long 0x4a03016b                  // eor w11,w11,w3
  .long 0x4a160339                  // eor w25,w25,w22
  .long 0x0b1b0318                  // add w24,w24,w27  // e+=rot(a,5)
  .long 0x13950ab5                  // ror w21,w21,#2
  .long 0x4a08016b                  // eor w11,w11,w8
  .long 0x0b0a02f7                  // add w23,w23,w10  // future e+=X[i]
  .long 0x0b190318                  // add w24,w24,w25  // e+=F(b,c,d)
  .long 0x138b7d6b                  // ror w11,w11,#31
  .long 0x4a0e018c                  // eor w12,w12,w14
  .long 0x4a1402d9                  // eor w25,w22,w20
  .long 0x13986f1b                  // ror w27,w24,#27
  .long 0x0b1c02d6                  // add w22,w22,w28  // future e+=K
  .long 0x4a04018c                  // eor w12,w12,w4
  .long 0x4a150339                  // eor w25,w25,w21
  .long 0x0b1b02f7                  // add w23,w23,w27  // e+=rot(a,5)
  .long 0x13940a94                  // ror w20,w20,#2
  .long 0x4a09018c                  // eor w12,w12,w9
  .long 0x0b0b02d6                  // add w22,w22,w11  // future e+=X[i]
  .long 0x0b1902f7                  // add w23,w23,w25  // e+=F(b,c,d)
  .long 0x138c7d8c                  // ror w12,w12,#31
  .long 0x4a0f01ad                  // eor w13,w13,w15
  .long 0x4a1802b9                  // eor w25,w21,w24
  .long 0x13976efb                  // ror w27,w23,#27
  .long 0x0b1c02b5                  // add w21,w21,w28  // future e+=K
  .long 0x4a0501ad                  // eor w13,w13,w5
  .long 0x4a140339                  // eor w25,w25,w20
  .long 0x0b1b02d6                  // add w22,w22,w27  // e+=rot(a,5)
  .long 0x13980b18                  // ror w24,w24,#2
  .long 0x4a0a01ad                  // eor w13,w13,w10
  .long 0x0b0c02b5                  // add w21,w21,w12  // future e+=X[i]
  .long 0x0b1902d6                  // add w22,w22,w25  // e+=F(b,c,d)
  .long 0x138d7dad                  // ror w13,w13,#31
  .long 0x4a1001ce                  // eor w14,w14,w16
  .long 0x4a170299                  // eor w25,w20,w23
  .long 0x13966edb                  // ror w27,w22,#27
  .long 0x0b1c0294                  // add w20,w20,w28  // future e+=K
  .long 0x4a0601ce                  // eor w14,w14,w6
  .long 0x4a180339                  // eor w25,w25,w24
  .long 0x0b1b02b5                  // add w21,w21,w27  // e+=rot(a,5)
  .long 0x13970af7                  // ror w23,w23,#2
  .long 0x4a0b01ce                  // eor w14,w14,w11
  .long 0x0b0d0294                  // add w20,w20,w13  // future e+=X[i]
  .long 0x0b1902b5                  // add w21,w21,w25  // e+=F(b,c,d)
  .long 0x138e7dce                  // ror w14,w14,#31
  .long 0x4a1101ef                  // eor w15,w15,w17
  .long 0x4a160319                  // eor w25,w24,w22
  .long 0x13956ebb                  // ror w27,w21,#27
  .long 0x0b1c0318                  // add w24,w24,w28  // future e+=K
  .long 0x4a0701ef                  // eor w15,w15,w7
  .long 0x4a170339                  // eor w25,w25,w23
  .long 0x0b1b0294                  // add w20,w20,w27  // e+=rot(a,5)
  .long 0x13960ad6                  // ror w22,w22,#2
  .long 0x4a0c01ef                  // eor w15,w15,w12
  .long 0x0b0e0318                  // add w24,w24,w14  // future e+=X[i]
  .long 0x0b190294                  // add w20,w20,w25  // e+=F(b,c,d)
  .long 0x138f7def                  // ror w15,w15,#31
  .long 0x4a130210                  // eor w16,w16,w19
  .long 0x4a1502f9                  // eor w25,w23,w21
  .long 0x13946e9b                  // ror w27,w20,#27
  .long 0x0b1c02f7                  // add w23,w23,w28  // future e+=K
  .long 0x4a080210                  // eor w16,w16,w8
  .long 0x4a160339                  // eor w25,w25,w22
  .long 0x0b1b0318                  // add w24,w24,w27  // e+=rot(a,5)
  .long 0x13950ab5                  // ror w21,w21,#2
  .long 0x4a0d0210                  // eor w16,w16,w13
  .long 0x0b0f02f7                  // add w23,w23,w15  // future e+=X[i]
  .long 0x0b190318                  // add w24,w24,w25  // e+=F(b,c,d)
  .long 0x13907e10                  // ror w16,w16,#31
  .long 0x4a030231                  // eor w17,w17,w3
  .long 0x4a1402d9                  // eor w25,w22,w20
  .long 0x13986f1b                  // ror w27,w24,#27
  .long 0x0b1c02d6                  // add w22,w22,w28  // future e+=K
  .long 0x4a090231                  // eor w17,w17,w9
  .long 0x4a150339                  // eor w25,w25,w21
  .long 0x0b1b02f7                  // add w23,w23,w27  // e+=rot(a,5)
  .long 0x13940a94                  // ror w20,w20,#2
  .long 0x4a0e0231                  // eor w17,w17,w14
  .long 0x0b1002d6                  // add w22,w22,w16  // future e+=X[i]
  .long 0x0b1902f7                  // add w23,w23,w25  // e+=F(b,c,d)
  .long 0x13917e31                  // ror w17,w17,#31
  .long 0x4a040273                  // eor w19,w19,w4
  .long 0x4a1802b9                  // eor w25,w21,w24
  .long 0x13976efb                  // ror w27,w23,#27
  .long 0x0b1c02b5                  // add w21,w21,w28  // future e+=K
  .long 0x4a0a0273                  // eor w19,w19,w10
  .long 0x4a140339                  // eor w25,w25,w20
  .long 0x0b1b02d6                  // add w22,w22,w27  // e+=rot(a,5)
  .long 0x13980b18                  // ror w24,w24,#2
  .long 0x4a0f0273                  // eor w19,w19,w15
  .long 0x0b1102b5                  // add w21,w21,w17  // future e+=X[i]
  .long 0x0b1902d6                  // add w22,w22,w25  // e+=F(b,c,d)
  .long 0x13937e73                  // ror w19,w19,#31
  .long 0x29401404                  // ldp w4,w5,[x0]
  .long 0x4a170299                  // eor w25,w20,w23
  .long 0x13966edb                  // ror w27,w22,#27
  .long 0x0b1c0294                  // add w20,w20,w28  // future e+=K
  .long 0x4a180339                  // eor w25,w25,w24
  .long 0x0b1b02b5                  // add w21,w21,w27  // e+=rot(a,5)
  .long 0x13970af7                  // ror w23,w23,#2
  .long 0x0b130294                  // add w20,w20,w19  // future e+=X[i]
  .long 0x0b1902b5                  // add w21,w21,w25  // e+=F(b,c,d)
  .long 0x29411c06                  // ldp w6,w7,[x0,#8]
  .long 0x4a160319                  // eor w25,w24,w22
  .long 0x13956ebb                  // ror w27,w21,#27
  .long 0x4a170339                  // eor w25,w25,w23
  .long 0x0b1b0294                  // add w20,w20,w27  // e+=rot(a,5)
  .long 0x13960ad6                  // ror w22,w22,#2
  .long 0xb9401008                  // ldr w8,[x0,#16]
  .long 0x0b190294                  // add w20,w20,w25  // e+=F(b,c,d)
  .long 0x0b0502b5                  // add w21,w21,w5
  .long 0x0b0602d6                  // add w22,w22,w6
  .long 0x0b040294                  // add w20,w20,w4
  .long 0x0b0702f7                  // add w23,w23,w7
  .long 0x0b080318                  // add w24,w24,w8
  .long 0x29005414                  // stp w20,w21,[x0]
  .long 0x29015c16                  // stp w22,w23,[x0,#8]
  .long 0xb9001018                  // str w24,[x0,#16]
  cbnz	x2,.Lsha1_gpr_loop

  .long 0xa94153f3                  // ldp x19,x20,[sp,#16]
  .long 0xa9425bf5                  // ldp x21,x22,[sp,#32]
  .long 0xa94363f7                  // ldp x23,x24,[sp,#48]
  .long 0xa9446bf9                  // ldp x25,x26,[sp,#64]
  .long 0xa94573fb                  // ldp x27,x28,[sp,#80]
  .long 0xf84607fd                  // ldr x29,[sp],#96
  ret
