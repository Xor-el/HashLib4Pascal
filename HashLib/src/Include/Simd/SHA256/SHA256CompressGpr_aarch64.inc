// SHA-256 pure-GPR implementation (AArch64) for cores without the SHA-256
// crypto extension; the Gpr name states the ISA requirement: none beyond
// base AArch64. Serial SHA maps better onto the 31 GPRs than onto NEON
// lanes (single dependency chain, 1-op ror, rotate-folded eor operands).
// Expects AAPCS64 (after HlpSimdProc4Begin_aarch64): x0 = state ptr
//   (8 x UInt32), x1 = data ptr, w2 = numblocks, x3 = K256_Gpr ptr.
// K256_Gpr carries the 64 round constants PLUS a zero terminator word - the
// message-schedule loop ends when the loaded K word is zero (cbnz), exactly
// like the original's sentinel-terminated table; a plain K256 const cannot
// drive this loop.
// Frame: 128-byte AAPCS64 frame (x29/x30 + x19-x28 callee-saved) + 16 bytes
// schedule scratch; x30 (LR) is repurposed as the K walk pointer between the
// save and the restore, as in the original.
// AArch64 instructions are .long-encoded for broad assembler compatibility.
// Reference: OpenSSL CRYPTOGAMS sha512-armv8.pl (sha256_block_data_order,
// the plain path; the generator emits both SHA-256 and SHA-512).

  .long 0x2a0203e2                  // mov w2,w2  // zero-extend ANumBlocks (AAPCS64 leaves x2's top half undefined)
  .long 0xa9b87bfd                  // stp x29,x30,[sp,#-128]!
  .long 0x910003fd                  // add x29,sp,#0

  .long 0xa90153f3                  // stp x19,x20,[sp,#16]
  .long 0xa9025bf5                  // stp x21,x22,[sp,#32]
  .long 0xa90363f7                  // stp x23,x24,[sp,#48]
  .long 0xa9046bf9                  // stp x25,x26,[sp,#64]
  .long 0xa90573fb                  // stp x27,x28,[sp,#80]
  .long 0xd10043ff                  // sub sp,sp,#4*4

  .long 0x29405414                  // ldp w20,w21,[x0]  // load context
  .long 0x29415c16                  // ldp w22,w23,[x0,#2*4]
  .long 0x29426418                  // ldp w24,w25,[x0,#4*4]
  .long 0x8b021822                  // add x2,x1,x2, lsl #6  // end of input
  .long 0x29436c1a                  // ldp w26,w27,[x0,#6*4]
  .long 0xaa0303fe                  // mov x30,x3  // K256_Gpr (param 4; x3 is reused for message words below)
  .long 0xa9060ba0                  // stp x0,x2,[x29,#96]


.Lsha256_gpr_loop:
  .long 0x28c11023                  // ldp w3,w4,[x1],#2*4
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++
  .long 0x4a1602bc                  // eor w28,w21,w22  // magic seed
  .long 0xf9003ba1                  // str x1,[x29,#112]
  .long 0x5ac00863                  // rev w3,w3  // 0
  .long 0x13981b10                  // ror w16,w24,#6
  .long 0x0b13037b                  // add w27,w27,w19  // h+=K[i]
  .long 0x4ad83b06                  // eor w6,w24,w24, ror #14
  .long 0x0a180331                  // and w17,w25,w24
  .long 0x0a380353                  // bic w19,w26,w24
  .long 0x0b03037b                  // add w27,w27,w3  // h+=X[i]
  .long 0x2a130231                  // orr w17,w17,w19  // Ch(e,f,g)
  .long 0x4a150293                  // eor w19,w20,w21  // a^b, b^c in next round
  .long 0x4ac62e10                  // eor w16,w16,w6, ror #11  // Sigma1(e)
  .long 0x13940a86                  // ror w6,w20,#2
  .long 0x0b11037b                  // add w27,w27,w17  // h+=Ch(e,f,g)
  .long 0x4ad42691                  // eor w17,w20,w20, ror #9
  .long 0x0b10037b                  // add w27,w27,w16  // h+=Sigma1(e)
  .long 0x0a13039c                  // and w28,w28,w19  // (b^c)&=(a^b)
  .long 0x0b1b02f7                  // add w23,w23,w27  // d+=h
  .long 0x4a15039c                  // eor w28,w28,w21  // Maj(a,b,c)
  .long 0x4ad134d1                  // eor w17,w6,w17, ror #13  // Sigma0(a)
  .long 0x0b1c037b                  // add w27,w27,w28  // h+=Maj(a,b,c)
  .long 0xb84047dc                  // ldr w28,[x30],#4  // *K++, w19 in next round
  //add w27,w27,w17 // h+=Sigma0(a)
  .long 0x5ac00884                  // rev w4,w4  // 1
  .long 0x28c11825                  // ldp w5,w6,[x1],#2*4
  .long 0x0b11037b                  // add w27,w27,w17  // h+=Sigma0(a)
  .long 0x13971af0                  // ror w16,w23,#6
  .long 0x0b1c035a                  // add w26,w26,w28  // h+=K[i]
  .long 0x4ad73ae7                  // eor w7,w23,w23, ror #14
  .long 0x0a170311                  // and w17,w24,w23
  .long 0x0a37033c                  // bic w28,w25,w23
  .long 0x0b04035a                  // add w26,w26,w4  // h+=X[i]
  .long 0x2a1c0231                  // orr w17,w17,w28  // Ch(e,f,g)
  .long 0x4a14037c                  // eor w28,w27,w20  // a^b, b^c in next round
  .long 0x4ac72e10                  // eor w16,w16,w7, ror #11  // Sigma1(e)
  .long 0x139b0b67                  // ror w7,w27,#2
  .long 0x0b11035a                  // add w26,w26,w17  // h+=Ch(e,f,g)
  .long 0x4adb2771                  // eor w17,w27,w27, ror #9
  .long 0x0b10035a                  // add w26,w26,w16  // h+=Sigma1(e)
  .long 0x0a1c0273                  // and w19,w19,w28  // (b^c)&=(a^b)
  .long 0x0b1a02d6                  // add w22,w22,w26  // d+=h
  .long 0x4a140273                  // eor w19,w19,w20  // Maj(a,b,c)
  .long 0x4ad134f1                  // eor w17,w7,w17, ror #13  // Sigma0(a)
  .long 0x0b13035a                  // add w26,w26,w19  // h+=Maj(a,b,c)
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++, w28 in next round
  //add w26,w26,w17 // h+=Sigma0(a)
  .long 0x5ac008a5                  // rev w5,w5  // 2
  .long 0x0b11035a                  // add w26,w26,w17  // h+=Sigma0(a)
  .long 0x13961ad0                  // ror w16,w22,#6
  .long 0x0b130339                  // add w25,w25,w19  // h+=K[i]
  .long 0x4ad63ac8                  // eor w8,w22,w22, ror #14
  .long 0x0a1602f1                  // and w17,w23,w22
  .long 0x0a360313                  // bic w19,w24,w22
  .long 0x0b050339                  // add w25,w25,w5  // h+=X[i]
  .long 0x2a130231                  // orr w17,w17,w19  // Ch(e,f,g)
  .long 0x4a1b0353                  // eor w19,w26,w27  // a^b, b^c in next round
  .long 0x4ac82e10                  // eor w16,w16,w8, ror #11  // Sigma1(e)
  .long 0x139a0b48                  // ror w8,w26,#2
  .long 0x0b110339                  // add w25,w25,w17  // h+=Ch(e,f,g)
  .long 0x4ada2751                  // eor w17,w26,w26, ror #9
  .long 0x0b100339                  // add w25,w25,w16  // h+=Sigma1(e)
  .long 0x0a13039c                  // and w28,w28,w19  // (b^c)&=(a^b)
  .long 0x0b1902b5                  // add w21,w21,w25  // d+=h
  .long 0x4a1b039c                  // eor w28,w28,w27  // Maj(a,b,c)
  .long 0x4ad13511                  // eor w17,w8,w17, ror #13  // Sigma0(a)
  .long 0x0b1c0339                  // add w25,w25,w28  // h+=Maj(a,b,c)
  .long 0xb84047dc                  // ldr w28,[x30],#4  // *K++, w19 in next round
  //add w25,w25,w17 // h+=Sigma0(a)
  .long 0x5ac008c6                  // rev w6,w6  // 3
  .long 0x28c12027                  // ldp w7,w8,[x1],#2*4
  .long 0x0b110339                  // add w25,w25,w17  // h+=Sigma0(a)
  .long 0x13951ab0                  // ror w16,w21,#6
  .long 0x0b1c0318                  // add w24,w24,w28  // h+=K[i]
  .long 0x4ad53aa9                  // eor w9,w21,w21, ror #14
  .long 0x0a1502d1                  // and w17,w22,w21
  .long 0x0a3502fc                  // bic w28,w23,w21
  .long 0x0b060318                  // add w24,w24,w6  // h+=X[i]
  .long 0x2a1c0231                  // orr w17,w17,w28  // Ch(e,f,g)
  .long 0x4a1a033c                  // eor w28,w25,w26  // a^b, b^c in next round
  .long 0x4ac92e10                  // eor w16,w16,w9, ror #11  // Sigma1(e)
  .long 0x13990b29                  // ror w9,w25,#2
  .long 0x0b110318                  // add w24,w24,w17  // h+=Ch(e,f,g)
  .long 0x4ad92731                  // eor w17,w25,w25, ror #9
  .long 0x0b100318                  // add w24,w24,w16  // h+=Sigma1(e)
  .long 0x0a1c0273                  // and w19,w19,w28  // (b^c)&=(a^b)
  .long 0x0b180294                  // add w20,w20,w24  // d+=h
  .long 0x4a1a0273                  // eor w19,w19,w26  // Maj(a,b,c)
  .long 0x4ad13531                  // eor w17,w9,w17, ror #13  // Sigma0(a)
  .long 0x0b130318                  // add w24,w24,w19  // h+=Maj(a,b,c)
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++, w28 in next round
  //add w24,w24,w17 // h+=Sigma0(a)
  .long 0x5ac008e7                  // rev w7,w7  // 4
  .long 0x0b110318                  // add w24,w24,w17  // h+=Sigma0(a)
  .long 0x13941a90                  // ror w16,w20,#6
  .long 0x0b1302f7                  // add w23,w23,w19  // h+=K[i]
  .long 0x4ad43a8a                  // eor w10,w20,w20, ror #14
  .long 0x0a1402b1                  // and w17,w21,w20
  .long 0x0a3402d3                  // bic w19,w22,w20
  .long 0x0b0702f7                  // add w23,w23,w7  // h+=X[i]
  .long 0x2a130231                  // orr w17,w17,w19  // Ch(e,f,g)
  .long 0x4a190313                  // eor w19,w24,w25  // a^b, b^c in next round
  .long 0x4aca2e10                  // eor w16,w16,w10, ror #11  // Sigma1(e)
  .long 0x13980b0a                  // ror w10,w24,#2
  .long 0x0b1102f7                  // add w23,w23,w17  // h+=Ch(e,f,g)
  .long 0x4ad82711                  // eor w17,w24,w24, ror #9
  .long 0x0b1002f7                  // add w23,w23,w16  // h+=Sigma1(e)
  .long 0x0a13039c                  // and w28,w28,w19  // (b^c)&=(a^b)
  .long 0x0b17037b                  // add w27,w27,w23  // d+=h
  .long 0x4a19039c                  // eor w28,w28,w25  // Maj(a,b,c)
  .long 0x4ad13551                  // eor w17,w10,w17, ror #13  // Sigma0(a)
  .long 0x0b1c02f7                  // add w23,w23,w28  // h+=Maj(a,b,c)
  .long 0xb84047dc                  // ldr w28,[x30],#4  // *K++, w19 in next round
  //add w23,w23,w17 // h+=Sigma0(a)
  .long 0x5ac00908                  // rev w8,w8  // 5
  .long 0x28c12829                  // ldp w9,w10,[x1],#2*4
  .long 0x0b1102f7                  // add w23,w23,w17  // h+=Sigma0(a)
  .long 0x139b1b70                  // ror w16,w27,#6
  .long 0x0b1c02d6                  // add w22,w22,w28  // h+=K[i]
  .long 0x4adb3b6b                  // eor w11,w27,w27, ror #14
  .long 0x0a1b0291                  // and w17,w20,w27
  .long 0x0a3b02bc                  // bic w28,w21,w27
  .long 0x0b0802d6                  // add w22,w22,w8  // h+=X[i]
  .long 0x2a1c0231                  // orr w17,w17,w28  // Ch(e,f,g)
  .long 0x4a1802fc                  // eor w28,w23,w24  // a^b, b^c in next round
  .long 0x4acb2e10                  // eor w16,w16,w11, ror #11  // Sigma1(e)
  .long 0x13970aeb                  // ror w11,w23,#2
  .long 0x0b1102d6                  // add w22,w22,w17  // h+=Ch(e,f,g)
  .long 0x4ad726f1                  // eor w17,w23,w23, ror #9
  .long 0x0b1002d6                  // add w22,w22,w16  // h+=Sigma1(e)
  .long 0x0a1c0273                  // and w19,w19,w28  // (b^c)&=(a^b)
  .long 0x0b16035a                  // add w26,w26,w22  // d+=h
  .long 0x4a180273                  // eor w19,w19,w24  // Maj(a,b,c)
  .long 0x4ad13571                  // eor w17,w11,w17, ror #13  // Sigma0(a)
  .long 0x0b1302d6                  // add w22,w22,w19  // h+=Maj(a,b,c)
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++, w28 in next round
  //add w22,w22,w17 // h+=Sigma0(a)
  .long 0x5ac00929                  // rev w9,w9  // 6
  .long 0x0b1102d6                  // add w22,w22,w17  // h+=Sigma0(a)
  .long 0x139a1b50                  // ror w16,w26,#6
  .long 0x0b1302b5                  // add w21,w21,w19  // h+=K[i]
  .long 0x4ada3b4c                  // eor w12,w26,w26, ror #14
  .long 0x0a1a0371                  // and w17,w27,w26
  .long 0x0a3a0293                  // bic w19,w20,w26
  .long 0x0b0902b5                  // add w21,w21,w9  // h+=X[i]
  .long 0x2a130231                  // orr w17,w17,w19  // Ch(e,f,g)
  .long 0x4a1702d3                  // eor w19,w22,w23  // a^b, b^c in next round
  .long 0x4acc2e10                  // eor w16,w16,w12, ror #11  // Sigma1(e)
  .long 0x13960acc                  // ror w12,w22,#2
  .long 0x0b1102b5                  // add w21,w21,w17  // h+=Ch(e,f,g)
  .long 0x4ad626d1                  // eor w17,w22,w22, ror #9
  .long 0x0b1002b5                  // add w21,w21,w16  // h+=Sigma1(e)
  .long 0x0a13039c                  // and w28,w28,w19  // (b^c)&=(a^b)
  .long 0x0b150339                  // add w25,w25,w21  // d+=h
  .long 0x4a17039c                  // eor w28,w28,w23  // Maj(a,b,c)
  .long 0x4ad13591                  // eor w17,w12,w17, ror #13  // Sigma0(a)
  .long 0x0b1c02b5                  // add w21,w21,w28  // h+=Maj(a,b,c)
  .long 0xb84047dc                  // ldr w28,[x30],#4  // *K++, w19 in next round
  //add w21,w21,w17 // h+=Sigma0(a)
  .long 0x5ac0094a                  // rev w10,w10  // 7
  .long 0x28c1302b                  // ldp w11,w12,[x1],#2*4
  .long 0x0b1102b5                  // add w21,w21,w17  // h+=Sigma0(a)
  .long 0x13991b30                  // ror w16,w25,#6
  .long 0x0b1c0294                  // add w20,w20,w28  // h+=K[i]
  .long 0x4ad93b2d                  // eor w13,w25,w25, ror #14
  .long 0x0a190351                  // and w17,w26,w25
  .long 0x0a39037c                  // bic w28,w27,w25
  .long 0x0b0a0294                  // add w20,w20,w10  // h+=X[i]
  .long 0x2a1c0231                  // orr w17,w17,w28  // Ch(e,f,g)
  .long 0x4a1602bc                  // eor w28,w21,w22  // a^b, b^c in next round
  .long 0x4acd2e10                  // eor w16,w16,w13, ror #11  // Sigma1(e)
  .long 0x13950aad                  // ror w13,w21,#2
  .long 0x0b110294                  // add w20,w20,w17  // h+=Ch(e,f,g)
  .long 0x4ad526b1                  // eor w17,w21,w21, ror #9
  .long 0x0b100294                  // add w20,w20,w16  // h+=Sigma1(e)
  .long 0x0a1c0273                  // and w19,w19,w28  // (b^c)&=(a^b)
  .long 0x0b140318                  // add w24,w24,w20  // d+=h
  .long 0x4a160273                  // eor w19,w19,w22  // Maj(a,b,c)
  .long 0x4ad135b1                  // eor w17,w13,w17, ror #13  // Sigma0(a)
  .long 0x0b130294                  // add w20,w20,w19  // h+=Maj(a,b,c)
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++, w28 in next round
  //add w20,w20,w17 // h+=Sigma0(a)
  .long 0x5ac0096b                  // rev w11,w11  // 8
  .long 0x0b110294                  // add w20,w20,w17  // h+=Sigma0(a)
  .long 0x13981b10                  // ror w16,w24,#6
  .long 0x0b13037b                  // add w27,w27,w19  // h+=K[i]
  .long 0x4ad83b0e                  // eor w14,w24,w24, ror #14
  .long 0x0a180331                  // and w17,w25,w24
  .long 0x0a380353                  // bic w19,w26,w24
  .long 0x0b0b037b                  // add w27,w27,w11  // h+=X[i]
  .long 0x2a130231                  // orr w17,w17,w19  // Ch(e,f,g)
  .long 0x4a150293                  // eor w19,w20,w21  // a^b, b^c in next round
  .long 0x4ace2e10                  // eor w16,w16,w14, ror #11  // Sigma1(e)
  .long 0x13940a8e                  // ror w14,w20,#2
  .long 0x0b11037b                  // add w27,w27,w17  // h+=Ch(e,f,g)
  .long 0x4ad42691                  // eor w17,w20,w20, ror #9
  .long 0x0b10037b                  // add w27,w27,w16  // h+=Sigma1(e)
  .long 0x0a13039c                  // and w28,w28,w19  // (b^c)&=(a^b)
  .long 0x0b1b02f7                  // add w23,w23,w27  // d+=h
  .long 0x4a15039c                  // eor w28,w28,w21  // Maj(a,b,c)
  .long 0x4ad135d1                  // eor w17,w14,w17, ror #13  // Sigma0(a)
  .long 0x0b1c037b                  // add w27,w27,w28  // h+=Maj(a,b,c)
  .long 0xb84047dc                  // ldr w28,[x30],#4  // *K++, w19 in next round
  //add w27,w27,w17 // h+=Sigma0(a)
  .long 0x5ac0098c                  // rev w12,w12  // 9
  .long 0x28c1382d                  // ldp w13,w14,[x1],#2*4
  .long 0x0b11037b                  // add w27,w27,w17  // h+=Sigma0(a)
  .long 0x13971af0                  // ror w16,w23,#6
  .long 0x0b1c035a                  // add w26,w26,w28  // h+=K[i]
  .long 0x4ad73aef                  // eor w15,w23,w23, ror #14
  .long 0x0a170311                  // and w17,w24,w23
  .long 0x0a37033c                  // bic w28,w25,w23
  .long 0x0b0c035a                  // add w26,w26,w12  // h+=X[i]
  .long 0x2a1c0231                  // orr w17,w17,w28  // Ch(e,f,g)
  .long 0x4a14037c                  // eor w28,w27,w20  // a^b, b^c in next round
  .long 0x4acf2e10                  // eor w16,w16,w15, ror #11  // Sigma1(e)
  .long 0x139b0b6f                  // ror w15,w27,#2
  .long 0x0b11035a                  // add w26,w26,w17  // h+=Ch(e,f,g)
  .long 0x4adb2771                  // eor w17,w27,w27, ror #9
  .long 0x0b10035a                  // add w26,w26,w16  // h+=Sigma1(e)
  .long 0x0a1c0273                  // and w19,w19,w28  // (b^c)&=(a^b)
  .long 0x0b1a02d6                  // add w22,w22,w26  // d+=h
  .long 0x4a140273                  // eor w19,w19,w20  // Maj(a,b,c)
  .long 0x4ad135f1                  // eor w17,w15,w17, ror #13  // Sigma0(a)
  .long 0x0b13035a                  // add w26,w26,w19  // h+=Maj(a,b,c)
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++, w28 in next round
  //add w26,w26,w17 // h+=Sigma0(a)
  .long 0x5ac009ad                  // rev w13,w13  // 10
  .long 0x0b11035a                  // add w26,w26,w17  // h+=Sigma0(a)
  .long 0x13961ad0                  // ror w16,w22,#6
  .long 0x0b130339                  // add w25,w25,w19  // h+=K[i]
  .long 0x4ad63ac0                  // eor w0,w22,w22, ror #14
  .long 0x0a1602f1                  // and w17,w23,w22
  .long 0x0a360313                  // bic w19,w24,w22
  .long 0x0b0d0339                  // add w25,w25,w13  // h+=X[i]
  .long 0x2a130231                  // orr w17,w17,w19  // Ch(e,f,g)
  .long 0x4a1b0353                  // eor w19,w26,w27  // a^b, b^c in next round
  .long 0x4ac02e10                  // eor w16,w16,w0, ror #11  // Sigma1(e)
  .long 0x139a0b40                  // ror w0,w26,#2
  .long 0x0b110339                  // add w25,w25,w17  // h+=Ch(e,f,g)
  .long 0x4ada2751                  // eor w17,w26,w26, ror #9
  .long 0x0b100339                  // add w25,w25,w16  // h+=Sigma1(e)
  .long 0x0a13039c                  // and w28,w28,w19  // (b^c)&=(a^b)
  .long 0x0b1902b5                  // add w21,w21,w25  // d+=h
  .long 0x4a1b039c                  // eor w28,w28,w27  // Maj(a,b,c)
  .long 0x4ad13411                  // eor w17,w0,w17, ror #13  // Sigma0(a)
  .long 0x0b1c0339                  // add w25,w25,w28  // h+=Maj(a,b,c)
  .long 0xb84047dc                  // ldr w28,[x30],#4  // *K++, w19 in next round
  //add w25,w25,w17 // h+=Sigma0(a)
  .long 0x5ac009ce                  // rev w14,w14  // 11
  .long 0x28c1002f                  // ldp w15,w0,[x1],#2*4
  .long 0x0b110339                  // add w25,w25,w17  // h+=Sigma0(a)
  .long 0xb9000fe6                  // str w6,[sp,#12]
  .long 0x13951ab0                  // ror w16,w21,#6
  .long 0x0b1c0318                  // add w24,w24,w28  // h+=K[i]
  .long 0x4ad53aa6                  // eor w6,w21,w21, ror #14
  .long 0x0a1502d1                  // and w17,w22,w21
  .long 0x0a3502fc                  // bic w28,w23,w21
  .long 0x0b0e0318                  // add w24,w24,w14  // h+=X[i]
  .long 0x2a1c0231                  // orr w17,w17,w28  // Ch(e,f,g)
  .long 0x4a1a033c                  // eor w28,w25,w26  // a^b, b^c in next round
  .long 0x4ac62e10                  // eor w16,w16,w6, ror #11  // Sigma1(e)
  .long 0x13990b26                  // ror w6,w25,#2
  .long 0x0b110318                  // add w24,w24,w17  // h+=Ch(e,f,g)
  .long 0x4ad92731                  // eor w17,w25,w25, ror #9
  .long 0x0b100318                  // add w24,w24,w16  // h+=Sigma1(e)
  .long 0x0a1c0273                  // and w19,w19,w28  // (b^c)&=(a^b)
  .long 0x0b180294                  // add w20,w20,w24  // d+=h
  .long 0x4a1a0273                  // eor w19,w19,w26  // Maj(a,b,c)
  .long 0x4ad134d1                  // eor w17,w6,w17, ror #13  // Sigma0(a)
  .long 0x0b130318                  // add w24,w24,w19  // h+=Maj(a,b,c)
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++, w28 in next round
  //add w24,w24,w17 // h+=Sigma0(a)
  .long 0x5ac009ef                  // rev w15,w15  // 12
  .long 0x0b110318                  // add w24,w24,w17  // h+=Sigma0(a)
  .long 0xb90003e7                  // str w7,[sp,#0]
  .long 0x13941a90                  // ror w16,w20,#6
  .long 0x0b1302f7                  // add w23,w23,w19  // h+=K[i]
  .long 0x4ad43a87                  // eor w7,w20,w20, ror #14
  .long 0x0a1402b1                  // and w17,w21,w20
  .long 0x0a3402d3                  // bic w19,w22,w20
  .long 0x0b0f02f7                  // add w23,w23,w15  // h+=X[i]
  .long 0x2a130231                  // orr w17,w17,w19  // Ch(e,f,g)
  .long 0x4a190313                  // eor w19,w24,w25  // a^b, b^c in next round
  .long 0x4ac72e10                  // eor w16,w16,w7, ror #11  // Sigma1(e)
  .long 0x13980b07                  // ror w7,w24,#2
  .long 0x0b1102f7                  // add w23,w23,w17  // h+=Ch(e,f,g)
  .long 0x4ad82711                  // eor w17,w24,w24, ror #9
  .long 0x0b1002f7                  // add w23,w23,w16  // h+=Sigma1(e)
  .long 0x0a13039c                  // and w28,w28,w19  // (b^c)&=(a^b)
  .long 0x0b17037b                  // add w27,w27,w23  // d+=h
  .long 0x4a19039c                  // eor w28,w28,w25  // Maj(a,b,c)
  .long 0x4ad134f1                  // eor w17,w7,w17, ror #13  // Sigma0(a)
  .long 0x0b1c02f7                  // add w23,w23,w28  // h+=Maj(a,b,c)
  .long 0xb84047dc                  // ldr w28,[x30],#4  // *K++, w19 in next round
  //add w23,w23,w17 // h+=Sigma0(a)
  .long 0x5ac00800                  // rev w0,w0  // 13
  .long 0x29400821                  // ldp w1,w2,[x1]
  .long 0x0b1102f7                  // add w23,w23,w17  // h+=Sigma0(a)
  .long 0xb90007e8                  // str w8,[sp,#4]
  .long 0x139b1b70                  // ror w16,w27,#6
  .long 0x0b1c02d6                  // add w22,w22,w28  // h+=K[i]
  .long 0x4adb3b68                  // eor w8,w27,w27, ror #14
  .long 0x0a1b0291                  // and w17,w20,w27
  .long 0x0a3b02bc                  // bic w28,w21,w27
  .long 0x0b0002d6                  // add w22,w22,w0  // h+=X[i]
  .long 0x2a1c0231                  // orr w17,w17,w28  // Ch(e,f,g)
  .long 0x4a1802fc                  // eor w28,w23,w24  // a^b, b^c in next round
  .long 0x4ac82e10                  // eor w16,w16,w8, ror #11  // Sigma1(e)
  .long 0x13970ae8                  // ror w8,w23,#2
  .long 0x0b1102d6                  // add w22,w22,w17  // h+=Ch(e,f,g)
  .long 0x4ad726f1                  // eor w17,w23,w23, ror #9
  .long 0x0b1002d6                  // add w22,w22,w16  // h+=Sigma1(e)
  .long 0x0a1c0273                  // and w19,w19,w28  // (b^c)&=(a^b)
  .long 0x0b16035a                  // add w26,w26,w22  // d+=h
  .long 0x4a180273                  // eor w19,w19,w24  // Maj(a,b,c)
  .long 0x4ad13511                  // eor w17,w8,w17, ror #13  // Sigma0(a)
  .long 0x0b1302d6                  // add w22,w22,w19  // h+=Maj(a,b,c)
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++, w28 in next round
  //add w22,w22,w17 // h+=Sigma0(a)
  .long 0x5ac00821                  // rev w1,w1  // 14
  .long 0xb9400fe6                  // ldr w6,[sp,#12]
  .long 0x0b1102d6                  // add w22,w22,w17  // h+=Sigma0(a)
  .long 0xb9000be9                  // str w9,[sp,#8]
  .long 0x139a1b50                  // ror w16,w26,#6
  .long 0x0b1302b5                  // add w21,w21,w19  // h+=K[i]
  .long 0x4ada3b49                  // eor w9,w26,w26, ror #14
  .long 0x0a1a0371                  // and w17,w27,w26
  .long 0x0a3a0293                  // bic w19,w20,w26
  .long 0x0b0102b5                  // add w21,w21,w1  // h+=X[i]
  .long 0x2a130231                  // orr w17,w17,w19  // Ch(e,f,g)
  .long 0x4a1702d3                  // eor w19,w22,w23  // a^b, b^c in next round
  .long 0x4ac92e10                  // eor w16,w16,w9, ror #11  // Sigma1(e)
  .long 0x13960ac9                  // ror w9,w22,#2
  .long 0x0b1102b5                  // add w21,w21,w17  // h+=Ch(e,f,g)
  .long 0x4ad626d1                  // eor w17,w22,w22, ror #9
  .long 0x0b1002b5                  // add w21,w21,w16  // h+=Sigma1(e)
  .long 0x0a13039c                  // and w28,w28,w19  // (b^c)&=(a^b)
  .long 0x0b150339                  // add w25,w25,w21  // d+=h
  .long 0x4a17039c                  // eor w28,w28,w23  // Maj(a,b,c)
  .long 0x4ad13531                  // eor w17,w9,w17, ror #13  // Sigma0(a)
  .long 0x0b1c02b5                  // add w21,w21,w28  // h+=Maj(a,b,c)
  .long 0xb84047dc                  // ldr w28,[x30],#4  // *K++, w19 in next round
  //add w21,w21,w17 // h+=Sigma0(a)
  .long 0x5ac00842                  // rev w2,w2  // 15
  .long 0xb94003e7                  // ldr w7,[sp,#0]
  .long 0x0b1102b5                  // add w21,w21,w17  // h+=Sigma0(a)
  .long 0xb9000fea                  // str w10,[sp,#12]
  .long 0x13991b30                  // ror w16,w25,#6
  .long 0x0b1c0294                  // add w20,w20,w28  // h+=K[i]
  .long 0x13841c89                  // ror w9,w4,#7
  .long 0x0a190351                  // and w17,w26,w25
  .long 0x13814428                  // ror w8,w1,#17
  .long 0x0a39037c                  // bic w28,w27,w25
  .long 0x13950aaa                  // ror w10,w21,#2
  .long 0x0b020294                  // add w20,w20,w2  // h+=X[i]
  .long 0x4ad92e10                  // eor w16,w16,w25, ror #11
  .long 0x4ac44929                  // eor w9,w9,w4, ror #18
  .long 0x2a1c0231                  // orr w17,w17,w28  // Ch(e,f,g)
  .long 0x4a1602bc                  // eor w28,w21,w22  // a^b, b^c in next round
  .long 0x4ad96610                  // eor w16,w16,w25, ror #25  // Sigma1(e)
  .long 0x4ad5354a                  // eor w10,w10,w21, ror #13
  .long 0x0b110294                  // add w20,w20,w17  // h+=Ch(e,f,g)
  .long 0x0a1c0273                  // and w19,w19,w28  // (b^c)&=(a^b)
  .long 0x4ac14d08                  // eor w8,w8,w1, ror #19
  .long 0x4a440d29                  // eor w9,w9,w4, lsr #3  // sigma0(X[i+1])
  .long 0x0b100294                  // add w20,w20,w16  // h+=Sigma1(e)
  .long 0x4a160273                  // eor w19,w19,w22  // Maj(a,b,c)
  .long 0x4ad55951                  // eor w17,w10,w21, ror #22  // Sigma0(a)
  .long 0x4a412908                  // eor w8,w8,w1, lsr #10  // sigma1(X[i+14])
  .long 0x0b0c0063                  // add w3,w3,w12
  .long 0x0b140318                  // add w24,w24,w20  // d+=h
  .long 0x0b130294                  // add w20,w20,w19  // h+=Maj(a,b,c)
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++, w28 in next round
  .long 0x0b090063                  // add w3,w3,w9
  .long 0x0b110294                  // add w20,w20,w17  // h+=Sigma0(a)
  .long 0x0b080063                  // add w3,w3,w8

.Lsha256_gpr_loop_16_xx:
  .long 0xb94007e8                  // ldr w8,[sp,#4]
  .long 0xb90003eb                  // str w11,[sp,#0]
  .long 0x13981b10                  // ror w16,w24,#6
  .long 0x0b13037b                  // add w27,w27,w19  // h+=K[i]
  .long 0x13851caa                  // ror w10,w5,#7
  .long 0x0a180331                  // and w17,w25,w24
  .long 0x13824449                  // ror w9,w2,#17
  .long 0x0a380353                  // bic w19,w26,w24
  .long 0x13940a8b                  // ror w11,w20,#2
  .long 0x0b03037b                  // add w27,w27,w3  // h+=X[i]
  .long 0x4ad82e10                  // eor w16,w16,w24, ror #11
  .long 0x4ac5494a                  // eor w10,w10,w5, ror #18
  .long 0x2a130231                  // orr w17,w17,w19  // Ch(e,f,g)
  .long 0x4a150293                  // eor w19,w20,w21  // a^b, b^c in next round
  .long 0x4ad86610                  // eor w16,w16,w24, ror #25  // Sigma1(e)
  .long 0x4ad4356b                  // eor w11,w11,w20, ror #13
  .long 0x0b11037b                  // add w27,w27,w17  // h+=Ch(e,f,g)
  .long 0x0a13039c                  // and w28,w28,w19  // (b^c)&=(a^b)
  .long 0x4ac24d29                  // eor w9,w9,w2, ror #19
  .long 0x4a450d4a                  // eor w10,w10,w5, lsr #3  // sigma0(X[i+1])
  .long 0x0b10037b                  // add w27,w27,w16  // h+=Sigma1(e)
  .long 0x4a15039c                  // eor w28,w28,w21  // Maj(a,b,c)
  .long 0x4ad45971                  // eor w17,w11,w20, ror #22  // Sigma0(a)
  .long 0x4a422929                  // eor w9,w9,w2, lsr #10  // sigma1(X[i+14])
  .long 0x0b0d0084                  // add w4,w4,w13
  .long 0x0b1b02f7                  // add w23,w23,w27  // d+=h
  .long 0x0b1c037b                  // add w27,w27,w28  // h+=Maj(a,b,c)
  .long 0xb84047dc                  // ldr w28,[x30],#4  // *K++, w19 in next round
  .long 0x0b0a0084                  // add w4,w4,w10
  .long 0x0b11037b                  // add w27,w27,w17  // h+=Sigma0(a)
  .long 0x0b090084                  // add w4,w4,w9
  .long 0xb9400be9                  // ldr w9,[sp,#8]
  .long 0xb90007ec                  // str w12,[sp,#4]
  .long 0x13971af0                  // ror w16,w23,#6
  .long 0x0b1c035a                  // add w26,w26,w28  // h+=K[i]
  .long 0x13861ccb                  // ror w11,w6,#7
  .long 0x0a170311                  // and w17,w24,w23
  .long 0x1383446a                  // ror w10,w3,#17
  .long 0x0a37033c                  // bic w28,w25,w23
  .long 0x139b0b6c                  // ror w12,w27,#2
  .long 0x0b04035a                  // add w26,w26,w4  // h+=X[i]
  .long 0x4ad72e10                  // eor w16,w16,w23, ror #11
  .long 0x4ac6496b                  // eor w11,w11,w6, ror #18
  .long 0x2a1c0231                  // orr w17,w17,w28  // Ch(e,f,g)
  .long 0x4a14037c                  // eor w28,w27,w20  // a^b, b^c in next round
  .long 0x4ad76610                  // eor w16,w16,w23, ror #25  // Sigma1(e)
  .long 0x4adb358c                  // eor w12,w12,w27, ror #13
  .long 0x0b11035a                  // add w26,w26,w17  // h+=Ch(e,f,g)
  .long 0x0a1c0273                  // and w19,w19,w28  // (b^c)&=(a^b)
  .long 0x4ac34d4a                  // eor w10,w10,w3, ror #19
  .long 0x4a460d6b                  // eor w11,w11,w6, lsr #3  // sigma0(X[i+1])
  .long 0x0b10035a                  // add w26,w26,w16  // h+=Sigma1(e)
  .long 0x4a140273                  // eor w19,w19,w20  // Maj(a,b,c)
  .long 0x4adb5991                  // eor w17,w12,w27, ror #22  // Sigma0(a)
  .long 0x4a43294a                  // eor w10,w10,w3, lsr #10  // sigma1(X[i+14])
  .long 0x0b0e00a5                  // add w5,w5,w14
  .long 0x0b1a02d6                  // add w22,w22,w26  // d+=h
  .long 0x0b13035a                  // add w26,w26,w19  // h+=Maj(a,b,c)
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++, w28 in next round
  .long 0x0b0b00a5                  // add w5,w5,w11
  .long 0x0b11035a                  // add w26,w26,w17  // h+=Sigma0(a)
  .long 0x0b0a00a5                  // add w5,w5,w10
  .long 0xb9400fea                  // ldr w10,[sp,#12]
  .long 0xb9000bed                  // str w13,[sp,#8]
  .long 0x13961ad0                  // ror w16,w22,#6
  .long 0x0b130339                  // add w25,w25,w19  // h+=K[i]
  .long 0x13871cec                  // ror w12,w7,#7
  .long 0x0a1602f1                  // and w17,w23,w22
  .long 0x1384448b                  // ror w11,w4,#17
  .long 0x0a360313                  // bic w19,w24,w22
  .long 0x139a0b4d                  // ror w13,w26,#2
  .long 0x0b050339                  // add w25,w25,w5  // h+=X[i]
  .long 0x4ad62e10                  // eor w16,w16,w22, ror #11
  .long 0x4ac7498c                  // eor w12,w12,w7, ror #18
  .long 0x2a130231                  // orr w17,w17,w19  // Ch(e,f,g)
  .long 0x4a1b0353                  // eor w19,w26,w27  // a^b, b^c in next round
  .long 0x4ad66610                  // eor w16,w16,w22, ror #25  // Sigma1(e)
  .long 0x4ada35ad                  // eor w13,w13,w26, ror #13
  .long 0x0b110339                  // add w25,w25,w17  // h+=Ch(e,f,g)
  .long 0x0a13039c                  // and w28,w28,w19  // (b^c)&=(a^b)
  .long 0x4ac44d6b                  // eor w11,w11,w4, ror #19
  .long 0x4a470d8c                  // eor w12,w12,w7, lsr #3  // sigma0(X[i+1])
  .long 0x0b100339                  // add w25,w25,w16  // h+=Sigma1(e)
  .long 0x4a1b039c                  // eor w28,w28,w27  // Maj(a,b,c)
  .long 0x4ada59b1                  // eor w17,w13,w26, ror #22  // Sigma0(a)
  .long 0x4a44296b                  // eor w11,w11,w4, lsr #10  // sigma1(X[i+14])
  .long 0x0b0f00c6                  // add w6,w6,w15
  .long 0x0b1902b5                  // add w21,w21,w25  // d+=h
  .long 0x0b1c0339                  // add w25,w25,w28  // h+=Maj(a,b,c)
  .long 0xb84047dc                  // ldr w28,[x30],#4  // *K++, w19 in next round
  .long 0x0b0c00c6                  // add w6,w6,w12
  .long 0x0b110339                  // add w25,w25,w17  // h+=Sigma0(a)
  .long 0x0b0b00c6                  // add w6,w6,w11
  .long 0xb94003eb                  // ldr w11,[sp,#0]
  .long 0xb9000fee                  // str w14,[sp,#12]
  .long 0x13951ab0                  // ror w16,w21,#6
  .long 0x0b1c0318                  // add w24,w24,w28  // h+=K[i]
  .long 0x13881d0d                  // ror w13,w8,#7
  .long 0x0a1502d1                  // and w17,w22,w21
  .long 0x138544ac                  // ror w12,w5,#17
  .long 0x0a3502fc                  // bic w28,w23,w21
  .long 0x13990b2e                  // ror w14,w25,#2
  .long 0x0b060318                  // add w24,w24,w6  // h+=X[i]
  .long 0x4ad52e10                  // eor w16,w16,w21, ror #11
  .long 0x4ac849ad                  // eor w13,w13,w8, ror #18
  .long 0x2a1c0231                  // orr w17,w17,w28  // Ch(e,f,g)
  .long 0x4a1a033c                  // eor w28,w25,w26  // a^b, b^c in next round
  .long 0x4ad56610                  // eor w16,w16,w21, ror #25  // Sigma1(e)
  .long 0x4ad935ce                  // eor w14,w14,w25, ror #13
  .long 0x0b110318                  // add w24,w24,w17  // h+=Ch(e,f,g)
  .long 0x0a1c0273                  // and w19,w19,w28  // (b^c)&=(a^b)
  .long 0x4ac54d8c                  // eor w12,w12,w5, ror #19
  .long 0x4a480dad                  // eor w13,w13,w8, lsr #3  // sigma0(X[i+1])
  .long 0x0b100318                  // add w24,w24,w16  // h+=Sigma1(e)
  .long 0x4a1a0273                  // eor w19,w19,w26  // Maj(a,b,c)
  .long 0x4ad959d1                  // eor w17,w14,w25, ror #22  // Sigma0(a)
  .long 0x4a45298c                  // eor w12,w12,w5, lsr #10  // sigma1(X[i+14])
  .long 0x0b0000e7                  // add w7,w7,w0
  .long 0x0b180294                  // add w20,w20,w24  // d+=h
  .long 0x0b130318                  // add w24,w24,w19  // h+=Maj(a,b,c)
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++, w28 in next round
  .long 0x0b0d00e7                  // add w7,w7,w13
  .long 0x0b110318                  // add w24,w24,w17  // h+=Sigma0(a)
  .long 0x0b0c00e7                  // add w7,w7,w12
  .long 0xb94007ec                  // ldr w12,[sp,#4]
  .long 0xb90003ef                  // str w15,[sp,#0]
  .long 0x13941a90                  // ror w16,w20,#6
  .long 0x0b1302f7                  // add w23,w23,w19  // h+=K[i]
  .long 0x13891d2e                  // ror w14,w9,#7
  .long 0x0a1402b1                  // and w17,w21,w20
  .long 0x138644cd                  // ror w13,w6,#17
  .long 0x0a3402d3                  // bic w19,w22,w20
  .long 0x13980b0f                  // ror w15,w24,#2
  .long 0x0b0702f7                  // add w23,w23,w7  // h+=X[i]
  .long 0x4ad42e10                  // eor w16,w16,w20, ror #11
  .long 0x4ac949ce                  // eor w14,w14,w9, ror #18
  .long 0x2a130231                  // orr w17,w17,w19  // Ch(e,f,g)
  .long 0x4a190313                  // eor w19,w24,w25  // a^b, b^c in next round
  .long 0x4ad46610                  // eor w16,w16,w20, ror #25  // Sigma1(e)
  .long 0x4ad835ef                  // eor w15,w15,w24, ror #13
  .long 0x0b1102f7                  // add w23,w23,w17  // h+=Ch(e,f,g)
  .long 0x0a13039c                  // and w28,w28,w19  // (b^c)&=(a^b)
  .long 0x4ac64dad                  // eor w13,w13,w6, ror #19
  .long 0x4a490dce                  // eor w14,w14,w9, lsr #3  // sigma0(X[i+1])
  .long 0x0b1002f7                  // add w23,w23,w16  // h+=Sigma1(e)
  .long 0x4a19039c                  // eor w28,w28,w25  // Maj(a,b,c)
  .long 0x4ad859f1                  // eor w17,w15,w24, ror #22  // Sigma0(a)
  .long 0x4a4629ad                  // eor w13,w13,w6, lsr #10  // sigma1(X[i+14])
  .long 0x0b010108                  // add w8,w8,w1
  .long 0x0b17037b                  // add w27,w27,w23  // d+=h
  .long 0x0b1c02f7                  // add w23,w23,w28  // h+=Maj(a,b,c)
  .long 0xb84047dc                  // ldr w28,[x30],#4  // *K++, w19 in next round
  .long 0x0b0e0108                  // add w8,w8,w14
  .long 0x0b1102f7                  // add w23,w23,w17  // h+=Sigma0(a)
  .long 0x0b0d0108                  // add w8,w8,w13
  .long 0xb9400bed                  // ldr w13,[sp,#8]
  .long 0xb90007e0                  // str w0,[sp,#4]
  .long 0x139b1b70                  // ror w16,w27,#6
  .long 0x0b1c02d6                  // add w22,w22,w28  // h+=K[i]
  .long 0x138a1d4f                  // ror w15,w10,#7
  .long 0x0a1b0291                  // and w17,w20,w27
  .long 0x138744ee                  // ror w14,w7,#17
  .long 0x0a3b02bc                  // bic w28,w21,w27
  .long 0x13970ae0                  // ror w0,w23,#2
  .long 0x0b0802d6                  // add w22,w22,w8  // h+=X[i]
  .long 0x4adb2e10                  // eor w16,w16,w27, ror #11
  .long 0x4aca49ef                  // eor w15,w15,w10, ror #18
  .long 0x2a1c0231                  // orr w17,w17,w28  // Ch(e,f,g)
  .long 0x4a1802fc                  // eor w28,w23,w24  // a^b, b^c in next round
  .long 0x4adb6610                  // eor w16,w16,w27, ror #25  // Sigma1(e)
  .long 0x4ad73400                  // eor w0,w0,w23, ror #13
  .long 0x0b1102d6                  // add w22,w22,w17  // h+=Ch(e,f,g)
  .long 0x0a1c0273                  // and w19,w19,w28  // (b^c)&=(a^b)
  .long 0x4ac74dce                  // eor w14,w14,w7, ror #19
  .long 0x4a4a0def                  // eor w15,w15,w10, lsr #3  // sigma0(X[i+1])
  .long 0x0b1002d6                  // add w22,w22,w16  // h+=Sigma1(e)
  .long 0x4a180273                  // eor w19,w19,w24  // Maj(a,b,c)
  .long 0x4ad75811                  // eor w17,w0,w23, ror #22  // Sigma0(a)
  .long 0x4a4729ce                  // eor w14,w14,w7, lsr #10  // sigma1(X[i+14])
  .long 0x0b020129                  // add w9,w9,w2
  .long 0x0b16035a                  // add w26,w26,w22  // d+=h
  .long 0x0b1302d6                  // add w22,w22,w19  // h+=Maj(a,b,c)
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++, w28 in next round
  .long 0x0b0f0129                  // add w9,w9,w15
  .long 0x0b1102d6                  // add w22,w22,w17  // h+=Sigma0(a)
  .long 0x0b0e0129                  // add w9,w9,w14
  .long 0xb9400fee                  // ldr w14,[sp,#12]
  .long 0xb9000be1                  // str w1,[sp,#8]
  .long 0x139a1b50                  // ror w16,w26,#6
  .long 0x0b1302b5                  // add w21,w21,w19  // h+=K[i]
  .long 0x138b1d60                  // ror w0,w11,#7
  .long 0x0a1a0371                  // and w17,w27,w26
  .long 0x1388450f                  // ror w15,w8,#17
  .long 0x0a3a0293                  // bic w19,w20,w26
  .long 0x13960ac1                  // ror w1,w22,#2
  .long 0x0b0902b5                  // add w21,w21,w9  // h+=X[i]
  .long 0x4ada2e10                  // eor w16,w16,w26, ror #11
  .long 0x4acb4800                  // eor w0,w0,w11, ror #18
  .long 0x2a130231                  // orr w17,w17,w19  // Ch(e,f,g)
  .long 0x4a1702d3                  // eor w19,w22,w23  // a^b, b^c in next round
  .long 0x4ada6610                  // eor w16,w16,w26, ror #25  // Sigma1(e)
  .long 0x4ad63421                  // eor w1,w1,w22, ror #13
  .long 0x0b1102b5                  // add w21,w21,w17  // h+=Ch(e,f,g)
  .long 0x0a13039c                  // and w28,w28,w19  // (b^c)&=(a^b)
  .long 0x4ac84def                  // eor w15,w15,w8, ror #19
  .long 0x4a4b0c00                  // eor w0,w0,w11, lsr #3  // sigma0(X[i+1])
  .long 0x0b1002b5                  // add w21,w21,w16  // h+=Sigma1(e)
  .long 0x4a17039c                  // eor w28,w28,w23  // Maj(a,b,c)
  .long 0x4ad65831                  // eor w17,w1,w22, ror #22  // Sigma0(a)
  .long 0x4a4829ef                  // eor w15,w15,w8, lsr #10  // sigma1(X[i+14])
  .long 0x0b03014a                  // add w10,w10,w3
  .long 0x0b150339                  // add w25,w25,w21  // d+=h
  .long 0x0b1c02b5                  // add w21,w21,w28  // h+=Maj(a,b,c)
  .long 0xb84047dc                  // ldr w28,[x30],#4  // *K++, w19 in next round
  .long 0x0b00014a                  // add w10,w10,w0
  .long 0x0b1102b5                  // add w21,w21,w17  // h+=Sigma0(a)
  .long 0x0b0f014a                  // add w10,w10,w15
  .long 0xb94003ef                  // ldr w15,[sp,#0]
  .long 0xb9000fe2                  // str w2,[sp,#12]
  .long 0x13991b30                  // ror w16,w25,#6
  .long 0x0b1c0294                  // add w20,w20,w28  // h+=K[i]
  .long 0x138c1d81                  // ror w1,w12,#7
  .long 0x0a190351                  // and w17,w26,w25
  .long 0x13894520                  // ror w0,w9,#17
  .long 0x0a39037c                  // bic w28,w27,w25
  .long 0x13950aa2                  // ror w2,w21,#2
  .long 0x0b0a0294                  // add w20,w20,w10  // h+=X[i]
  .long 0x4ad92e10                  // eor w16,w16,w25, ror #11
  .long 0x4acc4821                  // eor w1,w1,w12, ror #18
  .long 0x2a1c0231                  // orr w17,w17,w28  // Ch(e,f,g)
  .long 0x4a1602bc                  // eor w28,w21,w22  // a^b, b^c in next round
  .long 0x4ad96610                  // eor w16,w16,w25, ror #25  // Sigma1(e)
  .long 0x4ad53442                  // eor w2,w2,w21, ror #13
  .long 0x0b110294                  // add w20,w20,w17  // h+=Ch(e,f,g)
  .long 0x0a1c0273                  // and w19,w19,w28  // (b^c)&=(a^b)
  .long 0x4ac94c00                  // eor w0,w0,w9, ror #19
  .long 0x4a4c0c21                  // eor w1,w1,w12, lsr #3  // sigma0(X[i+1])
  .long 0x0b100294                  // add w20,w20,w16  // h+=Sigma1(e)
  .long 0x4a160273                  // eor w19,w19,w22  // Maj(a,b,c)
  .long 0x4ad55851                  // eor w17,w2,w21, ror #22  // Sigma0(a)
  .long 0x4a492800                  // eor w0,w0,w9, lsr #10  // sigma1(X[i+14])
  .long 0x0b04016b                  // add w11,w11,w4
  .long 0x0b140318                  // add w24,w24,w20  // d+=h
  .long 0x0b130294                  // add w20,w20,w19  // h+=Maj(a,b,c)
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++, w28 in next round
  .long 0x0b01016b                  // add w11,w11,w1
  .long 0x0b110294                  // add w20,w20,w17  // h+=Sigma0(a)
  .long 0x0b00016b                  // add w11,w11,w0
  .long 0xb94007e0                  // ldr w0,[sp,#4]
  .long 0xb90003e3                  // str w3,[sp,#0]
  .long 0x13981b10                  // ror w16,w24,#6
  .long 0x0b13037b                  // add w27,w27,w19  // h+=K[i]
  .long 0x138d1da2                  // ror w2,w13,#7
  .long 0x0a180331                  // and w17,w25,w24
  .long 0x138a4541                  // ror w1,w10,#17
  .long 0x0a380353                  // bic w19,w26,w24
  .long 0x13940a83                  // ror w3,w20,#2
  .long 0x0b0b037b                  // add w27,w27,w11  // h+=X[i]
  .long 0x4ad82e10                  // eor w16,w16,w24, ror #11
  .long 0x4acd4842                  // eor w2,w2,w13, ror #18
  .long 0x2a130231                  // orr w17,w17,w19  // Ch(e,f,g)
  .long 0x4a150293                  // eor w19,w20,w21  // a^b, b^c in next round
  .long 0x4ad86610                  // eor w16,w16,w24, ror #25  // Sigma1(e)
  .long 0x4ad43463                  // eor w3,w3,w20, ror #13
  .long 0x0b11037b                  // add w27,w27,w17  // h+=Ch(e,f,g)
  .long 0x0a13039c                  // and w28,w28,w19  // (b^c)&=(a^b)
  .long 0x4aca4c21                  // eor w1,w1,w10, ror #19
  .long 0x4a4d0c42                  // eor w2,w2,w13, lsr #3  // sigma0(X[i+1])
  .long 0x0b10037b                  // add w27,w27,w16  // h+=Sigma1(e)
  .long 0x4a15039c                  // eor w28,w28,w21  // Maj(a,b,c)
  .long 0x4ad45871                  // eor w17,w3,w20, ror #22  // Sigma0(a)
  .long 0x4a4a2821                  // eor w1,w1,w10, lsr #10  // sigma1(X[i+14])
  .long 0x0b05018c                  // add w12,w12,w5
  .long 0x0b1b02f7                  // add w23,w23,w27  // d+=h
  .long 0x0b1c037b                  // add w27,w27,w28  // h+=Maj(a,b,c)
  .long 0xb84047dc                  // ldr w28,[x30],#4  // *K++, w19 in next round
  .long 0x0b02018c                  // add w12,w12,w2
  .long 0x0b11037b                  // add w27,w27,w17  // h+=Sigma0(a)
  .long 0x0b01018c                  // add w12,w12,w1
  .long 0xb9400be1                  // ldr w1,[sp,#8]
  .long 0xb90007e4                  // str w4,[sp,#4]
  .long 0x13971af0                  // ror w16,w23,#6
  .long 0x0b1c035a                  // add w26,w26,w28  // h+=K[i]
  .long 0x138e1dc3                  // ror w3,w14,#7
  .long 0x0a170311                  // and w17,w24,w23
  .long 0x138b4562                  // ror w2,w11,#17
  .long 0x0a37033c                  // bic w28,w25,w23
  .long 0x139b0b64                  // ror w4,w27,#2
  .long 0x0b0c035a                  // add w26,w26,w12  // h+=X[i]
  .long 0x4ad72e10                  // eor w16,w16,w23, ror #11
  .long 0x4ace4863                  // eor w3,w3,w14, ror #18
  .long 0x2a1c0231                  // orr w17,w17,w28  // Ch(e,f,g)
  .long 0x4a14037c                  // eor w28,w27,w20  // a^b, b^c in next round
  .long 0x4ad76610                  // eor w16,w16,w23, ror #25  // Sigma1(e)
  .long 0x4adb3484                  // eor w4,w4,w27, ror #13
  .long 0x0b11035a                  // add w26,w26,w17  // h+=Ch(e,f,g)
  .long 0x0a1c0273                  // and w19,w19,w28  // (b^c)&=(a^b)
  .long 0x4acb4c42                  // eor w2,w2,w11, ror #19
  .long 0x4a4e0c63                  // eor w3,w3,w14, lsr #3  // sigma0(X[i+1])
  .long 0x0b10035a                  // add w26,w26,w16  // h+=Sigma1(e)
  .long 0x4a140273                  // eor w19,w19,w20  // Maj(a,b,c)
  .long 0x4adb5891                  // eor w17,w4,w27, ror #22  // Sigma0(a)
  .long 0x4a4b2842                  // eor w2,w2,w11, lsr #10  // sigma1(X[i+14])
  .long 0x0b0601ad                  // add w13,w13,w6
  .long 0x0b1a02d6                  // add w22,w22,w26  // d+=h
  .long 0x0b13035a                  // add w26,w26,w19  // h+=Maj(a,b,c)
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++, w28 in next round
  .long 0x0b0301ad                  // add w13,w13,w3
  .long 0x0b11035a                  // add w26,w26,w17  // h+=Sigma0(a)
  .long 0x0b0201ad                  // add w13,w13,w2
  .long 0xb9400fe2                  // ldr w2,[sp,#12]
  .long 0xb9000be5                  // str w5,[sp,#8]
  .long 0x13961ad0                  // ror w16,w22,#6
  .long 0x0b130339                  // add w25,w25,w19  // h+=K[i]
  .long 0x138f1de4                  // ror w4,w15,#7
  .long 0x0a1602f1                  // and w17,w23,w22
  .long 0x138c4583                  // ror w3,w12,#17
  .long 0x0a360313                  // bic w19,w24,w22
  .long 0x139a0b45                  // ror w5,w26,#2
  .long 0x0b0d0339                  // add w25,w25,w13  // h+=X[i]
  .long 0x4ad62e10                  // eor w16,w16,w22, ror #11
  .long 0x4acf4884                  // eor w4,w4,w15, ror #18
  .long 0x2a130231                  // orr w17,w17,w19  // Ch(e,f,g)
  .long 0x4a1b0353                  // eor w19,w26,w27  // a^b, b^c in next round
  .long 0x4ad66610                  // eor w16,w16,w22, ror #25  // Sigma1(e)
  .long 0x4ada34a5                  // eor w5,w5,w26, ror #13
  .long 0x0b110339                  // add w25,w25,w17  // h+=Ch(e,f,g)
  .long 0x0a13039c                  // and w28,w28,w19  // (b^c)&=(a^b)
  .long 0x4acc4c63                  // eor w3,w3,w12, ror #19
  .long 0x4a4f0c84                  // eor w4,w4,w15, lsr #3  // sigma0(X[i+1])
  .long 0x0b100339                  // add w25,w25,w16  // h+=Sigma1(e)
  .long 0x4a1b039c                  // eor w28,w28,w27  // Maj(a,b,c)
  .long 0x4ada58b1                  // eor w17,w5,w26, ror #22  // Sigma0(a)
  .long 0x4a4c2863                  // eor w3,w3,w12, lsr #10  // sigma1(X[i+14])
  .long 0x0b0701ce                  // add w14,w14,w7
  .long 0x0b1902b5                  // add w21,w21,w25  // d+=h
  .long 0x0b1c0339                  // add w25,w25,w28  // h+=Maj(a,b,c)
  .long 0xb84047dc                  // ldr w28,[x30],#4  // *K++, w19 in next round
  .long 0x0b0401ce                  // add w14,w14,w4
  .long 0x0b110339                  // add w25,w25,w17  // h+=Sigma0(a)
  .long 0x0b0301ce                  // add w14,w14,w3
  .long 0xb94003e3                  // ldr w3,[sp,#0]
  .long 0xb9000fe6                  // str w6,[sp,#12]
  .long 0x13951ab0                  // ror w16,w21,#6
  .long 0x0b1c0318                  // add w24,w24,w28  // h+=K[i]
  .long 0x13801c05                  // ror w5,w0,#7
  .long 0x0a1502d1                  // and w17,w22,w21
  .long 0x138d45a4                  // ror w4,w13,#17
  .long 0x0a3502fc                  // bic w28,w23,w21
  .long 0x13990b26                  // ror w6,w25,#2
  .long 0x0b0e0318                  // add w24,w24,w14  // h+=X[i]
  .long 0x4ad52e10                  // eor w16,w16,w21, ror #11
  .long 0x4ac048a5                  // eor w5,w5,w0, ror #18
  .long 0x2a1c0231                  // orr w17,w17,w28  // Ch(e,f,g)
  .long 0x4a1a033c                  // eor w28,w25,w26  // a^b, b^c in next round
  .long 0x4ad56610                  // eor w16,w16,w21, ror #25  // Sigma1(e)
  .long 0x4ad934c6                  // eor w6,w6,w25, ror #13
  .long 0x0b110318                  // add w24,w24,w17  // h+=Ch(e,f,g)
  .long 0x0a1c0273                  // and w19,w19,w28  // (b^c)&=(a^b)
  .long 0x4acd4c84                  // eor w4,w4,w13, ror #19
  .long 0x4a400ca5                  // eor w5,w5,w0, lsr #3  // sigma0(X[i+1])
  .long 0x0b100318                  // add w24,w24,w16  // h+=Sigma1(e)
  .long 0x4a1a0273                  // eor w19,w19,w26  // Maj(a,b,c)
  .long 0x4ad958d1                  // eor w17,w6,w25, ror #22  // Sigma0(a)
  .long 0x4a4d2884                  // eor w4,w4,w13, lsr #10  // sigma1(X[i+14])
  .long 0x0b0801ef                  // add w15,w15,w8
  .long 0x0b180294                  // add w20,w20,w24  // d+=h
  .long 0x0b130318                  // add w24,w24,w19  // h+=Maj(a,b,c)
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++, w28 in next round
  .long 0x0b0501ef                  // add w15,w15,w5
  .long 0x0b110318                  // add w24,w24,w17  // h+=Sigma0(a)
  .long 0x0b0401ef                  // add w15,w15,w4
  .long 0xb94007e4                  // ldr w4,[sp,#4]
  .long 0xb90003e7                  // str w7,[sp,#0]
  .long 0x13941a90                  // ror w16,w20,#6
  .long 0x0b1302f7                  // add w23,w23,w19  // h+=K[i]
  .long 0x13811c26                  // ror w6,w1,#7
  .long 0x0a1402b1                  // and w17,w21,w20
  .long 0x138e45c5                  // ror w5,w14,#17
  .long 0x0a3402d3                  // bic w19,w22,w20
  .long 0x13980b07                  // ror w7,w24,#2
  .long 0x0b0f02f7                  // add w23,w23,w15  // h+=X[i]
  .long 0x4ad42e10                  // eor w16,w16,w20, ror #11
  .long 0x4ac148c6                  // eor w6,w6,w1, ror #18
  .long 0x2a130231                  // orr w17,w17,w19  // Ch(e,f,g)
  .long 0x4a190313                  // eor w19,w24,w25  // a^b, b^c in next round
  .long 0x4ad46610                  // eor w16,w16,w20, ror #25  // Sigma1(e)
  .long 0x4ad834e7                  // eor w7,w7,w24, ror #13
  .long 0x0b1102f7                  // add w23,w23,w17  // h+=Ch(e,f,g)
  .long 0x0a13039c                  // and w28,w28,w19  // (b^c)&=(a^b)
  .long 0x4ace4ca5                  // eor w5,w5,w14, ror #19
  .long 0x4a410cc6                  // eor w6,w6,w1, lsr #3  // sigma0(X[i+1])
  .long 0x0b1002f7                  // add w23,w23,w16  // h+=Sigma1(e)
  .long 0x4a19039c                  // eor w28,w28,w25  // Maj(a,b,c)
  .long 0x4ad858f1                  // eor w17,w7,w24, ror #22  // Sigma0(a)
  .long 0x4a4e28a5                  // eor w5,w5,w14, lsr #10  // sigma1(X[i+14])
  .long 0x0b090000                  // add w0,w0,w9
  .long 0x0b17037b                  // add w27,w27,w23  // d+=h
  .long 0x0b1c02f7                  // add w23,w23,w28  // h+=Maj(a,b,c)
  .long 0xb84047dc                  // ldr w28,[x30],#4  // *K++, w19 in next round
  .long 0x0b060000                  // add w0,w0,w6
  .long 0x0b1102f7                  // add w23,w23,w17  // h+=Sigma0(a)
  .long 0x0b050000                  // add w0,w0,w5
  .long 0xb9400be5                  // ldr w5,[sp,#8]
  .long 0xb90007e8                  // str w8,[sp,#4]
  .long 0x139b1b70                  // ror w16,w27,#6
  .long 0x0b1c02d6                  // add w22,w22,w28  // h+=K[i]
  .long 0x13821c47                  // ror w7,w2,#7
  .long 0x0a1b0291                  // and w17,w20,w27
  .long 0x138f45e6                  // ror w6,w15,#17
  .long 0x0a3b02bc                  // bic w28,w21,w27
  .long 0x13970ae8                  // ror w8,w23,#2
  .long 0x0b0002d6                  // add w22,w22,w0  // h+=X[i]
  .long 0x4adb2e10                  // eor w16,w16,w27, ror #11
  .long 0x4ac248e7                  // eor w7,w7,w2, ror #18
  .long 0x2a1c0231                  // orr w17,w17,w28  // Ch(e,f,g)
  .long 0x4a1802fc                  // eor w28,w23,w24  // a^b, b^c in next round
  .long 0x4adb6610                  // eor w16,w16,w27, ror #25  // Sigma1(e)
  .long 0x4ad73508                  // eor w8,w8,w23, ror #13
  .long 0x0b1102d6                  // add w22,w22,w17  // h+=Ch(e,f,g)
  .long 0x0a1c0273                  // and w19,w19,w28  // (b^c)&=(a^b)
  .long 0x4acf4cc6                  // eor w6,w6,w15, ror #19
  .long 0x4a420ce7                  // eor w7,w7,w2, lsr #3  // sigma0(X[i+1])
  .long 0x0b1002d6                  // add w22,w22,w16  // h+=Sigma1(e)
  .long 0x4a180273                  // eor w19,w19,w24  // Maj(a,b,c)
  .long 0x4ad75911                  // eor w17,w8,w23, ror #22  // Sigma0(a)
  .long 0x4a4f28c6                  // eor w6,w6,w15, lsr #10  // sigma1(X[i+14])
  .long 0x0b0a0021                  // add w1,w1,w10
  .long 0x0b16035a                  // add w26,w26,w22  // d+=h
  .long 0x0b1302d6                  // add w22,w22,w19  // h+=Maj(a,b,c)
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++, w28 in next round
  .long 0x0b070021                  // add w1,w1,w7
  .long 0x0b1102d6                  // add w22,w22,w17  // h+=Sigma0(a)
  .long 0x0b060021                  // add w1,w1,w6
  .long 0xb9400fe6                  // ldr w6,[sp,#12]
  .long 0xb9000be9                  // str w9,[sp,#8]
  .long 0x139a1b50                  // ror w16,w26,#6
  .long 0x0b1302b5                  // add w21,w21,w19  // h+=K[i]
  .long 0x13831c68                  // ror w8,w3,#7
  .long 0x0a1a0371                  // and w17,w27,w26
  .long 0x13804407                  // ror w7,w0,#17
  .long 0x0a3a0293                  // bic w19,w20,w26
  .long 0x13960ac9                  // ror w9,w22,#2
  .long 0x0b0102b5                  // add w21,w21,w1  // h+=X[i]
  .long 0x4ada2e10                  // eor w16,w16,w26, ror #11
  .long 0x4ac34908                  // eor w8,w8,w3, ror #18
  .long 0x2a130231                  // orr w17,w17,w19  // Ch(e,f,g)
  .long 0x4a1702d3                  // eor w19,w22,w23  // a^b, b^c in next round
  .long 0x4ada6610                  // eor w16,w16,w26, ror #25  // Sigma1(e)
  .long 0x4ad63529                  // eor w9,w9,w22, ror #13
  .long 0x0b1102b5                  // add w21,w21,w17  // h+=Ch(e,f,g)
  .long 0x0a13039c                  // and w28,w28,w19  // (b^c)&=(a^b)
  .long 0x4ac04ce7                  // eor w7,w7,w0, ror #19
  .long 0x4a430d08                  // eor w8,w8,w3, lsr #3  // sigma0(X[i+1])
  .long 0x0b1002b5                  // add w21,w21,w16  // h+=Sigma1(e)
  .long 0x4a17039c                  // eor w28,w28,w23  // Maj(a,b,c)
  .long 0x4ad65931                  // eor w17,w9,w22, ror #22  // Sigma0(a)
  .long 0x4a4028e7                  // eor w7,w7,w0, lsr #10  // sigma1(X[i+14])
  .long 0x0b0b0042                  // add w2,w2,w11
  .long 0x0b150339                  // add w25,w25,w21  // d+=h
  .long 0x0b1c02b5                  // add w21,w21,w28  // h+=Maj(a,b,c)
  .long 0xb84047dc                  // ldr w28,[x30],#4  // *K++, w19 in next round
  .long 0x0b080042                  // add w2,w2,w8
  .long 0x0b1102b5                  // add w21,w21,w17  // h+=Sigma0(a)
  .long 0x0b070042                  // add w2,w2,w7
  .long 0xb94003e7                  // ldr w7,[sp,#0]
  .long 0xb9000fea                  // str w10,[sp,#12]
  .long 0x13991b30                  // ror w16,w25,#6
  .long 0x0b1c0294                  // add w20,w20,w28  // h+=K[i]
  .long 0x13841c89                  // ror w9,w4,#7
  .long 0x0a190351                  // and w17,w26,w25
  .long 0x13814428                  // ror w8,w1,#17
  .long 0x0a39037c                  // bic w28,w27,w25
  .long 0x13950aaa                  // ror w10,w21,#2
  .long 0x0b020294                  // add w20,w20,w2  // h+=X[i]
  .long 0x4ad92e10                  // eor w16,w16,w25, ror #11
  .long 0x4ac44929                  // eor w9,w9,w4, ror #18
  .long 0x2a1c0231                  // orr w17,w17,w28  // Ch(e,f,g)
  .long 0x4a1602bc                  // eor w28,w21,w22  // a^b, b^c in next round
  .long 0x4ad96610                  // eor w16,w16,w25, ror #25  // Sigma1(e)
  .long 0x4ad5354a                  // eor w10,w10,w21, ror #13
  .long 0x0b110294                  // add w20,w20,w17  // h+=Ch(e,f,g)
  .long 0x0a1c0273                  // and w19,w19,w28  // (b^c)&=(a^b)
  .long 0x4ac14d08                  // eor w8,w8,w1, ror #19
  .long 0x4a440d29                  // eor w9,w9,w4, lsr #3  // sigma0(X[i+1])
  .long 0x0b100294                  // add w20,w20,w16  // h+=Sigma1(e)
  .long 0x4a160273                  // eor w19,w19,w22  // Maj(a,b,c)
  .long 0x4ad55951                  // eor w17,w10,w21, ror #22  // Sigma0(a)
  .long 0x4a412908                  // eor w8,w8,w1, lsr #10  // sigma1(X[i+14])
  .long 0x0b0c0063                  // add w3,w3,w12
  .long 0x0b140318                  // add w24,w24,w20  // d+=h
  .long 0x0b130294                  // add w20,w20,w19  // h+=Maj(a,b,c)
  .long 0xb84047d3                  // ldr w19,[x30],#4  // *K++, w28 in next round
  .long 0x0b090063                  // add w3,w3,w9
  .long 0x0b110294                  // add w20,w20,w17  // h+=Sigma0(a)
  .long 0x0b080063                  // add w3,w3,w8
  cbnz w19,.Lsha256_gpr_loop_16_xx

  .long 0xa9460ba0                  // ldp x0,x2,[x29,#96]
  .long 0xf9403ba1                  // ldr x1,[x29,#112]
  .long 0xd10413de                  // sub x30,x30,#260  // rewind

  .long 0x29401003                  // ldp w3,w4,[x0]
  .long 0x29411805                  // ldp w5,w6,[x0,#2*4]
  .long 0x9100e021                  // add x1,x1,#14*4  // advance input pointer
  .long 0x29422007                  // ldp w7,w8,[x0,#4*4]
  .long 0x0b030294                  // add w20,w20,w3
  .long 0x29432809                  // ldp w9,w10,[x0,#6*4]
  .long 0x0b0402b5                  // add w21,w21,w4
  .long 0x0b0502d6                  // add w22,w22,w5
  .long 0x0b0602f7                  // add w23,w23,w6
  .long 0x29005414                  // stp w20,w21,[x0]
  .long 0x0b070318                  // add w24,w24,w7
  .long 0x0b080339                  // add w25,w25,w8
  .long 0x29015c16                  // stp w22,w23,[x0,#2*4]
  .long 0x0b09035a                  // add w26,w26,w9
  .long 0x0b0a037b                  // add w27,w27,w10
  .long 0xeb02003f                  // cmp x1,x2
  .long 0x29026418                  // stp w24,w25,[x0,#4*4]
  .long 0x29036c1a                  // stp w26,w27,[x0,#6*4]
  b.ne .Lsha256_gpr_loop

  .long 0xa94153b3                  // ldp x19,x20,[x29,#16]
  .long 0x910043ff                  // add sp,sp,#4*4
  .long 0xa9425bb5                  // ldp x21,x22,[x29,#32]
  .long 0xa94363b7                  // ldp x23,x24,[x29,#48]
  .long 0xa9446bb9                  // ldp x25,x26,[x29,#64]
  .long 0xa94573bb                  // ldp x27,x28,[x29,#80]
  .long 0xa8c87bfd                  // ldp x29,x30,[sp],#128
  ret
