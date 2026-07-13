// Gpr implementation of SHA-512 compress (AArch64) for cores without
// FEAT_SHA512 (absent on most consumer Cortex-A7x); the Gpr name states
// the ISA requirement: none beyond base AArch64. Serial SHA maps better
// onto the 31 GPRs than onto NEON lanes (single dependency chain, 1-op
// ror, rotate-folded eor operands).
// ABI (after HlpSimdProc4Begin_aarch64.inc): x0 = state ptr (8 x UInt64),
//   x1 = data ptr, w2 = numblocks, x3 = K512_Gpr ptr.
//   K512_Gpr carries the 80 round constants PLUS a zero terminator quad -
//   the message-schedule loop ends when the loaded K word is zero (cbnz),
//   exactly like the original's sentinel-terminated table; a plain K512
//   const cannot drive this loop.
// Frame: 128-byte AAPCS64 frame (x29/x30 + x19-x28 callee-saved) + 32
//   bytes schedule scratch; x30 (LR) is repurposed as the K walk pointer
//   between the save and the restore, as in the original.
// AArch64 instructions are .long-encoded for broad assembler compatibility.
// Reference: OpenSSL CRYPTOGAMS sha512-armv8.pl (sha512_block_data_order,
// the plain path).

  .long 0x2a0203e2                  // mov w2,w2  // zero-extend ANumBlocks (AAPCS64 leaves x2's top half undefined)
  .long 0xa9b87bfd                  // stp x29,x30,[sp,#-128]!
  .long 0x910003fd                  // add x29,sp,#0

  .long 0xa90153f3                  // stp x19,x20,[sp,#16]
  .long 0xa9025bf5                  // stp x21,x22,[sp,#32]
  .long 0xa90363f7                  // stp x23,x24,[sp,#48]
  .long 0xa9046bf9                  // stp x25,x26,[sp,#64]
  .long 0xa90573fb                  // stp x27,x28,[sp,#80]
  .long 0xd10083ff                  // sub sp,sp,#4*8

  .long 0xa9405414                  // ldp x20,x21,[x0]  // load context
  .long 0xa9415c16                  // ldp x22,x23,[x0,#2*8]
  .long 0xa9426418                  // ldp x24,x25,[x0,#4*8]
  .long 0x8b021c22                  // add x2,x1,x2, lsl #7  // end of input
  .long 0xa9436c1a                  // ldp x26,x27,[x0,#6*8]
  .long 0xaa0303fe                  // mov x30,x3  // K512_Gpr (param 4; x3 is reused for message words below)
  .long 0xa9060ba0                  // stp x0,x2,[x29,#96]


.Lsha512_gpr_loop:
  .long 0xa8c11023                  // ldp x3,x4,[x1],#2*8
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++
  .long 0xca1602bc                  // eor x28,x21,x22  // magic seed
  .long 0xf9003ba1                  // str x1,[x29,#112]
  .long 0xdac00c63                  // rev x3,x3  // 0
  .long 0x93d83b10                  // ror x16,x24,#14
  .long 0x8b13037b                  // add x27,x27,x19  // h+=K[i]
  .long 0xcad85f06                  // eor x6,x24,x24, ror #23
  .long 0x8a180331                  // and x17,x25,x24
  .long 0x8a380353                  // bic x19,x26,x24
  .long 0x8b03037b                  // add x27,x27,x3  // h+=X[i]
  .long 0xaa130231                  // orr x17,x17,x19  // Ch(e,f,g)
  .long 0xca150293                  // eor x19,x20,x21  // a^b, b^c in next round
  .long 0xcac64a10                  // eor x16,x16,x6, ror #18  // Sigma1(e)
  .long 0x93d47286                  // ror x6,x20,#28
  .long 0x8b11037b                  // add x27,x27,x17  // h+=Ch(e,f,g)
  .long 0xcad41691                  // eor x17,x20,x20, ror #5
  .long 0x8b10037b                  // add x27,x27,x16  // h+=Sigma1(e)
  .long 0x8a13039c                  // and x28,x28,x19  // (b^c)&=(a^b)
  .long 0x8b1b02f7                  // add x23,x23,x27  // d+=h
  .long 0xca15039c                  // eor x28,x28,x21  // Maj(a,b,c)
  .long 0xcad188d1                  // eor x17,x6,x17, ror #34  // Sigma0(a)
  .long 0x8b1c037b                  // add x27,x27,x28  // h+=Maj(a,b,c)
  .long 0xf84087dc                  // ldr x28,[x30],#8  // *K++, x19 in next round
  //add	x27,x27,x17			// h+=Sigma0(a)
  .long 0xdac00c84                  // rev x4,x4  // 1
  .long 0xa8c11825                  // ldp x5,x6,[x1],#2*8
  .long 0x8b11037b                  // add x27,x27,x17  // h+=Sigma0(a)
  .long 0x93d73af0                  // ror x16,x23,#14
  .long 0x8b1c035a                  // add x26,x26,x28  // h+=K[i]
  .long 0xcad75ee7                  // eor x7,x23,x23, ror #23
  .long 0x8a170311                  // and x17,x24,x23
  .long 0x8a37033c                  // bic x28,x25,x23
  .long 0x8b04035a                  // add x26,x26,x4  // h+=X[i]
  .long 0xaa1c0231                  // orr x17,x17,x28  // Ch(e,f,g)
  .long 0xca14037c                  // eor x28,x27,x20  // a^b, b^c in next round
  .long 0xcac74a10                  // eor x16,x16,x7, ror #18  // Sigma1(e)
  .long 0x93db7367                  // ror x7,x27,#28
  .long 0x8b11035a                  // add x26,x26,x17  // h+=Ch(e,f,g)
  .long 0xcadb1771                  // eor x17,x27,x27, ror #5
  .long 0x8b10035a                  // add x26,x26,x16  // h+=Sigma1(e)
  .long 0x8a1c0273                  // and x19,x19,x28  // (b^c)&=(a^b)
  .long 0x8b1a02d6                  // add x22,x22,x26  // d+=h
  .long 0xca140273                  // eor x19,x19,x20  // Maj(a,b,c)
  .long 0xcad188f1                  // eor x17,x7,x17, ror #34  // Sigma0(a)
  .long 0x8b13035a                  // add x26,x26,x19  // h+=Maj(a,b,c)
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++, x28 in next round
  //add	x26,x26,x17			// h+=Sigma0(a)
  .long 0xdac00ca5                  // rev x5,x5  // 2
  .long 0x8b11035a                  // add x26,x26,x17  // h+=Sigma0(a)
  .long 0x93d63ad0                  // ror x16,x22,#14
  .long 0x8b130339                  // add x25,x25,x19  // h+=K[i]
  .long 0xcad65ec8                  // eor x8,x22,x22, ror #23
  .long 0x8a1602f1                  // and x17,x23,x22
  .long 0x8a360313                  // bic x19,x24,x22
  .long 0x8b050339                  // add x25,x25,x5  // h+=X[i]
  .long 0xaa130231                  // orr x17,x17,x19  // Ch(e,f,g)
  .long 0xca1b0353                  // eor x19,x26,x27  // a^b, b^c in next round
  .long 0xcac84a10                  // eor x16,x16,x8, ror #18  // Sigma1(e)
  .long 0x93da7348                  // ror x8,x26,#28
  .long 0x8b110339                  // add x25,x25,x17  // h+=Ch(e,f,g)
  .long 0xcada1751                  // eor x17,x26,x26, ror #5
  .long 0x8b100339                  // add x25,x25,x16  // h+=Sigma1(e)
  .long 0x8a13039c                  // and x28,x28,x19  // (b^c)&=(a^b)
  .long 0x8b1902b5                  // add x21,x21,x25  // d+=h
  .long 0xca1b039c                  // eor x28,x28,x27  // Maj(a,b,c)
  .long 0xcad18911                  // eor x17,x8,x17, ror #34  // Sigma0(a)
  .long 0x8b1c0339                  // add x25,x25,x28  // h+=Maj(a,b,c)
  .long 0xf84087dc                  // ldr x28,[x30],#8  // *K++, x19 in next round
  //add	x25,x25,x17			// h+=Sigma0(a)
  .long 0xdac00cc6                  // rev x6,x6  // 3
  .long 0xa8c12027                  // ldp x7,x8,[x1],#2*8
  .long 0x8b110339                  // add x25,x25,x17  // h+=Sigma0(a)
  .long 0x93d53ab0                  // ror x16,x21,#14
  .long 0x8b1c0318                  // add x24,x24,x28  // h+=K[i]
  .long 0xcad55ea9                  // eor x9,x21,x21, ror #23
  .long 0x8a1502d1                  // and x17,x22,x21
  .long 0x8a3502fc                  // bic x28,x23,x21
  .long 0x8b060318                  // add x24,x24,x6  // h+=X[i]
  .long 0xaa1c0231                  // orr x17,x17,x28  // Ch(e,f,g)
  .long 0xca1a033c                  // eor x28,x25,x26  // a^b, b^c in next round
  .long 0xcac94a10                  // eor x16,x16,x9, ror #18  // Sigma1(e)
  .long 0x93d97329                  // ror x9,x25,#28
  .long 0x8b110318                  // add x24,x24,x17  // h+=Ch(e,f,g)
  .long 0xcad91731                  // eor x17,x25,x25, ror #5
  .long 0x8b100318                  // add x24,x24,x16  // h+=Sigma1(e)
  .long 0x8a1c0273                  // and x19,x19,x28  // (b^c)&=(a^b)
  .long 0x8b180294                  // add x20,x20,x24  // d+=h
  .long 0xca1a0273                  // eor x19,x19,x26  // Maj(a,b,c)
  .long 0xcad18931                  // eor x17,x9,x17, ror #34  // Sigma0(a)
  .long 0x8b130318                  // add x24,x24,x19  // h+=Maj(a,b,c)
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++, x28 in next round
  //add	x24,x24,x17			// h+=Sigma0(a)
  .long 0xdac00ce7                  // rev x7,x7  // 4
  .long 0x8b110318                  // add x24,x24,x17  // h+=Sigma0(a)
  .long 0x93d43a90                  // ror x16,x20,#14
  .long 0x8b1302f7                  // add x23,x23,x19  // h+=K[i]
  .long 0xcad45e8a                  // eor x10,x20,x20, ror #23
  .long 0x8a1402b1                  // and x17,x21,x20
  .long 0x8a3402d3                  // bic x19,x22,x20
  .long 0x8b0702f7                  // add x23,x23,x7  // h+=X[i]
  .long 0xaa130231                  // orr x17,x17,x19  // Ch(e,f,g)
  .long 0xca190313                  // eor x19,x24,x25  // a^b, b^c in next round
  .long 0xcaca4a10                  // eor x16,x16,x10, ror #18  // Sigma1(e)
  .long 0x93d8730a                  // ror x10,x24,#28
  .long 0x8b1102f7                  // add x23,x23,x17  // h+=Ch(e,f,g)
  .long 0xcad81711                  // eor x17,x24,x24, ror #5
  .long 0x8b1002f7                  // add x23,x23,x16  // h+=Sigma1(e)
  .long 0x8a13039c                  // and x28,x28,x19  // (b^c)&=(a^b)
  .long 0x8b17037b                  // add x27,x27,x23  // d+=h
  .long 0xca19039c                  // eor x28,x28,x25  // Maj(a,b,c)
  .long 0xcad18951                  // eor x17,x10,x17, ror #34  // Sigma0(a)
  .long 0x8b1c02f7                  // add x23,x23,x28  // h+=Maj(a,b,c)
  .long 0xf84087dc                  // ldr x28,[x30],#8  // *K++, x19 in next round
  //add	x23,x23,x17			// h+=Sigma0(a)
  .long 0xdac00d08                  // rev x8,x8  // 5
  .long 0xa8c12829                  // ldp x9,x10,[x1],#2*8
  .long 0x8b1102f7                  // add x23,x23,x17  // h+=Sigma0(a)
  .long 0x93db3b70                  // ror x16,x27,#14
  .long 0x8b1c02d6                  // add x22,x22,x28  // h+=K[i]
  .long 0xcadb5f6b                  // eor x11,x27,x27, ror #23
  .long 0x8a1b0291                  // and x17,x20,x27
  .long 0x8a3b02bc                  // bic x28,x21,x27
  .long 0x8b0802d6                  // add x22,x22,x8  // h+=X[i]
  .long 0xaa1c0231                  // orr x17,x17,x28  // Ch(e,f,g)
  .long 0xca1802fc                  // eor x28,x23,x24  // a^b, b^c in next round
  .long 0xcacb4a10                  // eor x16,x16,x11, ror #18  // Sigma1(e)
  .long 0x93d772eb                  // ror x11,x23,#28
  .long 0x8b1102d6                  // add x22,x22,x17  // h+=Ch(e,f,g)
  .long 0xcad716f1                  // eor x17,x23,x23, ror #5
  .long 0x8b1002d6                  // add x22,x22,x16  // h+=Sigma1(e)
  .long 0x8a1c0273                  // and x19,x19,x28  // (b^c)&=(a^b)
  .long 0x8b16035a                  // add x26,x26,x22  // d+=h
  .long 0xca180273                  // eor x19,x19,x24  // Maj(a,b,c)
  .long 0xcad18971                  // eor x17,x11,x17, ror #34  // Sigma0(a)
  .long 0x8b1302d6                  // add x22,x22,x19  // h+=Maj(a,b,c)
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++, x28 in next round
  //add	x22,x22,x17			// h+=Sigma0(a)
  .long 0xdac00d29                  // rev x9,x9  // 6
  .long 0x8b1102d6                  // add x22,x22,x17  // h+=Sigma0(a)
  .long 0x93da3b50                  // ror x16,x26,#14
  .long 0x8b1302b5                  // add x21,x21,x19  // h+=K[i]
  .long 0xcada5f4c                  // eor x12,x26,x26, ror #23
  .long 0x8a1a0371                  // and x17,x27,x26
  .long 0x8a3a0293                  // bic x19,x20,x26
  .long 0x8b0902b5                  // add x21,x21,x9  // h+=X[i]
  .long 0xaa130231                  // orr x17,x17,x19  // Ch(e,f,g)
  .long 0xca1702d3                  // eor x19,x22,x23  // a^b, b^c in next round
  .long 0xcacc4a10                  // eor x16,x16,x12, ror #18  // Sigma1(e)
  .long 0x93d672cc                  // ror x12,x22,#28
  .long 0x8b1102b5                  // add x21,x21,x17  // h+=Ch(e,f,g)
  .long 0xcad616d1                  // eor x17,x22,x22, ror #5
  .long 0x8b1002b5                  // add x21,x21,x16  // h+=Sigma1(e)
  .long 0x8a13039c                  // and x28,x28,x19  // (b^c)&=(a^b)
  .long 0x8b150339                  // add x25,x25,x21  // d+=h
  .long 0xca17039c                  // eor x28,x28,x23  // Maj(a,b,c)
  .long 0xcad18991                  // eor x17,x12,x17, ror #34  // Sigma0(a)
  .long 0x8b1c02b5                  // add x21,x21,x28  // h+=Maj(a,b,c)
  .long 0xf84087dc                  // ldr x28,[x30],#8  // *K++, x19 in next round
  //add	x21,x21,x17			// h+=Sigma0(a)
  .long 0xdac00d4a                  // rev x10,x10  // 7
  .long 0xa8c1302b                  // ldp x11,x12,[x1],#2*8
  .long 0x8b1102b5                  // add x21,x21,x17  // h+=Sigma0(a)
  .long 0x93d93b30                  // ror x16,x25,#14
  .long 0x8b1c0294                  // add x20,x20,x28  // h+=K[i]
  .long 0xcad95f2d                  // eor x13,x25,x25, ror #23
  .long 0x8a190351                  // and x17,x26,x25
  .long 0x8a39037c                  // bic x28,x27,x25
  .long 0x8b0a0294                  // add x20,x20,x10  // h+=X[i]
  .long 0xaa1c0231                  // orr x17,x17,x28  // Ch(e,f,g)
  .long 0xca1602bc                  // eor x28,x21,x22  // a^b, b^c in next round
  .long 0xcacd4a10                  // eor x16,x16,x13, ror #18  // Sigma1(e)
  .long 0x93d572ad                  // ror x13,x21,#28
  .long 0x8b110294                  // add x20,x20,x17  // h+=Ch(e,f,g)
  .long 0xcad516b1                  // eor x17,x21,x21, ror #5
  .long 0x8b100294                  // add x20,x20,x16  // h+=Sigma1(e)
  .long 0x8a1c0273                  // and x19,x19,x28  // (b^c)&=(a^b)
  .long 0x8b140318                  // add x24,x24,x20  // d+=h
  .long 0xca160273                  // eor x19,x19,x22  // Maj(a,b,c)
  .long 0xcad189b1                  // eor x17,x13,x17, ror #34  // Sigma0(a)
  .long 0x8b130294                  // add x20,x20,x19  // h+=Maj(a,b,c)
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++, x28 in next round
  //add	x20,x20,x17			// h+=Sigma0(a)
  .long 0xdac00d6b                  // rev x11,x11  // 8
  .long 0x8b110294                  // add x20,x20,x17  // h+=Sigma0(a)
  .long 0x93d83b10                  // ror x16,x24,#14
  .long 0x8b13037b                  // add x27,x27,x19  // h+=K[i]
  .long 0xcad85f0e                  // eor x14,x24,x24, ror #23
  .long 0x8a180331                  // and x17,x25,x24
  .long 0x8a380353                  // bic x19,x26,x24
  .long 0x8b0b037b                  // add x27,x27,x11  // h+=X[i]
  .long 0xaa130231                  // orr x17,x17,x19  // Ch(e,f,g)
  .long 0xca150293                  // eor x19,x20,x21  // a^b, b^c in next round
  .long 0xcace4a10                  // eor x16,x16,x14, ror #18  // Sigma1(e)
  .long 0x93d4728e                  // ror x14,x20,#28
  .long 0x8b11037b                  // add x27,x27,x17  // h+=Ch(e,f,g)
  .long 0xcad41691                  // eor x17,x20,x20, ror #5
  .long 0x8b10037b                  // add x27,x27,x16  // h+=Sigma1(e)
  .long 0x8a13039c                  // and x28,x28,x19  // (b^c)&=(a^b)
  .long 0x8b1b02f7                  // add x23,x23,x27  // d+=h
  .long 0xca15039c                  // eor x28,x28,x21  // Maj(a,b,c)
  .long 0xcad189d1                  // eor x17,x14,x17, ror #34  // Sigma0(a)
  .long 0x8b1c037b                  // add x27,x27,x28  // h+=Maj(a,b,c)
  .long 0xf84087dc                  // ldr x28,[x30],#8  // *K++, x19 in next round
  //add	x27,x27,x17			// h+=Sigma0(a)
  .long 0xdac00d8c                  // rev x12,x12  // 9
  .long 0xa8c1382d                  // ldp x13,x14,[x1],#2*8
  .long 0x8b11037b                  // add x27,x27,x17  // h+=Sigma0(a)
  .long 0x93d73af0                  // ror x16,x23,#14
  .long 0x8b1c035a                  // add x26,x26,x28  // h+=K[i]
  .long 0xcad75eef                  // eor x15,x23,x23, ror #23
  .long 0x8a170311                  // and x17,x24,x23
  .long 0x8a37033c                  // bic x28,x25,x23
  .long 0x8b0c035a                  // add x26,x26,x12  // h+=X[i]
  .long 0xaa1c0231                  // orr x17,x17,x28  // Ch(e,f,g)
  .long 0xca14037c                  // eor x28,x27,x20  // a^b, b^c in next round
  .long 0xcacf4a10                  // eor x16,x16,x15, ror #18  // Sigma1(e)
  .long 0x93db736f                  // ror x15,x27,#28
  .long 0x8b11035a                  // add x26,x26,x17  // h+=Ch(e,f,g)
  .long 0xcadb1771                  // eor x17,x27,x27, ror #5
  .long 0x8b10035a                  // add x26,x26,x16  // h+=Sigma1(e)
  .long 0x8a1c0273                  // and x19,x19,x28  // (b^c)&=(a^b)
  .long 0x8b1a02d6                  // add x22,x22,x26  // d+=h
  .long 0xca140273                  // eor x19,x19,x20  // Maj(a,b,c)
  .long 0xcad189f1                  // eor x17,x15,x17, ror #34  // Sigma0(a)
  .long 0x8b13035a                  // add x26,x26,x19  // h+=Maj(a,b,c)
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++, x28 in next round
  //add	x26,x26,x17			// h+=Sigma0(a)
  .long 0xdac00dad                  // rev x13,x13  // 10
  .long 0x8b11035a                  // add x26,x26,x17  // h+=Sigma0(a)
  .long 0x93d63ad0                  // ror x16,x22,#14
  .long 0x8b130339                  // add x25,x25,x19  // h+=K[i]
  .long 0xcad65ec0                  // eor x0,x22,x22, ror #23
  .long 0x8a1602f1                  // and x17,x23,x22
  .long 0x8a360313                  // bic x19,x24,x22
  .long 0x8b0d0339                  // add x25,x25,x13  // h+=X[i]
  .long 0xaa130231                  // orr x17,x17,x19  // Ch(e,f,g)
  .long 0xca1b0353                  // eor x19,x26,x27  // a^b, b^c in next round
  .long 0xcac04a10                  // eor x16,x16,x0, ror #18  // Sigma1(e)
  .long 0x93da7340                  // ror x0,x26,#28
  .long 0x8b110339                  // add x25,x25,x17  // h+=Ch(e,f,g)
  .long 0xcada1751                  // eor x17,x26,x26, ror #5
  .long 0x8b100339                  // add x25,x25,x16  // h+=Sigma1(e)
  .long 0x8a13039c                  // and x28,x28,x19  // (b^c)&=(a^b)
  .long 0x8b1902b5                  // add x21,x21,x25  // d+=h
  .long 0xca1b039c                  // eor x28,x28,x27  // Maj(a,b,c)
  .long 0xcad18811                  // eor x17,x0,x17, ror #34  // Sigma0(a)
  .long 0x8b1c0339                  // add x25,x25,x28  // h+=Maj(a,b,c)
  .long 0xf84087dc                  // ldr x28,[x30],#8  // *K++, x19 in next round
  //add	x25,x25,x17			// h+=Sigma0(a)
  .long 0xdac00dce                  // rev x14,x14  // 11
  .long 0xa8c1002f                  // ldp x15,x0,[x1],#2*8
  .long 0x8b110339                  // add x25,x25,x17  // h+=Sigma0(a)
  .long 0xf9000fe6                  // str x6,[sp,#24]
  .long 0x93d53ab0                  // ror x16,x21,#14
  .long 0x8b1c0318                  // add x24,x24,x28  // h+=K[i]
  .long 0xcad55ea6                  // eor x6,x21,x21, ror #23
  .long 0x8a1502d1                  // and x17,x22,x21
  .long 0x8a3502fc                  // bic x28,x23,x21
  .long 0x8b0e0318                  // add x24,x24,x14  // h+=X[i]
  .long 0xaa1c0231                  // orr x17,x17,x28  // Ch(e,f,g)
  .long 0xca1a033c                  // eor x28,x25,x26  // a^b, b^c in next round
  .long 0xcac64a10                  // eor x16,x16,x6, ror #18  // Sigma1(e)
  .long 0x93d97326                  // ror x6,x25,#28
  .long 0x8b110318                  // add x24,x24,x17  // h+=Ch(e,f,g)
  .long 0xcad91731                  // eor x17,x25,x25, ror #5
  .long 0x8b100318                  // add x24,x24,x16  // h+=Sigma1(e)
  .long 0x8a1c0273                  // and x19,x19,x28  // (b^c)&=(a^b)
  .long 0x8b180294                  // add x20,x20,x24  // d+=h
  .long 0xca1a0273                  // eor x19,x19,x26  // Maj(a,b,c)
  .long 0xcad188d1                  // eor x17,x6,x17, ror #34  // Sigma0(a)
  .long 0x8b130318                  // add x24,x24,x19  // h+=Maj(a,b,c)
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++, x28 in next round
  //add	x24,x24,x17			// h+=Sigma0(a)
  .long 0xdac00def                  // rev x15,x15  // 12
  .long 0x8b110318                  // add x24,x24,x17  // h+=Sigma0(a)
  .long 0xf90003e7                  // str x7,[sp,#0]
  .long 0x93d43a90                  // ror x16,x20,#14
  .long 0x8b1302f7                  // add x23,x23,x19  // h+=K[i]
  .long 0xcad45e87                  // eor x7,x20,x20, ror #23
  .long 0x8a1402b1                  // and x17,x21,x20
  .long 0x8a3402d3                  // bic x19,x22,x20
  .long 0x8b0f02f7                  // add x23,x23,x15  // h+=X[i]
  .long 0xaa130231                  // orr x17,x17,x19  // Ch(e,f,g)
  .long 0xca190313                  // eor x19,x24,x25  // a^b, b^c in next round
  .long 0xcac74a10                  // eor x16,x16,x7, ror #18  // Sigma1(e)
  .long 0x93d87307                  // ror x7,x24,#28
  .long 0x8b1102f7                  // add x23,x23,x17  // h+=Ch(e,f,g)
  .long 0xcad81711                  // eor x17,x24,x24, ror #5
  .long 0x8b1002f7                  // add x23,x23,x16  // h+=Sigma1(e)
  .long 0x8a13039c                  // and x28,x28,x19  // (b^c)&=(a^b)
  .long 0x8b17037b                  // add x27,x27,x23  // d+=h
  .long 0xca19039c                  // eor x28,x28,x25  // Maj(a,b,c)
  .long 0xcad188f1                  // eor x17,x7,x17, ror #34  // Sigma0(a)
  .long 0x8b1c02f7                  // add x23,x23,x28  // h+=Maj(a,b,c)
  .long 0xf84087dc                  // ldr x28,[x30],#8  // *K++, x19 in next round
  //add	x23,x23,x17			// h+=Sigma0(a)
  .long 0xdac00c00                  // rev x0,x0  // 13
  .long 0xa9400821                  // ldp x1,x2,[x1]
  .long 0x8b1102f7                  // add x23,x23,x17  // h+=Sigma0(a)
  .long 0xf90007e8                  // str x8,[sp,#8]
  .long 0x93db3b70                  // ror x16,x27,#14
  .long 0x8b1c02d6                  // add x22,x22,x28  // h+=K[i]
  .long 0xcadb5f68                  // eor x8,x27,x27, ror #23
  .long 0x8a1b0291                  // and x17,x20,x27
  .long 0x8a3b02bc                  // bic x28,x21,x27
  .long 0x8b0002d6                  // add x22,x22,x0  // h+=X[i]
  .long 0xaa1c0231                  // orr x17,x17,x28  // Ch(e,f,g)
  .long 0xca1802fc                  // eor x28,x23,x24  // a^b, b^c in next round
  .long 0xcac84a10                  // eor x16,x16,x8, ror #18  // Sigma1(e)
  .long 0x93d772e8                  // ror x8,x23,#28
  .long 0x8b1102d6                  // add x22,x22,x17  // h+=Ch(e,f,g)
  .long 0xcad716f1                  // eor x17,x23,x23, ror #5
  .long 0x8b1002d6                  // add x22,x22,x16  // h+=Sigma1(e)
  .long 0x8a1c0273                  // and x19,x19,x28  // (b^c)&=(a^b)
  .long 0x8b16035a                  // add x26,x26,x22  // d+=h
  .long 0xca180273                  // eor x19,x19,x24  // Maj(a,b,c)
  .long 0xcad18911                  // eor x17,x8,x17, ror #34  // Sigma0(a)
  .long 0x8b1302d6                  // add x22,x22,x19  // h+=Maj(a,b,c)
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++, x28 in next round
  //add	x22,x22,x17			// h+=Sigma0(a)
  .long 0xdac00c21                  // rev x1,x1  // 14
  .long 0xf9400fe6                  // ldr x6,[sp,#24]
  .long 0x8b1102d6                  // add x22,x22,x17  // h+=Sigma0(a)
  .long 0xf9000be9                  // str x9,[sp,#16]
  .long 0x93da3b50                  // ror x16,x26,#14
  .long 0x8b1302b5                  // add x21,x21,x19  // h+=K[i]
  .long 0xcada5f49                  // eor x9,x26,x26, ror #23
  .long 0x8a1a0371                  // and x17,x27,x26
  .long 0x8a3a0293                  // bic x19,x20,x26
  .long 0x8b0102b5                  // add x21,x21,x1  // h+=X[i]
  .long 0xaa130231                  // orr x17,x17,x19  // Ch(e,f,g)
  .long 0xca1702d3                  // eor x19,x22,x23  // a^b, b^c in next round
  .long 0xcac94a10                  // eor x16,x16,x9, ror #18  // Sigma1(e)
  .long 0x93d672c9                  // ror x9,x22,#28
  .long 0x8b1102b5                  // add x21,x21,x17  // h+=Ch(e,f,g)
  .long 0xcad616d1                  // eor x17,x22,x22, ror #5
  .long 0x8b1002b5                  // add x21,x21,x16  // h+=Sigma1(e)
  .long 0x8a13039c                  // and x28,x28,x19  // (b^c)&=(a^b)
  .long 0x8b150339                  // add x25,x25,x21  // d+=h
  .long 0xca17039c                  // eor x28,x28,x23  // Maj(a,b,c)
  .long 0xcad18931                  // eor x17,x9,x17, ror #34  // Sigma0(a)
  .long 0x8b1c02b5                  // add x21,x21,x28  // h+=Maj(a,b,c)
  .long 0xf84087dc                  // ldr x28,[x30],#8  // *K++, x19 in next round
  //add	x21,x21,x17			// h+=Sigma0(a)
  .long 0xdac00c42                  // rev x2,x2  // 15
  .long 0xf94003e7                  // ldr x7,[sp,#0]
  .long 0x8b1102b5                  // add x21,x21,x17  // h+=Sigma0(a)
  .long 0xf9000fea                  // str x10,[sp,#24]
  .long 0x93d93b30                  // ror x16,x25,#14
  .long 0x8b1c0294                  // add x20,x20,x28  // h+=K[i]
  .long 0x93c40489                  // ror x9,x4,#1
  .long 0x8a190351                  // and x17,x26,x25
  .long 0x93c14c28                  // ror x8,x1,#19
  .long 0x8a39037c                  // bic x28,x27,x25
  .long 0x93d572aa                  // ror x10,x21,#28
  .long 0x8b020294                  // add x20,x20,x2  // h+=X[i]
  .long 0xcad94a10                  // eor x16,x16,x25, ror #18
  .long 0xcac42129                  // eor x9,x9,x4, ror #8
  .long 0xaa1c0231                  // orr x17,x17,x28  // Ch(e,f,g)
  .long 0xca1602bc                  // eor x28,x21,x22  // a^b, b^c in next round
  .long 0xcad9a610                  // eor x16,x16,x25, ror #41  // Sigma1(e)
  .long 0xcad5894a                  // eor x10,x10,x21, ror #34
  .long 0x8b110294                  // add x20,x20,x17  // h+=Ch(e,f,g)
  .long 0x8a1c0273                  // and x19,x19,x28  // (b^c)&=(a^b)
  .long 0xcac1f508                  // eor x8,x8,x1, ror #61
  .long 0xca441d29                  // eor x9,x9,x4, lsr #7  // sigma0(X[i+1])
  .long 0x8b100294                  // add x20,x20,x16  // h+=Sigma1(e)
  .long 0xca160273                  // eor x19,x19,x22  // Maj(a,b,c)
  .long 0xcad59d51                  // eor x17,x10,x21, ror #39  // Sigma0(a)
  .long 0xca411908                  // eor x8,x8,x1, lsr #6  // sigma1(X[i+14])
  .long 0x8b0c0063                  // add x3,x3,x12
  .long 0x8b140318                  // add x24,x24,x20  // d+=h
  .long 0x8b130294                  // add x20,x20,x19  // h+=Maj(a,b,c)
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++, x28 in next round
  .long 0x8b090063                  // add x3,x3,x9
  .long 0x8b110294                  // add x20,x20,x17  // h+=Sigma0(a)
  .long 0x8b080063                  // add x3,x3,x8

.Lsha512_gpr_loop_16_xx:
  .long 0xf94007e8                  // ldr x8,[sp,#8]
  .long 0xf90003eb                  // str x11,[sp,#0]
  .long 0x93d83b10                  // ror x16,x24,#14
  .long 0x8b13037b                  // add x27,x27,x19  // h+=K[i]
  .long 0x93c504aa                  // ror x10,x5,#1
  .long 0x8a180331                  // and x17,x25,x24
  .long 0x93c24c49                  // ror x9,x2,#19
  .long 0x8a380353                  // bic x19,x26,x24
  .long 0x93d4728b                  // ror x11,x20,#28
  .long 0x8b03037b                  // add x27,x27,x3  // h+=X[i]
  .long 0xcad84a10                  // eor x16,x16,x24, ror #18
  .long 0xcac5214a                  // eor x10,x10,x5, ror #8
  .long 0xaa130231                  // orr x17,x17,x19  // Ch(e,f,g)
  .long 0xca150293                  // eor x19,x20,x21  // a^b, b^c in next round
  .long 0xcad8a610                  // eor x16,x16,x24, ror #41  // Sigma1(e)
  .long 0xcad4896b                  // eor x11,x11,x20, ror #34
  .long 0x8b11037b                  // add x27,x27,x17  // h+=Ch(e,f,g)
  .long 0x8a13039c                  // and x28,x28,x19  // (b^c)&=(a^b)
  .long 0xcac2f529                  // eor x9,x9,x2, ror #61
  .long 0xca451d4a                  // eor x10,x10,x5, lsr #7  // sigma0(X[i+1])
  .long 0x8b10037b                  // add x27,x27,x16  // h+=Sigma1(e)
  .long 0xca15039c                  // eor x28,x28,x21  // Maj(a,b,c)
  .long 0xcad49d71                  // eor x17,x11,x20, ror #39  // Sigma0(a)
  .long 0xca421929                  // eor x9,x9,x2, lsr #6  // sigma1(X[i+14])
  .long 0x8b0d0084                  // add x4,x4,x13
  .long 0x8b1b02f7                  // add x23,x23,x27  // d+=h
  .long 0x8b1c037b                  // add x27,x27,x28  // h+=Maj(a,b,c)
  .long 0xf84087dc                  // ldr x28,[x30],#8  // *K++, x19 in next round
  .long 0x8b0a0084                  // add x4,x4,x10
  .long 0x8b11037b                  // add x27,x27,x17  // h+=Sigma0(a)
  .long 0x8b090084                  // add x4,x4,x9
  .long 0xf9400be9                  // ldr x9,[sp,#16]
  .long 0xf90007ec                  // str x12,[sp,#8]
  .long 0x93d73af0                  // ror x16,x23,#14
  .long 0x8b1c035a                  // add x26,x26,x28  // h+=K[i]
  .long 0x93c604cb                  // ror x11,x6,#1
  .long 0x8a170311                  // and x17,x24,x23
  .long 0x93c34c6a                  // ror x10,x3,#19
  .long 0x8a37033c                  // bic x28,x25,x23
  .long 0x93db736c                  // ror x12,x27,#28
  .long 0x8b04035a                  // add x26,x26,x4  // h+=X[i]
  .long 0xcad74a10                  // eor x16,x16,x23, ror #18
  .long 0xcac6216b                  // eor x11,x11,x6, ror #8
  .long 0xaa1c0231                  // orr x17,x17,x28  // Ch(e,f,g)
  .long 0xca14037c                  // eor x28,x27,x20  // a^b, b^c in next round
  .long 0xcad7a610                  // eor x16,x16,x23, ror #41  // Sigma1(e)
  .long 0xcadb898c                  // eor x12,x12,x27, ror #34
  .long 0x8b11035a                  // add x26,x26,x17  // h+=Ch(e,f,g)
  .long 0x8a1c0273                  // and x19,x19,x28  // (b^c)&=(a^b)
  .long 0xcac3f54a                  // eor x10,x10,x3, ror #61
  .long 0xca461d6b                  // eor x11,x11,x6, lsr #7  // sigma0(X[i+1])
  .long 0x8b10035a                  // add x26,x26,x16  // h+=Sigma1(e)
  .long 0xca140273                  // eor x19,x19,x20  // Maj(a,b,c)
  .long 0xcadb9d91                  // eor x17,x12,x27, ror #39  // Sigma0(a)
  .long 0xca43194a                  // eor x10,x10,x3, lsr #6  // sigma1(X[i+14])
  .long 0x8b0e00a5                  // add x5,x5,x14
  .long 0x8b1a02d6                  // add x22,x22,x26  // d+=h
  .long 0x8b13035a                  // add x26,x26,x19  // h+=Maj(a,b,c)
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++, x28 in next round
  .long 0x8b0b00a5                  // add x5,x5,x11
  .long 0x8b11035a                  // add x26,x26,x17  // h+=Sigma0(a)
  .long 0x8b0a00a5                  // add x5,x5,x10
  .long 0xf9400fea                  // ldr x10,[sp,#24]
  .long 0xf9000bed                  // str x13,[sp,#16]
  .long 0x93d63ad0                  // ror x16,x22,#14
  .long 0x8b130339                  // add x25,x25,x19  // h+=K[i]
  .long 0x93c704ec                  // ror x12,x7,#1
  .long 0x8a1602f1                  // and x17,x23,x22
  .long 0x93c44c8b                  // ror x11,x4,#19
  .long 0x8a360313                  // bic x19,x24,x22
  .long 0x93da734d                  // ror x13,x26,#28
  .long 0x8b050339                  // add x25,x25,x5  // h+=X[i]
  .long 0xcad64a10                  // eor x16,x16,x22, ror #18
  .long 0xcac7218c                  // eor x12,x12,x7, ror #8
  .long 0xaa130231                  // orr x17,x17,x19  // Ch(e,f,g)
  .long 0xca1b0353                  // eor x19,x26,x27  // a^b, b^c in next round
  .long 0xcad6a610                  // eor x16,x16,x22, ror #41  // Sigma1(e)
  .long 0xcada89ad                  // eor x13,x13,x26, ror #34
  .long 0x8b110339                  // add x25,x25,x17  // h+=Ch(e,f,g)
  .long 0x8a13039c                  // and x28,x28,x19  // (b^c)&=(a^b)
  .long 0xcac4f56b                  // eor x11,x11,x4, ror #61
  .long 0xca471d8c                  // eor x12,x12,x7, lsr #7  // sigma0(X[i+1])
  .long 0x8b100339                  // add x25,x25,x16  // h+=Sigma1(e)
  .long 0xca1b039c                  // eor x28,x28,x27  // Maj(a,b,c)
  .long 0xcada9db1                  // eor x17,x13,x26, ror #39  // Sigma0(a)
  .long 0xca44196b                  // eor x11,x11,x4, lsr #6  // sigma1(X[i+14])
  .long 0x8b0f00c6                  // add x6,x6,x15
  .long 0x8b1902b5                  // add x21,x21,x25  // d+=h
  .long 0x8b1c0339                  // add x25,x25,x28  // h+=Maj(a,b,c)
  .long 0xf84087dc                  // ldr x28,[x30],#8  // *K++, x19 in next round
  .long 0x8b0c00c6                  // add x6,x6,x12
  .long 0x8b110339                  // add x25,x25,x17  // h+=Sigma0(a)
  .long 0x8b0b00c6                  // add x6,x6,x11
  .long 0xf94003eb                  // ldr x11,[sp,#0]
  .long 0xf9000fee                  // str x14,[sp,#24]
  .long 0x93d53ab0                  // ror x16,x21,#14
  .long 0x8b1c0318                  // add x24,x24,x28  // h+=K[i]
  .long 0x93c8050d                  // ror x13,x8,#1
  .long 0x8a1502d1                  // and x17,x22,x21
  .long 0x93c54cac                  // ror x12,x5,#19
  .long 0x8a3502fc                  // bic x28,x23,x21
  .long 0x93d9732e                  // ror x14,x25,#28
  .long 0x8b060318                  // add x24,x24,x6  // h+=X[i]
  .long 0xcad54a10                  // eor x16,x16,x21, ror #18
  .long 0xcac821ad                  // eor x13,x13,x8, ror #8
  .long 0xaa1c0231                  // orr x17,x17,x28  // Ch(e,f,g)
  .long 0xca1a033c                  // eor x28,x25,x26  // a^b, b^c in next round
  .long 0xcad5a610                  // eor x16,x16,x21, ror #41  // Sigma1(e)
  .long 0xcad989ce                  // eor x14,x14,x25, ror #34
  .long 0x8b110318                  // add x24,x24,x17  // h+=Ch(e,f,g)
  .long 0x8a1c0273                  // and x19,x19,x28  // (b^c)&=(a^b)
  .long 0xcac5f58c                  // eor x12,x12,x5, ror #61
  .long 0xca481dad                  // eor x13,x13,x8, lsr #7  // sigma0(X[i+1])
  .long 0x8b100318                  // add x24,x24,x16  // h+=Sigma1(e)
  .long 0xca1a0273                  // eor x19,x19,x26  // Maj(a,b,c)
  .long 0xcad99dd1                  // eor x17,x14,x25, ror #39  // Sigma0(a)
  .long 0xca45198c                  // eor x12,x12,x5, lsr #6  // sigma1(X[i+14])
  .long 0x8b0000e7                  // add x7,x7,x0
  .long 0x8b180294                  // add x20,x20,x24  // d+=h
  .long 0x8b130318                  // add x24,x24,x19  // h+=Maj(a,b,c)
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++, x28 in next round
  .long 0x8b0d00e7                  // add x7,x7,x13
  .long 0x8b110318                  // add x24,x24,x17  // h+=Sigma0(a)
  .long 0x8b0c00e7                  // add x7,x7,x12
  .long 0xf94007ec                  // ldr x12,[sp,#8]
  .long 0xf90003ef                  // str x15,[sp,#0]
  .long 0x93d43a90                  // ror x16,x20,#14
  .long 0x8b1302f7                  // add x23,x23,x19  // h+=K[i]
  .long 0x93c9052e                  // ror x14,x9,#1
  .long 0x8a1402b1                  // and x17,x21,x20
  .long 0x93c64ccd                  // ror x13,x6,#19
  .long 0x8a3402d3                  // bic x19,x22,x20
  .long 0x93d8730f                  // ror x15,x24,#28
  .long 0x8b0702f7                  // add x23,x23,x7  // h+=X[i]
  .long 0xcad44a10                  // eor x16,x16,x20, ror #18
  .long 0xcac921ce                  // eor x14,x14,x9, ror #8
  .long 0xaa130231                  // orr x17,x17,x19  // Ch(e,f,g)
  .long 0xca190313                  // eor x19,x24,x25  // a^b, b^c in next round
  .long 0xcad4a610                  // eor x16,x16,x20, ror #41  // Sigma1(e)
  .long 0xcad889ef                  // eor x15,x15,x24, ror #34
  .long 0x8b1102f7                  // add x23,x23,x17  // h+=Ch(e,f,g)
  .long 0x8a13039c                  // and x28,x28,x19  // (b^c)&=(a^b)
  .long 0xcac6f5ad                  // eor x13,x13,x6, ror #61
  .long 0xca491dce                  // eor x14,x14,x9, lsr #7  // sigma0(X[i+1])
  .long 0x8b1002f7                  // add x23,x23,x16  // h+=Sigma1(e)
  .long 0xca19039c                  // eor x28,x28,x25  // Maj(a,b,c)
  .long 0xcad89df1                  // eor x17,x15,x24, ror #39  // Sigma0(a)
  .long 0xca4619ad                  // eor x13,x13,x6, lsr #6  // sigma1(X[i+14])
  .long 0x8b010108                  // add x8,x8,x1
  .long 0x8b17037b                  // add x27,x27,x23  // d+=h
  .long 0x8b1c02f7                  // add x23,x23,x28  // h+=Maj(a,b,c)
  .long 0xf84087dc                  // ldr x28,[x30],#8  // *K++, x19 in next round
  .long 0x8b0e0108                  // add x8,x8,x14
  .long 0x8b1102f7                  // add x23,x23,x17  // h+=Sigma0(a)
  .long 0x8b0d0108                  // add x8,x8,x13
  .long 0xf9400bed                  // ldr x13,[sp,#16]
  .long 0xf90007e0                  // str x0,[sp,#8]
  .long 0x93db3b70                  // ror x16,x27,#14
  .long 0x8b1c02d6                  // add x22,x22,x28  // h+=K[i]
  .long 0x93ca054f                  // ror x15,x10,#1
  .long 0x8a1b0291                  // and x17,x20,x27
  .long 0x93c74cee                  // ror x14,x7,#19
  .long 0x8a3b02bc                  // bic x28,x21,x27
  .long 0x93d772e0                  // ror x0,x23,#28
  .long 0x8b0802d6                  // add x22,x22,x8  // h+=X[i]
  .long 0xcadb4a10                  // eor x16,x16,x27, ror #18
  .long 0xcaca21ef                  // eor x15,x15,x10, ror #8
  .long 0xaa1c0231                  // orr x17,x17,x28  // Ch(e,f,g)
  .long 0xca1802fc                  // eor x28,x23,x24  // a^b, b^c in next round
  .long 0xcadba610                  // eor x16,x16,x27, ror #41  // Sigma1(e)
  .long 0xcad78800                  // eor x0,x0,x23, ror #34
  .long 0x8b1102d6                  // add x22,x22,x17  // h+=Ch(e,f,g)
  .long 0x8a1c0273                  // and x19,x19,x28  // (b^c)&=(a^b)
  .long 0xcac7f5ce                  // eor x14,x14,x7, ror #61
  .long 0xca4a1def                  // eor x15,x15,x10, lsr #7  // sigma0(X[i+1])
  .long 0x8b1002d6                  // add x22,x22,x16  // h+=Sigma1(e)
  .long 0xca180273                  // eor x19,x19,x24  // Maj(a,b,c)
  .long 0xcad79c11                  // eor x17,x0,x23, ror #39  // Sigma0(a)
  .long 0xca4719ce                  // eor x14,x14,x7, lsr #6  // sigma1(X[i+14])
  .long 0x8b020129                  // add x9,x9,x2
  .long 0x8b16035a                  // add x26,x26,x22  // d+=h
  .long 0x8b1302d6                  // add x22,x22,x19  // h+=Maj(a,b,c)
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++, x28 in next round
  .long 0x8b0f0129                  // add x9,x9,x15
  .long 0x8b1102d6                  // add x22,x22,x17  // h+=Sigma0(a)
  .long 0x8b0e0129                  // add x9,x9,x14
  .long 0xf9400fee                  // ldr x14,[sp,#24]
  .long 0xf9000be1                  // str x1,[sp,#16]
  .long 0x93da3b50                  // ror x16,x26,#14
  .long 0x8b1302b5                  // add x21,x21,x19  // h+=K[i]
  .long 0x93cb0560                  // ror x0,x11,#1
  .long 0x8a1a0371                  // and x17,x27,x26
  .long 0x93c84d0f                  // ror x15,x8,#19
  .long 0x8a3a0293                  // bic x19,x20,x26
  .long 0x93d672c1                  // ror x1,x22,#28
  .long 0x8b0902b5                  // add x21,x21,x9  // h+=X[i]
  .long 0xcada4a10                  // eor x16,x16,x26, ror #18
  .long 0xcacb2000                  // eor x0,x0,x11, ror #8
  .long 0xaa130231                  // orr x17,x17,x19  // Ch(e,f,g)
  .long 0xca1702d3                  // eor x19,x22,x23  // a^b, b^c in next round
  .long 0xcadaa610                  // eor x16,x16,x26, ror #41  // Sigma1(e)
  .long 0xcad68821                  // eor x1,x1,x22, ror #34
  .long 0x8b1102b5                  // add x21,x21,x17  // h+=Ch(e,f,g)
  .long 0x8a13039c                  // and x28,x28,x19  // (b^c)&=(a^b)
  .long 0xcac8f5ef                  // eor x15,x15,x8, ror #61
  .long 0xca4b1c00                  // eor x0,x0,x11, lsr #7  // sigma0(X[i+1])
  .long 0x8b1002b5                  // add x21,x21,x16  // h+=Sigma1(e)
  .long 0xca17039c                  // eor x28,x28,x23  // Maj(a,b,c)
  .long 0xcad69c31                  // eor x17,x1,x22, ror #39  // Sigma0(a)
  .long 0xca4819ef                  // eor x15,x15,x8, lsr #6  // sigma1(X[i+14])
  .long 0x8b03014a                  // add x10,x10,x3
  .long 0x8b150339                  // add x25,x25,x21  // d+=h
  .long 0x8b1c02b5                  // add x21,x21,x28  // h+=Maj(a,b,c)
  .long 0xf84087dc                  // ldr x28,[x30],#8  // *K++, x19 in next round
  .long 0x8b00014a                  // add x10,x10,x0
  .long 0x8b1102b5                  // add x21,x21,x17  // h+=Sigma0(a)
  .long 0x8b0f014a                  // add x10,x10,x15
  .long 0xf94003ef                  // ldr x15,[sp,#0]
  .long 0xf9000fe2                  // str x2,[sp,#24]
  .long 0x93d93b30                  // ror x16,x25,#14
  .long 0x8b1c0294                  // add x20,x20,x28  // h+=K[i]
  .long 0x93cc0581                  // ror x1,x12,#1
  .long 0x8a190351                  // and x17,x26,x25
  .long 0x93c94d20                  // ror x0,x9,#19
  .long 0x8a39037c                  // bic x28,x27,x25
  .long 0x93d572a2                  // ror x2,x21,#28
  .long 0x8b0a0294                  // add x20,x20,x10  // h+=X[i]
  .long 0xcad94a10                  // eor x16,x16,x25, ror #18
  .long 0xcacc2021                  // eor x1,x1,x12, ror #8
  .long 0xaa1c0231                  // orr x17,x17,x28  // Ch(e,f,g)
  .long 0xca1602bc                  // eor x28,x21,x22  // a^b, b^c in next round
  .long 0xcad9a610                  // eor x16,x16,x25, ror #41  // Sigma1(e)
  .long 0xcad58842                  // eor x2,x2,x21, ror #34
  .long 0x8b110294                  // add x20,x20,x17  // h+=Ch(e,f,g)
  .long 0x8a1c0273                  // and x19,x19,x28  // (b^c)&=(a^b)
  .long 0xcac9f400                  // eor x0,x0,x9, ror #61
  .long 0xca4c1c21                  // eor x1,x1,x12, lsr #7  // sigma0(X[i+1])
  .long 0x8b100294                  // add x20,x20,x16  // h+=Sigma1(e)
  .long 0xca160273                  // eor x19,x19,x22  // Maj(a,b,c)
  .long 0xcad59c51                  // eor x17,x2,x21, ror #39  // Sigma0(a)
  .long 0xca491800                  // eor x0,x0,x9, lsr #6  // sigma1(X[i+14])
  .long 0x8b04016b                  // add x11,x11,x4
  .long 0x8b140318                  // add x24,x24,x20  // d+=h
  .long 0x8b130294                  // add x20,x20,x19  // h+=Maj(a,b,c)
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++, x28 in next round
  .long 0x8b01016b                  // add x11,x11,x1
  .long 0x8b110294                  // add x20,x20,x17  // h+=Sigma0(a)
  .long 0x8b00016b                  // add x11,x11,x0
  .long 0xf94007e0                  // ldr x0,[sp,#8]
  .long 0xf90003e3                  // str x3,[sp,#0]
  .long 0x93d83b10                  // ror x16,x24,#14
  .long 0x8b13037b                  // add x27,x27,x19  // h+=K[i]
  .long 0x93cd05a2                  // ror x2,x13,#1
  .long 0x8a180331                  // and x17,x25,x24
  .long 0x93ca4d41                  // ror x1,x10,#19
  .long 0x8a380353                  // bic x19,x26,x24
  .long 0x93d47283                  // ror x3,x20,#28
  .long 0x8b0b037b                  // add x27,x27,x11  // h+=X[i]
  .long 0xcad84a10                  // eor x16,x16,x24, ror #18
  .long 0xcacd2042                  // eor x2,x2,x13, ror #8
  .long 0xaa130231                  // orr x17,x17,x19  // Ch(e,f,g)
  .long 0xca150293                  // eor x19,x20,x21  // a^b, b^c in next round
  .long 0xcad8a610                  // eor x16,x16,x24, ror #41  // Sigma1(e)
  .long 0xcad48863                  // eor x3,x3,x20, ror #34
  .long 0x8b11037b                  // add x27,x27,x17  // h+=Ch(e,f,g)
  .long 0x8a13039c                  // and x28,x28,x19  // (b^c)&=(a^b)
  .long 0xcacaf421                  // eor x1,x1,x10, ror #61
  .long 0xca4d1c42                  // eor x2,x2,x13, lsr #7  // sigma0(X[i+1])
  .long 0x8b10037b                  // add x27,x27,x16  // h+=Sigma1(e)
  .long 0xca15039c                  // eor x28,x28,x21  // Maj(a,b,c)
  .long 0xcad49c71                  // eor x17,x3,x20, ror #39  // Sigma0(a)
  .long 0xca4a1821                  // eor x1,x1,x10, lsr #6  // sigma1(X[i+14])
  .long 0x8b05018c                  // add x12,x12,x5
  .long 0x8b1b02f7                  // add x23,x23,x27  // d+=h
  .long 0x8b1c037b                  // add x27,x27,x28  // h+=Maj(a,b,c)
  .long 0xf84087dc                  // ldr x28,[x30],#8  // *K++, x19 in next round
  .long 0x8b02018c                  // add x12,x12,x2
  .long 0x8b11037b                  // add x27,x27,x17  // h+=Sigma0(a)
  .long 0x8b01018c                  // add x12,x12,x1
  .long 0xf9400be1                  // ldr x1,[sp,#16]
  .long 0xf90007e4                  // str x4,[sp,#8]
  .long 0x93d73af0                  // ror x16,x23,#14
  .long 0x8b1c035a                  // add x26,x26,x28  // h+=K[i]
  .long 0x93ce05c3                  // ror x3,x14,#1
  .long 0x8a170311                  // and x17,x24,x23
  .long 0x93cb4d62                  // ror x2,x11,#19
  .long 0x8a37033c                  // bic x28,x25,x23
  .long 0x93db7364                  // ror x4,x27,#28
  .long 0x8b0c035a                  // add x26,x26,x12  // h+=X[i]
  .long 0xcad74a10                  // eor x16,x16,x23, ror #18
  .long 0xcace2063                  // eor x3,x3,x14, ror #8
  .long 0xaa1c0231                  // orr x17,x17,x28  // Ch(e,f,g)
  .long 0xca14037c                  // eor x28,x27,x20  // a^b, b^c in next round
  .long 0xcad7a610                  // eor x16,x16,x23, ror #41  // Sigma1(e)
  .long 0xcadb8884                  // eor x4,x4,x27, ror #34
  .long 0x8b11035a                  // add x26,x26,x17  // h+=Ch(e,f,g)
  .long 0x8a1c0273                  // and x19,x19,x28  // (b^c)&=(a^b)
  .long 0xcacbf442                  // eor x2,x2,x11, ror #61
  .long 0xca4e1c63                  // eor x3,x3,x14, lsr #7  // sigma0(X[i+1])
  .long 0x8b10035a                  // add x26,x26,x16  // h+=Sigma1(e)
  .long 0xca140273                  // eor x19,x19,x20  // Maj(a,b,c)
  .long 0xcadb9c91                  // eor x17,x4,x27, ror #39  // Sigma0(a)
  .long 0xca4b1842                  // eor x2,x2,x11, lsr #6  // sigma1(X[i+14])
  .long 0x8b0601ad                  // add x13,x13,x6
  .long 0x8b1a02d6                  // add x22,x22,x26  // d+=h
  .long 0x8b13035a                  // add x26,x26,x19  // h+=Maj(a,b,c)
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++, x28 in next round
  .long 0x8b0301ad                  // add x13,x13,x3
  .long 0x8b11035a                  // add x26,x26,x17  // h+=Sigma0(a)
  .long 0x8b0201ad                  // add x13,x13,x2
  .long 0xf9400fe2                  // ldr x2,[sp,#24]
  .long 0xf9000be5                  // str x5,[sp,#16]
  .long 0x93d63ad0                  // ror x16,x22,#14
  .long 0x8b130339                  // add x25,x25,x19  // h+=K[i]
  .long 0x93cf05e4                  // ror x4,x15,#1
  .long 0x8a1602f1                  // and x17,x23,x22
  .long 0x93cc4d83                  // ror x3,x12,#19
  .long 0x8a360313                  // bic x19,x24,x22
  .long 0x93da7345                  // ror x5,x26,#28
  .long 0x8b0d0339                  // add x25,x25,x13  // h+=X[i]
  .long 0xcad64a10                  // eor x16,x16,x22, ror #18
  .long 0xcacf2084                  // eor x4,x4,x15, ror #8
  .long 0xaa130231                  // orr x17,x17,x19  // Ch(e,f,g)
  .long 0xca1b0353                  // eor x19,x26,x27  // a^b, b^c in next round
  .long 0xcad6a610                  // eor x16,x16,x22, ror #41  // Sigma1(e)
  .long 0xcada88a5                  // eor x5,x5,x26, ror #34
  .long 0x8b110339                  // add x25,x25,x17  // h+=Ch(e,f,g)
  .long 0x8a13039c                  // and x28,x28,x19  // (b^c)&=(a^b)
  .long 0xcaccf463                  // eor x3,x3,x12, ror #61
  .long 0xca4f1c84                  // eor x4,x4,x15, lsr #7  // sigma0(X[i+1])
  .long 0x8b100339                  // add x25,x25,x16  // h+=Sigma1(e)
  .long 0xca1b039c                  // eor x28,x28,x27  // Maj(a,b,c)
  .long 0xcada9cb1                  // eor x17,x5,x26, ror #39  // Sigma0(a)
  .long 0xca4c1863                  // eor x3,x3,x12, lsr #6  // sigma1(X[i+14])
  .long 0x8b0701ce                  // add x14,x14,x7
  .long 0x8b1902b5                  // add x21,x21,x25  // d+=h
  .long 0x8b1c0339                  // add x25,x25,x28  // h+=Maj(a,b,c)
  .long 0xf84087dc                  // ldr x28,[x30],#8  // *K++, x19 in next round
  .long 0x8b0401ce                  // add x14,x14,x4
  .long 0x8b110339                  // add x25,x25,x17  // h+=Sigma0(a)
  .long 0x8b0301ce                  // add x14,x14,x3
  .long 0xf94003e3                  // ldr x3,[sp,#0]
  .long 0xf9000fe6                  // str x6,[sp,#24]
  .long 0x93d53ab0                  // ror x16,x21,#14
  .long 0x8b1c0318                  // add x24,x24,x28  // h+=K[i]
  .long 0x93c00405                  // ror x5,x0,#1
  .long 0x8a1502d1                  // and x17,x22,x21
  .long 0x93cd4da4                  // ror x4,x13,#19
  .long 0x8a3502fc                  // bic x28,x23,x21
  .long 0x93d97326                  // ror x6,x25,#28
  .long 0x8b0e0318                  // add x24,x24,x14  // h+=X[i]
  .long 0xcad54a10                  // eor x16,x16,x21, ror #18
  .long 0xcac020a5                  // eor x5,x5,x0, ror #8
  .long 0xaa1c0231                  // orr x17,x17,x28  // Ch(e,f,g)
  .long 0xca1a033c                  // eor x28,x25,x26  // a^b, b^c in next round
  .long 0xcad5a610                  // eor x16,x16,x21, ror #41  // Sigma1(e)
  .long 0xcad988c6                  // eor x6,x6,x25, ror #34
  .long 0x8b110318                  // add x24,x24,x17  // h+=Ch(e,f,g)
  .long 0x8a1c0273                  // and x19,x19,x28  // (b^c)&=(a^b)
  .long 0xcacdf484                  // eor x4,x4,x13, ror #61
  .long 0xca401ca5                  // eor x5,x5,x0, lsr #7  // sigma0(X[i+1])
  .long 0x8b100318                  // add x24,x24,x16  // h+=Sigma1(e)
  .long 0xca1a0273                  // eor x19,x19,x26  // Maj(a,b,c)
  .long 0xcad99cd1                  // eor x17,x6,x25, ror #39  // Sigma0(a)
  .long 0xca4d1884                  // eor x4,x4,x13, lsr #6  // sigma1(X[i+14])
  .long 0x8b0801ef                  // add x15,x15,x8
  .long 0x8b180294                  // add x20,x20,x24  // d+=h
  .long 0x8b130318                  // add x24,x24,x19  // h+=Maj(a,b,c)
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++, x28 in next round
  .long 0x8b0501ef                  // add x15,x15,x5
  .long 0x8b110318                  // add x24,x24,x17  // h+=Sigma0(a)
  .long 0x8b0401ef                  // add x15,x15,x4
  .long 0xf94007e4                  // ldr x4,[sp,#8]
  .long 0xf90003e7                  // str x7,[sp,#0]
  .long 0x93d43a90                  // ror x16,x20,#14
  .long 0x8b1302f7                  // add x23,x23,x19  // h+=K[i]
  .long 0x93c10426                  // ror x6,x1,#1
  .long 0x8a1402b1                  // and x17,x21,x20
  .long 0x93ce4dc5                  // ror x5,x14,#19
  .long 0x8a3402d3                  // bic x19,x22,x20
  .long 0x93d87307                  // ror x7,x24,#28
  .long 0x8b0f02f7                  // add x23,x23,x15  // h+=X[i]
  .long 0xcad44a10                  // eor x16,x16,x20, ror #18
  .long 0xcac120c6                  // eor x6,x6,x1, ror #8
  .long 0xaa130231                  // orr x17,x17,x19  // Ch(e,f,g)
  .long 0xca190313                  // eor x19,x24,x25  // a^b, b^c in next round
  .long 0xcad4a610                  // eor x16,x16,x20, ror #41  // Sigma1(e)
  .long 0xcad888e7                  // eor x7,x7,x24, ror #34
  .long 0x8b1102f7                  // add x23,x23,x17  // h+=Ch(e,f,g)
  .long 0x8a13039c                  // and x28,x28,x19  // (b^c)&=(a^b)
  .long 0xcacef4a5                  // eor x5,x5,x14, ror #61
  .long 0xca411cc6                  // eor x6,x6,x1, lsr #7  // sigma0(X[i+1])
  .long 0x8b1002f7                  // add x23,x23,x16  // h+=Sigma1(e)
  .long 0xca19039c                  // eor x28,x28,x25  // Maj(a,b,c)
  .long 0xcad89cf1                  // eor x17,x7,x24, ror #39  // Sigma0(a)
  .long 0xca4e18a5                  // eor x5,x5,x14, lsr #6  // sigma1(X[i+14])
  .long 0x8b090000                  // add x0,x0,x9
  .long 0x8b17037b                  // add x27,x27,x23  // d+=h
  .long 0x8b1c02f7                  // add x23,x23,x28  // h+=Maj(a,b,c)
  .long 0xf84087dc                  // ldr x28,[x30],#8  // *K++, x19 in next round
  .long 0x8b060000                  // add x0,x0,x6
  .long 0x8b1102f7                  // add x23,x23,x17  // h+=Sigma0(a)
  .long 0x8b050000                  // add x0,x0,x5
  .long 0xf9400be5                  // ldr x5,[sp,#16]
  .long 0xf90007e8                  // str x8,[sp,#8]
  .long 0x93db3b70                  // ror x16,x27,#14
  .long 0x8b1c02d6                  // add x22,x22,x28  // h+=K[i]
  .long 0x93c20447                  // ror x7,x2,#1
  .long 0x8a1b0291                  // and x17,x20,x27
  .long 0x93cf4de6                  // ror x6,x15,#19
  .long 0x8a3b02bc                  // bic x28,x21,x27
  .long 0x93d772e8                  // ror x8,x23,#28
  .long 0x8b0002d6                  // add x22,x22,x0  // h+=X[i]
  .long 0xcadb4a10                  // eor x16,x16,x27, ror #18
  .long 0xcac220e7                  // eor x7,x7,x2, ror #8
  .long 0xaa1c0231                  // orr x17,x17,x28  // Ch(e,f,g)
  .long 0xca1802fc                  // eor x28,x23,x24  // a^b, b^c in next round
  .long 0xcadba610                  // eor x16,x16,x27, ror #41  // Sigma1(e)
  .long 0xcad78908                  // eor x8,x8,x23, ror #34
  .long 0x8b1102d6                  // add x22,x22,x17  // h+=Ch(e,f,g)
  .long 0x8a1c0273                  // and x19,x19,x28  // (b^c)&=(a^b)
  .long 0xcacff4c6                  // eor x6,x6,x15, ror #61
  .long 0xca421ce7                  // eor x7,x7,x2, lsr #7  // sigma0(X[i+1])
  .long 0x8b1002d6                  // add x22,x22,x16  // h+=Sigma1(e)
  .long 0xca180273                  // eor x19,x19,x24  // Maj(a,b,c)
  .long 0xcad79d11                  // eor x17,x8,x23, ror #39  // Sigma0(a)
  .long 0xca4f18c6                  // eor x6,x6,x15, lsr #6  // sigma1(X[i+14])
  .long 0x8b0a0021                  // add x1,x1,x10
  .long 0x8b16035a                  // add x26,x26,x22  // d+=h
  .long 0x8b1302d6                  // add x22,x22,x19  // h+=Maj(a,b,c)
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++, x28 in next round
  .long 0x8b070021                  // add x1,x1,x7
  .long 0x8b1102d6                  // add x22,x22,x17  // h+=Sigma0(a)
  .long 0x8b060021                  // add x1,x1,x6
  .long 0xf9400fe6                  // ldr x6,[sp,#24]
  .long 0xf9000be9                  // str x9,[sp,#16]
  .long 0x93da3b50                  // ror x16,x26,#14
  .long 0x8b1302b5                  // add x21,x21,x19  // h+=K[i]
  .long 0x93c30468                  // ror x8,x3,#1
  .long 0x8a1a0371                  // and x17,x27,x26
  .long 0x93c04c07                  // ror x7,x0,#19
  .long 0x8a3a0293                  // bic x19,x20,x26
  .long 0x93d672c9                  // ror x9,x22,#28
  .long 0x8b0102b5                  // add x21,x21,x1  // h+=X[i]
  .long 0xcada4a10                  // eor x16,x16,x26, ror #18
  .long 0xcac32108                  // eor x8,x8,x3, ror #8
  .long 0xaa130231                  // orr x17,x17,x19  // Ch(e,f,g)
  .long 0xca1702d3                  // eor x19,x22,x23  // a^b, b^c in next round
  .long 0xcadaa610                  // eor x16,x16,x26, ror #41  // Sigma1(e)
  .long 0xcad68929                  // eor x9,x9,x22, ror #34
  .long 0x8b1102b5                  // add x21,x21,x17  // h+=Ch(e,f,g)
  .long 0x8a13039c                  // and x28,x28,x19  // (b^c)&=(a^b)
  .long 0xcac0f4e7                  // eor x7,x7,x0, ror #61
  .long 0xca431d08                  // eor x8,x8,x3, lsr #7  // sigma0(X[i+1])
  .long 0x8b1002b5                  // add x21,x21,x16  // h+=Sigma1(e)
  .long 0xca17039c                  // eor x28,x28,x23  // Maj(a,b,c)
  .long 0xcad69d31                  // eor x17,x9,x22, ror #39  // Sigma0(a)
  .long 0xca4018e7                  // eor x7,x7,x0, lsr #6  // sigma1(X[i+14])
  .long 0x8b0b0042                  // add x2,x2,x11
  .long 0x8b150339                  // add x25,x25,x21  // d+=h
  .long 0x8b1c02b5                  // add x21,x21,x28  // h+=Maj(a,b,c)
  .long 0xf84087dc                  // ldr x28,[x30],#8  // *K++, x19 in next round
  .long 0x8b080042                  // add x2,x2,x8
  .long 0x8b1102b5                  // add x21,x21,x17  // h+=Sigma0(a)
  .long 0x8b070042                  // add x2,x2,x7
  .long 0xf94003e7                  // ldr x7,[sp,#0]
  .long 0xf9000fea                  // str x10,[sp,#24]
  .long 0x93d93b30                  // ror x16,x25,#14
  .long 0x8b1c0294                  // add x20,x20,x28  // h+=K[i]
  .long 0x93c40489                  // ror x9,x4,#1
  .long 0x8a190351                  // and x17,x26,x25
  .long 0x93c14c28                  // ror x8,x1,#19
  .long 0x8a39037c                  // bic x28,x27,x25
  .long 0x93d572aa                  // ror x10,x21,#28
  .long 0x8b020294                  // add x20,x20,x2  // h+=X[i]
  .long 0xcad94a10                  // eor x16,x16,x25, ror #18
  .long 0xcac42129                  // eor x9,x9,x4, ror #8
  .long 0xaa1c0231                  // orr x17,x17,x28  // Ch(e,f,g)
  .long 0xca1602bc                  // eor x28,x21,x22  // a^b, b^c in next round
  .long 0xcad9a610                  // eor x16,x16,x25, ror #41  // Sigma1(e)
  .long 0xcad5894a                  // eor x10,x10,x21, ror #34
  .long 0x8b110294                  // add x20,x20,x17  // h+=Ch(e,f,g)
  .long 0x8a1c0273                  // and x19,x19,x28  // (b^c)&=(a^b)
  .long 0xcac1f508                  // eor x8,x8,x1, ror #61
  .long 0xca441d29                  // eor x9,x9,x4, lsr #7  // sigma0(X[i+1])
  .long 0x8b100294                  // add x20,x20,x16  // h+=Sigma1(e)
  .long 0xca160273                  // eor x19,x19,x22  // Maj(a,b,c)
  .long 0xcad59d51                  // eor x17,x10,x21, ror #39  // Sigma0(a)
  .long 0xca411908                  // eor x8,x8,x1, lsr #6  // sigma1(X[i+14])
  .long 0x8b0c0063                  // add x3,x3,x12
  .long 0x8b140318                  // add x24,x24,x20  // d+=h
  .long 0x8b130294                  // add x20,x20,x19  // h+=Maj(a,b,c)
  .long 0xf84087d3                  // ldr x19,[x30],#8  // *K++, x28 in next round
  .long 0x8b090063                  // add x3,x3,x9
  .long 0x8b110294                  // add x20,x20,x17  // h+=Sigma0(a)
  .long 0x8b080063                  // add x3,x3,x8
  cbnz	x19,.Lsha512_gpr_loop_16_xx

  .long 0xa9460ba0                  // ldp x0,x2,[x29,#96]
  .long 0xf9403ba1                  // ldr x1,[x29,#112]
  .long 0xd10a23de                  // sub x30,x30,#648  // rewind

  .long 0xa9401003                  // ldp x3,x4,[x0]
  .long 0xa9411805                  // ldp x5,x6,[x0,#2*8]
  .long 0x9101c021                  // add x1,x1,#14*8  // advance input pointer
  .long 0xa9422007                  // ldp x7,x8,[x0,#4*8]
  .long 0x8b030294                  // add x20,x20,x3
  .long 0xa9432809                  // ldp x9,x10,[x0,#6*8]
  .long 0x8b0402b5                  // add x21,x21,x4
  .long 0x8b0502d6                  // add x22,x22,x5
  .long 0x8b0602f7                  // add x23,x23,x6
  .long 0xa9005414                  // stp x20,x21,[x0]
  .long 0x8b070318                  // add x24,x24,x7
  .long 0x8b080339                  // add x25,x25,x8
  .long 0xa9015c16                  // stp x22,x23,[x0,#2*8]
  .long 0x8b09035a                  // add x26,x26,x9
  .long 0x8b0a037b                  // add x27,x27,x10
  .long 0xeb02003f                  // cmp x1,x2
  .long 0xa9026418                  // stp x24,x25,[x0,#4*8]
  .long 0xa9036c1a                  // stp x26,x27,[x0,#6*8]
  b.ne	.Lsha512_gpr_loop

  .long 0xa94153b3                  // ldp x19,x20,[x29,#16]
  .long 0x910083ff                  // add sp,sp,#4*8
  .long 0xa9425bb5                  // ldp x21,x22,[x29,#32]
  .long 0xa94363b7                  // ldp x23,x24,[x29,#48]
  .long 0xa9446bb9                  // ldp x25,x26,[x29,#64]
  .long 0xa94573bb                  // ldp x27,x28,[x29,#80]
  .long 0xa8c87bfd                  // ldp x29,x30,[sp],#128
  ret
