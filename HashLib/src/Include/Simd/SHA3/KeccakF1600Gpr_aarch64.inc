// Keccak-f[1600] pure-GPR permutation (AArch64) for cores without FEAT_SHA3;
// the Gpr name states the ISA requirement: none beyond base AArch64. The 25
// lanes live in x0-x17/x19-x25 with x26-x28/x30 as temps; chi is computed
// directly with bic, so no lane complementing exists in this lineage.
// Expects AAPCS64 (after HlpSimdProc2Begin_aarch64): x0 = AState
//   (25 x UInt64, standard layout), x1 = AConstants (iotas: 24 x UInt64).
// The original round loop ended on a 256-ALIGNED iotas table (tst #255),
// which a Pascal const cannot guarantee - the termination is patched to an
// end-pointer compare (iotas end stashed at [sp,#40]; the Iota xor is
// hoisted to free x30 for the test; the intervening bic/eor stream writes
// no flags, so the b.ne polarity is unchanged).
// The inner keeps the original called shape (bl/ret); x30 (LR) doubles as a
// temp inside the rounds, as in the original.
// AArch64 instructions are .long-encoded for broad assembler compatibility.
// Reference: OpenSSL CRYPTOGAMS keccak1600-armv8.pl (KeccakF1600 +
// KeccakF1600_int, the plain path) by Andy Polyakov.

  .long 0xa9b87bfd                  // stp x29,x30,[sp,#-128]!
  .long 0x910003fd                  // add x29,sp,#0
  .long 0xa90153f3                  // stp x19,x20,[sp,#16]
  .long 0xa9025bf5                  // stp x21,x22,[sp,#32]
  .long 0xa90363f7                  // stp x23,x24,[sp,#48]
  .long 0xa9046bf9                  // stp x25,x26,[sp,#64]
  .long 0xa90573fb                  // stp x27,x28,[sp,#80]
  .long 0xd100c3ff                  // sub sp,sp,#48
  .long 0x91030021                  // add x1,x1,#192  // iotas end = AConstants + 24*8
  .long 0xf90017e1                  // str x1,[sp,#40]  // stashed for the inner (frame slot is free)

  .long 0xf90013e0                  // str x0,[sp,#32]  // offload argument
  .long 0xaa0003fa                  // mov x26,x0
  .long 0xa9400400                  // ldp x0,x1,[x0,#16*0]
  .long 0xa9410f42                  // ldp x2,x3,[x26,#16*1]
  .long 0xa9421744                  // ldp x4,x5,[x26,#16*2]
  .long 0xa9431f46                  // ldp x6,x7,[x26,#16*3]
  .long 0xa9442748                  // ldp x8,x9,[x26,#16*4]
  .long 0xa9452f4a                  // ldp x10,x11,[x26,#16*5]
  .long 0xa946374c                  // ldp x12,x13,[x26,#16*6]
  .long 0xa9473f4e                  // ldp x14,x15,[x26,#16*7]
  .long 0xa9484750                  // ldp x16,x17,[x26,#16*8]
  .long 0xa9494f59                  // ldp x25,x19,[x26,#16*9]
  .long 0xa94a5754                  // ldp x20,x21,[x26,#16*10]
  .long 0xa94b5f56                  // ldp x22,x23,[x26,#16*11]
  .long 0xf9406358                  // ldr x24,[x26,#16*12]

  bl	.Lkeccak_gpr_int

  .long 0xf94013fa                  // ldr x26,[sp,#32]
  .long 0xa9000740                  // stp x0,x1,[x26,#16*0]
  .long 0xa9010f42                  // stp x2,x3,[x26,#16*1]
  .long 0xa9021744                  // stp x4,x5,[x26,#16*2]
  .long 0xa9031f46                  // stp x6,x7,[x26,#16*3]
  .long 0xa9042748                  // stp x8,x9,[x26,#16*4]
  .long 0xa9052f4a                  // stp x10,x11,[x26,#16*5]
  .long 0xa906374c                  // stp x12,x13,[x26,#16*6]
  .long 0xa9073f4e                  // stp x14,x15,[x26,#16*7]
  .long 0xa9084750                  // stp x16,x17,[x26,#16*8]
  .long 0xa9094f59                  // stp x25,x19,[x26,#16*9]
  .long 0xa90a5754                  // stp x20,x21,[x26,#16*10]
  .long 0xa90b5f56                  // stp x22,x23,[x26,#16*11]
  .long 0xf9006358                  // str x24,[x26,#16*12]

  .long 0xa94153b3                  // ldp x19,x20,[x29,#16]
  .long 0x9100c3ff                  // add sp,sp,#48
  .long 0xa9425bb5                  // ldp x21,x22,[x29,#32]
  .long 0xa94363b7                  // ldp x23,x24,[x29,#48]
  .long 0xa9446bb9                  // ldp x25,x26,[x29,#64]
  .long 0xa94573bb                  // ldp x27,x28,[x29,#80]
  .long 0xa8c87bfd                  // ldp x29,x30,[sp],#128
  ret


.Lkeccak_gpr_int:
  .long 0xf94017fc                  // ldr x28,[sp,#40]  // iotas end (stashed by the wrapper)
  .long 0xd103039c                  // sub x28,x28,#192  // iotas base (24 x 8)
  .long 0xa9017bfc                  // stp x28,x30,[sp,#16]  // 32 bytes on top are mine
  b	.Lkeccak_gpr_loop

.Lkeccak_gpr_loop:
  ////////////////////////////////////////// Theta
  .long 0xca05001a                  // eor x26,x0,x5
  .long 0xa90027e4                  // stp x4,x9,[sp,#0]  // offload pair...
  .long 0xca06003b                  // eor x27,x1,x6
  .long 0xca07005c                  // eor x28,x2,x7
  .long 0xca08007e                  // eor x30,x3,x8
  .long 0xca090084                  // eor x4,x4,x9
  .long 0xca0a035a                  // eor x26,x26,x10
  .long 0xca0b037b                  // eor x27,x27,x11
  .long 0xca0c039c                  // eor x28,x28,x12
  .long 0xca0d03de                  // eor x30,x30,x13
  .long 0xca0e0084                  // eor x4,x4,x14
  .long 0xca0f035a                  // eor x26,x26,x15
  .long 0xca10037b                  // eor x27,x27,x16
  .long 0xca11039c                  // eor x28,x28,x17
  .long 0xca1903de                  // eor x30,x30,x25
  .long 0xca130084                  // eor x4,x4,x19
  .long 0xca14035a                  // eor x26,x26,x20
  .long 0xca16039c                  // eor x28,x28,x22
  .long 0xca15037b                  // eor x27,x27,x21
  .long 0xca1703de                  // eor x30,x30,x23
  .long 0xca180084                  // eor x4,x4,x24

  .long 0xcadcff49                  // eor x9,x26,x28, ror #63

  .long 0xca090021                  // eor x1,x1,x9
  .long 0xca0900c6                  // eor x6,x6,x9
  .long 0xca09016b                  // eor x11,x11,x9
  .long 0xca090210                  // eor x16,x16,x9
  .long 0xca0902b5                  // eor x21,x21,x9

  .long 0xcadeff69                  // eor x9,x27,x30, ror #63
  .long 0xcac4ff9c                  // eor x28,x28,x4, ror #63
  .long 0xcadaffde                  // eor x30,x30,x26, ror #63
  .long 0xcadbfc84                  // eor x4,x4,x27, ror #63

  .long 0xca09005b                  // eor x27, x2,x9  // mov	x27,x2
  .long 0xca0900e7                  // eor x7,x7,x9
  .long 0xca09018c                  // eor x12,x12,x9
  .long 0xca090231                  // eor x17,x17,x9
  .long 0xca0902d6                  // eor x22,x22,x9

  .long 0xca040000                  // eor x0,x0,x4
  .long 0xca0400a5                  // eor x5,x5,x4
  .long 0xca04014a                  // eor x10,x10,x4
  .long 0xca0401ef                  // eor x15,x15,x4
  .long 0xca040294                  // eor x20,x20,x4
  .long 0xa94027e4                  // ldp x4,x9,[sp,#0]  // re-load offloaded data
  .long 0xca1c007a                  // eor x26, x3,x28  // mov	x26,x3
  .long 0xca1c0108                  // eor x8,x8,x28
  .long 0xca1c01ad                  // eor x13,x13,x28
  .long 0xca1c0339                  // eor x25,x25,x28
  .long 0xca1c02f7                  // eor x23,x23,x28

  .long 0xca1e009c                  // eor x28, x4,x30  // mov	x28,x4
  .long 0xca1e0129                  // eor x9,x9,x30
  .long 0xca1e01ce                  // eor x14,x14,x30
  .long 0xca1e0273                  // eor x19,x19,x30
  .long 0xca1e0318                  // eor x24,x24,x30

  ////////////////////////////////////////// Rho+Pi
  .long 0xaa0103fe                  // mov x30,x1
  .long 0x93c650c1                  // ror x1,x6,#64-44
  //mov	x27,x2
  .long 0x93cc5582                  // ror x2,x12,#64-43
  //mov	x26,x3
  .long 0x93d9af23                  // ror x3,x25,#64-21
  //mov	x28,x4
  .long 0x93d8cb04                  // ror x4,x24,#64-14

  .long 0x93c9b126                  // ror x6,x9,#64-20
  .long 0x93cd9dac                  // ror x12,x13,#64-25
  .long 0x93d1c639                  // ror x25,x17,#64-15
  .long 0x93d5fab8                  // ror x24,x21,#64-2

  .long 0x93d60ec9                  // ror x9,x22,#64-61
  .long 0x93d3e26d                  // ror x13,x19,#64-8
  .long 0x93cbd971                  // ror x17,x11,#64-10
  .long 0x93c82515                  // ror x21,x8,#64-55

  .long 0x93ce65d6                  // ror x22,x14,#64-39
  .long 0x93d722f3                  // ror x19,x23,#64-56
  .long 0x93c7e8eb                  // ror x11,x7,#64-6
  .long 0x93d04e08                  // ror x8,x16,#64-45

  .long 0x93d4ba8e                  // ror x14,x20,#64-18
  .long 0x93cf5df7                  // ror x23,x15,#64-41
  .long 0x93caf547                  // ror x7,x10,#64-3
  .long 0x93c570b0                  // ror x16,x5,#64-36

  .long 0x93da9345                  // ror x5,x26,#64-28
  .long 0x93deffca                  // ror x10,x30,#64-1
  .long 0x93dc978f                  // ror x15,x28,#64-27
  .long 0x93db0b74                  // ror x20,x27,#64-62

  ////////////////////////////////////////// Chi+Iota
  .long 0x8a21005a                  // bic x26,x2,x1
  .long 0x8a22007b                  // bic x27,x3,x2
  .long 0x8a24001c                  // bic x28,x0,x4
  .long 0x8a20003e                  // bic x30,x1,x0
  .long 0xca1a0000                  // eor x0,x0,x26
  .long 0x8a23009a                  // bic x26,x4,x3
  .long 0xca1b0021                  // eor x1,x1,x27
  .long 0xf9400bfb                  // ldr x27,[sp,#16]
  .long 0xca1c0063                  // eor x3,x3,x28
  .long 0xca1e0084                  // eor x4,x4,x30
  .long 0xca1a0042                  // eor x2,x2,x26
  .long 0xf840877e                  // ldr x30,[x27],#8  // Iota[i++]
  .long 0xca1e0000                  // eor x0,x0,x30  // A[0][0] ^= Iota (hoisted - frees x30 for the end test)

  .long 0x8a2600fa                  // bic x26,x7,x6
  .long 0xf94017fe                  // ldr x30,[sp,#40]  // iotas end
  .long 0xeb1e037f                  // cmp x27,x30  // are we done? (end-pointer test; a Pascal const
  // cannot provide the original's 256-aligned table)
  .long 0xf9000bfb                  // str x27,[sp,#16]
  .long 0x8a27011b                  // bic x27,x8,x7
  .long 0x8a2900bc                  // bic x28,x5,x9
  .long 0x8a2500de                  // bic x30,x6,x5
  .long 0xca1a00a5                  // eor x5,x5,x26
  .long 0x8a28013a                  // bic x26,x9,x8
  .long 0xca1b00c6                  // eor x6,x6,x27
  .long 0xca1c0108                  // eor x8,x8,x28
  .long 0xca1e0129                  // eor x9,x9,x30
  .long 0xca1a00e7                  // eor x7,x7,x26

  .long 0x8a2b019a                  // bic x26,x12,x11
  .long 0x8a2c01bb                  // bic x27,x13,x12
  .long 0x8a2e015c                  // bic x28,x10,x14
  .long 0x8a2a017e                  // bic x30,x11,x10
  .long 0xca1a014a                  // eor x10,x10,x26
  .long 0x8a2d01da                  // bic x26,x14,x13
  .long 0xca1b016b                  // eor x11,x11,x27
  .long 0xca1c01ad                  // eor x13,x13,x28
  .long 0xca1e01ce                  // eor x14,x14,x30
  .long 0xca1a018c                  // eor x12,x12,x26

  .long 0x8a30023a                  // bic x26,x17,x16
  .long 0x8a31033b                  // bic x27,x25,x17
  .long 0x8a3301fc                  // bic x28,x15,x19
  .long 0x8a2f021e                  // bic x30,x16,x15
  .long 0xca1a01ef                  // eor x15,x15,x26
  .long 0x8a39027a                  // bic x26,x19,x25
  .long 0xca1b0210                  // eor x16,x16,x27
  .long 0xca1c0339                  // eor x25,x25,x28
  .long 0xca1e0273                  // eor x19,x19,x30
  .long 0xca1a0231                  // eor x17,x17,x26

  .long 0x8a3502da                  // bic x26,x22,x21
  .long 0x8a3602fb                  // bic x27,x23,x22
  .long 0x8a38029c                  // bic x28,x20,x24
  .long 0x8a3402be                  // bic x30,x21,x20
  .long 0xca1a0294                  // eor x20,x20,x26
  .long 0x8a37031a                  // bic x26,x24,x23
  .long 0xca1b02b5                  // eor x21,x21,x27
  .long 0xca1c02f7                  // eor x23,x23,x28
  .long 0xca1e0318                  // eor x24,x24,x30
  .long 0xca1a02d6                  // eor x22,x22,x26

  b.ne	.Lkeccak_gpr_loop

  .long 0xf9400ffe                  // ldr x30,[sp,#24]
  ret
