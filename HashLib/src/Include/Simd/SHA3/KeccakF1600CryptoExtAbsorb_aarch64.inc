// SHA-3 (Keccak-F1600) ARMv8 Crypto Extension (FEAT_SHA3) sponge absorb.
// Expects AAPCS64: x0 = state ptr (25 x UInt64), x1 = data ptr,
//   w2 = numblocks, w3 = blocksize (bytes, = rate), x4 = iotas ptr.
// For each block it XORs blocksize bytes (per 64-bit lane, little-endian)
//   into the low lanes and runs the inlined 24-round permutation, resetting
//   the iota pointer (x4 -> x10) before every permute. The per-lane
//   cmp/b.lo/b.eq dispatch mirrors OpenSSL so any rate <= 200 bytes works;
//   the outer loop counts blocks (HlpSHA3 contract) rather than byte length.
//   v8-v15 (callee-saved d8-d15) are saved/restored; still a leaf (no calls).
// Reference: OpenSSL CRYPTOGAMS keccak1600-armv8.S (SHA3_absorb_cext).
//
// Instruction encodings (for assembler compatibility):
//   FPC 3.2.2's inline assembler cannot encode AArch64 vector/crypto mnemonics
//   (subscripted vector regs and the FEAT_SHA3 ops require FPC 3.3+, and
//   ldp/stp/ldr/str with dN crash the 3.2.2 assembler). Each such instruction
//   is emitted as its raw 32-bit '.long' opcode, with the equivalent mnemonic
//   in the trailing comment; only mov/cmp/sub/cbz/cbnz/b.lo/b.eq/ret stay as
//   text.
//
// Register map:
//   v0-v24   = Keccak state lanes (data is XORed lane-by-lane into v0..)
//   v25-v31  = permutation scratch; v31 also holds each loaded input lane

  .long 0x6dbc27e8                    // stp d8, d9, [sp, #-64]!
  .long 0x6d012fea                    // stp d10, d11, [sp, #16]
  .long 0x6d0237ec                    // stp d12, d13, [sp, #32]
  .long 0x6d033fee                    // stp d14, d15, [sp, #48]
  .long 0x6d400400                    // ldp d0, d1, [x0]
  .long 0x6d410c02                    // ldp d2, d3, [x0, #16]
  .long 0x6d421404                    // ldp d4, d5, [x0, #32]
  .long 0x6d431c06                    // ldp d6, d7, [x0, #48]
  .long 0x6d442408                    // ldp d8, d9, [x0, #64]
  .long 0x6d452c0a                    // ldp d10, d11, [x0, #80]
  .long 0x6d46340c                    // ldp d12, d13, [x0, #96]
  .long 0x6d473c0e                    // ldp d14, d15, [x0, #112]
  .long 0x6d484410                    // ldp d16, d17, [x0, #128]
  .long 0x6d494c12                    // ldp d18, d19, [x0, #144]
  .long 0x6d4a5414                    // ldp d20, d21, [x0, #160]
  .long 0x6d4b5c16                    // ldp d22, d23, [x0, #176]
  .long 0xfd406018                    // ldr d24, [x0, #192]
  cbz w2, .Lcryptoext_keccak_absorbed
.Lcryptoext_keccak_absorb_loop:
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  cmp w3, #16
  b.lo .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  b.eq .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  cmp w3, #32
  b.lo .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  b.eq .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  cmp w3, #48
  b.lo .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  b.eq .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  cmp w3, #64
  b.lo .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
  b.eq .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  cmp w3, #80
  b.lo .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1d29                    // eor v9.16b, v9.16b, v31.16b
  b.eq .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1d4a                    // eor v10.16b, v10.16b, v31.16b
  cmp w3, #96
  b.lo .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1d6b                    // eor v11.16b, v11.16b, v31.16b
  b.eq .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1d8c                    // eor v12.16b, v12.16b, v31.16b
  cmp w3, #112
  b.lo .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1dad                    // eor v13.16b, v13.16b, v31.16b
  b.eq .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1dce                    // eor v14.16b, v14.16b, v31.16b
  cmp w3, #128
  b.lo .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1def                    // eor v15.16b, v15.16b, v31.16b
  b.eq .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1e10                    // eor v16.16b, v16.16b, v31.16b
  cmp w3, #144
  b.lo .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1e31                    // eor v17.16b, v17.16b, v31.16b
  b.eq .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1e52                    // eor v18.16b, v18.16b, v31.16b
  cmp w3, #160
  b.lo .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1e73                    // eor v19.16b, v19.16b, v31.16b
  b.eq .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1e94                    // eor v20.16b, v20.16b, v31.16b
  cmp w3, #176
  b.lo .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1eb5                    // eor v21.16b, v21.16b, v31.16b
  b.eq .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1ed6                    // eor v22.16b, v22.16b, v31.16b
  cmp w3, #192
  b.lo .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1ef7                    // eor v23.16b, v23.16b, v31.16b
  b.eq .Lcryptoext_keccak_permute
  .long 0xfc40843f                    // ldr d31, [x1], #8
  .long 0x6e3f1f18                    // eor v24.16b, v24.16b, v31.16b
.Lcryptoext_keccak_permute:
  mov x10, x4
  mov w9, #24
.Lcryptoext_keccak_absorb_round:
  .long 0xce0f2a99                    // eor3 v25.16b, v20.16b, v15.16b, v10.16b
  .long 0xce102eba                    // eor3 v26.16b, v21.16b, v16.16b, v11.16b
  .long 0xce1132db                    // eor3 v27.16b, v22.16b, v17.16b, v12.16b
  .long 0xce1236fc                    // eor3 v28.16b, v23.16b, v18.16b, v13.16b
  .long 0xce133b1d                    // eor3 v29.16b, v24.16b, v19.16b, v14.16b
  .long 0xce050339                    // eor3 v25.16b, v25.16b, v5.16b, v0.16b
  .long 0xce06075a                    // eor3 v26.16b, v26.16b, v6.16b, v1.16b
  .long 0xce070b7b                    // eor3 v27.16b, v27.16b, v7.16b, v2.16b
  .long 0xce080f9c                    // eor3 v28.16b, v28.16b, v8.16b, v3.16b
  .long 0xce0913bd                    // eor3 v29.16b, v29.16b, v9.16b, v4.16b
  .long 0xce7b8f3e                    // rax1 v30.2d, v25.2d, v27.2d
  .long 0xce7c8f5f                    // rax1 v31.2d, v26.2d, v28.2d
  .long 0xce7d8f7b                    // rax1 v27.2d, v27.2d, v29.2d
  .long 0xce798f9c                    // rax1 v28.2d, v28.2d, v25.2d
  .long 0xce7a8fbd                    // rax1 v29.2d, v29.2d, v26.2d
  .long 0xce9efc39                    // xar v25.2d, v1.2d, v30.2d, #63
  .long 0xce9e50c1                    // xar v1.2d, v6.2d, v30.2d, #20
  .long 0xce9cb126                    // xar v6.2d, v9.2d, v28.2d, #44
  .long 0xce9f0ec9                    // xar v9.2d, v22.2d, v31.2d, #3
  .long 0xce9c65d6                    // xar v22.2d, v14.2d, v28.2d, #25
  .long 0xce9dba8e                    // xar v14.2d, v20.2d, v29.2d, #46
  .long 0xce9f085a                    // xar v26.2d, v2.2d, v31.2d, #2
  .long 0xce9f5582                    // xar v2.2d, v12.2d, v31.2d, #21
  .long 0xce9b9dac                    // xar v12.2d, v13.2d, v27.2d, #39
  .long 0xce9ce26d                    // xar v13.2d, v19.2d, v28.2d, #56
  .long 0xce9b22f3                    // xar v19.2d, v23.2d, v27.2d, #8
  .long 0xce9d5df7                    // xar v23.2d, v15.2d, v29.2d, #23
  .long 0xce9c948f                    // xar v15.2d, v4.2d, v28.2d, #37
  .long 0xce9ccb1c                    // xar v28.2d, v24.2d, v28.2d, #50
  .long 0xce9efab8                    // xar v24.2d, v21.2d, v30.2d, #62
  .long 0xce9b2508                    // xar v8.2d, v8.2d, v27.2d, #9
  .long 0xce9e4e04                    // xar v4.2d, v16.2d, v30.2d, #19
  .long 0xce9d70b0                    // xar v16.2d, v5.2d, v29.2d, #28
  .long 0xce9b9065                    // xar v5.2d, v3.2d, v27.2d, #36
  .long 0x6e3d1c00                    // eor v0.16b, v0.16b, v29.16b
  .long 0xce9bae5b                    // xar v27.2d, v18.2d, v27.2d, #43
  .long 0xce9fc623                    // xar v3.2d, v17.2d, v31.2d, #49
  .long 0xce9ed97e                    // xar v30.2d, v11.2d, v30.2d, #54
  .long 0xce9fe8ff                    // xar v31.2d, v7.2d, v31.2d, #58
  .long 0xce9df55d                    // xar v29.2d, v10.2d, v29.2d, #61
  .long 0xce362354                    // bcax v20.16b, v26.16b, v22.16b, v8.16b
  .long 0xce375915                    // bcax v21.16b, v8.16b, v23.16b, v22.16b
  .long 0xce385ed6                    // bcax v22.16b, v22.16b, v24.16b, v23.16b
  .long 0xce3a62f7                    // bcax v23.16b, v23.16b, v26.16b, v24.16b
  .long 0xce286b18                    // bcax v24.16b, v24.16b, v8.16b, v26.16b
  .long 0x4ddfcd5a                    // ld1r {v26.2d}, [x10], #8
  .long 0xce330fd1                    // bcax v17.16b, v30.16b, v19.16b, v3.16b
  .long 0xce2f4c72                    // bcax v18.16b, v3.16b, v15.16b, v19.16b
  .long 0xce303e73                    // bcax v19.16b, v19.16b, v16.16b, v15.16b
  .long 0xce3e41ef                    // bcax v15.16b, v15.16b, v30.16b, v16.16b
  .long 0xce237a10                    // bcax v16.16b, v16.16b, v3.16b, v30.16b
  .long 0xce2c7f2a                    // bcax v10.16b, v25.16b, v12.16b, v31.16b
  .long 0xce2d33eb                    // bcax v11.16b, v31.16b, v13.16b, v12.16b
  .long 0xce2e358c                    // bcax v12.16b, v12.16b, v14.16b, v13.16b
  .long 0xce3939ad                    // bcax v13.16b, v13.16b, v25.16b, v14.16b
  .long 0xce3f65ce                    // bcax v14.16b, v14.16b, v31.16b, v25.16b
  .long 0xce2913a7                    // bcax v7.16b, v29.16b, v9.16b, v4.16b
  .long 0xce252488                    // bcax v8.16b, v4.16b, v5.16b, v9.16b
  .long 0xce261529                    // bcax v9.16b, v9.16b, v6.16b, v5.16b
  .long 0xce3d18a5                    // bcax v5.16b, v5.16b, v29.16b, v6.16b
  .long 0xce2474c6                    // bcax v6.16b, v6.16b, v4.16b, v29.16b
  .long 0xce207363                    // bcax v3.16b, v27.16b, v0.16b, v28.16b
  .long 0xce210384                    // bcax v4.16b, v28.16b, v1.16b, v0.16b
  .long 0xce220400                    // bcax v0.16b, v0.16b, v2.16b, v1.16b
  .long 0xce3b0821                    // bcax v1.16b, v1.16b, v27.16b, v2.16b
  .long 0xce3c6c42                    // bcax v2.16b, v2.16b, v28.16b, v27.16b
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  sub w9, w9, #1
  cbnz w9, .Lcryptoext_keccak_absorb_round
  sub w2, w2, #1
  cbnz w2, .Lcryptoext_keccak_absorb_loop
.Lcryptoext_keccak_absorbed:
  .long 0x6d000400                    // stp d0, d1, [x0]
  .long 0x6d010c02                    // stp d2, d3, [x0, #16]
  .long 0x6d021404                    // stp d4, d5, [x0, #32]
  .long 0x6d031c06                    // stp d6, d7, [x0, #48]
  .long 0x6d042408                    // stp d8, d9, [x0, #64]
  .long 0x6d052c0a                    // stp d10, d11, [x0, #80]
  .long 0x6d06340c                    // stp d12, d13, [x0, #96]
  .long 0x6d073c0e                    // stp d14, d15, [x0, #112]
  .long 0x6d084410                    // stp d16, d17, [x0, #128]
  .long 0x6d094c12                    // stp d18, d19, [x0, #144]
  .long 0x6d0a5414                    // stp d20, d21, [x0, #160]
  .long 0x6d0b5c16                    // stp d22, d23, [x0, #176]
  .long 0xfd006018                    // str d24, [x0, #192]
  .long 0x6d412fea                    // ldp d10, d11, [sp, #16]
  .long 0x6d4237ec                    // ldp d12, d13, [sp, #32]
  .long 0x6d433fee                    // ldp d14, d15, [sp, #48]
  .long 0x6cc427e8                    // ldp d8, d9, [sp], #64
  ret
