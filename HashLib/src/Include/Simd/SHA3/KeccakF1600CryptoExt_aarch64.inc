// Keccak-F1600 permute AArch64 FEAT_SHA3 implementation.
// Expects AAPCS64: x0 = state ptr (25 x UInt64, little-endian lanes),
//   x1 = iotas ptr (24 x UInt64 round constants == HlpSHA3 RC table).
// Saves/restores d8-d15 on 64-byte frame; state uses v0-v24 (clobbers d8-d15 lanes).
// Leaf (no calls); x30 untouched.
// Reference: OpenSSL CRYPTOGAMS keccak1600-armv8.S.
// AArch64 vector/crypto instructions are .long-encoded for broad assembler compatibility.
// Register map:
//   v0-v24   = Keccak state lanes A[y][x] (lane k = v[k], 64 bits in low half)
//   v25-v29  = Theta C[]/D[] column scratch
//   v26      = iota round constant (ld1r)
//   v30-v31  = Rho/Pi scratch

  {$I ..\Include\Simd\Common\HlpSimdNonVolatileSave_aarch64.inc}
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
  mov w9, #24
.Lcryptoext_keccak_round:
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
  .long 0x4ddfcc3a                    // ld1r {v26.2d}, [x1], #8
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
  cbnz w9, .Lcryptoext_keccak_round
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
  {$I ..\Include\Simd\Common\HlpSimdNonVolatileRestore_aarch64.inc}
  ret
