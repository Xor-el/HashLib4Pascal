// SHA-256 ARMv8 Crypto Extensions implementation.
// Expects AAPCS64: x0 = state ptr, x1 = data ptr, w2 = numblocks.
// Uses v0-v7, v16-v19, v2, v18-v19; no callee-saved SIMD regs touched.
// Reference: OpenSSL CRYPTOGAMS sha256-armv8.S (sha256_block_armv8 / .Lv8_entry).
//
// ARMv8 Crypto Extension raw encodings (.byte LE; FPC GAS rejects .inst):
//   sha256h   q0, q1, vN.4s  = 0x5e104020 / 0x5e114020 (variant by Rn)
//   sha256h2  q1, q2, vN.4s  = 0x5e105041 / 0x5e115041
//   sha256su0 vN.16b, vM.16b  = 0x5e2828xx
//   sha256su1 vN.16b, vM.16b, vK.16b = 0x5e0760xx / 0x5e0460xx / 0x5e0560xx / 0x5e0660xx
//
// Register map (per block):
//   v0, v1  = working SHA-256 state (ABCD, EFGH)
//   v4-v7   = message schedule vectors (W)
//   v16-v17 = W+K for sha256h/sha256h2 rounds
//   v18-v19 = saved state at block start
//   v2      = sha256h2 temp (copy of v0)

  cbz w2, .Lcryptoext_sha256_done

  ld1 {v0.4s, v1.4s}, [x0]
  adr x3, K256

.Lcryptoext_sha256_block_loop:

  ld1 {v4.16b-v7.16b}, [x1], #64
  sub w2, w2, #1
  ld1 {v16.4s}, [x3], #16
  rev32 v4.16b, v4.16b
  rev32 v5.16b, v5.16b
  rev32 v6.16b, v6.16b
  rev32 v7.16b, v7.16b
  orr v18.16b, v0.16b, v0.16b
  orr v19.16b, v1.16b, v1.16b
  ld1 {v17.4s}, [x3], #16
  add v16.4s, v16.4s, v4.4s
  .byte 0xa4, 0x28, 0x28, 0x5e                    // sha256su0 v4.16b, v5.16b
  orr v2.16b, v0.16b, v0.16b
  .byte 0x20, 0x40, 0x10, 0x5e                    // sha256h v0.16b, v1.16b, v16.4s
  .byte 0x41, 0x50, 0x10, 0x5e                    // sha256h2 v1.16b, v2.16b, v16.4s
  .byte 0xc4, 0x60, 0x07, 0x5e                    // sha256su1 v4.16b, v6.16b, v7.16b
  ld1 {v16.4s}, [x3], #16
  add v17.4s, v17.4s, v5.4s
  .byte 0xc5, 0x28, 0x28, 0x5e                    // sha256su0 v5.16b, v6.16b
  orr v2.16b, v0.16b, v0.16b
  .byte 0x20, 0x40, 0x11, 0x5e                    // sha256h v0.16b, v1.16b, v17.4s
  .byte 0x41, 0x50, 0x11, 0x5e                    // sha256h2 v1.16b, v2.16b, v17.4s
  .byte 0xe5, 0x60, 0x04, 0x5e                    // sha256su1 v5.16b, v7.16b, v4.16b
  ld1 {v17.4s}, [x3], #16
  add v16.4s, v16.4s, v6.4s
  .byte 0xe6, 0x28, 0x28, 0x5e                    // sha256su0 v6.16b, v7.16b
  orr v2.16b, v0.16b, v0.16b
  .byte 0x20, 0x40, 0x10, 0x5e                    // sha256h v0.16b, v1.16b, v16.4s
  .byte 0x41, 0x50, 0x10, 0x5e                    // sha256h2 v1.16b, v2.16b, v16.4s
  .byte 0x86, 0x60, 0x05, 0x5e                    // sha256su1 v6.16b, v4.16b, v5.16b
  ld1 {v16.4s}, [x3], #16
  add v17.4s, v17.4s, v7.4s
  .byte 0x87, 0x28, 0x28, 0x5e                    // sha256su0 v7.16b, v4.16b
  orr v2.16b, v0.16b, v0.16b
  .byte 0x20, 0x40, 0x11, 0x5e                    // sha256h v0.16b, v1.16b, v17.4s
  .byte 0x41, 0x50, 0x11, 0x5e                    // sha256h2 v1.16b, v2.16b, v17.4s
  .byte 0xa7, 0x60, 0x06, 0x5e                    // sha256su1 v7.16b, v5.16b, v6.16b
  ld1 {v17.4s}, [x3], #16
  add v16.4s, v16.4s, v4.4s
  .byte 0xa4, 0x28, 0x28, 0x5e                    // sha256su0 v4.16b, v5.16b
  orr v2.16b, v0.16b, v0.16b
  .byte 0x20, 0x40, 0x10, 0x5e                    // sha256h v0.16b, v1.16b, v16.4s
  .byte 0x41, 0x50, 0x10, 0x5e                    // sha256h2 v1.16b, v2.16b, v16.4s
  .byte 0xc4, 0x60, 0x07, 0x5e                    // sha256su1 v4.16b, v6.16b, v7.16b
  ld1 {v16.4s}, [x3], #16
  add v17.4s, v17.4s, v5.4s
  .byte 0xc5, 0x28, 0x28, 0x5e                    // sha256su0 v5.16b, v6.16b
  orr v2.16b, v0.16b, v0.16b
  .byte 0x20, 0x40, 0x11, 0x5e                    // sha256h v0.16b, v1.16b, v17.4s
  .byte 0x41, 0x50, 0x11, 0x5e                    // sha256h2 v1.16b, v2.16b, v17.4s
  .byte 0xe5, 0x60, 0x04, 0x5e                    // sha256su1 v5.16b, v7.16b, v4.16b
  ld1 {v17.4s}, [x3], #16
  add v16.4s, v16.4s, v6.4s
  .byte 0xe6, 0x28, 0x28, 0x5e                    // sha256su0 v6.16b, v7.16b
  orr v2.16b, v0.16b, v0.16b
  .byte 0x20, 0x40, 0x10, 0x5e                    // sha256h v0.16b, v1.16b, v16.4s
  .byte 0x41, 0x50, 0x10, 0x5e                    // sha256h2 v1.16b, v2.16b, v16.4s
  .byte 0x86, 0x60, 0x05, 0x5e                    // sha256su1 v6.16b, v4.16b, v5.16b
  ld1 {v16.4s}, [x3], #16
  add v17.4s, v17.4s, v7.4s
  .byte 0x87, 0x28, 0x28, 0x5e                    // sha256su0 v7.16b, v4.16b
  orr v2.16b, v0.16b, v0.16b
  .byte 0x20, 0x40, 0x11, 0x5e                    // sha256h v0.16b, v1.16b, v17.4s
  .byte 0x41, 0x50, 0x11, 0x5e                    // sha256h2 v1.16b, v2.16b, v17.4s
  .byte 0xa7, 0x60, 0x06, 0x5e                    // sha256su1 v7.16b, v5.16b, v6.16b
  ld1 {v17.4s}, [x3], #16
  add v16.4s, v16.4s, v4.4s
  .byte 0xa4, 0x28, 0x28, 0x5e                    // sha256su0 v4.16b, v5.16b
  orr v2.16b, v0.16b, v0.16b
  .byte 0x20, 0x40, 0x10, 0x5e                    // sha256h v0.16b, v1.16b, v16.4s
  .byte 0x41, 0x50, 0x10, 0x5e                    // sha256h2 v1.16b, v2.16b, v16.4s
  .byte 0xc4, 0x60, 0x07, 0x5e                    // sha256su1 v4.16b, v6.16b, v7.16b
  ld1 {v16.4s}, [x3], #16
  add v17.4s, v17.4s, v5.4s
  .byte 0xc5, 0x28, 0x28, 0x5e                    // sha256su0 v5.16b, v6.16b
  orr v2.16b, v0.16b, v0.16b
  .byte 0x20, 0x40, 0x11, 0x5e                    // sha256h v0.16b, v1.16b, v17.4s
  .byte 0x41, 0x50, 0x11, 0x5e                    // sha256h2 v1.16b, v2.16b, v17.4s
  .byte 0xe5, 0x60, 0x04, 0x5e                    // sha256su1 v5.16b, v7.16b, v4.16b
  ld1 {v17.4s}, [x3], #16
  add v16.4s, v16.4s, v6.4s
  .byte 0xe6, 0x28, 0x28, 0x5e                    // sha256su0 v6.16b, v7.16b
  orr v2.16b, v0.16b, v0.16b
  .byte 0x20, 0x40, 0x10, 0x5e                    // sha256h v0.16b, v1.16b, v16.4s
  .byte 0x41, 0x50, 0x10, 0x5e                    // sha256h2 v1.16b, v2.16b, v16.4s
  .byte 0x86, 0x60, 0x05, 0x5e                    // sha256su1 v6.16b, v4.16b, v5.16b
  ld1 {v16.4s}, [x3], #16
  add v17.4s, v17.4s, v7.4s
  .byte 0x87, 0x28, 0x28, 0x5e                    // sha256su0 v7.16b, v4.16b
  orr v2.16b, v0.16b, v0.16b
  .byte 0x20, 0x40, 0x11, 0x5e                    // sha256h v0.16b, v1.16b, v17.4s
  .byte 0x41, 0x50, 0x11, 0x5e                    // sha256h2 v1.16b, v2.16b, v17.4s
  .byte 0xa7, 0x60, 0x06, 0x5e                    // sha256su1 v7.16b, v5.16b, v6.16b
  ld1 {v17.4s}, [x3], #16
  add v16.4s, v16.4s, v4.4s
  orr v2.16b, v0.16b, v0.16b
  .byte 0x20, 0x40, 0x10, 0x5e                    // sha256h v0.16b, v1.16b, v16.4s
  .byte 0x41, 0x50, 0x10, 0x5e                    // sha256h2 v1.16b, v2.16b, v16.4s

  ld1 {v16.4s}, [x3], #16
  add v17.4s, v17.4s, v5.4s
  orr v2.16b, v0.16b, v0.16b
  .byte 0x20, 0x40, 0x11, 0x5e                    // sha256h v0.16b, v1.16b, v17.4s
  .byte 0x41, 0x50, 0x11, 0x5e                    // sha256h2 v1.16b, v2.16b, v17.4s

  ld1 {v17.4s}, [x3]
  add v16.4s, v16.4s, v6.4s
  sub x3, x3, #240                    // rewind K256 pointer (64*4 - 16)
  orr v2.16b, v0.16b, v0.16b
  .byte 0x20, 0x40, 0x10, 0x5e                    // sha256h v0.16b, v1.16b, v16.4s
  .byte 0x41, 0x50, 0x10, 0x5e                    // sha256h2 v1.16b, v2.16b, v16.4s

  add v17.4s, v17.4s, v7.4s
  orr v2.16b, v0.16b, v0.16b
  .byte 0x20, 0x40, 0x11, 0x5e                    // sha256h v0.16b, v1.16b, v17.4s
  .byte 0x41, 0x50, 0x11, 0x5e                    // sha256h2 v1.16b, v2.16b, v17.4s

  add v0.4s, v0.4s, v18.4s
  add v1.4s, v1.4s, v19.4s

  cbnz w2, .Lcryptoext_sha256_block_loop

  st1 {v0.4s, v1.4s}, [x0]

.Lcryptoext_sha256_done:
