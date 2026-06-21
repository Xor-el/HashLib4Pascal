// SHA-1 ARMv8 Crypto Extensions implementation.
// Expects AAPCS64: x0 = state ptr, x1 = data ptr, w2 = numblocks.
// Uses v0-v7, v16-v23; no callee-saved SIMD regs touched.
// Reference: OpenSSL CRYPTOGAMS sha1-armv8.S (sha1_block_armv8 / .Lv8_entry).
//
// ARMv8 Crypto Extension raw encodings (.byte LE; FPC GAS rejects .inst):
//   sha1h   vN.16b, vM.16b       = 0x5e280802 / 0x5e280803
//   sha1c   v0, v1, vK.4s        = 0x5e140020 / 0x5e150060 / ...
//   sha1p   v0, v1, vK.4s        = 0x5e141040 / 0x5e151060 / ...
//   sha1m   v0, v1, vK.4s        = 0x5e142040 / 0x5e152060 / ...
//   sha1su0 vN.16b, vM.16b, vK.16b = 0x5e0630xx / 0x5e0730xx / ...
//   sha1su1 vN.16b, vM.16b       = 0x5e2818xx
//
// Register map:
//   v0      = ABCD working state
//   v1      = E (in v1.s[0]) + ping-pong with v2/v3 via sha1h
//   v2, v3  = sha1h ping-pong temporaries
//   v4-v7   = message schedule vectors
//   v16-v19 = K round constants (K_00_19 .. K_60_79), loaded from K_SHA1
//   v20-v21 = W+K for sha1c/sha1p/sha1m
//   v22     = saved ABCD at block start

  cbz w2, .Lcryptoext_sha1_done

  eor v1.16b, v1.16b, v1.16b
  ld1 {v0.4s}, [x0], #16
  ld1 {v1.s}[0], [x0]
  sub x0, x0, #16
  adr x4, K_SHA1
  ld1 {v16.4s-v19.4s}, [x4]

.Lcryptoext_sha1_block_loop:

  ld1 {v4.16b-v7.16b}, [x1], #64
  sub w2, w2, #1
  rev32 v4.16b, v4.16b
  rev32 v5.16b, v5.16b
  add v20.4s, v16.4s, v4.4s
  rev32 v6.16b, v6.16b
  orr v22.16b, v0.16b, v0.16b
  add v21.4s, v16.4s, v5.4s
  rev32 v7.16b, v7.16b
  .byte 0x03, 0x08, 0x28, 0x5e                    // sha1h v3.16b, v0.16b
  .byte 0x20, 0x00, 0x14, 0x5e                    // sha1c v0.16b, v1.16b, v20.4s
  add v20.4s, v16.4s, v6.4s
  .byte 0xa4, 0x30, 0x06, 0x5e                    // sha1su0 v4.16b, v5.16b, v6.16b
  .byte 0x02, 0x08, 0x28, 0x5e                    // sha1h v2.16b, v0.16b
  .byte 0x60, 0x00, 0x15, 0x5e                    // sha1c v0.16b, v3.16b, v21.4s
  add v21.4s, v16.4s, v7.4s
  .byte 0xe4, 0x18, 0x28, 0x5e                    // sha1su1 v4.16b, v7.16b
  .byte 0xc5, 0x30, 0x07, 0x5e                    // sha1su0 v5.16b, v6.16b, v7.16b
  .byte 0x03, 0x08, 0x28, 0x5e                    // sha1h v3.16b, v0.16b
  .byte 0x40, 0x00, 0x14, 0x5e                    // sha1c v0.16b, v2.16b, v20.4s
  add v20.4s, v16.4s, v4.4s
  .byte 0x85, 0x18, 0x28, 0x5e                    // sha1su1 v5.16b, v4.16b
  .byte 0xe6, 0x30, 0x04, 0x5e                    // sha1su0 v6.16b, v7.16b, v4.16b
  .byte 0x02, 0x08, 0x28, 0x5e                    // sha1h v2.16b, v0.16b
  .byte 0x60, 0x00, 0x15, 0x5e                    // sha1c v0.16b, v3.16b, v21.4s
  add v21.4s, v17.4s, v5.4s
  .byte 0xa6, 0x18, 0x28, 0x5e                    // sha1su1 v6.16b, v5.16b
  .byte 0x87, 0x30, 0x05, 0x5e                    // sha1su0 v7.16b, v4.16b, v5.16b
  .byte 0x03, 0x08, 0x28, 0x5e                    // sha1h v3.16b, v0.16b
  .byte 0x40, 0x00, 0x14, 0x5e                    // sha1c v0.16b, v2.16b, v20.4s
  add v20.4s, v17.4s, v6.4s
  .byte 0xc7, 0x18, 0x28, 0x5e                    // sha1su1 v7.16b, v6.16b
  .byte 0xa4, 0x30, 0x06, 0x5e                    // sha1su0 v4.16b, v5.16b, v6.16b
  .byte 0x02, 0x08, 0x28, 0x5e                    // sha1h v2.16b, v0.16b
  .byte 0x60, 0x10, 0x15, 0x5e                    // sha1p v0.16b, v3.16b, v21.4s
  add v21.4s, v17.4s, v7.4s
  .byte 0xe4, 0x18, 0x28, 0x5e                    // sha1su1 v4.16b, v7.16b
  .byte 0xc5, 0x30, 0x07, 0x5e                    // sha1su0 v5.16b, v6.16b, v7.16b
  .byte 0x03, 0x08, 0x28, 0x5e                    // sha1h v3.16b, v0.16b
  .byte 0x40, 0x10, 0x14, 0x5e                    // sha1p v0.16b, v2.16b, v20.4s
  add v20.4s, v17.4s, v4.4s
  .byte 0x85, 0x18, 0x28, 0x5e                    // sha1su1 v5.16b, v4.16b
  .byte 0xe6, 0x30, 0x04, 0x5e                    // sha1su0 v6.16b, v7.16b, v4.16b
  .byte 0x02, 0x08, 0x28, 0x5e                    // sha1h v2.16b, v0.16b
  .byte 0x60, 0x10, 0x15, 0x5e                    // sha1p v0.16b, v3.16b, v21.4s
  add v21.4s, v17.4s, v5.4s
  .byte 0xa6, 0x18, 0x28, 0x5e                    // sha1su1 v6.16b, v5.16b
  .byte 0x87, 0x30, 0x05, 0x5e                    // sha1su0 v7.16b, v4.16b, v5.16b
  .byte 0x03, 0x08, 0x28, 0x5e                    // sha1h v3.16b, v0.16b
  .byte 0x40, 0x10, 0x14, 0x5e                    // sha1p v0.16b, v2.16b, v20.4s
  add v20.4s, v18.4s, v6.4s
  .byte 0xc7, 0x18, 0x28, 0x5e                    // sha1su1 v7.16b, v6.16b
  .byte 0xa4, 0x30, 0x06, 0x5e                    // sha1su0 v4.16b, v5.16b, v6.16b
  .byte 0x02, 0x08, 0x28, 0x5e                    // sha1h v2.16b, v0.16b
  .byte 0x60, 0x10, 0x15, 0x5e                    // sha1p v0.16b, v3.16b, v21.4s
  add v21.4s, v18.4s, v7.4s
  .byte 0xe4, 0x18, 0x28, 0x5e                    // sha1su1 v4.16b, v7.16b
  .byte 0xc5, 0x30, 0x07, 0x5e                    // sha1su0 v5.16b, v6.16b, v7.16b
  .byte 0x03, 0x08, 0x28, 0x5e                    // sha1h v3.16b, v0.16b
  .byte 0x40, 0x20, 0x14, 0x5e                    // sha1m v0.16b, v2.16b, v20.4s
  add v20.4s, v18.4s, v4.4s
  .byte 0x85, 0x18, 0x28, 0x5e                    // sha1su1 v5.16b, v4.16b
  .byte 0xe6, 0x30, 0x04, 0x5e                    // sha1su0 v6.16b, v7.16b, v4.16b
  .byte 0x02, 0x08, 0x28, 0x5e                    // sha1h v2.16b, v0.16b
  .byte 0x60, 0x20, 0x15, 0x5e                    // sha1m v0.16b, v3.16b, v21.4s
  add v21.4s, v18.4s, v5.4s
  .byte 0xa6, 0x18, 0x28, 0x5e                    // sha1su1 v6.16b, v5.16b
  .byte 0x87, 0x30, 0x05, 0x5e                    // sha1su0 v7.16b, v4.16b, v5.16b
  .byte 0x03, 0x08, 0x28, 0x5e                    // sha1h v3.16b, v0.16b
  .byte 0x40, 0x20, 0x14, 0x5e                    // sha1m v0.16b, v2.16b, v20.4s
  add v20.4s, v18.4s, v6.4s
  .byte 0xc7, 0x18, 0x28, 0x5e                    // sha1su1 v7.16b, v6.16b
  .byte 0xa4, 0x30, 0x06, 0x5e                    // sha1su0 v4.16b, v5.16b, v6.16b
  .byte 0x02, 0x08, 0x28, 0x5e                    // sha1h v2.16b, v0.16b
  .byte 0x60, 0x20, 0x15, 0x5e                    // sha1m v0.16b, v3.16b, v21.4s
  add v21.4s, v19.4s, v7.4s
  .byte 0xe4, 0x18, 0x28, 0x5e                    // sha1su1 v4.16b, v7.16b
  .byte 0xc5, 0x30, 0x07, 0x5e                    // sha1su0 v5.16b, v6.16b, v7.16b
  .byte 0x03, 0x08, 0x28, 0x5e                    // sha1h v3.16b, v0.16b
  .byte 0x40, 0x20, 0x14, 0x5e                    // sha1m v0.16b, v2.16b, v20.4s
  add v20.4s, v19.4s, v4.4s
  .byte 0x85, 0x18, 0x28, 0x5e                    // sha1su1 v5.16b, v4.16b
  .byte 0xe6, 0x30, 0x04, 0x5e                    // sha1su0 v6.16b, v7.16b, v4.16b
  .byte 0x02, 0x08, 0x28, 0x5e                    // sha1h v2.16b, v0.16b
  .byte 0x60, 0x10, 0x15, 0x5e                    // sha1p v0.16b, v3.16b, v21.4s
  add v21.4s, v19.4s, v5.4s
  .byte 0xa6, 0x18, 0x28, 0x5e                    // sha1su1 v6.16b, v5.16b
  .byte 0x87, 0x30, 0x05, 0x5e                    // sha1su0 v7.16b, v4.16b, v5.16b
  .byte 0x03, 0x08, 0x28, 0x5e                    // sha1h v3.16b, v0.16b
  .byte 0x40, 0x10, 0x14, 0x5e                    // sha1p v0.16b, v2.16b, v20.4s
  add v20.4s, v19.4s, v6.4s
  .byte 0xc7, 0x18, 0x28, 0x5e                    // sha1su1 v7.16b, v6.16b
  .byte 0x02, 0x08, 0x28, 0x5e                    // sha1h v2.16b, v0.16b
  .byte 0x60, 0x10, 0x15, 0x5e                    // sha1p v0.16b, v3.16b, v21.4s
  add v21.4s, v19.4s, v7.4s

  .byte 0x03, 0x08, 0x28, 0x5e                    // sha1h v3.16b, v0.16b
  .byte 0x40, 0x10, 0x14, 0x5e                    // sha1p v0.16b, v2.16b, v20.4s

  .byte 0x02, 0x08, 0x28, 0x5e                    // sha1h v2.16b, v0.16b
  .byte 0x60, 0x10, 0x15, 0x5e                    // sha1p v0.16b, v3.16b, v21.4s

  add v1.4s, v1.4s, v2.4s
  add v0.4s, v0.4s, v22.4s

  cbnz w2, .Lcryptoext_sha1_block_loop

  st1 {v0.4s}, [x0], #16
  st1 {v1.s}[0], [x0]

.Lcryptoext_sha1_done:
