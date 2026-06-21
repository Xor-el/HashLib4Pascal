// SHA-256 ARMv8 Crypto Extensions.
// Expects AAPCS64: x0 = state, x1 = data, w2 = numblocks; x3 = K256 via literal pool.
// Reference: OpenSSL CRYPTOGAMS sha256-armv8.S (sha256_block_armv8).
//
// FPC 3.2.2 inline asm limitation (see Lazarus forum topic 55289, svn rev 47116):
//   Subscripted vector regs (v0.4s, v1.16b, ld1 {v0.4s}, …) require FPC 3.3+.
//   FPC 3.2.2 a64reg.dat exposes q0-q31 / s0-s31 for loads/stores only.
//
// Encoding strategy for FPC 3.2.2 compatibility (forum topics 52909, 70561; FPC #41196):
//   FPC 3.2.2 crashes on ldr/ldp/str/stp with qN/sN mnemonics — encode as .long.
//   FPC 3.2.2 adr only accepts local labels — load K256 via ldr + .quad pool.
//   .long for REV32, vector add/orr, memory traffic, and FEAT_SHA256 crypto ops
//
// Register map (per block):
//   q0, q1  = working state (ABCD, EFGH)
//   q4-q7   = message schedule (W)
//   q16-q17 = W+K for sha256h/sha256h2
//   q18-q19 = saved state at block start
//   q2      = sha256h2 temp (copy of q0)

  cbz w2, .Lcryptoext_sha256_done

  .long 0xad400400                    // ldp q0, q1, [x0]
  ldr x3, .Lcryptoext_k256

.Lcryptoext_sha256_block_loop:
  .long 0xacc11424                    // ldp q4, q5, [x1], #32
  .long 0xacc11c26                    // ldp q6, q7, [x1], #32
  sub w2, w2, #1
  .long 0x3cc10470                    // ldr q16, [x3], #16
  .long 0x05c80284                    // rev32 q4, q4
  .long 0x05c802a5                    // rev32 q5, q5
  .long 0x05c802c6                    // rev32 q6, q6
  .long 0x05c802e7                    // rev32 q7, q7
  .long 0x4e201c12                    // orr q18, q0, q0
  .long 0x4e211c33                    // orr q19, q1, q1
  .long 0x3cc10471                    // ldr q17, [x3], #16
  .long 0x4e24d610                    // add q16, q16, q4
  .long 0x5e2828a4                    // sha256su0 v4.16b, v5.16b
  .long 0x4e201c02                    // orr q2, q0, q0
  .long 0x5e104020                    // sha256h v0.16b, v1.16b, v16.4s
  .long 0x5e105041                    // sha256h2 v1.16b, v2.16b, v16.4s
  .long 0x5e0760c4                    // sha256su1 v4.16b, v6.16b, v7.16b
  .long 0x3cc10470                    // ldr q16, [x3], #16
  .long 0x4e25d631                    // add q17, q17, q5
  .long 0x5e2828c5                    // sha256su0 v5.16b, v6.16b
  .long 0x4e201c02                    // orr q2, q0, q0
  .long 0x5e114020                    // sha256h v0.16b, v1.16b, v17.4s
  .long 0x5e115041                    // sha256h2 v1.16b, v2.16b, v17.4s
  .long 0x5e0460e5                    // sha256su1 v5.16b, v7.16b, v4.16b
  .long 0x3cc10471                    // ldr q17, [x3], #16
  .long 0x4e26d610                    // add q16, q16, q6
  .long 0x5e2828e6                    // sha256su0 v6.16b, v7.16b
  .long 0x4e201c02                    // orr q2, q0, q0
  .long 0x5e104020                    // sha256h v0.16b, v1.16b, v16.4s
  .long 0x5e105041                    // sha256h2 v1.16b, v2.16b, v16.4s
  .long 0x5e056086                    // sha256su1 v6.16b, v4.16b, v5.16b
  .long 0x3cc10470                    // ldr q16, [x3], #16
  .long 0x4e27d631                    // add q17, q17, q7
  .long 0x5e282887                    // sha256su0 v7.16b, v4.16b
  .long 0x4e201c02                    // orr q2, q0, q0
  .long 0x5e114020                    // sha256h v0.16b, v1.16b, v17.4s
  .long 0x5e115041                    // sha256h2 v1.16b, v2.16b, v17.4s
  .long 0x5e0660a7                    // sha256su1 v7.16b, v5.16b, v6.16b
  .long 0x3cc10471                    // ldr q17, [x3], #16
  .long 0x4e24d610                    // add q16, q16, q4
  .long 0x5e2828a4                    // sha256su0 v4.16b, v5.16b
  .long 0x4e201c02                    // orr q2, q0, q0
  .long 0x5e104020                    // sha256h v0.16b, v1.16b, v16.4s
  .long 0x5e105041                    // sha256h2 v1.16b, v2.16b, v16.4s
  .long 0x5e0760c4                    // sha256su1 v4.16b, v6.16b, v7.16b
  .long 0x3cc10470                    // ldr q16, [x3], #16
  .long 0x4e25d631                    // add q17, q17, q5
  .long 0x5e2828c5                    // sha256su0 v5.16b, v6.16b
  .long 0x4e201c02                    // orr q2, q0, q0
  .long 0x5e114020                    // sha256h v0.16b, v1.16b, v17.4s
  .long 0x5e115041                    // sha256h2 v1.16b, v2.16b, v17.4s
  .long 0x5e0460e5                    // sha256su1 v5.16b, v7.16b, v4.16b
  .long 0x3cc10471                    // ldr q17, [x3], #16
  .long 0x4e26d610                    // add q16, q16, q6
  .long 0x5e2828e6                    // sha256su0 v6.16b, v7.16b
  .long 0x4e201c02                    // orr q2, q0, q0
  .long 0x5e104020                    // sha256h v0.16b, v1.16b, v16.4s
  .long 0x5e105041                    // sha256h2 v1.16b, v2.16b, v16.4s
  .long 0x5e056086                    // sha256su1 v6.16b, v4.16b, v5.16b
  .long 0x3cc10470                    // ldr q16, [x3], #16
  .long 0x4e27d631                    // add q17, q17, q7
  .long 0x5e282887                    // sha256su0 v7.16b, v4.16b
  .long 0x4e201c02                    // orr q2, q0, q0
  .long 0x5e114020                    // sha256h v0.16b, v1.16b, v17.4s
  .long 0x5e115041                    // sha256h2 v1.16b, v2.16b, v17.4s
  .long 0x5e0660a7                    // sha256su1 v7.16b, v5.16b, v6.16b
  .long 0x3cc10471                    // ldr q17, [x3], #16
  .long 0x4e24d610                    // add q16, q16, q4
  .long 0x5e2828a4                    // sha256su0 v4.16b, v5.16b
  .long 0x4e201c02                    // orr q2, q0, q0
  .long 0x5e104020                    // sha256h v0.16b, v1.16b, v16.4s
  .long 0x5e105041                    // sha256h2 v1.16b, v2.16b, v16.4s
  .long 0x5e0760c4                    // sha256su1 v4.16b, v6.16b, v7.16b
  .long 0x3cc10470                    // ldr q16, [x3], #16
  .long 0x4e25d631                    // add q17, q17, q5
  .long 0x5e2828c5                    // sha256su0 v5.16b, v6.16b
  .long 0x4e201c02                    // orr q2, q0, q0
  .long 0x5e114020                    // sha256h v0.16b, v1.16b, v17.4s
  .long 0x5e115041                    // sha256h2 v1.16b, v2.16b, v17.4s
  .long 0x5e0460e5                    // sha256su1 v5.16b, v7.16b, v4.16b
  .long 0x3cc10471                    // ldr q17, [x3], #16
  .long 0x4e26d610                    // add q16, q16, q6
  .long 0x5e2828e6                    // sha256su0 v6.16b, v7.16b
  .long 0x4e201c02                    // orr q2, q0, q0
  .long 0x5e104020                    // sha256h v0.16b, v1.16b, v16.4s
  .long 0x5e105041                    // sha256h2 v1.16b, v2.16b, v16.4s
  .long 0x5e056086                    // sha256su1 v6.16b, v4.16b, v5.16b
  .long 0x3cc10470                    // ldr q16, [x3], #16
  .long 0x4e27d631                    // add q17, q17, q7
  .long 0x5e282887                    // sha256su0 v7.16b, v4.16b
  .long 0x4e201c02                    // orr q2, q0, q0
  .long 0x5e114020                    // sha256h v0.16b, v1.16b, v17.4s
  .long 0x5e115041                    // sha256h2 v1.16b, v2.16b, v17.4s
  .long 0x5e0660a7                    // sha256su1 v7.16b, v5.16b, v6.16b
  .long 0x3cc10471                    // ldr q17, [x3], #16
  .long 0x4e24d610                    // add q16, q16, q4
  .long 0x4e201c02                    // orr q2, q0, q0
  .long 0x5e104020                    // sha256h v0.16b, v1.16b, v16.4s
  .long 0x5e105041                    // sha256h2 v1.16b, v2.16b, v16.4s
  .long 0x3cc10470                    // ldr q16, [x3], #16
  .long 0x4e25d631                    // add q17, q17, q5
  .long 0x4e201c02                    // orr q2, q0, q0
  .long 0x5e114020                    // sha256h v0.16b, v1.16b, v17.4s
  .long 0x5e115041                    // sha256h2 v1.16b, v2.16b, v17.4s
  .long 0x3dc00071                    // ldr q17, [x3]
  .long 0x4e26d610                    // add q16, q16, q6
  sub x3, x3, #240                    // rewind K256 pointer (64*4 - 16)
  .long 0x4e201c02                    // orr q2, q0, q0
  .long 0x5e104020                    // sha256h v0.16b, v1.16b, v16.4s
  .long 0x5e105041                    // sha256h2 v1.16b, v2.16b, v16.4s
  .long 0x4e27d631                    // add q17, q17, q7
  .long 0x4e201c02                    // orr q2, q0, q0
  .long 0x5e114020                    // sha256h v0.16b, v1.16b, v17.4s
  .long 0x5e115041                    // sha256h2 v1.16b, v2.16b, v17.4s
  .long 0x4e32d400                    // add q0, q0, q18
  .long 0x4e33d421                    // add q1, q1, q19
  cbnz w2, .Lcryptoext_sha256_block_loop
  .long 0xad000400                    // stp q0, q1, [x0]
  b .Lcryptoext_sha256_done
.Lcryptoext_k256:
  .quad K256
  .Lcryptoext_sha256_done:
