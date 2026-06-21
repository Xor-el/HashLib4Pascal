// SHA-256 ARMv8 Crypto Extensions.
// Expects AAPCS64: x0 = state, x1 = data, w2 = numblocks.
// K256: adr x3, .Lcryptoext_k256 (local pool — FPC rejects adr on Pascal globals).
// Reference: OpenSSL CRYPTOGAMS sha256-armv8.S (sha256_block_armv8).
//
// FPC 3.2.2 inline asm limitation (see Lazarus forum topic 55289, svn rev 47116):
//   Subscripted vector regs (v0.4s, v1.16b, ld1 {v0.4s}, …) require FPC 3.3+.
//   FPC 3.2.2 a64reg.dat exposes q0-q31 / s0-s31 for loads/stores only.
//
// Encoding strategy for FPC 3.2.2 compatibility (forum topics 52909, 70561; FPC #41196):
//   FPC 3.2.2 crashes on ldr/ldp/str/stp with qN/sN mnemonics — encode as .long.
//   K table via adr x3, .Lcryptoext_k256 + inline .long pool (OpenSSL K256 pattern).
//   .long for REV32, vector add/orr, memory traffic, and FEAT_SHA256 crypto ops
//
// Register map (per block):
//   q0, q1  = working state (ABCD, EFGH)
//   q4-q7   = message schedule (W)
//   q16-q17 = W+K for sha256h/sha256h2
//   q18-q19 = saved state at block start
//   q2      = sha256h2 temp (copy of q0)

  cbz w2, .Lcryptoext_sha256_done

  adr x3, .Lcryptoext_k256
  .long 0xad400400                    // ldp q0, q1, [x0]

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
  .long 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
  .long 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
  .long 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
  .long 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
  .long 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
  .long 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
  .long 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
  .long 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
  .long 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
  .long 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
  .long 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
  .long 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
  .long 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
  .long 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
  .long 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
  .long 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  .Lcryptoext_sha256_done:
