// SHA-256 AArch64 FEAT_SHA256 implementation.
// Expects AAPCS64: x0 = state ptr (8 x UInt32), x1 = data ptr,
//   w2 = numblocks, x3 = K256 ptr (64 UInt32 round constants).
// Leaf nostackframe; caller-saved GPR/vector only.
// K pointer rewound each block (sub x3, #240) after post-index loads.
// Reference: OpenSSL CRYPTOGAMS sha256-armv8.S, HashLib SHA256CompressSse2_x86_64.inc.
// AArch64 vector/crypto instructions are .long-encoded for broad assembler compatibility.
// Register map:
//   v0, v1   = working state (ABCD, EFGH)
//   v2       = sha256h2 temp (copy of v0 before each h/h2 pair)
//   v4-v7    = message schedule (W)
//   v16, v17 = W+K for sha256h / sha256h2 (ping-pong)
//   v18, v19 = saved state (ABCD, EFGH) for the final add

  cbz w2, .Lcryptoext_sha256_done
  .long 0xad400400                    // ldp q0, q1, [x0]
.Lcryptoext_sha256_block_loop:
  .long 0xacc11424                    // ldp q4, q5, [x1], #32
  .long 0xacc11c26                    // ldp q6, q7, [x1], #32
  sub w2, w2, #1
  .long 0x6e200884                    // rev32 v4.16b, v4.16b
  .long 0x6e2008a5                    // rev32 v5.16b, v5.16b
  .long 0x6e2008c6                    // rev32 v6.16b, v6.16b
  .long 0x6e2008e7                    // rev32 v7.16b, v7.16b
  .long 0x4ea01c12                    // orr v18.16b, v0.16b, v0.16b
  .long 0x4ea11c33                    // orr v19.16b, v1.16b, v1.16b
  .long 0x3cc10470                    // ldr q16, [x3], #16
  .long 0x4ea48610                    // add v16.4s, v16.4s, v4.4s
  .long 0x5e2828a4                    // sha256su0 v4.4s, v5.4s
  .long 0x4ea01c02                    // orr v2.16b, v0.16b, v0.16b
  .long 0x5e104020                    // sha256h q0, q1, v16.4s
  .long 0x5e105041                    // sha256h2 q1, q2, v16.4s
  .long 0x5e0760c4                    // sha256su1 v4.4s, v6.4s, v7.4s
  .long 0x3cc10471                    // ldr q17, [x3], #16
  .long 0x4ea58631                    // add v17.4s, v17.4s, v5.4s
  .long 0x5e2828c5                    // sha256su0 v5.4s, v6.4s
  .long 0x4ea01c02                    // orr v2.16b, v0.16b, v0.16b
  .long 0x5e114020                    // sha256h q0, q1, v17.4s
  .long 0x5e115041                    // sha256h2 q1, q2, v17.4s
  .long 0x5e0460e5                    // sha256su1 v5.4s, v7.4s, v4.4s
  .long 0x3cc10470                    // ldr q16, [x3], #16
  .long 0x4ea68610                    // add v16.4s, v16.4s, v6.4s
  .long 0x5e2828e6                    // sha256su0 v6.4s, v7.4s
  .long 0x4ea01c02                    // orr v2.16b, v0.16b, v0.16b
  .long 0x5e104020                    // sha256h q0, q1, v16.4s
  .long 0x5e105041                    // sha256h2 q1, q2, v16.4s
  .long 0x5e056086                    // sha256su1 v6.4s, v4.4s, v5.4s
  .long 0x3cc10471                    // ldr q17, [x3], #16
  .long 0x4ea78631                    // add v17.4s, v17.4s, v7.4s
  .long 0x5e282887                    // sha256su0 v7.4s, v4.4s
  .long 0x4ea01c02                    // orr v2.16b, v0.16b, v0.16b
  .long 0x5e114020                    // sha256h q0, q1, v17.4s
  .long 0x5e115041                    // sha256h2 q1, q2, v17.4s
  .long 0x5e0660a7                    // sha256su1 v7.4s, v5.4s, v6.4s
  .long 0x3cc10470                    // ldr q16, [x3], #16
  .long 0x4ea48610                    // add v16.4s, v16.4s, v4.4s
  .long 0x5e2828a4                    // sha256su0 v4.4s, v5.4s
  .long 0x4ea01c02                    // orr v2.16b, v0.16b, v0.16b
  .long 0x5e104020                    // sha256h q0, q1, v16.4s
  .long 0x5e105041                    // sha256h2 q1, q2, v16.4s
  .long 0x5e0760c4                    // sha256su1 v4.4s, v6.4s, v7.4s
  .long 0x3cc10471                    // ldr q17, [x3], #16
  .long 0x4ea58631                    // add v17.4s, v17.4s, v5.4s
  .long 0x5e2828c5                    // sha256su0 v5.4s, v6.4s
  .long 0x4ea01c02                    // orr v2.16b, v0.16b, v0.16b
  .long 0x5e114020                    // sha256h q0, q1, v17.4s
  .long 0x5e115041                    // sha256h2 q1, q2, v17.4s
  .long 0x5e0460e5                    // sha256su1 v5.4s, v7.4s, v4.4s
  .long 0x3cc10470                    // ldr q16, [x3], #16
  .long 0x4ea68610                    // add v16.4s, v16.4s, v6.4s
  .long 0x5e2828e6                    // sha256su0 v6.4s, v7.4s
  .long 0x4ea01c02                    // orr v2.16b, v0.16b, v0.16b
  .long 0x5e104020                    // sha256h q0, q1, v16.4s
  .long 0x5e105041                    // sha256h2 q1, q2, v16.4s
  .long 0x5e056086                    // sha256su1 v6.4s, v4.4s, v5.4s
  .long 0x3cc10471                    // ldr q17, [x3], #16
  .long 0x4ea78631                    // add v17.4s, v17.4s, v7.4s
  .long 0x5e282887                    // sha256su0 v7.4s, v4.4s
  .long 0x4ea01c02                    // orr v2.16b, v0.16b, v0.16b
  .long 0x5e114020                    // sha256h q0, q1, v17.4s
  .long 0x5e115041                    // sha256h2 q1, q2, v17.4s
  .long 0x5e0660a7                    // sha256su1 v7.4s, v5.4s, v6.4s
  .long 0x3cc10470                    // ldr q16, [x3], #16
  .long 0x4ea48610                    // add v16.4s, v16.4s, v4.4s
  .long 0x5e2828a4                    // sha256su0 v4.4s, v5.4s
  .long 0x4ea01c02                    // orr v2.16b, v0.16b, v0.16b
  .long 0x5e104020                    // sha256h q0, q1, v16.4s
  .long 0x5e105041                    // sha256h2 q1, q2, v16.4s
  .long 0x5e0760c4                    // sha256su1 v4.4s, v6.4s, v7.4s
  .long 0x3cc10471                    // ldr q17, [x3], #16
  .long 0x4ea58631                    // add v17.4s, v17.4s, v5.4s
  .long 0x5e2828c5                    // sha256su0 v5.4s, v6.4s
  .long 0x4ea01c02                    // orr v2.16b, v0.16b, v0.16b
  .long 0x5e114020                    // sha256h q0, q1, v17.4s
  .long 0x5e115041                    // sha256h2 q1, q2, v17.4s
  .long 0x5e0460e5                    // sha256su1 v5.4s, v7.4s, v4.4s
  .long 0x3cc10470                    // ldr q16, [x3], #16
  .long 0x4ea68610                    // add v16.4s, v16.4s, v6.4s
  .long 0x5e2828e6                    // sha256su0 v6.4s, v7.4s
  .long 0x4ea01c02                    // orr v2.16b, v0.16b, v0.16b
  .long 0x5e104020                    // sha256h q0, q1, v16.4s
  .long 0x5e105041                    // sha256h2 q1, q2, v16.4s
  .long 0x5e056086                    // sha256su1 v6.4s, v4.4s, v5.4s
  .long 0x3cc10471                    // ldr q17, [x3], #16
  .long 0x4ea78631                    // add v17.4s, v17.4s, v7.4s
  .long 0x5e282887                    // sha256su0 v7.4s, v4.4s
  .long 0x4ea01c02                    // orr v2.16b, v0.16b, v0.16b
  .long 0x5e114020                    // sha256h q0, q1, v17.4s
  .long 0x5e115041                    // sha256h2 q1, q2, v17.4s
  .long 0x5e0660a7                    // sha256su1 v7.4s, v5.4s, v6.4s
  .long 0x3cc10470                    // ldr q16, [x3], #16
  .long 0x4ea48610                    // add v16.4s, v16.4s, v4.4s
  .long 0x4ea01c02                    // orr v2.16b, v0.16b, v0.16b
  .long 0x5e104020                    // sha256h q0, q1, v16.4s
  .long 0x5e105041                    // sha256h2 q1, q2, v16.4s
  .long 0x3cc10471                    // ldr q17, [x3], #16
  .long 0x4ea58631                    // add v17.4s, v17.4s, v5.4s
  .long 0x4ea01c02                    // orr v2.16b, v0.16b, v0.16b
  .long 0x5e114020                    // sha256h q0, q1, v17.4s
  .long 0x5e115041                    // sha256h2 q1, q2, v17.4s
  .long 0x3cc10470                    // ldr q16, [x3], #16
  .long 0x4ea68610                    // add v16.4s, v16.4s, v6.4s
  .long 0x4ea01c02                    // orr v2.16b, v0.16b, v0.16b
  .long 0x5e104020                    // sha256h q0, q1, v16.4s
  .long 0x5e105041                    // sha256h2 q1, q2, v16.4s
  .long 0x3dc00071                    // ldr q17, [x3]
  .long 0x4ea78631                    // add v17.4s, v17.4s, v7.4s
  .long 0x4ea01c02                    // orr v2.16b, v0.16b, v0.16b
  .long 0x5e114020                    // sha256h q0, q1, v17.4s
  .long 0x5e115041                    // sha256h2 q1, q2, v17.4s
  sub x3, x3, #240
  .long 0x4eb28400                    // add v0.4s, v0.4s, v18.4s
  .long 0x4eb38421                    // add v1.4s, v1.4s, v19.4s
  cbnz w2, .Lcryptoext_sha256_block_loop
  .long 0xad000400                    // stp q0, q1, [x0]
.Lcryptoext_sha256_done:
  ret
