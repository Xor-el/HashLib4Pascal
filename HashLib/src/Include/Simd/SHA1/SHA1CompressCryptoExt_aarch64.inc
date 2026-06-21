// SHA-1 ARMv8 Crypto Extensions.
// Expects AAPCS64: x0 = state, x1 = data, w2 = numblocks.
// K_SHA1 must be in scope in the including unit (HlpSHA1Dispatch.pas).
// FPC 3.2.2 cannot use adr/adrp on rodata in included asm — load K via PC-relative pool.
// Reference: OpenSSL CRYPTOGAMS sha1-armv8.S (sha1_block_armv8).
//
// FPC 3.2.2 inline asm limitation (see Lazarus forum topic 55289, svn rev 47116):
//   Subscripted vector regs (v0.4s, v1.s[0], ld1 {v0.4s}, …) require FPC 3.3+.
//   FPC 3.2.2 a64reg.dat exposes q0-q31 / s0-s31 for loads/stores only.
//
// Encoding strategy for FPC 3.2.2 compatibility (forum topics 52909, 70561; FPC #41196):
//   FPC 3.2.2 crashes on ldr/ldp/str/stp with qN/sN mnemonics — encode as .long.
//   .long for REV32, vector add/orr/eor, memory traffic, and FEAT_SHA1 crypto ops
//
// Register map:
//   q0 = ABCD; s4 = E (q1 lane 0)
//   x4 = K table pointer (OpenSSL sha1_block_armv8)
//   q2, q3 = sha1h ping-pong; q4-q7 = message schedule
//   q16-q19 = K constants; q20-q21 = W+K; q22 = saved ABCD

  cbz w2, .Lcryptoext_sha1_done
  ldr x4, .Lcryptoext_k_sha1
  b .Lcryptoext_k_sha1_loaded
  .balign 8
.Lcryptoext_k_sha1:
  .quad K_SHA1
.Lcryptoext_k_sha1_loaded:
  .long 0x4e611c21                    // eor q1, q1, q1
  .long 0x3dc00000                    // ldr q0, [x0]
  .long 0xbd401004                    // ldr s4, [x0, #16]
  .long 0xad404490                    // ldp q16, q17, [x4]
  .long 0xad414c92                    // ldp q18, q19, [x4, #32]

.Lcryptoext_sha1_block_loop:
  .long 0xacc11424                    // ldp q4, q5, [x1], #32
  .long 0xacc11c26                    // ldp q6, q7, [x1], #32
  sub w2, w2, #1
  .long 0x05c80284                    // rev32 q4, q4
  .long 0x05c802a5                    // rev32 q5, q5
  .long 0x4e24d614                    // add q20, q16, q4
  .long 0x05c802c6                    // rev32 q6, q6
  .long 0x4e201c16                    // orr q22, q0, q0
  .long 0x4e25d615                    // add q21, q16, q5
  .long 0x05c802e7                    // rev32 q7, q7
  .long 0x5e280803                    // sha1h v3.16b, v0.16b
  .long 0x5e140020                    // sha1c v0.16b, v1.16b, v20.4s
  .long 0x4e26d614                    // add q20, q16, q6
  .long 0x5e0630a4                    // sha1su0 v4.16b, v5.16b, v6.16b
  .long 0x5e280802                    // sha1h v2.16b, v0.16b
  .long 0x5e150060                    // sha1c v0.16b, v3.16b, v21.4s
  .long 0x4e27d615                    // add q21, q16, q7
  .long 0x5e2818e4                    // sha1su1 v4.16b, v7.16b
  .long 0x5e0730c5                    // sha1su0 v5.16b, v6.16b, v7.16b
  .long 0x5e280803                    // sha1h v3.16b, v0.16b
  .long 0x5e140040                    // sha1c v0.16b, v2.16b, v20.4s
  .long 0x4e24d614                    // add q20, q16, q4
  .long 0x5e281885                    // sha1su1 v5.16b, v4.16b
  .long 0x5e0430e6                    // sha1su0 v6.16b, v7.16b, v4.16b
  .long 0x5e280802                    // sha1h v2.16b, v0.16b
  .long 0x5e150060                    // sha1c v0.16b, v3.16b, v21.4s
  .long 0x4e25d635                    // add q21, q17, q5
  .long 0x5e2818a6                    // sha1su1 v6.16b, v5.16b
  .long 0x5e053087                    // sha1su0 v7.16b, v4.16b, v5.16b
  .long 0x5e280803                    // sha1h v3.16b, v0.16b
  .long 0x5e140040                    // sha1c v0.16b, v2.16b, v20.4s
  .long 0x4e26d634                    // add q20, q17, q6
  .long 0x5e2818c7                    // sha1su1 v7.16b, v6.16b
  .long 0x5e0630a4                    // sha1su0 v4.16b, v5.16b, v6.16b
  .long 0x5e280802                    // sha1h v2.16b, v0.16b
  .long 0x5e151060                    // sha1p v0.16b, v3.16b, v21.4s
  .long 0x4e27d635                    // add q21, q17, q7
  .long 0x5e2818e4                    // sha1su1 v4.16b, v7.16b
  .long 0x5e0730c5                    // sha1su0 v5.16b, v6.16b, v7.16b
  .long 0x5e280803                    // sha1h v3.16b, v0.16b
  .long 0x5e141040                    // sha1p v0.16b, v2.16b, v20.4s
  .long 0x4e24d634                    // add q20, q17, q4
  .long 0x5e281885                    // sha1su1 v5.16b, v4.16b
  .long 0x5e0430e6                    // sha1su0 v6.16b, v7.16b, v4.16b
  .long 0x5e280802                    // sha1h v2.16b, v0.16b
  .long 0x5e151060                    // sha1p v0.16b, v3.16b, v21.4s
  .long 0x4e25d635                    // add q21, q17, q5
  .long 0x5e2818a6                    // sha1su1 v6.16b, v5.16b
  .long 0x5e053087                    // sha1su0 v7.16b, v4.16b, v5.16b
  .long 0x5e280803                    // sha1h v3.16b, v0.16b
  .long 0x5e141040                    // sha1p v0.16b, v2.16b, v20.4s
  .long 0x4e26d654                    // add q20, q18, q6
  .long 0x5e2818c7                    // sha1su1 v7.16b, v6.16b
  .long 0x5e0630a4                    // sha1su0 v4.16b, v5.16b, v6.16b
  .long 0x5e280802                    // sha1h v2.16b, v0.16b
  .long 0x5e151060                    // sha1p v0.16b, v3.16b, v21.4s
  .long 0x4e27d655                    // add q21, q18, q7
  .long 0x5e2818e4                    // sha1su1 v4.16b, v7.16b
  .long 0x5e0730c5                    // sha1su0 v5.16b, v6.16b, v7.16b
  .long 0x5e280803                    // sha1h v3.16b, v0.16b
  .long 0x5e142040                    // sha1m v0.16b, v2.16b, v20.4s
  .long 0x4e24d654                    // add q20, q18, q4
  .long 0x5e281885                    // sha1su1 v5.16b, v4.16b
  .long 0x5e0430e6                    // sha1su0 v6.16b, v7.16b, v4.16b
  .long 0x5e280802                    // sha1h v2.16b, v0.16b
  .long 0x5e152060                    // sha1m v0.16b, v3.16b, v21.4s
  .long 0x4e25d655                    // add q21, q18, q5
  .long 0x5e2818a6                    // sha1su1 v6.16b, v5.16b
  .long 0x5e053087                    // sha1su0 v7.16b, v4.16b, v5.16b
  .long 0x5e280803                    // sha1h v3.16b, v0.16b
  .long 0x5e142040                    // sha1m v0.16b, v2.16b, v20.4s
  .long 0x4e26d654                    // add q20, q18, q6
  .long 0x5e2818c7                    // sha1su1 v7.16b, v6.16b
  .long 0x5e0630a4                    // sha1su0 v4.16b, v5.16b, v6.16b
  .long 0x5e280802                    // sha1h v2.16b, v0.16b
  .long 0x5e152060                    // sha1m v0.16b, v3.16b, v21.4s
  .long 0x4e27d675                    // add q21, q19, q7
  .long 0x5e2818e4                    // sha1su1 v4.16b, v7.16b
  .long 0x5e0730c5                    // sha1su0 v5.16b, v6.16b, v7.16b
  .long 0x5e280803                    // sha1h v3.16b, v0.16b
  .long 0x5e142040                    // sha1m v0.16b, v2.16b, v20.4s
  .long 0x4e24d674                    // add q20, q19, q4
  .long 0x5e281885                    // sha1su1 v5.16b, v4.16b
  .long 0x5e0430e6                    // sha1su0 v6.16b, v7.16b, v4.16b
  .long 0x5e280802                    // sha1h v2.16b, v0.16b
  .long 0x5e151060                    // sha1p v0.16b, v3.16b, v21.4s
  .long 0x4e25d675                    // add q21, q19, q5
  .long 0x5e2818a6                    // sha1su1 v6.16b, v5.16b
  .long 0x5e053087                    // sha1su0 v7.16b, v4.16b, v5.16b
  .long 0x5e280803                    // sha1h v3.16b, v0.16b
  .long 0x5e141040                    // sha1p v0.16b, v2.16b, v20.4s
  .long 0x4e26d674                    // add q20, q19, q6
  .long 0x5e2818c7                    // sha1su1 v7.16b, v6.16b
  .long 0x5e280802                    // sha1h v2.16b, v0.16b
  .long 0x5e151060                    // sha1p v0.16b, v3.16b, v21.4s
  .long 0x4e27d675                    // add q21, q19, q7
  .long 0x5e280803                    // sha1h v3.16b, v0.16b
  .long 0x5e141040                    // sha1p v0.16b, v2.16b, v20.4s
  .long 0x5e280802                    // sha1h v2.16b, v0.16b
  .long 0x5e151060                    // sha1p v0.16b, v3.16b, v21.4s
  .long 0x4e22d421                    // add q1, q1, q2
  .long 0x4e36d400                    // add q0, q0, q22
  cbnz w2, .Lcryptoext_sha1_block_loop
  .long 0x3d800000                    // str q0, [x0]
  .long 0xbd001004                    // str s4, [x0, #16]
  b .Lcryptoext_sha1_done
.Lcryptoext_sha1_done:
  ret
