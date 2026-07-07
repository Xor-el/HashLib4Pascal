// SHA-512 AArch64 FEAT_SHA512 implementation.
// Expects AAPCS64: x0 = state ptr (8 x UInt64), x1 = data ptr,
//   w2 = numblocks, x3 = K512 ptr (80 UInt64 round constants).
// Leaf nostackframe; caller-saved GPR/vector only.
// K pointer rewound each block (sub x3, #640). Two rounds per iteration; csel avoids OOB prefetch.
// Reference: OpenSSL CRYPTOGAMS sha512-armv8.S.
// AArch64 vector/crypto instructions are .long-encoded for broad assembler compatibility.
// Register map:
//   v0-v3    = working state (a..h, two UInt64 per register)
//   v5, v6   = ext scratch (fg, de)  v7 = ext scratch (m9_10)
//   v16-v23  = message schedule (W)
//   v24, v25 = K + W ping-pong pair
//   v26-v29  = saved state for the final add

  cbz w2, .Lcryptoext_sha512_done
  .long 0xacc14430                    // ldp q16, q17, [x1], #32
  .long 0xacc14c32                    // ldp q18, q19, [x1], #32
  .long 0xacc15434                    // ldp q20, q21, [x1], #32
  .long 0xacc15c36                    // ldp q22, q23, [x1], #32
  .long 0xad400400                    // ldp q0, q1, [x0]
  .long 0xad410c02                    // ldp q2, q3, [x0, #32]
  .long 0x4e200a10                    // rev64 v16.16b, v16.16b
  .long 0x4e200a31                    // rev64 v17.16b, v17.16b
  .long 0x4e200a52                    // rev64 v18.16b, v18.16b
  .long 0x4e200a73                    // rev64 v19.16b, v19.16b
  .long 0x4e200a94                    // rev64 v20.16b, v20.16b
  .long 0x4e200ab5                    // rev64 v21.16b, v21.16b
  .long 0x4e200ad6                    // rev64 v22.16b, v22.16b
  .long 0x4e200af7                    // rev64 v23.16b, v23.16b
.Lcryptoext_sha512_block_loop:
  .long 0x3cc10478                    // ldr q24, [x3], #16
  subs w2, w2, #1
  sub x4, x1, #128
  .long 0x4ea01c1a                    // orr v26.16b, v0.16b, v0.16b
  .long 0x4ea11c3b                    // orr v27.16b, v1.16b, v1.16b
  .long 0x4ea21c5c                    // orr v28.16b, v2.16b, v2.16b
  .long 0x4ea31c7d                    // orr v29.16b, v3.16b, v3.16b
  csel x1, x1, x4, ne
  .long 0x4ef08718                    // add v24.2d, v24.2d, v16.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e034045                    // ext v5.16b, v2.16b, v3.16b, #8
  .long 0x6e024026                    // ext v6.16b, v1.16b, v2.16b, #8
  .long 0x4ef88463                    // add v3.2d, v3.2d, v24.2d
  .long 0xcec08230                    // sha512su0 v16.2d, v17.2d
  .long 0x6e154287                    // ext v7.16b, v20.16b, v21.16b, #8
  .long 0xce6680a3                    // sha512h q3, q5, v6.2d
  .long 0xce678af0                    // sha512su1 v16.2d, v23.2d, v7.2d
  .long 0x4ee38424                    // add v4.2d, v1.2d, v3.2d
  .long 0xce608423                    // sha512h2 q3, q1, v0.2d
  .long 0x4ef18739                    // add v25.2d, v25.2d, v17.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e024085                    // ext v5.16b, v4.16b, v2.16b, #8
  .long 0x6e044006                    // ext v6.16b, v0.16b, v4.16b, #8
  .long 0x4ef98442                    // add v2.2d, v2.2d, v25.2d
  .long 0xcec08251                    // sha512su0 v17.2d, v18.2d
  .long 0x6e1642a7                    // ext v7.16b, v21.16b, v22.16b, #8
  .long 0xce6680a2                    // sha512h q2, q5, v6.2d
  .long 0xce678a11                    // sha512su1 v17.2d, v16.2d, v7.2d
  .long 0x4ee28401                    // add v1.2d, v0.2d, v2.2d
  .long 0xce638402                    // sha512h2 q2, q0, v3.2d
  .long 0x4ef28718                    // add v24.2d, v24.2d, v18.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e044025                    // ext v5.16b, v1.16b, v4.16b, #8
  .long 0x6e014066                    // ext v6.16b, v3.16b, v1.16b, #8
  .long 0x4ef88484                    // add v4.2d, v4.2d, v24.2d
  .long 0xcec08272                    // sha512su0 v18.2d, v19.2d
  .long 0x6e1742c7                    // ext v7.16b, v22.16b, v23.16b, #8
  .long 0xce6680a4                    // sha512h q4, q5, v6.2d
  .long 0xce678a32                    // sha512su1 v18.2d, v17.2d, v7.2d
  .long 0x4ee48460                    // add v0.2d, v3.2d, v4.2d
  .long 0xce628464                    // sha512h2 q4, q3, v2.2d
  .long 0x4ef38739                    // add v25.2d, v25.2d, v19.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e014005                    // ext v5.16b, v0.16b, v1.16b, #8
  .long 0x6e004046                    // ext v6.16b, v2.16b, v0.16b, #8
  .long 0x4ef98421                    // add v1.2d, v1.2d, v25.2d
  .long 0xcec08293                    // sha512su0 v19.2d, v20.2d
  .long 0x6e1042e7                    // ext v7.16b, v23.16b, v16.16b, #8
  .long 0xce6680a1                    // sha512h q1, q5, v6.2d
  .long 0xce678a53                    // sha512su1 v19.2d, v18.2d, v7.2d
  .long 0x4ee18443                    // add v3.2d, v2.2d, v1.2d
  .long 0xce648441                    // sha512h2 q1, q2, v4.2d
  .long 0x4ef48718                    // add v24.2d, v24.2d, v20.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e004065                    // ext v5.16b, v3.16b, v0.16b, #8
  .long 0x6e034086                    // ext v6.16b, v4.16b, v3.16b, #8
  .long 0x4ef88400                    // add v0.2d, v0.2d, v24.2d
  .long 0xcec082b4                    // sha512su0 v20.2d, v21.2d
  .long 0x6e114207                    // ext v7.16b, v16.16b, v17.16b, #8
  .long 0xce6680a0                    // sha512h q0, q5, v6.2d
  .long 0xce678a74                    // sha512su1 v20.2d, v19.2d, v7.2d
  .long 0x4ee08482                    // add v2.2d, v4.2d, v0.2d
  .long 0xce618480                    // sha512h2 q0, q4, v1.2d
  .long 0x4ef58739                    // add v25.2d, v25.2d, v21.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e034045                    // ext v5.16b, v2.16b, v3.16b, #8
  .long 0x6e024026                    // ext v6.16b, v1.16b, v2.16b, #8
  .long 0x4ef98463                    // add v3.2d, v3.2d, v25.2d
  .long 0xcec082d5                    // sha512su0 v21.2d, v22.2d
  .long 0x6e124227                    // ext v7.16b, v17.16b, v18.16b, #8
  .long 0xce6680a3                    // sha512h q3, q5, v6.2d
  .long 0xce678a95                    // sha512su1 v21.2d, v20.2d, v7.2d
  .long 0x4ee38424                    // add v4.2d, v1.2d, v3.2d
  .long 0xce608423                    // sha512h2 q3, q1, v0.2d
  .long 0x4ef68718                    // add v24.2d, v24.2d, v22.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e024085                    // ext v5.16b, v4.16b, v2.16b, #8
  .long 0x6e044006                    // ext v6.16b, v0.16b, v4.16b, #8
  .long 0x4ef88442                    // add v2.2d, v2.2d, v24.2d
  .long 0xcec082f6                    // sha512su0 v22.2d, v23.2d
  .long 0x6e134247                    // ext v7.16b, v18.16b, v19.16b, #8
  .long 0xce6680a2                    // sha512h q2, q5, v6.2d
  .long 0xce678ab6                    // sha512su1 v22.2d, v21.2d, v7.2d
  .long 0x4ee28401                    // add v1.2d, v0.2d, v2.2d
  .long 0xce638402                    // sha512h2 q2, q0, v3.2d
  .long 0x4ef78739                    // add v25.2d, v25.2d, v23.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e044025                    // ext v5.16b, v1.16b, v4.16b, #8
  .long 0x6e014066                    // ext v6.16b, v3.16b, v1.16b, #8
  .long 0x4ef98484                    // add v4.2d, v4.2d, v25.2d
  .long 0xcec08217                    // sha512su0 v23.2d, v16.2d
  .long 0x6e144267                    // ext v7.16b, v19.16b, v20.16b, #8
  .long 0xce6680a4                    // sha512h q4, q5, v6.2d
  .long 0xce678ad7                    // sha512su1 v23.2d, v22.2d, v7.2d
  .long 0x4ee48460                    // add v0.2d, v3.2d, v4.2d
  .long 0xce628464                    // sha512h2 q4, q3, v2.2d
  .long 0x4ef08718                    // add v24.2d, v24.2d, v16.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e014005                    // ext v5.16b, v0.16b, v1.16b, #8
  .long 0x6e004046                    // ext v6.16b, v2.16b, v0.16b, #8
  .long 0x4ef88421                    // add v1.2d, v1.2d, v24.2d
  .long 0xcec08230                    // sha512su0 v16.2d, v17.2d
  .long 0x6e154287                    // ext v7.16b, v20.16b, v21.16b, #8
  .long 0xce6680a1                    // sha512h q1, q5, v6.2d
  .long 0xce678af0                    // sha512su1 v16.2d, v23.2d, v7.2d
  .long 0x4ee18443                    // add v3.2d, v2.2d, v1.2d
  .long 0xce648441                    // sha512h2 q1, q2, v4.2d
  .long 0x4ef18739                    // add v25.2d, v25.2d, v17.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e004065                    // ext v5.16b, v3.16b, v0.16b, #8
  .long 0x6e034086                    // ext v6.16b, v4.16b, v3.16b, #8
  .long 0x4ef98400                    // add v0.2d, v0.2d, v25.2d
  .long 0xcec08251                    // sha512su0 v17.2d, v18.2d
  .long 0x6e1642a7                    // ext v7.16b, v21.16b, v22.16b, #8
  .long 0xce6680a0                    // sha512h q0, q5, v6.2d
  .long 0xce678a11                    // sha512su1 v17.2d, v16.2d, v7.2d
  .long 0x4ee08482                    // add v2.2d, v4.2d, v0.2d
  .long 0xce618480                    // sha512h2 q0, q4, v1.2d
  .long 0x4ef28718                    // add v24.2d, v24.2d, v18.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e034045                    // ext v5.16b, v2.16b, v3.16b, #8
  .long 0x6e024026                    // ext v6.16b, v1.16b, v2.16b, #8
  .long 0x4ef88463                    // add v3.2d, v3.2d, v24.2d
  .long 0xcec08272                    // sha512su0 v18.2d, v19.2d
  .long 0x6e1742c7                    // ext v7.16b, v22.16b, v23.16b, #8
  .long 0xce6680a3                    // sha512h q3, q5, v6.2d
  .long 0xce678a32                    // sha512su1 v18.2d, v17.2d, v7.2d
  .long 0x4ee38424                    // add v4.2d, v1.2d, v3.2d
  .long 0xce608423                    // sha512h2 q3, q1, v0.2d
  .long 0x4ef38739                    // add v25.2d, v25.2d, v19.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e024085                    // ext v5.16b, v4.16b, v2.16b, #8
  .long 0x6e044006                    // ext v6.16b, v0.16b, v4.16b, #8
  .long 0x4ef98442                    // add v2.2d, v2.2d, v25.2d
  .long 0xcec08293                    // sha512su0 v19.2d, v20.2d
  .long 0x6e1042e7                    // ext v7.16b, v23.16b, v16.16b, #8
  .long 0xce6680a2                    // sha512h q2, q5, v6.2d
  .long 0xce678a53                    // sha512su1 v19.2d, v18.2d, v7.2d
  .long 0x4ee28401                    // add v1.2d, v0.2d, v2.2d
  .long 0xce638402                    // sha512h2 q2, q0, v3.2d
  .long 0x4ef48718                    // add v24.2d, v24.2d, v20.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e044025                    // ext v5.16b, v1.16b, v4.16b, #8
  .long 0x6e014066                    // ext v6.16b, v3.16b, v1.16b, #8
  .long 0x4ef88484                    // add v4.2d, v4.2d, v24.2d
  .long 0xcec082b4                    // sha512su0 v20.2d, v21.2d
  .long 0x6e114207                    // ext v7.16b, v16.16b, v17.16b, #8
  .long 0xce6680a4                    // sha512h q4, q5, v6.2d
  .long 0xce678a74                    // sha512su1 v20.2d, v19.2d, v7.2d
  .long 0x4ee48460                    // add v0.2d, v3.2d, v4.2d
  .long 0xce628464                    // sha512h2 q4, q3, v2.2d
  .long 0x4ef58739                    // add v25.2d, v25.2d, v21.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e014005                    // ext v5.16b, v0.16b, v1.16b, #8
  .long 0x6e004046                    // ext v6.16b, v2.16b, v0.16b, #8
  .long 0x4ef98421                    // add v1.2d, v1.2d, v25.2d
  .long 0xcec082d5                    // sha512su0 v21.2d, v22.2d
  .long 0x6e124227                    // ext v7.16b, v17.16b, v18.16b, #8
  .long 0xce6680a1                    // sha512h q1, q5, v6.2d
  .long 0xce678a95                    // sha512su1 v21.2d, v20.2d, v7.2d
  .long 0x4ee18443                    // add v3.2d, v2.2d, v1.2d
  .long 0xce648441                    // sha512h2 q1, q2, v4.2d
  .long 0x4ef68718                    // add v24.2d, v24.2d, v22.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e004065                    // ext v5.16b, v3.16b, v0.16b, #8
  .long 0x6e034086                    // ext v6.16b, v4.16b, v3.16b, #8
  .long 0x4ef88400                    // add v0.2d, v0.2d, v24.2d
  .long 0xcec082f6                    // sha512su0 v22.2d, v23.2d
  .long 0x6e134247                    // ext v7.16b, v18.16b, v19.16b, #8
  .long 0xce6680a0                    // sha512h q0, q5, v6.2d
  .long 0xce678ab6                    // sha512su1 v22.2d, v21.2d, v7.2d
  .long 0x4ee08482                    // add v2.2d, v4.2d, v0.2d
  .long 0xce618480                    // sha512h2 q0, q4, v1.2d
  .long 0x4ef78739                    // add v25.2d, v25.2d, v23.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e034045                    // ext v5.16b, v2.16b, v3.16b, #8
  .long 0x6e024026                    // ext v6.16b, v1.16b, v2.16b, #8
  .long 0x4ef98463                    // add v3.2d, v3.2d, v25.2d
  .long 0xcec08217                    // sha512su0 v23.2d, v16.2d
  .long 0x6e144267                    // ext v7.16b, v19.16b, v20.16b, #8
  .long 0xce6680a3                    // sha512h q3, q5, v6.2d
  .long 0xce678ad7                    // sha512su1 v23.2d, v22.2d, v7.2d
  .long 0x4ee38424                    // add v4.2d, v1.2d, v3.2d
  .long 0xce608423                    // sha512h2 q3, q1, v0.2d
  .long 0x4ef08718                    // add v24.2d, v24.2d, v16.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e024085                    // ext v5.16b, v4.16b, v2.16b, #8
  .long 0x6e044006                    // ext v6.16b, v0.16b, v4.16b, #8
  .long 0x4ef88442                    // add v2.2d, v2.2d, v24.2d
  .long 0xcec08230                    // sha512su0 v16.2d, v17.2d
  .long 0x6e154287                    // ext v7.16b, v20.16b, v21.16b, #8
  .long 0xce6680a2                    // sha512h q2, q5, v6.2d
  .long 0xce678af0                    // sha512su1 v16.2d, v23.2d, v7.2d
  .long 0x4ee28401                    // add v1.2d, v0.2d, v2.2d
  .long 0xce638402                    // sha512h2 q2, q0, v3.2d
  .long 0x4ef18739                    // add v25.2d, v25.2d, v17.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e044025                    // ext v5.16b, v1.16b, v4.16b, #8
  .long 0x6e014066                    // ext v6.16b, v3.16b, v1.16b, #8
  .long 0x4ef98484                    // add v4.2d, v4.2d, v25.2d
  .long 0xcec08251                    // sha512su0 v17.2d, v18.2d
  .long 0x6e1642a7                    // ext v7.16b, v21.16b, v22.16b, #8
  .long 0xce6680a4                    // sha512h q4, q5, v6.2d
  .long 0xce678a11                    // sha512su1 v17.2d, v16.2d, v7.2d
  .long 0x4ee48460                    // add v0.2d, v3.2d, v4.2d
  .long 0xce628464                    // sha512h2 q4, q3, v2.2d
  .long 0x4ef28718                    // add v24.2d, v24.2d, v18.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e014005                    // ext v5.16b, v0.16b, v1.16b, #8
  .long 0x6e004046                    // ext v6.16b, v2.16b, v0.16b, #8
  .long 0x4ef88421                    // add v1.2d, v1.2d, v24.2d
  .long 0xcec08272                    // sha512su0 v18.2d, v19.2d
  .long 0x6e1742c7                    // ext v7.16b, v22.16b, v23.16b, #8
  .long 0xce6680a1                    // sha512h q1, q5, v6.2d
  .long 0xce678a32                    // sha512su1 v18.2d, v17.2d, v7.2d
  .long 0x4ee18443                    // add v3.2d, v2.2d, v1.2d
  .long 0xce648441                    // sha512h2 q1, q2, v4.2d
  .long 0x4ef38739                    // add v25.2d, v25.2d, v19.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e004065                    // ext v5.16b, v3.16b, v0.16b, #8
  .long 0x6e034086                    // ext v6.16b, v4.16b, v3.16b, #8
  .long 0x4ef98400                    // add v0.2d, v0.2d, v25.2d
  .long 0xcec08293                    // sha512su0 v19.2d, v20.2d
  .long 0x6e1042e7                    // ext v7.16b, v23.16b, v16.16b, #8
  .long 0xce6680a0                    // sha512h q0, q5, v6.2d
  .long 0xce678a53                    // sha512su1 v19.2d, v18.2d, v7.2d
  .long 0x4ee08482                    // add v2.2d, v4.2d, v0.2d
  .long 0xce618480                    // sha512h2 q0, q4, v1.2d
  .long 0x4ef48718                    // add v24.2d, v24.2d, v20.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e034045                    // ext v5.16b, v2.16b, v3.16b, #8
  .long 0x6e024026                    // ext v6.16b, v1.16b, v2.16b, #8
  .long 0x4ef88463                    // add v3.2d, v3.2d, v24.2d
  .long 0xcec082b4                    // sha512su0 v20.2d, v21.2d
  .long 0x6e114207                    // ext v7.16b, v16.16b, v17.16b, #8
  .long 0xce6680a3                    // sha512h q3, q5, v6.2d
  .long 0xce678a74                    // sha512su1 v20.2d, v19.2d, v7.2d
  .long 0x4ee38424                    // add v4.2d, v1.2d, v3.2d
  .long 0xce608423                    // sha512h2 q3, q1, v0.2d
  .long 0x4ef58739                    // add v25.2d, v25.2d, v21.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e024085                    // ext v5.16b, v4.16b, v2.16b, #8
  .long 0x6e044006                    // ext v6.16b, v0.16b, v4.16b, #8
  .long 0x4ef98442                    // add v2.2d, v2.2d, v25.2d
  .long 0xcec082d5                    // sha512su0 v21.2d, v22.2d
  .long 0x6e124227                    // ext v7.16b, v17.16b, v18.16b, #8
  .long 0xce6680a2                    // sha512h q2, q5, v6.2d
  .long 0xce678a95                    // sha512su1 v21.2d, v20.2d, v7.2d
  .long 0x4ee28401                    // add v1.2d, v0.2d, v2.2d
  .long 0xce638402                    // sha512h2 q2, q0, v3.2d
  .long 0x4ef68718                    // add v24.2d, v24.2d, v22.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e044025                    // ext v5.16b, v1.16b, v4.16b, #8
  .long 0x6e014066                    // ext v6.16b, v3.16b, v1.16b, #8
  .long 0x4ef88484                    // add v4.2d, v4.2d, v24.2d
  .long 0xcec082f6                    // sha512su0 v22.2d, v23.2d
  .long 0x6e134247                    // ext v7.16b, v18.16b, v19.16b, #8
  .long 0xce6680a4                    // sha512h q4, q5, v6.2d
  .long 0xce678ab6                    // sha512su1 v22.2d, v21.2d, v7.2d
  .long 0x4ee48460                    // add v0.2d, v3.2d, v4.2d
  .long 0xce628464                    // sha512h2 q4, q3, v2.2d
  .long 0x4ef78739                    // add v25.2d, v25.2d, v23.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e014005                    // ext v5.16b, v0.16b, v1.16b, #8
  .long 0x6e004046                    // ext v6.16b, v2.16b, v0.16b, #8
  .long 0x4ef98421                    // add v1.2d, v1.2d, v25.2d
  .long 0xcec08217                    // sha512su0 v23.2d, v16.2d
  .long 0x6e144267                    // ext v7.16b, v19.16b, v20.16b, #8
  .long 0xce6680a1                    // sha512h q1, q5, v6.2d
  .long 0xce678ad7                    // sha512su1 v23.2d, v22.2d, v7.2d
  .long 0x4ee18443                    // add v3.2d, v2.2d, v1.2d
  .long 0xce648441                    // sha512h2 q1, q2, v4.2d
  .long 0x4ef08718                    // add v24.2d, v24.2d, v16.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e004065                    // ext v5.16b, v3.16b, v0.16b, #8
  .long 0x6e034086                    // ext v6.16b, v4.16b, v3.16b, #8
  .long 0x4ef88400                    // add v0.2d, v0.2d, v24.2d
  .long 0xcec08230                    // sha512su0 v16.2d, v17.2d
  .long 0x6e154287                    // ext v7.16b, v20.16b, v21.16b, #8
  .long 0xce6680a0                    // sha512h q0, q5, v6.2d
  .long 0xce678af0                    // sha512su1 v16.2d, v23.2d, v7.2d
  .long 0x4ee08482                    // add v2.2d, v4.2d, v0.2d
  .long 0xce618480                    // sha512h2 q0, q4, v1.2d
  .long 0x4ef18739                    // add v25.2d, v25.2d, v17.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e034045                    // ext v5.16b, v2.16b, v3.16b, #8
  .long 0x6e024026                    // ext v6.16b, v1.16b, v2.16b, #8
  .long 0x4ef98463                    // add v3.2d, v3.2d, v25.2d
  .long 0xcec08251                    // sha512su0 v17.2d, v18.2d
  .long 0x6e1642a7                    // ext v7.16b, v21.16b, v22.16b, #8
  .long 0xce6680a3                    // sha512h q3, q5, v6.2d
  .long 0xce678a11                    // sha512su1 v17.2d, v16.2d, v7.2d
  .long 0x4ee38424                    // add v4.2d, v1.2d, v3.2d
  .long 0xce608423                    // sha512h2 q3, q1, v0.2d
  .long 0x4ef28718                    // add v24.2d, v24.2d, v18.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e024085                    // ext v5.16b, v4.16b, v2.16b, #8
  .long 0x6e044006                    // ext v6.16b, v0.16b, v4.16b, #8
  .long 0x4ef88442                    // add v2.2d, v2.2d, v24.2d
  .long 0xcec08272                    // sha512su0 v18.2d, v19.2d
  .long 0x6e1742c7                    // ext v7.16b, v22.16b, v23.16b, #8
  .long 0xce6680a2                    // sha512h q2, q5, v6.2d
  .long 0xce678a32                    // sha512su1 v18.2d, v17.2d, v7.2d
  .long 0x4ee28401                    // add v1.2d, v0.2d, v2.2d
  .long 0xce638402                    // sha512h2 q2, q0, v3.2d
  .long 0x4ef38739                    // add v25.2d, v25.2d, v19.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e044025                    // ext v5.16b, v1.16b, v4.16b, #8
  .long 0x6e014066                    // ext v6.16b, v3.16b, v1.16b, #8
  .long 0x4ef98484                    // add v4.2d, v4.2d, v25.2d
  .long 0xcec08293                    // sha512su0 v19.2d, v20.2d
  .long 0x6e1042e7                    // ext v7.16b, v23.16b, v16.16b, #8
  .long 0xce6680a4                    // sha512h q4, q5, v6.2d
  .long 0xce678a53                    // sha512su1 v19.2d, v18.2d, v7.2d
  .long 0x4ee48460                    // add v0.2d, v3.2d, v4.2d
  .long 0xce628464                    // sha512h2 q4, q3, v2.2d
  .long 0x4ef48718                    // add v24.2d, v24.2d, v20.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e014005                    // ext v5.16b, v0.16b, v1.16b, #8
  .long 0x6e004046                    // ext v6.16b, v2.16b, v0.16b, #8
  .long 0x4ef88421                    // add v1.2d, v1.2d, v24.2d
  .long 0xcec082b4                    // sha512su0 v20.2d, v21.2d
  .long 0x6e114207                    // ext v7.16b, v16.16b, v17.16b, #8
  .long 0xce6680a1                    // sha512h q1, q5, v6.2d
  .long 0xce678a74                    // sha512su1 v20.2d, v19.2d, v7.2d
  .long 0x4ee18443                    // add v3.2d, v2.2d, v1.2d
  .long 0xce648441                    // sha512h2 q1, q2, v4.2d
  .long 0x4ef58739                    // add v25.2d, v25.2d, v21.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e004065                    // ext v5.16b, v3.16b, v0.16b, #8
  .long 0x6e034086                    // ext v6.16b, v4.16b, v3.16b, #8
  .long 0x4ef98400                    // add v0.2d, v0.2d, v25.2d
  .long 0xcec082d5                    // sha512su0 v21.2d, v22.2d
  .long 0x6e124227                    // ext v7.16b, v17.16b, v18.16b, #8
  .long 0xce6680a0                    // sha512h q0, q5, v6.2d
  .long 0xce678a95                    // sha512su1 v21.2d, v20.2d, v7.2d
  .long 0x4ee08482                    // add v2.2d, v4.2d, v0.2d
  .long 0xce618480                    // sha512h2 q0, q4, v1.2d
  .long 0x4ef68718                    // add v24.2d, v24.2d, v22.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e034045                    // ext v5.16b, v2.16b, v3.16b, #8
  .long 0x6e024026                    // ext v6.16b, v1.16b, v2.16b, #8
  .long 0x4ef88463                    // add v3.2d, v3.2d, v24.2d
  .long 0xcec082f6                    // sha512su0 v22.2d, v23.2d
  .long 0x6e134247                    // ext v7.16b, v18.16b, v19.16b, #8
  .long 0xce6680a3                    // sha512h q3, q5, v6.2d
  .long 0xce678ab6                    // sha512su1 v22.2d, v21.2d, v7.2d
  .long 0x4ee38424                    // add v4.2d, v1.2d, v3.2d
  .long 0xce608423                    // sha512h2 q3, q1, v0.2d
  .long 0x4ef78739                    // add v25.2d, v25.2d, v23.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e024085                    // ext v5.16b, v4.16b, v2.16b, #8
  .long 0x6e044006                    // ext v6.16b, v0.16b, v4.16b, #8
  .long 0x4ef98442                    // add v2.2d, v2.2d, v25.2d
  .long 0xcec08217                    // sha512su0 v23.2d, v16.2d
  .long 0x6e144267                    // ext v7.16b, v19.16b, v20.16b, #8
  .long 0xce6680a2                    // sha512h q2, q5, v6.2d
  .long 0xce678ad7                    // sha512su1 v23.2d, v22.2d, v7.2d
  .long 0x4ee28401                    // add v1.2d, v0.2d, v2.2d
  .long 0xce638402                    // sha512h2 q2, q0, v3.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x4ef08718                    // add v24.2d, v24.2d, v16.2d
  .long 0x3cc10430                    // ldr q16, [x1], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e044025                    // ext v5.16b, v1.16b, v4.16b, #8
  .long 0x6e014066                    // ext v6.16b, v3.16b, v1.16b, #8
  .long 0x4ef88484                    // add v4.2d, v4.2d, v24.2d
  .long 0xce6680a4                    // sha512h q4, q5, v6.2d
  .long 0x4e200a10                    // rev64 v16.16b, v16.16b
  .long 0x4ee48460                    // add v0.2d, v3.2d, v4.2d
  .long 0xce628464                    // sha512h2 q4, q3, v2.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x4ef18739                    // add v25.2d, v25.2d, v17.2d
  .long 0x3cc10431                    // ldr q17, [x1], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e014005                    // ext v5.16b, v0.16b, v1.16b, #8
  .long 0x6e004046                    // ext v6.16b, v2.16b, v0.16b, #8
  .long 0x4ef98421                    // add v1.2d, v1.2d, v25.2d
  .long 0xce6680a1                    // sha512h q1, q5, v6.2d
  .long 0x4e200a31                    // rev64 v17.16b, v17.16b
  .long 0x4ee18443                    // add v3.2d, v2.2d, v1.2d
  .long 0xce648441                    // sha512h2 q1, q2, v4.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x4ef28718                    // add v24.2d, v24.2d, v18.2d
  .long 0x3cc10432                    // ldr q18, [x1], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e004065                    // ext v5.16b, v3.16b, v0.16b, #8
  .long 0x6e034086                    // ext v6.16b, v4.16b, v3.16b, #8
  .long 0x4ef88400                    // add v0.2d, v0.2d, v24.2d
  .long 0xce6680a0                    // sha512h q0, q5, v6.2d
  .long 0x4e200a52                    // rev64 v18.16b, v18.16b
  .long 0x4ee08482                    // add v2.2d, v4.2d, v0.2d
  .long 0xce618480                    // sha512h2 q0, q4, v1.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x4ef38739                    // add v25.2d, v25.2d, v19.2d
  .long 0x3cc10433                    // ldr q19, [x1], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e034045                    // ext v5.16b, v2.16b, v3.16b, #8
  .long 0x6e024026                    // ext v6.16b, v1.16b, v2.16b, #8
  .long 0x4ef98463                    // add v3.2d, v3.2d, v25.2d
  .long 0xce6680a3                    // sha512h q3, q5, v6.2d
  .long 0x4e200a73                    // rev64 v19.16b, v19.16b
  .long 0x4ee38424                    // add v4.2d, v1.2d, v3.2d
  .long 0xce608423                    // sha512h2 q3, q1, v0.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x4ef48718                    // add v24.2d, v24.2d, v20.2d
  .long 0x3cc10434                    // ldr q20, [x1], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e024085                    // ext v5.16b, v4.16b, v2.16b, #8
  .long 0x6e044006                    // ext v6.16b, v0.16b, v4.16b, #8
  .long 0x4ef88442                    // add v2.2d, v2.2d, v24.2d
  .long 0xce6680a2                    // sha512h q2, q5, v6.2d
  .long 0x4e200a94                    // rev64 v20.16b, v20.16b
  .long 0x4ee28401                    // add v1.2d, v0.2d, v2.2d
  .long 0xce638402                    // sha512h2 q2, q0, v3.2d
  .long 0x3cc10478                    // ldr q24, [x3], #16
  .long 0x4ef58739                    // add v25.2d, v25.2d, v21.2d
  .long 0x3cc10435                    // ldr q21, [x1], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e044025                    // ext v5.16b, v1.16b, v4.16b, #8
  .long 0x6e014066                    // ext v6.16b, v3.16b, v1.16b, #8
  .long 0x4ef98484                    // add v4.2d, v4.2d, v25.2d
  .long 0xce6680a4                    // sha512h q4, q5, v6.2d
  .long 0x4e200ab5                    // rev64 v21.16b, v21.16b
  .long 0x4ee48460                    // add v0.2d, v3.2d, v4.2d
  .long 0xce628464                    // sha512h2 q4, q3, v2.2d
  .long 0x3cc10479                    // ldr q25, [x3], #16
  .long 0x4ef68718                    // add v24.2d, v24.2d, v22.2d
  .long 0x3cc10436                    // ldr q22, [x1], #16
  .long 0x6e184318                    // ext v24.16b, v24.16b, v24.16b, #8
  .long 0x6e014005                    // ext v5.16b, v0.16b, v1.16b, #8
  .long 0x6e004046                    // ext v6.16b, v2.16b, v0.16b, #8
  .long 0x4ef88421                    // add v1.2d, v1.2d, v24.2d
  .long 0xce6680a1                    // sha512h q1, q5, v6.2d
  .long 0x4e200ad6                    // rev64 v22.16b, v22.16b
  .long 0x4ee18443                    // add v3.2d, v2.2d, v1.2d
  .long 0xce648441                    // sha512h2 q1, q2, v4.2d
  sub x3, x3, #640
  .long 0x4ef78739                    // add v25.2d, v25.2d, v23.2d
  .long 0x3cc10437                    // ldr q23, [x1], #16
  .long 0x6e194339                    // ext v25.16b, v25.16b, v25.16b, #8
  .long 0x6e004065                    // ext v5.16b, v3.16b, v0.16b, #8
  .long 0x6e034086                    // ext v6.16b, v4.16b, v3.16b, #8
  .long 0x4ef98400                    // add v0.2d, v0.2d, v25.2d
  .long 0xce6680a0                    // sha512h q0, q5, v6.2d
  .long 0x4e200af7                    // rev64 v23.16b, v23.16b
  .long 0x4ee08482                    // add v2.2d, v4.2d, v0.2d
  .long 0xce618480                    // sha512h2 q0, q4, v1.2d
  .long 0x4efa8400                    // add v0.2d, v0.2d, v26.2d
  .long 0x4efb8421                    // add v1.2d, v1.2d, v27.2d
  .long 0x4efc8442                    // add v2.2d, v2.2d, v28.2d
  .long 0x4efd8463                    // add v3.2d, v3.2d, v29.2d
  cbnz w2, .Lcryptoext_sha512_block_loop
  .long 0xad000400                    // stp q0, q1, [x0]
  .long 0xad010c02                    // stp q2, q3, [x0, #32]
.Lcryptoext_sha512_done:
  ret
