// NEON implementation of BLAKE2s compress (fully unrolled 10 rounds).
// ABI (after HlpSimdProc4Begin_aarch64.inc): x0 = state ptr (8 x UInt32),
//   x1 = message ptr (64 bytes), x2 = counter+flags ptr (16 bytes: t[0..1],
//   f[0..1]), x3 = IV ptr (8 x UInt32).
// Register map:
//   v0       = row1 (h[0..3] working)
//   v1       = row2 (h[4..7] working)
//   v2       = row3 (IV[0..3])
//   v3       = row4 (IV[4..7] XOR counter+flags)
//   v4-v7    = message block (16 x UInt32)
//   v16, v17 = saved initial row1/row2 for the final feed-forward XOR
//   v20      = message gather temp (G function)
//   v21-v23  = rotate temps (2-op ushr+sli rotates rename the rotated row
//     through them; rows return home before the final feed-forward)
// Saves: none (leaf nostackframe; caller-saved GPR/vector only).
// AArch64 vector instructions are .long-encoded for broad assembler compatibility.
// Reference: BLAKE2/BLAKE2 neon/blake2s-neon.c, HashLib
//   Blake2SCompressSse2_x86_64.inc.

  .long 0xad400400                    // ldp q0, q1, [x0]
  .long 0x4ea01c10                    // orr v16.16b, v0.16b, v0.16b
  .long 0x4ea11c31                    // orr v17.16b, v1.16b, v1.16b
  .long 0xad400c62                    // ldp q2, q3, [x3]
  .long 0x3dc00055                    // ldr q21, [x2]
  .long 0x6e351c63                    // eor v3.16b, v3.16b, v21.16b
  .long 0x4c402824                    // ld1 {v4.4s-v7.4s}, [x1]
  .long 0x6e040494                    // ins v20.s[0], v4.s[0]
  .long 0x6e0c4494                    // ins v20.s[1], v4.s[2]
  .long 0x6e1404b4                    // ins v20.s[2], v5.s[0]
  .long 0x6e1c44b4                    // ins v20.s[3], v5.s[2]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340435                    // ushr v21.4s, v1.4s, #12
  .long 0x6f345435                    // sli v21.4s, v1.4s, #20
  .long 0x6e042494                    // ins v20.s[0], v4.s[1]
  .long 0x6e0c6494                    // ins v20.s[1], v4.s[3]
  .long 0x6e1424b4                    // ins v20.s[2], v5.s[1]
  .long 0x6e1c64b4                    // ins v20.s[3], v5.s[3]
  .long 0x4eb58694                    // add v20.4s, v20.4s, v21.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380476                    // ushr v22.4s, v3.4s, #8
  .long 0x6f385476                    // sli v22.4s, v3.4s, #24
  .long 0x4eb68442                    // add v2.4s, v2.4s, v22.4s
  .long 0x6e221eb5                    // eor v21.16b, v21.16b, v2.16b
  .long 0x6f3906a1                    // ushr v1.4s, v21.4s, #7
  .long 0x6f3956a1                    // sli v1.4s, v21.4s, #25
  .long 0x6e012021                    // ext v1.16b, v1.16b, v1.16b, #4
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e1662d6                    // ext v22.16b, v22.16b, v22.16b, #12
  .long 0x6e0404d4                    // ins v20.s[0], v6.s[0]
  .long 0x6e0c44d4                    // ins v20.s[1], v6.s[2]
  .long 0x6e1404f4                    // ins v20.s[2], v7.s[0]
  .long 0x6e1c44f4                    // ins v20.s[3], v7.s[2]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201ed6                    // eor v22.16b, v22.16b, v0.16b
  .long 0x6e600ad6                    // rev32 v22.8h, v22.8h
  .long 0x4eb68442                    // add v2.4s, v2.4s, v22.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340423                    // ushr v3.4s, v1.4s, #12
  .long 0x6f345423                    // sli v3.4s, v1.4s, #20
  .long 0x6e0424d4                    // ins v20.s[0], v6.s[1]
  .long 0x6e0c64d4                    // ins v20.s[1], v6.s[3]
  .long 0x6e1424f4                    // ins v20.s[2], v7.s[1]
  .long 0x6e1c64f4                    // ins v20.s[3], v7.s[3]
  .long 0x4ea38694                    // add v20.4s, v20.4s, v3.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201ed6                    // eor v22.16b, v22.16b, v0.16b
  .long 0x6f3806d5                    // ushr v21.4s, v22.4s, #8
  .long 0x6f3856d5                    // sli v21.4s, v22.4s, #24
  .long 0x4eb58442                    // add v2.4s, v2.4s, v21.4s
  .long 0x6e221c63                    // eor v3.16b, v3.16b, v2.16b
  .long 0x6f390461                    // ushr v1.4s, v3.4s, #7
  .long 0x6f395461                    // sli v1.4s, v3.4s, #25
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e1522b5                    // ext v21.16b, v21.16b, v21.16b, #4
  .long 0x6e0444f4                    // ins v20.s[0], v7.s[2]
  .long 0x6e0c04b4                    // ins v20.s[1], v5.s[0]
  .long 0x6e1424d4                    // ins v20.s[2], v6.s[1]
  .long 0x6e1c24f4                    // ins v20.s[3], v7.s[1]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201eb5                    // eor v21.16b, v21.16b, v0.16b
  .long 0x6e600ab5                    // rev32 v21.8h, v21.8h
  .long 0x4eb58442                    // add v2.4s, v2.4s, v21.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340436                    // ushr v22.4s, v1.4s, #12
  .long 0x6f345436                    // sli v22.4s, v1.4s, #20
  .long 0x6e0444d4                    // ins v20.s[0], v6.s[2]
  .long 0x6e0c04d4                    // ins v20.s[1], v6.s[0]
  .long 0x6e1464f4                    // ins v20.s[2], v7.s[3]
  .long 0x6e1c44b4                    // ins v20.s[3], v5.s[2]
  .long 0x4eb68694                    // add v20.4s, v20.4s, v22.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201eb5                    // eor v21.16b, v21.16b, v0.16b
  .long 0x6f3806a3                    // ushr v3.4s, v21.4s, #8
  .long 0x6f3856a3                    // sli v3.4s, v21.4s, #24
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221ed6                    // eor v22.16b, v22.16b, v2.16b
  .long 0x6f3906c1                    // ushr v1.4s, v22.4s, #7
  .long 0x6f3956c1                    // sli v1.4s, v22.4s, #25
  .long 0x6e012021                    // ext v1.16b, v1.16b, v1.16b, #4
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e036063                    // ext v3.16b, v3.16b, v3.16b, #12
  .long 0x6e042494                    // ins v20.s[0], v4.s[1]
  .long 0x6e0c0494                    // ins v20.s[1], v4.s[0]
  .long 0x6e1464d4                    // ins v20.s[2], v6.s[3]
  .long 0x6e1c24b4                    // ins v20.s[3], v5.s[1]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340435                    // ushr v21.4s, v1.4s, #12
  .long 0x6f345435                    // sli v21.4s, v1.4s, #20
  .long 0x6e0404f4                    // ins v20.s[0], v7.s[0]
  .long 0x6e0c4494                    // ins v20.s[1], v4.s[2]
  .long 0x6e1464b4                    // ins v20.s[2], v5.s[3]
  .long 0x6e1c6494                    // ins v20.s[3], v4.s[3]
  .long 0x4eb58694                    // add v20.4s, v20.4s, v21.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380476                    // ushr v22.4s, v3.4s, #8
  .long 0x6f385476                    // sli v22.4s, v3.4s, #24
  .long 0x4eb68442                    // add v2.4s, v2.4s, v22.4s
  .long 0x6e221eb5                    // eor v21.16b, v21.16b, v2.16b
  .long 0x6f3906a1                    // ushr v1.4s, v21.4s, #7
  .long 0x6f3956a1                    // sli v1.4s, v21.4s, #25
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e1622d6                    // ext v22.16b, v22.16b, v22.16b, #4
  .long 0x6e0464d4                    // ins v20.s[0], v6.s[3]
  .long 0x6e0c04f4                    // ins v20.s[1], v7.s[0]
  .long 0x6e1424b4                    // ins v20.s[2], v5.s[1]
  .long 0x6e1c64f4                    // ins v20.s[3], v7.s[3]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201ed6                    // eor v22.16b, v22.16b, v0.16b
  .long 0x6e600ad6                    // rev32 v22.8h, v22.8h
  .long 0x4eb68442                    // add v2.4s, v2.4s, v22.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340423                    // ushr v3.4s, v1.4s, #12
  .long 0x6f345423                    // sli v3.4s, v1.4s, #20
  .long 0x6e0404d4                    // ins v20.s[0], v6.s[0]
  .long 0x6e0c0494                    // ins v20.s[1], v4.s[0]
  .long 0x6e144494                    // ins v20.s[2], v4.s[2]
  .long 0x6e1c24f4                    // ins v20.s[3], v7.s[1]
  .long 0x4ea38694                    // add v20.4s, v20.4s, v3.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201ed6                    // eor v22.16b, v22.16b, v0.16b
  .long 0x6f3806d5                    // ushr v21.4s, v22.4s, #8
  .long 0x6f3856d5                    // sli v21.4s, v22.4s, #24
  .long 0x4eb58442                    // add v2.4s, v2.4s, v21.4s
  .long 0x6e221c63                    // eor v3.16b, v3.16b, v2.16b
  .long 0x6f390461                    // ushr v1.4s, v3.4s, #7
  .long 0x6f395461                    // sli v1.4s, v3.4s, #25
  .long 0x6e012021                    // ext v1.16b, v1.16b, v1.16b, #4
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e1562b5                    // ext v21.16b, v21.16b, v21.16b, #12
  .long 0x6e0444d4                    // ins v20.s[0], v6.s[2]
  .long 0x6e0c6494                    // ins v20.s[1], v4.s[3]
  .long 0x6e1464b4                    // ins v20.s[2], v5.s[3]
  .long 0x6e1c24d4                    // ins v20.s[3], v6.s[1]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201eb5                    // eor v21.16b, v21.16b, v0.16b
  .long 0x6e600ab5                    // rev32 v21.8h, v21.8h
  .long 0x4eb58442                    // add v2.4s, v2.4s, v21.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340436                    // ushr v22.4s, v1.4s, #12
  .long 0x6f345436                    // sli v22.4s, v1.4s, #20
  .long 0x6e0444f4                    // ins v20.s[0], v7.s[2]
  .long 0x6e0c44b4                    // ins v20.s[1], v5.s[2]
  .long 0x6e142494                    // ins v20.s[2], v4.s[1]
  .long 0x6e1c04b4                    // ins v20.s[3], v5.s[0]
  .long 0x4eb68694                    // add v20.4s, v20.4s, v22.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201eb5                    // eor v21.16b, v21.16b, v0.16b
  .long 0x6f3806a3                    // ushr v3.4s, v21.4s, #8
  .long 0x6f3856a3                    // sli v3.4s, v21.4s, #24
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221ed6                    // eor v22.16b, v22.16b, v2.16b
  .long 0x6f3906c1                    // ushr v1.4s, v22.4s, #7
  .long 0x6f3956c1                    // sli v1.4s, v22.4s, #25
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e032063                    // ext v3.16b, v3.16b, v3.16b, #4
  .long 0x6e0464b4                    // ins v20.s[0], v5.s[3]
  .long 0x6e0c6494                    // ins v20.s[1], v4.s[3]
  .long 0x6e1424f4                    // ins v20.s[2], v7.s[1]
  .long 0x6e1c64d4                    // ins v20.s[3], v6.s[3]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340435                    // ushr v21.4s, v1.4s, #12
  .long 0x6f345435                    // sli v21.4s, v1.4s, #20
  .long 0x6e0424d4                    // ins v20.s[0], v6.s[1]
  .long 0x6e0c2494                    // ins v20.s[1], v4.s[1]
  .long 0x6e1404f4                    // ins v20.s[2], v7.s[0]
  .long 0x6e1c44f4                    // ins v20.s[3], v7.s[2]
  .long 0x4eb58694                    // add v20.4s, v20.4s, v21.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380476                    // ushr v22.4s, v3.4s, #8
  .long 0x6f385476                    // sli v22.4s, v3.4s, #24
  .long 0x4eb68442                    // add v2.4s, v2.4s, v22.4s
  .long 0x6e221eb5                    // eor v21.16b, v21.16b, v2.16b
  .long 0x6f3906a1                    // ushr v1.4s, v21.4s, #7
  .long 0x6f3956a1                    // sli v1.4s, v21.4s, #25
  .long 0x6e012021                    // ext v1.16b, v1.16b, v1.16b, #4
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e1662d6                    // ext v22.16b, v22.16b, v22.16b, #12
  .long 0x6e044494                    // ins v20.s[0], v4.s[2]
  .long 0x6e0c24b4                    // ins v20.s[1], v5.s[1]
  .long 0x6e1404b4                    // ins v20.s[2], v5.s[0]
  .long 0x6e1c64f4                    // ins v20.s[3], v7.s[3]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201ed6                    // eor v22.16b, v22.16b, v0.16b
  .long 0x6e600ad6                    // rev32 v22.8h, v22.8h
  .long 0x4eb68442                    // add v2.4s, v2.4s, v22.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340423                    // ushr v3.4s, v1.4s, #12
  .long 0x6f345423                    // sli v3.4s, v1.4s, #20
  .long 0x6e0444b4                    // ins v20.s[0], v5.s[2]
  .long 0x6e0c44d4                    // ins v20.s[1], v6.s[2]
  .long 0x6e140494                    // ins v20.s[2], v4.s[0]
  .long 0x6e1c04d4                    // ins v20.s[3], v6.s[0]
  .long 0x4ea38694                    // add v20.4s, v20.4s, v3.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201ed6                    // eor v22.16b, v22.16b, v0.16b
  .long 0x6f3806d5                    // ushr v21.4s, v22.4s, #8
  .long 0x6f3856d5                    // sli v21.4s, v22.4s, #24
  .long 0x4eb58442                    // add v2.4s, v2.4s, v21.4s
  .long 0x6e221c63                    // eor v3.16b, v3.16b, v2.16b
  .long 0x6f390461                    // ushr v1.4s, v3.4s, #7
  .long 0x6f395461                    // sli v1.4s, v3.4s, #25
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e1522b5                    // ext v21.16b, v21.16b, v21.16b, #4
  .long 0x6e0424d4                    // ins v20.s[0], v6.s[1]
  .long 0x6e0c24b4                    // ins v20.s[1], v5.s[1]
  .long 0x6e144494                    // ins v20.s[2], v4.s[2]
  .long 0x6e1c44d4                    // ins v20.s[3], v6.s[2]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201eb5                    // eor v21.16b, v21.16b, v0.16b
  .long 0x6e600ab5                    // rev32 v21.8h, v21.8h
  .long 0x4eb58442                    // add v2.4s, v2.4s, v21.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340436                    // ushr v22.4s, v1.4s, #12
  .long 0x6f345436                    // sli v22.4s, v1.4s, #20
  .long 0x6e040494                    // ins v20.s[0], v4.s[0]
  .long 0x6e0c64b4                    // ins v20.s[1], v5.s[3]
  .long 0x6e1404b4                    // ins v20.s[2], v5.s[0]
  .long 0x6e1c64f4                    // ins v20.s[3], v7.s[3]
  .long 0x4eb68694                    // add v20.4s, v20.4s, v22.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201eb5                    // eor v21.16b, v21.16b, v0.16b
  .long 0x6f3806a3                    // ushr v3.4s, v21.4s, #8
  .long 0x6f3856a3                    // sli v3.4s, v21.4s, #24
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221ed6                    // eor v22.16b, v22.16b, v2.16b
  .long 0x6f3906c1                    // ushr v1.4s, v22.4s, #7
  .long 0x6f3956c1                    // sli v1.4s, v22.4s, #25
  .long 0x6e012021                    // ext v1.16b, v1.16b, v1.16b, #4
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e036063                    // ext v3.16b, v3.16b, v3.16b, #12
  .long 0x6e0444f4                    // ins v20.s[0], v7.s[2]
  .long 0x6e0c64d4                    // ins v20.s[1], v6.s[3]
  .long 0x6e1444b4                    // ins v20.s[2], v5.s[2]
  .long 0x6e1c6494                    // ins v20.s[3], v4.s[3]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340435                    // ushr v21.4s, v1.4s, #12
  .long 0x6f345435                    // sli v21.4s, v1.4s, #20
  .long 0x6e042494                    // ins v20.s[0], v4.s[1]
  .long 0x6e0c04f4                    // ins v20.s[1], v7.s[0]
  .long 0x6e1404d4                    // ins v20.s[2], v6.s[0]
  .long 0x6e1c24f4                    // ins v20.s[3], v7.s[1]
  .long 0x4eb58694                    // add v20.4s, v20.4s, v21.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380476                    // ushr v22.4s, v3.4s, #8
  .long 0x6f385476                    // sli v22.4s, v3.4s, #24
  .long 0x4eb68442                    // add v2.4s, v2.4s, v22.4s
  .long 0x6e221eb5                    // eor v21.16b, v21.16b, v2.16b
  .long 0x6f3906a1                    // ushr v1.4s, v21.4s, #7
  .long 0x6f3956a1                    // sli v1.4s, v21.4s, #25
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e1622d6                    // ext v22.16b, v22.16b, v22.16b, #4
  .long 0x6e044494                    // ins v20.s[0], v4.s[2]
  .long 0x6e0c44b4                    // ins v20.s[1], v5.s[2]
  .long 0x6e140494                    // ins v20.s[2], v4.s[0]
  .long 0x6e1c04d4                    // ins v20.s[3], v6.s[0]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201ed6                    // eor v22.16b, v22.16b, v0.16b
  .long 0x6e600ad6                    // rev32 v22.8h, v22.8h
  .long 0x4eb68442                    // add v2.4s, v2.4s, v22.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340423                    // ushr v3.4s, v1.4s, #12
  .long 0x6f345423                    // sli v3.4s, v1.4s, #20
  .long 0x6e0404f4                    // ins v20.s[0], v7.s[0]
  .long 0x6e0c44d4                    // ins v20.s[1], v6.s[2]
  .long 0x6e1464d4                    // ins v20.s[2], v6.s[3]
  .long 0x6e1c6494                    // ins v20.s[3], v4.s[3]
  .long 0x4ea38694                    // add v20.4s, v20.4s, v3.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201ed6                    // eor v22.16b, v22.16b, v0.16b
  .long 0x6f3806d5                    // ushr v21.4s, v22.4s, #8
  .long 0x6f3856d5                    // sli v21.4s, v22.4s, #24
  .long 0x4eb58442                    // add v2.4s, v2.4s, v21.4s
  .long 0x6e221c63                    // eor v3.16b, v3.16b, v2.16b
  .long 0x6f390461                    // ushr v1.4s, v3.4s, #7
  .long 0x6f395461                    // sli v1.4s, v3.4s, #25
  .long 0x6e012021                    // ext v1.16b, v1.16b, v1.16b, #4
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e1562b5                    // ext v21.16b, v21.16b, v21.16b, #12
  .long 0x6e0404b4                    // ins v20.s[0], v5.s[0]
  .long 0x6e0c64b4                    // ins v20.s[1], v5.s[3]
  .long 0x6e1464f4                    // ins v20.s[2], v7.s[3]
  .long 0x6e1c2494                    // ins v20.s[3], v4.s[1]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201eb5                    // eor v21.16b, v21.16b, v0.16b
  .long 0x6e600ab5                    // rev32 v21.8h, v21.8h
  .long 0x4eb58442                    // add v2.4s, v2.4s, v21.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340436                    // ushr v22.4s, v1.4s, #12
  .long 0x6f345436                    // sli v22.4s, v1.4s, #20
  .long 0x6e0424f4                    // ins v20.s[0], v7.s[1]
  .long 0x6e0c24b4                    // ins v20.s[1], v5.s[1]
  .long 0x6e1444f4                    // ins v20.s[2], v7.s[2]
  .long 0x6e1c24d4                    // ins v20.s[3], v6.s[1]
  .long 0x4eb68694                    // add v20.4s, v20.4s, v22.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201eb5                    // eor v21.16b, v21.16b, v0.16b
  .long 0x6f3806a3                    // ushr v3.4s, v21.4s, #8
  .long 0x6f3856a3                    // sli v3.4s, v21.4s, #24
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221ed6                    // eor v22.16b, v22.16b, v2.16b
  .long 0x6f3906c1                    // ushr v1.4s, v22.4s, #7
  .long 0x6f3956c1                    // sli v1.4s, v22.4s, #25
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e032063                    // ext v3.16b, v3.16b, v3.16b, #4
  .long 0x6e0404f4                    // ins v20.s[0], v7.s[0]
  .long 0x6e0c2494                    // ins v20.s[1], v4.s[1]
  .long 0x6e1444f4                    // ins v20.s[2], v7.s[2]
  .long 0x6e1c04b4                    // ins v20.s[3], v5.s[0]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340435                    // ushr v21.4s, v1.4s, #12
  .long 0x6f345435                    // sli v21.4s, v1.4s, #20
  .long 0x6e0424b4                    // ins v20.s[0], v5.s[1]
  .long 0x6e0c64f4                    // ins v20.s[1], v7.s[3]
  .long 0x6e1424f4                    // ins v20.s[2], v7.s[1]
  .long 0x6e1c44d4                    // ins v20.s[3], v6.s[2]
  .long 0x4eb58694                    // add v20.4s, v20.4s, v21.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380476                    // ushr v22.4s, v3.4s, #8
  .long 0x6f385476                    // sli v22.4s, v3.4s, #24
  .long 0x4eb68442                    // add v2.4s, v2.4s, v22.4s
  .long 0x6e221eb5                    // eor v21.16b, v21.16b, v2.16b
  .long 0x6f3906a1                    // ushr v1.4s, v21.4s, #7
  .long 0x6f3956a1                    // sli v1.4s, v21.4s, #25
  .long 0x6e012021                    // ext v1.16b, v1.16b, v1.16b, #4
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e1662d6                    // ext v22.16b, v22.16b, v22.16b, #12
  .long 0x6e040494                    // ins v20.s[0], v4.s[0]
  .long 0x6e0c44b4                    // ins v20.s[1], v5.s[2]
  .long 0x6e1424d4                    // ins v20.s[2], v6.s[1]
  .long 0x6e1c04d4                    // ins v20.s[3], v6.s[0]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201ed6                    // eor v22.16b, v22.16b, v0.16b
  .long 0x6e600ad6                    // rev32 v22.8h, v22.8h
  .long 0x4eb68442                    // add v2.4s, v2.4s, v22.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340423                    // ushr v3.4s, v1.4s, #12
  .long 0x6f345423                    // sli v3.4s, v1.4s, #20
  .long 0x6e0464b4                    // ins v20.s[0], v5.s[3]
  .long 0x6e0c6494                    // ins v20.s[1], v4.s[3]
  .long 0x6e144494                    // ins v20.s[2], v4.s[2]
  .long 0x6e1c64d4                    // ins v20.s[3], v6.s[3]
  .long 0x4ea38694                    // add v20.4s, v20.4s, v3.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201ed6                    // eor v22.16b, v22.16b, v0.16b
  .long 0x6f3806d5                    // ushr v21.4s, v22.4s, #8
  .long 0x6f3856d5                    // sli v21.4s, v22.4s, #24
  .long 0x4eb58442                    // add v2.4s, v2.4s, v21.4s
  .long 0x6e221c63                    // eor v3.16b, v3.16b, v2.16b
  .long 0x6f390461                    // ushr v1.4s, v3.4s, #7
  .long 0x6f395461                    // sli v1.4s, v3.4s, #25
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e1522b5                    // ext v21.16b, v21.16b, v21.16b, #4
  .long 0x6e0424f4                    // ins v20.s[0], v7.s[1]
  .long 0x6e0c64b4                    // ins v20.s[1], v5.s[3]
  .long 0x6e1404f4                    // ins v20.s[2], v7.s[0]
  .long 0x6e1c6494                    // ins v20.s[3], v4.s[3]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201eb5                    // eor v21.16b, v21.16b, v0.16b
  .long 0x6e600ab5                    // rev32 v21.8h, v21.8h
  .long 0x4eb58442                    // add v2.4s, v2.4s, v21.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340436                    // ushr v22.4s, v1.4s, #12
  .long 0x6f345436                    // sli v22.4s, v1.4s, #20
  .long 0x6e0464d4                    // ins v20.s[0], v6.s[3]
  .long 0x6e0c44f4                    // ins v20.s[1], v7.s[2]
  .long 0x6e142494                    // ins v20.s[2], v4.s[1]
  .long 0x6e1c24d4                    // ins v20.s[3], v6.s[1]
  .long 0x4eb68694                    // add v20.4s, v20.4s, v22.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201eb5                    // eor v21.16b, v21.16b, v0.16b
  .long 0x6f3806a3                    // ushr v3.4s, v21.4s, #8
  .long 0x6f3856a3                    // sli v3.4s, v21.4s, #24
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221ed6                    // eor v22.16b, v22.16b, v2.16b
  .long 0x6f3906c1                    // ushr v1.4s, v22.4s, #7
  .long 0x6f3956c1                    // sli v1.4s, v22.4s, #25
  .long 0x6e012021                    // ext v1.16b, v1.16b, v1.16b, #4
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e036063                    // ext v3.16b, v3.16b, v3.16b, #12
  .long 0x6e0424b4                    // ins v20.s[0], v5.s[1]
  .long 0x6e0c64f4                    // ins v20.s[1], v7.s[3]
  .long 0x6e1404d4                    // ins v20.s[2], v6.s[0]
  .long 0x6e1c4494                    // ins v20.s[3], v4.s[2]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340435                    // ushr v21.4s, v1.4s, #12
  .long 0x6f345435                    // sli v21.4s, v1.4s, #20
  .long 0x6e040494                    // ins v20.s[0], v4.s[0]
  .long 0x6e0c04b4                    // ins v20.s[1], v5.s[0]
  .long 0x6e1444b4                    // ins v20.s[2], v5.s[2]
  .long 0x6e1c44d4                    // ins v20.s[3], v6.s[2]
  .long 0x4eb58694                    // add v20.4s, v20.4s, v21.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380476                    // ushr v22.4s, v3.4s, #8
  .long 0x6f385476                    // sli v22.4s, v3.4s, #24
  .long 0x4eb68442                    // add v2.4s, v2.4s, v22.4s
  .long 0x6e221eb5                    // eor v21.16b, v21.16b, v2.16b
  .long 0x6f3906a1                    // ushr v1.4s, v21.4s, #7
  .long 0x6f3956a1                    // sli v1.4s, v21.4s, #25
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e1622d6                    // ext v22.16b, v22.16b, v22.16b, #4
  .long 0x6e0444b4                    // ins v20.s[0], v5.s[2]
  .long 0x6e0c44f4                    // ins v20.s[1], v7.s[2]
  .long 0x6e1464d4                    // ins v20.s[2], v6.s[3]
  .long 0x6e1c0494                    // ins v20.s[3], v4.s[0]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201ed6                    // eor v22.16b, v22.16b, v0.16b
  .long 0x6e600ad6                    // rev32 v22.8h, v22.8h
  .long 0x4eb68442                    // add v2.4s, v2.4s, v22.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340423                    // ushr v3.4s, v1.4s, #12
  .long 0x6f345423                    // sli v3.4s, v1.4s, #20
  .long 0x6e0464f4                    // ins v20.s[0], v7.s[3]
  .long 0x6e0c24d4                    // ins v20.s[1], v6.s[1]
  .long 0x6e146494                    // ins v20.s[2], v4.s[3]
  .long 0x6e1c04d4                    // ins v20.s[3], v6.s[0]
  .long 0x4ea38694                    // add v20.4s, v20.4s, v3.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201ed6                    // eor v22.16b, v22.16b, v0.16b
  .long 0x6f3806d5                    // ushr v21.4s, v22.4s, #8
  .long 0x6f3856d5                    // sli v21.4s, v22.4s, #24
  .long 0x4eb58442                    // add v2.4s, v2.4s, v21.4s
  .long 0x6e221c63                    // eor v3.16b, v3.16b, v2.16b
  .long 0x6f390461                    // ushr v1.4s, v3.4s, #7
  .long 0x6f395461                    // sli v1.4s, v3.4s, #25
  .long 0x6e012021                    // ext v1.16b, v1.16b, v1.16b, #4
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e1562b5                    // ext v21.16b, v21.16b, v21.16b, #12
  .long 0x6e0404f4                    // ins v20.s[0], v7.s[0]
  .long 0x6e0c24f4                    // ins v20.s[1], v7.s[1]
  .long 0x6e142494                    // ins v20.s[2], v4.s[1]
  .long 0x6e1c44d4                    // ins v20.s[3], v6.s[2]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201eb5                    // eor v21.16b, v21.16b, v0.16b
  .long 0x6e600ab5                    // rev32 v21.8h, v21.8h
  .long 0x4eb58442                    // add v2.4s, v2.4s, v21.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340436                    // ushr v22.4s, v1.4s, #12
  .long 0x6f345436                    // sli v22.4s, v1.4s, #20
  .long 0x6e044494                    // ins v20.s[0], v4.s[2]
  .long 0x6e0c64b4                    // ins v20.s[1], v5.s[3]
  .long 0x6e1404b4                    // ins v20.s[2], v5.s[0]
  .long 0x6e1c24b4                    // ins v20.s[3], v5.s[1]
  .long 0x4eb68694                    // add v20.4s, v20.4s, v22.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201eb5                    // eor v21.16b, v21.16b, v0.16b
  .long 0x6f3806a3                    // ushr v3.4s, v21.4s, #8
  .long 0x6f3856a3                    // sli v3.4s, v21.4s, #24
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221ed6                    // eor v22.16b, v22.16b, v2.16b
  .long 0x6f3906c1                    // ushr v1.4s, v22.4s, #7
  .long 0x6f3956c1                    // sli v1.4s, v22.4s, #25
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e032063                    // ext v3.16b, v3.16b, v3.16b, #4
  .long 0x6e0444d4                    // ins v20.s[0], v6.s[2]
  .long 0x6e0c04d4                    // ins v20.s[1], v6.s[0]
  .long 0x6e1464b4                    // ins v20.s[2], v5.s[3]
  .long 0x6e1c2494                    // ins v20.s[3], v4.s[1]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340435                    // ushr v21.4s, v1.4s, #12
  .long 0x6f345435                    // sli v21.4s, v1.4s, #20
  .long 0x6e044494                    // ins v20.s[0], v4.s[2]
  .long 0x6e0c04b4                    // ins v20.s[1], v5.s[0]
  .long 0x6e1444b4                    // ins v20.s[2], v5.s[2]
  .long 0x6e1c24b4                    // ins v20.s[3], v5.s[1]
  .long 0x4eb58694                    // add v20.4s, v20.4s, v21.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380476                    // ushr v22.4s, v3.4s, #8
  .long 0x6f385476                    // sli v22.4s, v3.4s, #24
  .long 0x4eb68442                    // add v2.4s, v2.4s, v22.4s
  .long 0x6e221eb5                    // eor v21.16b, v21.16b, v2.16b
  .long 0x6f3906a1                    // ushr v1.4s, v21.4s, #7
  .long 0x6f3956a1                    // sli v1.4s, v21.4s, #25
  .long 0x6e012021                    // ext v1.16b, v1.16b, v1.16b, #4
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e1662d6                    // ext v22.16b, v22.16b, v22.16b, #12
  .long 0x6e0464f4                    // ins v20.s[0], v7.s[3]
  .long 0x6e0c24d4                    // ins v20.s[1], v6.s[1]
  .long 0x6e146494                    // ins v20.s[2], v4.s[3]
  .long 0x6e1c24f4                    // ins v20.s[3], v7.s[1]
  .long 0x4ea18694                    // add v20.4s, v20.4s, v1.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201ed6                    // eor v22.16b, v22.16b, v0.16b
  .long 0x6e600ad6                    // rev32 v22.8h, v22.8h
  .long 0x4eb68442                    // add v2.4s, v2.4s, v22.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x6f340423                    // ushr v3.4s, v1.4s, #12
  .long 0x6f345423                    // sli v3.4s, v1.4s, #20
  .long 0x6e0464d4                    // ins v20.s[0], v6.s[3]
  .long 0x6e0c44f4                    // ins v20.s[1], v7.s[2]
  .long 0x6e1404f4                    // ins v20.s[2], v7.s[0]
  .long 0x6e1c0494                    // ins v20.s[3], v4.s[0]
  .long 0x4ea38694                    // add v20.4s, v20.4s, v3.4s
  .long 0x4eb48400                    // add v0.4s, v0.4s, v20.4s
  .long 0x6e201ed6                    // eor v22.16b, v22.16b, v0.16b
  .long 0x6f3806d5                    // ushr v21.4s, v22.4s, #8
  .long 0x6f3856d5                    // sli v21.4s, v22.4s, #24
  .long 0x4eb58442                    // add v2.4s, v2.4s, v21.4s
  .long 0x6e221c63                    // eor v3.16b, v3.16b, v2.16b
  .long 0x6f390461                    // ushr v1.4s, v3.4s, #7
  .long 0x6f395461                    // sli v1.4s, v3.4s, #25
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e1522b5                    // ext v21.16b, v21.16b, v21.16b, #4
  .long 0x4eb51ea3                    // orr v3.16b, v21.16b, v21.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x6e201e00                    // eor v0.16b, v16.16b, v0.16b
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e211e21                    // eor v1.16b, v17.16b, v1.16b
  .long 0xad000400                    // stp q0, q1, [x0]
  ret
