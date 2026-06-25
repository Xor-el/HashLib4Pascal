// XXH3 initCustomSecret AArch64 NEON implementation (192-byte custom secret).
// Expects AAPCS64: x0 = customSecret ptr, x1 = defaultSecret ptr, x2 = seed (UInt64).
// Leaf nostackframe; caller-saved GPR/vector only.
// Reference: HashLib XXH3InitSecretSse2_x86_64.inc.
// AArch64 vector instructions are .long-encoded for broad assembler compatibility.
// Register map:
//   x3       = negated seed (-seed)
//   v0       = vSeed broadcast vector [seed, -seed]
//   v16-v17  = fmov staging for zip1 pack
//   v2       = defaultSecret block load / add temp
  neg x3, x2
  .long 0x9e670050                    // fmov d16, x2
  .long 0x9e670071                    // fmov d17, x3
  .long 0x4ed13a00                    // zip1 v0.2d, v16.2d, v17.2d
  // --- block 0: defaultSecret[0x0..] ---
  .long 0x3dc00022                    // ldr q2, [x1, #0x0]
  .long 0x4ee08442                    // add v2.2d, v2.2d, v0.2d
  .long 0x3d800002                    // str q2, [x0, #0x0]
  // --- block 1: defaultSecret[0x10..] ---
  .long 0x3dc00422                    // ldr q2, [x1, #0x10]
  .long 0x4ee08442                    // add v2.2d, v2.2d, v0.2d
  .long 0x3d800402                    // str q2, [x0, #0x10]
  // --- block 2: defaultSecret[0x20..] ---
  .long 0x3dc00822                    // ldr q2, [x1, #0x20]
  .long 0x4ee08442                    // add v2.2d, v2.2d, v0.2d
  .long 0x3d800802                    // str q2, [x0, #0x20]
  // --- block 3: defaultSecret[0x30..] ---
  .long 0x3dc00c22                    // ldr q2, [x1, #0x30]
  .long 0x4ee08442                    // add v2.2d, v2.2d, v0.2d
  .long 0x3d800c02                    // str q2, [x0, #0x30]
  // --- block 4: defaultSecret[0x40..] ---
  .long 0x3dc01022                    // ldr q2, [x1, #0x40]
  .long 0x4ee08442                    // add v2.2d, v2.2d, v0.2d
  .long 0x3d801002                    // str q2, [x0, #0x40]
  // --- block 5: defaultSecret[0x50..] ---
  .long 0x3dc01422                    // ldr q2, [x1, #0x50]
  .long 0x4ee08442                    // add v2.2d, v2.2d, v0.2d
  .long 0x3d801402                    // str q2, [x0, #0x50]
  // --- block 6: defaultSecret[0x60..] ---
  .long 0x3dc01822                    // ldr q2, [x1, #0x60]
  .long 0x4ee08442                    // add v2.2d, v2.2d, v0.2d
  .long 0x3d801802                    // str q2, [x0, #0x60]
  // --- block 7: defaultSecret[0x70..] ---
  .long 0x3dc01c22                    // ldr q2, [x1, #0x70]
  .long 0x4ee08442                    // add v2.2d, v2.2d, v0.2d
  .long 0x3d801c02                    // str q2, [x0, #0x70]
  // --- block 8: defaultSecret[0x80..] ---
  .long 0x3dc02022                    // ldr q2, [x1, #0x80]
  .long 0x4ee08442                    // add v2.2d, v2.2d, v0.2d
  .long 0x3d802002                    // str q2, [x0, #0x80]
  // --- block 9: defaultSecret[0x90..] ---
  .long 0x3dc02422                    // ldr q2, [x1, #0x90]
  .long 0x4ee08442                    // add v2.2d, v2.2d, v0.2d
  .long 0x3d802402                    // str q2, [x0, #0x90]
  // --- block 10: defaultSecret[0xa0..] ---
  .long 0x3dc02822                    // ldr q2, [x1, #0xa0]
  .long 0x4ee08442                    // add v2.2d, v2.2d, v0.2d
  .long 0x3d802802                    // str q2, [x0, #0xa0]
  // --- block 11: defaultSecret[0xb0..] ---
  .long 0x3dc02c22                    // ldr q2, [x1, #0xb0]
  .long 0x4ee08442                    // add v2.2d, v2.2d, v0.2d
  .long 0x3d802c02                    // str q2, [x0, #0xb0]
  ret
