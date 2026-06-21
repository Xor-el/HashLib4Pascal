// BLAKE3 compress AArch64 NEON implementation.
// Expects AAPCS64: x0 = state ptr (16 x UInt32), x1 = message ptr (64 bytes),
//   x2 = CV ptr (8 x UInt32), x3 = counter+flags ptr (16 bytes: t[0..1], len, flags).
// Reference: BLAKE3-team/BLAKE3 SSE2 compress; HashLib Blake3CompressSse2_x86_64.inc.
//
// Instruction encodings (for assembler compatibility):
//   FPC 3.2.2's inline assembler cannot encode AArch64 vector mnemonics
//   (subscripted vector regs require FPC 3.3+, and ldr/str/ldp with qN crash the
//   3.2.2 assembler). Each such instruction is therefore emitted as its raw 32-bit
//   '.long' opcode, with the equivalent mnemonic in the trailing comment; only
//   mov/sub/cbz/ret stay as text.
//
// Register map:
//   v0       = a (v[0..3])
//   v1       = b (v[4..7])
//   v2       = c (v[8..11], IV constants staged on stack)
//   v3       = d (v[12..15], counter+flags)
//   v4-v7    = message schedule registers m0..m3
//   v16-v17  = message permute temps
//   v18-v19  = rotate temps (vsri path)
//   v20      = permute temp (t14)
//   Stack: 16 bytes IV staging at [sp, #96] during prologue.

  sub sp, sp, #128
  .long 0x529ccceb                    // movz w11, #0xe667, lsl #0
  .long 0x72ad412b                    // movk w11, #0x6a09, lsl #16
  .long 0xb90063eb                    // str w11, [sp, #96]
  .long 0x5295d0ab                    // movz w11, #0xae85, lsl #0
  .long 0x72b76ceb                    // movk w11, #0xbb67, lsl #16
  .long 0xb90067eb                    // str w11, [sp, #100]
  .long 0x529e6e4b                    // movz w11, #0xf372, lsl #0
  .long 0x72a78dcb                    // movk w11, #0x3c6e, lsl #16
  .long 0xb9006beb                    // str w11, [sp, #104]
  .long 0x529ea74b                    // movz w11, #0xf53a, lsl #0
  .long 0x72b4a9eb                    // movk w11, #0xa54f, lsl #16
  .long 0xb9006feb                    // str w11, [sp, #108]
  .long 0x3dc01be2                    // ldr q2, [sp, #96]
  .long 0xad400440                    // ldp q0, q1, [x2]
  .long 0x3dc00063                    // ldr q3, [x3]
  .long 0x4c402824                    // ld1 {v4.4s-v7.4s}, [x1]
  .long 0x4ea41c90                    // orr v16.16b, v4.16b, v4.16b
  .long 0x6e040494                    // ins v20.s[0], v4.s[0]
  .long 0x6e0c4494                    // ins v20.s[1], v4.s[2]
  .long 0x6e1404b4                    // ins v20.s[2], v5.s[0]
  .long 0x6e1c44b4                    // ins v20.s[3], v5.s[2]
  .long 0x4eb41e84                    // orr v4.16b, v20.16b, v20.16b
  .long 0x6e042611                    // ins v17.s[0], v16.s[1]
  .long 0x6e0c6611                    // ins v17.s[1], v16.s[3]
  .long 0x6e1424b1                    // ins v17.s[2], v5.s[1]
  .long 0x6e1c64b1                    // ins v17.s[3], v5.s[3]
  .long 0x4eb11e25                    // orr v5.16b, v17.16b, v17.16b
  .long 0x4ea61cd0                    // orr v16.16b, v6.16b, v6.16b
  .long 0x6e0404d4                    // ins v20.s[0], v6.s[0]
  .long 0x6e0c44d4                    // ins v20.s[1], v6.s[2]
  .long 0x6e1404f4                    // ins v20.s[2], v7.s[0]
  .long 0x6e1c44f4                    // ins v20.s[3], v7.s[2]
  .long 0x4eb41e86                    // orr v6.16b, v20.16b, v20.16b
  .long 0x6e0464d4                    // ins v20.s[0], v6.s[3]
  .long 0x6e0c04d4                    // ins v20.s[1], v6.s[0]
  .long 0x6e1424d4                    // ins v20.s[2], v6.s[1]
  .long 0x6e1c44d4                    // ins v20.s[3], v6.s[2]
  .long 0x4eb41e86                    // orr v6.16b, v20.16b, v20.16b
  .long 0x6e042611                    // ins v17.s[0], v16.s[1]
  .long 0x6e0c6611                    // ins v17.s[1], v16.s[3]
  .long 0x6e1424f1                    // ins v17.s[2], v7.s[1]
  .long 0x6e1c64f1                    // ins v17.s[3], v7.s[3]
  .long 0x6e046627                    // ins v7.s[0], v17.s[3]
  .long 0x6e0c0627                    // ins v7.s[1], v17.s[0]
  .long 0x6e142627                    // ins v7.s[2], v17.s[1]
  .long 0x6e1c4627                    // ins v7.s[3], v17.s[2]
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f345652                    // shl v18.4s, v18.4s, #20
  .long 0x6f344432                    // sri v18.4s, v1.4s, #12
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380472                    // ushr v18.4s, v3.4s, #8
  .long 0x4f385473                    // shl v19.4s, v3.4s, #24
  .long 0x4eb31e43                    // orr v3.16b, v18.16b, v19.16b
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f395652                    // shl v18.4s, v18.4s, #25
  .long 0x6f394432                    // sri v18.4s, v1.4s, #7
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x6e046414                    // ins v20.s[0], v0.s[3]
  .long 0x6e0c0414                    // ins v20.s[1], v0.s[0]
  .long 0x6e142414                    // ins v20.s[2], v0.s[1]
  .long 0x6e1c4414                    // ins v20.s[3], v0.s[2]
  .long 0x4eb41e80                    // orr v0.16b, v20.16b, v20.16b
  .long 0x6e044474                    // ins v20.s[0], v3.s[2]
  .long 0x6e0c6474                    // ins v20.s[1], v3.s[3]
  .long 0x6e140474                    // ins v20.s[2], v3.s[0]
  .long 0x6e1c2474                    // ins v20.s[3], v3.s[1]
  .long 0x4eb41e83                    // orr v3.16b, v20.16b, v20.16b
  .long 0x6e042454                    // ins v20.s[0], v2.s[1]
  .long 0x6e0c4454                    // ins v20.s[1], v2.s[2]
  .long 0x6e146454                    // ins v20.s[2], v2.s[3]
  .long 0x6e1c0454                    // ins v20.s[3], v2.s[0]
  .long 0x4eb41e82                    // orr v2.16b, v20.16b, v20.16b
  .long 0x4ea68400                    // add v0.4s, v0.4s, v6.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f345652                    // shl v18.4s, v18.4s, #20
  .long 0x6f344432                    // sri v18.4s, v1.4s, #12
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x4ea78400                    // add v0.4s, v0.4s, v7.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380472                    // ushr v18.4s, v3.4s, #8
  .long 0x4f385473                    // shl v19.4s, v3.4s, #24
  .long 0x4eb31e43                    // orr v3.16b, v18.16b, v19.16b
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f395652                    // shl v18.4s, v18.4s, #25
  .long 0x6f394432                    // sri v18.4s, v1.4s, #7
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x6e042414                    // ins v20.s[0], v0.s[1]
  .long 0x6e0c4414                    // ins v20.s[1], v0.s[2]
  .long 0x6e146414                    // ins v20.s[2], v0.s[3]
  .long 0x6e1c0414                    // ins v20.s[3], v0.s[0]
  .long 0x4eb41e80                    // orr v0.16b, v20.16b, v20.16b
  .long 0x6e044474                    // ins v20.s[0], v3.s[2]
  .long 0x6e0c6474                    // ins v20.s[1], v3.s[3]
  .long 0x6e140474                    // ins v20.s[2], v3.s[0]
  .long 0x6e1c2474                    // ins v20.s[3], v3.s[1]
  .long 0x4eb41e83                    // orr v3.16b, v20.16b, v20.16b
  .long 0x6e046454                    // ins v20.s[0], v2.s[3]
  .long 0x6e0c0454                    // ins v20.s[1], v2.s[0]
  .long 0x6e142454                    // ins v20.s[2], v2.s[1]
  .long 0x6e1c4454                    // ins v20.s[3], v2.s[2]
  .long 0x4eb41e82                    // orr v2.16b, v20.16b, v20.16b
  .long 0x4ea41c90                    // orr v16.16b, v4.16b, v4.16b
  .long 0x6e044614                    // ins v20.s[0], v16.s[2]
  .long 0x6e0c2614                    // ins v20.s[1], v16.s[1]
  .long 0x6e1424b4                    // ins v20.s[2], v5.s[1]
  .long 0x6e1c64b4                    // ins v20.s[3], v5.s[3]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x4ea41c91                    // orr v17.16b, v4.16b, v4.16b
  .long 0x6e046634                    // ins v20.s[0], v17.s[3]
  .long 0x6e0c6634                    // ins v20.s[1], v17.s[3]
  .long 0x6e140634                    // ins v20.s[2], v17.s[0]
  .long 0x6e1c0634                    // ins v20.s[3], v17.s[0]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x6e042604                    // ins v4.s[0], v16.s[1]
  .long 0x6e0c4604                    // ins v4.s[1], v16.s[2]
  .long 0x6e146604                    // ins v4.s[2], v16.s[3]
  .long 0x6e1c0604                    // ins v4.s[3], v16.s[0]
  .long 0x4ea61cd0                    // orr v16.16b, v6.16b, v6.16b
  .long 0x6e044614                    // ins v20.s[0], v16.s[2]
  .long 0x6e0c4614                    // ins v20.s[1], v16.s[2]
  .long 0x6e1464f4                    // ins v20.s[2], v7.s[3]
  .long 0x6e1c64f4                    // ins v20.s[3], v7.s[3]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x6e040634                    // ins v20.s[0], v17.s[0]
  .long 0x6e0c4634                    // ins v20.s[1], v17.s[2]
  .long 0x6e142614                    // ins v20.s[2], v16.s[1]
  .long 0x6e1c6614                    // ins v20.s[3], v16.s[3]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x6e040634                    // ins v20.s[0], v17.s[0]
  .long 0x6e0c4634                    // ins v20.s[1], v17.s[2]
  .long 0x6e142634                    // ins v20.s[2], v17.s[1]
  .long 0x6e1c6634                    // ins v20.s[3], v17.s[3]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x4ea71cf0                    // orr v16.16b, v7.16b, v7.16b
  .long 0x4ec53a10                    // zip1 v16.2d, v16.2d, v5.2d
  .long 0x4e867a14                    // zip2 v20.4s, v16.4s, v6.4s
  .long 0x6e040611                    // ins v17.s[0], v16.s[0]
  .long 0x6e0c2611                    // ins v17.s[1], v16.s[1]
  .long 0x6e140691                    // ins v17.s[2], v20.s[0]
  .long 0x6e1c6691                    // ins v17.s[3], v20.s[3]
  .long 0x4eb11e30                    // orr v16.16b, v17.16b, v17.16b
  .long 0x6e040614                    // ins v20.s[0], v16.s[0]
  .long 0x6e0c4614                    // ins v20.s[1], v16.s[2]
  .long 0x6e146614                    // ins v20.s[2], v16.s[3]
  .long 0x6e1c2614                    // ins v20.s[3], v16.s[1]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x4e8778b4                    // zip2 v20.4s, v5.4s, v7.4s
  .long 0x4eb41e85                    // orr v5.16b, v20.16b, v20.16b
  .long 0x4e8538c6                    // zip1 v6.4s, v6.4s, v5.4s
  .long 0x6e0444c7                    // ins v7.s[0], v6.s[2]
  .long 0x6e0c64c7                    // ins v7.s[1], v6.s[3]
  .long 0x6e1424c7                    // ins v7.s[2], v6.s[1]
  .long 0x6e1c04c7                    // ins v7.s[3], v6.s[0]
  .long 0x4eb11e25                    // orr v5.16b, v17.16b, v17.16b
  .long 0x4eb01e06                    // orr v6.16b, v16.16b, v16.16b
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f345652                    // shl v18.4s, v18.4s, #20
  .long 0x6f344432                    // sri v18.4s, v1.4s, #12
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380472                    // ushr v18.4s, v3.4s, #8
  .long 0x4f385473                    // shl v19.4s, v3.4s, #24
  .long 0x4eb31e43                    // orr v3.16b, v18.16b, v19.16b
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f395652                    // shl v18.4s, v18.4s, #25
  .long 0x6f394432                    // sri v18.4s, v1.4s, #7
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x6e046414                    // ins v20.s[0], v0.s[3]
  .long 0x6e0c0414                    // ins v20.s[1], v0.s[0]
  .long 0x6e142414                    // ins v20.s[2], v0.s[1]
  .long 0x6e1c4414                    // ins v20.s[3], v0.s[2]
  .long 0x4eb41e80                    // orr v0.16b, v20.16b, v20.16b
  .long 0x6e044474                    // ins v20.s[0], v3.s[2]
  .long 0x6e0c6474                    // ins v20.s[1], v3.s[3]
  .long 0x6e140474                    // ins v20.s[2], v3.s[0]
  .long 0x6e1c2474                    // ins v20.s[3], v3.s[1]
  .long 0x4eb41e83                    // orr v3.16b, v20.16b, v20.16b
  .long 0x6e042454                    // ins v20.s[0], v2.s[1]
  .long 0x6e0c4454                    // ins v20.s[1], v2.s[2]
  .long 0x6e146454                    // ins v20.s[2], v2.s[3]
  .long 0x6e1c0454                    // ins v20.s[3], v2.s[0]
  .long 0x4eb41e82                    // orr v2.16b, v20.16b, v20.16b
  .long 0x4ea68400                    // add v0.4s, v0.4s, v6.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f345652                    // shl v18.4s, v18.4s, #20
  .long 0x6f344432                    // sri v18.4s, v1.4s, #12
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x4ea78400                    // add v0.4s, v0.4s, v7.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380472                    // ushr v18.4s, v3.4s, #8
  .long 0x4f385473                    // shl v19.4s, v3.4s, #24
  .long 0x4eb31e43                    // orr v3.16b, v18.16b, v19.16b
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f395652                    // shl v18.4s, v18.4s, #25
  .long 0x6f394432                    // sri v18.4s, v1.4s, #7
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x6e042414                    // ins v20.s[0], v0.s[1]
  .long 0x6e0c4414                    // ins v20.s[1], v0.s[2]
  .long 0x6e146414                    // ins v20.s[2], v0.s[3]
  .long 0x6e1c0414                    // ins v20.s[3], v0.s[0]
  .long 0x4eb41e80                    // orr v0.16b, v20.16b, v20.16b
  .long 0x6e044474                    // ins v20.s[0], v3.s[2]
  .long 0x6e0c6474                    // ins v20.s[1], v3.s[3]
  .long 0x6e140474                    // ins v20.s[2], v3.s[0]
  .long 0x6e1c2474                    // ins v20.s[3], v3.s[1]
  .long 0x4eb41e83                    // orr v3.16b, v20.16b, v20.16b
  .long 0x6e046454                    // ins v20.s[0], v2.s[3]
  .long 0x6e0c0454                    // ins v20.s[1], v2.s[0]
  .long 0x6e142454                    // ins v20.s[2], v2.s[1]
  .long 0x6e1c4454                    // ins v20.s[3], v2.s[2]
  .long 0x4eb41e82                    // orr v2.16b, v20.16b, v20.16b
  .long 0x4ea41c90                    // orr v16.16b, v4.16b, v4.16b
  .long 0x6e044614                    // ins v20.s[0], v16.s[2]
  .long 0x6e0c2614                    // ins v20.s[1], v16.s[1]
  .long 0x6e1424b4                    // ins v20.s[2], v5.s[1]
  .long 0x6e1c64b4                    // ins v20.s[3], v5.s[3]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x4ea41c91                    // orr v17.16b, v4.16b, v4.16b
  .long 0x6e046634                    // ins v20.s[0], v17.s[3]
  .long 0x6e0c6634                    // ins v20.s[1], v17.s[3]
  .long 0x6e140634                    // ins v20.s[2], v17.s[0]
  .long 0x6e1c0634                    // ins v20.s[3], v17.s[0]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x6e042604                    // ins v4.s[0], v16.s[1]
  .long 0x6e0c4604                    // ins v4.s[1], v16.s[2]
  .long 0x6e146604                    // ins v4.s[2], v16.s[3]
  .long 0x6e1c0604                    // ins v4.s[3], v16.s[0]
  .long 0x4ea61cd0                    // orr v16.16b, v6.16b, v6.16b
  .long 0x6e044614                    // ins v20.s[0], v16.s[2]
  .long 0x6e0c4614                    // ins v20.s[1], v16.s[2]
  .long 0x6e1464f4                    // ins v20.s[2], v7.s[3]
  .long 0x6e1c64f4                    // ins v20.s[3], v7.s[3]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x6e040634                    // ins v20.s[0], v17.s[0]
  .long 0x6e0c4634                    // ins v20.s[1], v17.s[2]
  .long 0x6e142614                    // ins v20.s[2], v16.s[1]
  .long 0x6e1c6614                    // ins v20.s[3], v16.s[3]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x6e040634                    // ins v20.s[0], v17.s[0]
  .long 0x6e0c4634                    // ins v20.s[1], v17.s[2]
  .long 0x6e142634                    // ins v20.s[2], v17.s[1]
  .long 0x6e1c6634                    // ins v20.s[3], v17.s[3]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x4ea71cf0                    // orr v16.16b, v7.16b, v7.16b
  .long 0x4ec53a10                    // zip1 v16.2d, v16.2d, v5.2d
  .long 0x4e867a14                    // zip2 v20.4s, v16.4s, v6.4s
  .long 0x6e040611                    // ins v17.s[0], v16.s[0]
  .long 0x6e0c2611                    // ins v17.s[1], v16.s[1]
  .long 0x6e140691                    // ins v17.s[2], v20.s[0]
  .long 0x6e1c6691                    // ins v17.s[3], v20.s[3]
  .long 0x4eb11e30                    // orr v16.16b, v17.16b, v17.16b
  .long 0x6e040614                    // ins v20.s[0], v16.s[0]
  .long 0x6e0c4614                    // ins v20.s[1], v16.s[2]
  .long 0x6e146614                    // ins v20.s[2], v16.s[3]
  .long 0x6e1c2614                    // ins v20.s[3], v16.s[1]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x4e8778b4                    // zip2 v20.4s, v5.4s, v7.4s
  .long 0x4eb41e85                    // orr v5.16b, v20.16b, v20.16b
  .long 0x4e8538c6                    // zip1 v6.4s, v6.4s, v5.4s
  .long 0x6e0444c7                    // ins v7.s[0], v6.s[2]
  .long 0x6e0c64c7                    // ins v7.s[1], v6.s[3]
  .long 0x6e1424c7                    // ins v7.s[2], v6.s[1]
  .long 0x6e1c04c7                    // ins v7.s[3], v6.s[0]
  .long 0x4eb11e25                    // orr v5.16b, v17.16b, v17.16b
  .long 0x4eb01e06                    // orr v6.16b, v16.16b, v16.16b
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f345652                    // shl v18.4s, v18.4s, #20
  .long 0x6f344432                    // sri v18.4s, v1.4s, #12
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380472                    // ushr v18.4s, v3.4s, #8
  .long 0x4f385473                    // shl v19.4s, v3.4s, #24
  .long 0x4eb31e43                    // orr v3.16b, v18.16b, v19.16b
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f395652                    // shl v18.4s, v18.4s, #25
  .long 0x6f394432                    // sri v18.4s, v1.4s, #7
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x6e046414                    // ins v20.s[0], v0.s[3]
  .long 0x6e0c0414                    // ins v20.s[1], v0.s[0]
  .long 0x6e142414                    // ins v20.s[2], v0.s[1]
  .long 0x6e1c4414                    // ins v20.s[3], v0.s[2]
  .long 0x4eb41e80                    // orr v0.16b, v20.16b, v20.16b
  .long 0x6e044474                    // ins v20.s[0], v3.s[2]
  .long 0x6e0c6474                    // ins v20.s[1], v3.s[3]
  .long 0x6e140474                    // ins v20.s[2], v3.s[0]
  .long 0x6e1c2474                    // ins v20.s[3], v3.s[1]
  .long 0x4eb41e83                    // orr v3.16b, v20.16b, v20.16b
  .long 0x6e042454                    // ins v20.s[0], v2.s[1]
  .long 0x6e0c4454                    // ins v20.s[1], v2.s[2]
  .long 0x6e146454                    // ins v20.s[2], v2.s[3]
  .long 0x6e1c0454                    // ins v20.s[3], v2.s[0]
  .long 0x4eb41e82                    // orr v2.16b, v20.16b, v20.16b
  .long 0x4ea68400                    // add v0.4s, v0.4s, v6.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f345652                    // shl v18.4s, v18.4s, #20
  .long 0x6f344432                    // sri v18.4s, v1.4s, #12
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x4ea78400                    // add v0.4s, v0.4s, v7.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380472                    // ushr v18.4s, v3.4s, #8
  .long 0x4f385473                    // shl v19.4s, v3.4s, #24
  .long 0x4eb31e43                    // orr v3.16b, v18.16b, v19.16b
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f395652                    // shl v18.4s, v18.4s, #25
  .long 0x6f394432                    // sri v18.4s, v1.4s, #7
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x6e042414                    // ins v20.s[0], v0.s[1]
  .long 0x6e0c4414                    // ins v20.s[1], v0.s[2]
  .long 0x6e146414                    // ins v20.s[2], v0.s[3]
  .long 0x6e1c0414                    // ins v20.s[3], v0.s[0]
  .long 0x4eb41e80                    // orr v0.16b, v20.16b, v20.16b
  .long 0x6e044474                    // ins v20.s[0], v3.s[2]
  .long 0x6e0c6474                    // ins v20.s[1], v3.s[3]
  .long 0x6e140474                    // ins v20.s[2], v3.s[0]
  .long 0x6e1c2474                    // ins v20.s[3], v3.s[1]
  .long 0x4eb41e83                    // orr v3.16b, v20.16b, v20.16b
  .long 0x6e046454                    // ins v20.s[0], v2.s[3]
  .long 0x6e0c0454                    // ins v20.s[1], v2.s[0]
  .long 0x6e142454                    // ins v20.s[2], v2.s[1]
  .long 0x6e1c4454                    // ins v20.s[3], v2.s[2]
  .long 0x4eb41e82                    // orr v2.16b, v20.16b, v20.16b
  .long 0x4ea41c90                    // orr v16.16b, v4.16b, v4.16b
  .long 0x6e044614                    // ins v20.s[0], v16.s[2]
  .long 0x6e0c2614                    // ins v20.s[1], v16.s[1]
  .long 0x6e1424b4                    // ins v20.s[2], v5.s[1]
  .long 0x6e1c64b4                    // ins v20.s[3], v5.s[3]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x4ea41c91                    // orr v17.16b, v4.16b, v4.16b
  .long 0x6e046634                    // ins v20.s[0], v17.s[3]
  .long 0x6e0c6634                    // ins v20.s[1], v17.s[3]
  .long 0x6e140634                    // ins v20.s[2], v17.s[0]
  .long 0x6e1c0634                    // ins v20.s[3], v17.s[0]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x6e042604                    // ins v4.s[0], v16.s[1]
  .long 0x6e0c4604                    // ins v4.s[1], v16.s[2]
  .long 0x6e146604                    // ins v4.s[2], v16.s[3]
  .long 0x6e1c0604                    // ins v4.s[3], v16.s[0]
  .long 0x4ea61cd0                    // orr v16.16b, v6.16b, v6.16b
  .long 0x6e044614                    // ins v20.s[0], v16.s[2]
  .long 0x6e0c4614                    // ins v20.s[1], v16.s[2]
  .long 0x6e1464f4                    // ins v20.s[2], v7.s[3]
  .long 0x6e1c64f4                    // ins v20.s[3], v7.s[3]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x6e040634                    // ins v20.s[0], v17.s[0]
  .long 0x6e0c4634                    // ins v20.s[1], v17.s[2]
  .long 0x6e142614                    // ins v20.s[2], v16.s[1]
  .long 0x6e1c6614                    // ins v20.s[3], v16.s[3]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x6e040634                    // ins v20.s[0], v17.s[0]
  .long 0x6e0c4634                    // ins v20.s[1], v17.s[2]
  .long 0x6e142634                    // ins v20.s[2], v17.s[1]
  .long 0x6e1c6634                    // ins v20.s[3], v17.s[3]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x4ea71cf0                    // orr v16.16b, v7.16b, v7.16b
  .long 0x4ec53a10                    // zip1 v16.2d, v16.2d, v5.2d
  .long 0x4e867a14                    // zip2 v20.4s, v16.4s, v6.4s
  .long 0x6e040611                    // ins v17.s[0], v16.s[0]
  .long 0x6e0c2611                    // ins v17.s[1], v16.s[1]
  .long 0x6e140691                    // ins v17.s[2], v20.s[0]
  .long 0x6e1c6691                    // ins v17.s[3], v20.s[3]
  .long 0x4eb11e30                    // orr v16.16b, v17.16b, v17.16b
  .long 0x6e040614                    // ins v20.s[0], v16.s[0]
  .long 0x6e0c4614                    // ins v20.s[1], v16.s[2]
  .long 0x6e146614                    // ins v20.s[2], v16.s[3]
  .long 0x6e1c2614                    // ins v20.s[3], v16.s[1]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x4e8778b4                    // zip2 v20.4s, v5.4s, v7.4s
  .long 0x4eb41e85                    // orr v5.16b, v20.16b, v20.16b
  .long 0x4e8538c6                    // zip1 v6.4s, v6.4s, v5.4s
  .long 0x6e0444c7                    // ins v7.s[0], v6.s[2]
  .long 0x6e0c64c7                    // ins v7.s[1], v6.s[3]
  .long 0x6e1424c7                    // ins v7.s[2], v6.s[1]
  .long 0x6e1c04c7                    // ins v7.s[3], v6.s[0]
  .long 0x4eb11e25                    // orr v5.16b, v17.16b, v17.16b
  .long 0x4eb01e06                    // orr v6.16b, v16.16b, v16.16b
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f345652                    // shl v18.4s, v18.4s, #20
  .long 0x6f344432                    // sri v18.4s, v1.4s, #12
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380472                    // ushr v18.4s, v3.4s, #8
  .long 0x4f385473                    // shl v19.4s, v3.4s, #24
  .long 0x4eb31e43                    // orr v3.16b, v18.16b, v19.16b
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f395652                    // shl v18.4s, v18.4s, #25
  .long 0x6f394432                    // sri v18.4s, v1.4s, #7
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x6e046414                    // ins v20.s[0], v0.s[3]
  .long 0x6e0c0414                    // ins v20.s[1], v0.s[0]
  .long 0x6e142414                    // ins v20.s[2], v0.s[1]
  .long 0x6e1c4414                    // ins v20.s[3], v0.s[2]
  .long 0x4eb41e80                    // orr v0.16b, v20.16b, v20.16b
  .long 0x6e044474                    // ins v20.s[0], v3.s[2]
  .long 0x6e0c6474                    // ins v20.s[1], v3.s[3]
  .long 0x6e140474                    // ins v20.s[2], v3.s[0]
  .long 0x6e1c2474                    // ins v20.s[3], v3.s[1]
  .long 0x4eb41e83                    // orr v3.16b, v20.16b, v20.16b
  .long 0x6e042454                    // ins v20.s[0], v2.s[1]
  .long 0x6e0c4454                    // ins v20.s[1], v2.s[2]
  .long 0x6e146454                    // ins v20.s[2], v2.s[3]
  .long 0x6e1c0454                    // ins v20.s[3], v2.s[0]
  .long 0x4eb41e82                    // orr v2.16b, v20.16b, v20.16b
  .long 0x4ea68400                    // add v0.4s, v0.4s, v6.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f345652                    // shl v18.4s, v18.4s, #20
  .long 0x6f344432                    // sri v18.4s, v1.4s, #12
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x4ea78400                    // add v0.4s, v0.4s, v7.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380472                    // ushr v18.4s, v3.4s, #8
  .long 0x4f385473                    // shl v19.4s, v3.4s, #24
  .long 0x4eb31e43                    // orr v3.16b, v18.16b, v19.16b
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f395652                    // shl v18.4s, v18.4s, #25
  .long 0x6f394432                    // sri v18.4s, v1.4s, #7
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x6e042414                    // ins v20.s[0], v0.s[1]
  .long 0x6e0c4414                    // ins v20.s[1], v0.s[2]
  .long 0x6e146414                    // ins v20.s[2], v0.s[3]
  .long 0x6e1c0414                    // ins v20.s[3], v0.s[0]
  .long 0x4eb41e80                    // orr v0.16b, v20.16b, v20.16b
  .long 0x6e044474                    // ins v20.s[0], v3.s[2]
  .long 0x6e0c6474                    // ins v20.s[1], v3.s[3]
  .long 0x6e140474                    // ins v20.s[2], v3.s[0]
  .long 0x6e1c2474                    // ins v20.s[3], v3.s[1]
  .long 0x4eb41e83                    // orr v3.16b, v20.16b, v20.16b
  .long 0x6e046454                    // ins v20.s[0], v2.s[3]
  .long 0x6e0c0454                    // ins v20.s[1], v2.s[0]
  .long 0x6e142454                    // ins v20.s[2], v2.s[1]
  .long 0x6e1c4454                    // ins v20.s[3], v2.s[2]
  .long 0x4eb41e82                    // orr v2.16b, v20.16b, v20.16b
  .long 0x4ea41c90                    // orr v16.16b, v4.16b, v4.16b
  .long 0x6e044614                    // ins v20.s[0], v16.s[2]
  .long 0x6e0c2614                    // ins v20.s[1], v16.s[1]
  .long 0x6e1424b4                    // ins v20.s[2], v5.s[1]
  .long 0x6e1c64b4                    // ins v20.s[3], v5.s[3]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x4ea41c91                    // orr v17.16b, v4.16b, v4.16b
  .long 0x6e046634                    // ins v20.s[0], v17.s[3]
  .long 0x6e0c6634                    // ins v20.s[1], v17.s[3]
  .long 0x6e140634                    // ins v20.s[2], v17.s[0]
  .long 0x6e1c0634                    // ins v20.s[3], v17.s[0]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x6e042604                    // ins v4.s[0], v16.s[1]
  .long 0x6e0c4604                    // ins v4.s[1], v16.s[2]
  .long 0x6e146604                    // ins v4.s[2], v16.s[3]
  .long 0x6e1c0604                    // ins v4.s[3], v16.s[0]
  .long 0x4ea61cd0                    // orr v16.16b, v6.16b, v6.16b
  .long 0x6e044614                    // ins v20.s[0], v16.s[2]
  .long 0x6e0c4614                    // ins v20.s[1], v16.s[2]
  .long 0x6e1464f4                    // ins v20.s[2], v7.s[3]
  .long 0x6e1c64f4                    // ins v20.s[3], v7.s[3]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x6e040634                    // ins v20.s[0], v17.s[0]
  .long 0x6e0c4634                    // ins v20.s[1], v17.s[2]
  .long 0x6e142614                    // ins v20.s[2], v16.s[1]
  .long 0x6e1c6614                    // ins v20.s[3], v16.s[3]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x6e040634                    // ins v20.s[0], v17.s[0]
  .long 0x6e0c4634                    // ins v20.s[1], v17.s[2]
  .long 0x6e142634                    // ins v20.s[2], v17.s[1]
  .long 0x6e1c6634                    // ins v20.s[3], v17.s[3]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x4ea71cf0                    // orr v16.16b, v7.16b, v7.16b
  .long 0x4ec53a10                    // zip1 v16.2d, v16.2d, v5.2d
  .long 0x4e867a14                    // zip2 v20.4s, v16.4s, v6.4s
  .long 0x6e040611                    // ins v17.s[0], v16.s[0]
  .long 0x6e0c2611                    // ins v17.s[1], v16.s[1]
  .long 0x6e140691                    // ins v17.s[2], v20.s[0]
  .long 0x6e1c6691                    // ins v17.s[3], v20.s[3]
  .long 0x4eb11e30                    // orr v16.16b, v17.16b, v17.16b
  .long 0x6e040614                    // ins v20.s[0], v16.s[0]
  .long 0x6e0c4614                    // ins v20.s[1], v16.s[2]
  .long 0x6e146614                    // ins v20.s[2], v16.s[3]
  .long 0x6e1c2614                    // ins v20.s[3], v16.s[1]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x4e8778b4                    // zip2 v20.4s, v5.4s, v7.4s
  .long 0x4eb41e85                    // orr v5.16b, v20.16b, v20.16b
  .long 0x4e8538c6                    // zip1 v6.4s, v6.4s, v5.4s
  .long 0x6e0444c7                    // ins v7.s[0], v6.s[2]
  .long 0x6e0c64c7                    // ins v7.s[1], v6.s[3]
  .long 0x6e1424c7                    // ins v7.s[2], v6.s[1]
  .long 0x6e1c04c7                    // ins v7.s[3], v6.s[0]
  .long 0x4eb11e25                    // orr v5.16b, v17.16b, v17.16b
  .long 0x4eb01e06                    // orr v6.16b, v16.16b, v16.16b
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f345652                    // shl v18.4s, v18.4s, #20
  .long 0x6f344432                    // sri v18.4s, v1.4s, #12
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380472                    // ushr v18.4s, v3.4s, #8
  .long 0x4f385473                    // shl v19.4s, v3.4s, #24
  .long 0x4eb31e43                    // orr v3.16b, v18.16b, v19.16b
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f395652                    // shl v18.4s, v18.4s, #25
  .long 0x6f394432                    // sri v18.4s, v1.4s, #7
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x6e046414                    // ins v20.s[0], v0.s[3]
  .long 0x6e0c0414                    // ins v20.s[1], v0.s[0]
  .long 0x6e142414                    // ins v20.s[2], v0.s[1]
  .long 0x6e1c4414                    // ins v20.s[3], v0.s[2]
  .long 0x4eb41e80                    // orr v0.16b, v20.16b, v20.16b
  .long 0x6e044474                    // ins v20.s[0], v3.s[2]
  .long 0x6e0c6474                    // ins v20.s[1], v3.s[3]
  .long 0x6e140474                    // ins v20.s[2], v3.s[0]
  .long 0x6e1c2474                    // ins v20.s[3], v3.s[1]
  .long 0x4eb41e83                    // orr v3.16b, v20.16b, v20.16b
  .long 0x6e042454                    // ins v20.s[0], v2.s[1]
  .long 0x6e0c4454                    // ins v20.s[1], v2.s[2]
  .long 0x6e146454                    // ins v20.s[2], v2.s[3]
  .long 0x6e1c0454                    // ins v20.s[3], v2.s[0]
  .long 0x4eb41e82                    // orr v2.16b, v20.16b, v20.16b
  .long 0x4ea68400                    // add v0.4s, v0.4s, v6.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f345652                    // shl v18.4s, v18.4s, #20
  .long 0x6f344432                    // sri v18.4s, v1.4s, #12
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x4ea78400                    // add v0.4s, v0.4s, v7.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380472                    // ushr v18.4s, v3.4s, #8
  .long 0x4f385473                    // shl v19.4s, v3.4s, #24
  .long 0x4eb31e43                    // orr v3.16b, v18.16b, v19.16b
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f395652                    // shl v18.4s, v18.4s, #25
  .long 0x6f394432                    // sri v18.4s, v1.4s, #7
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x6e042414                    // ins v20.s[0], v0.s[1]
  .long 0x6e0c4414                    // ins v20.s[1], v0.s[2]
  .long 0x6e146414                    // ins v20.s[2], v0.s[3]
  .long 0x6e1c0414                    // ins v20.s[3], v0.s[0]
  .long 0x4eb41e80                    // orr v0.16b, v20.16b, v20.16b
  .long 0x6e044474                    // ins v20.s[0], v3.s[2]
  .long 0x6e0c6474                    // ins v20.s[1], v3.s[3]
  .long 0x6e140474                    // ins v20.s[2], v3.s[0]
  .long 0x6e1c2474                    // ins v20.s[3], v3.s[1]
  .long 0x4eb41e83                    // orr v3.16b, v20.16b, v20.16b
  .long 0x6e046454                    // ins v20.s[0], v2.s[3]
  .long 0x6e0c0454                    // ins v20.s[1], v2.s[0]
  .long 0x6e142454                    // ins v20.s[2], v2.s[1]
  .long 0x6e1c4454                    // ins v20.s[3], v2.s[2]
  .long 0x4eb41e82                    // orr v2.16b, v20.16b, v20.16b
  .long 0x4ea41c90                    // orr v16.16b, v4.16b, v4.16b
  .long 0x6e044614                    // ins v20.s[0], v16.s[2]
  .long 0x6e0c2614                    // ins v20.s[1], v16.s[1]
  .long 0x6e1424b4                    // ins v20.s[2], v5.s[1]
  .long 0x6e1c64b4                    // ins v20.s[3], v5.s[3]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x4ea41c91                    // orr v17.16b, v4.16b, v4.16b
  .long 0x6e046634                    // ins v20.s[0], v17.s[3]
  .long 0x6e0c6634                    // ins v20.s[1], v17.s[3]
  .long 0x6e140634                    // ins v20.s[2], v17.s[0]
  .long 0x6e1c0634                    // ins v20.s[3], v17.s[0]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x6e042604                    // ins v4.s[0], v16.s[1]
  .long 0x6e0c4604                    // ins v4.s[1], v16.s[2]
  .long 0x6e146604                    // ins v4.s[2], v16.s[3]
  .long 0x6e1c0604                    // ins v4.s[3], v16.s[0]
  .long 0x4ea61cd0                    // orr v16.16b, v6.16b, v6.16b
  .long 0x6e044614                    // ins v20.s[0], v16.s[2]
  .long 0x6e0c4614                    // ins v20.s[1], v16.s[2]
  .long 0x6e1464f4                    // ins v20.s[2], v7.s[3]
  .long 0x6e1c64f4                    // ins v20.s[3], v7.s[3]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x6e040634                    // ins v20.s[0], v17.s[0]
  .long 0x6e0c4634                    // ins v20.s[1], v17.s[2]
  .long 0x6e142614                    // ins v20.s[2], v16.s[1]
  .long 0x6e1c6614                    // ins v20.s[3], v16.s[3]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x6e040634                    // ins v20.s[0], v17.s[0]
  .long 0x6e0c4634                    // ins v20.s[1], v17.s[2]
  .long 0x6e142634                    // ins v20.s[2], v17.s[1]
  .long 0x6e1c6634                    // ins v20.s[3], v17.s[3]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x4ea71cf0                    // orr v16.16b, v7.16b, v7.16b
  .long 0x4ec53a10                    // zip1 v16.2d, v16.2d, v5.2d
  .long 0x4e867a14                    // zip2 v20.4s, v16.4s, v6.4s
  .long 0x6e040611                    // ins v17.s[0], v16.s[0]
  .long 0x6e0c2611                    // ins v17.s[1], v16.s[1]
  .long 0x6e140691                    // ins v17.s[2], v20.s[0]
  .long 0x6e1c6691                    // ins v17.s[3], v20.s[3]
  .long 0x4eb11e30                    // orr v16.16b, v17.16b, v17.16b
  .long 0x6e040614                    // ins v20.s[0], v16.s[0]
  .long 0x6e0c4614                    // ins v20.s[1], v16.s[2]
  .long 0x6e146614                    // ins v20.s[2], v16.s[3]
  .long 0x6e1c2614                    // ins v20.s[3], v16.s[1]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x4e8778b4                    // zip2 v20.4s, v5.4s, v7.4s
  .long 0x4eb41e85                    // orr v5.16b, v20.16b, v20.16b
  .long 0x4e8538c6                    // zip1 v6.4s, v6.4s, v5.4s
  .long 0x6e0444c7                    // ins v7.s[0], v6.s[2]
  .long 0x6e0c64c7                    // ins v7.s[1], v6.s[3]
  .long 0x6e1424c7                    // ins v7.s[2], v6.s[1]
  .long 0x6e1c04c7                    // ins v7.s[3], v6.s[0]
  .long 0x4eb11e25                    // orr v5.16b, v17.16b, v17.16b
  .long 0x4eb01e06                    // orr v6.16b, v16.16b, v16.16b
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f345652                    // shl v18.4s, v18.4s, #20
  .long 0x6f344432                    // sri v18.4s, v1.4s, #12
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380472                    // ushr v18.4s, v3.4s, #8
  .long 0x4f385473                    // shl v19.4s, v3.4s, #24
  .long 0x4eb31e43                    // orr v3.16b, v18.16b, v19.16b
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f395652                    // shl v18.4s, v18.4s, #25
  .long 0x6f394432                    // sri v18.4s, v1.4s, #7
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x6e046414                    // ins v20.s[0], v0.s[3]
  .long 0x6e0c0414                    // ins v20.s[1], v0.s[0]
  .long 0x6e142414                    // ins v20.s[2], v0.s[1]
  .long 0x6e1c4414                    // ins v20.s[3], v0.s[2]
  .long 0x4eb41e80                    // orr v0.16b, v20.16b, v20.16b
  .long 0x6e044474                    // ins v20.s[0], v3.s[2]
  .long 0x6e0c6474                    // ins v20.s[1], v3.s[3]
  .long 0x6e140474                    // ins v20.s[2], v3.s[0]
  .long 0x6e1c2474                    // ins v20.s[3], v3.s[1]
  .long 0x4eb41e83                    // orr v3.16b, v20.16b, v20.16b
  .long 0x6e042454                    // ins v20.s[0], v2.s[1]
  .long 0x6e0c4454                    // ins v20.s[1], v2.s[2]
  .long 0x6e146454                    // ins v20.s[2], v2.s[3]
  .long 0x6e1c0454                    // ins v20.s[3], v2.s[0]
  .long 0x4eb41e82                    // orr v2.16b, v20.16b, v20.16b
  .long 0x4ea68400                    // add v0.4s, v0.4s, v6.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f345652                    // shl v18.4s, v18.4s, #20
  .long 0x6f344432                    // sri v18.4s, v1.4s, #12
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x4ea78400                    // add v0.4s, v0.4s, v7.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380472                    // ushr v18.4s, v3.4s, #8
  .long 0x4f385473                    // shl v19.4s, v3.4s, #24
  .long 0x4eb31e43                    // orr v3.16b, v18.16b, v19.16b
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f395652                    // shl v18.4s, v18.4s, #25
  .long 0x6f394432                    // sri v18.4s, v1.4s, #7
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x6e042414                    // ins v20.s[0], v0.s[1]
  .long 0x6e0c4414                    // ins v20.s[1], v0.s[2]
  .long 0x6e146414                    // ins v20.s[2], v0.s[3]
  .long 0x6e1c0414                    // ins v20.s[3], v0.s[0]
  .long 0x4eb41e80                    // orr v0.16b, v20.16b, v20.16b
  .long 0x6e044474                    // ins v20.s[0], v3.s[2]
  .long 0x6e0c6474                    // ins v20.s[1], v3.s[3]
  .long 0x6e140474                    // ins v20.s[2], v3.s[0]
  .long 0x6e1c2474                    // ins v20.s[3], v3.s[1]
  .long 0x4eb41e83                    // orr v3.16b, v20.16b, v20.16b
  .long 0x6e046454                    // ins v20.s[0], v2.s[3]
  .long 0x6e0c0454                    // ins v20.s[1], v2.s[0]
  .long 0x6e142454                    // ins v20.s[2], v2.s[1]
  .long 0x6e1c4454                    // ins v20.s[3], v2.s[2]
  .long 0x4eb41e82                    // orr v2.16b, v20.16b, v20.16b
  .long 0x4ea41c90                    // orr v16.16b, v4.16b, v4.16b
  .long 0x6e044614                    // ins v20.s[0], v16.s[2]
  .long 0x6e0c2614                    // ins v20.s[1], v16.s[1]
  .long 0x6e1424b4                    // ins v20.s[2], v5.s[1]
  .long 0x6e1c64b4                    // ins v20.s[3], v5.s[3]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x4ea41c91                    // orr v17.16b, v4.16b, v4.16b
  .long 0x6e046634                    // ins v20.s[0], v17.s[3]
  .long 0x6e0c6634                    // ins v20.s[1], v17.s[3]
  .long 0x6e140634                    // ins v20.s[2], v17.s[0]
  .long 0x6e1c0634                    // ins v20.s[3], v17.s[0]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x6e042604                    // ins v4.s[0], v16.s[1]
  .long 0x6e0c4604                    // ins v4.s[1], v16.s[2]
  .long 0x6e146604                    // ins v4.s[2], v16.s[3]
  .long 0x6e1c0604                    // ins v4.s[3], v16.s[0]
  .long 0x4ea61cd0                    // orr v16.16b, v6.16b, v6.16b
  .long 0x6e044614                    // ins v20.s[0], v16.s[2]
  .long 0x6e0c4614                    // ins v20.s[1], v16.s[2]
  .long 0x6e1464f4                    // ins v20.s[2], v7.s[3]
  .long 0x6e1c64f4                    // ins v20.s[3], v7.s[3]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x6e040634                    // ins v20.s[0], v17.s[0]
  .long 0x6e0c4634                    // ins v20.s[1], v17.s[2]
  .long 0x6e142614                    // ins v20.s[2], v16.s[1]
  .long 0x6e1c6614                    // ins v20.s[3], v16.s[3]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x6e040634                    // ins v20.s[0], v17.s[0]
  .long 0x6e0c4634                    // ins v20.s[1], v17.s[2]
  .long 0x6e142634                    // ins v20.s[2], v17.s[1]
  .long 0x6e1c6634                    // ins v20.s[3], v17.s[3]
  .long 0x4eb41e91                    // orr v17.16b, v20.16b, v20.16b
  .long 0x4ea71cf0                    // orr v16.16b, v7.16b, v7.16b
  .long 0x4ec53a10                    // zip1 v16.2d, v16.2d, v5.2d
  .long 0x4e867a14                    // zip2 v20.4s, v16.4s, v6.4s
  .long 0x6e040611                    // ins v17.s[0], v16.s[0]
  .long 0x6e0c2611                    // ins v17.s[1], v16.s[1]
  .long 0x6e140691                    // ins v17.s[2], v20.s[0]
  .long 0x6e1c6691                    // ins v17.s[3], v20.s[3]
  .long 0x4eb11e30                    // orr v16.16b, v17.16b, v17.16b
  .long 0x6e040614                    // ins v20.s[0], v16.s[0]
  .long 0x6e0c4614                    // ins v20.s[1], v16.s[2]
  .long 0x6e146614                    // ins v20.s[2], v16.s[3]
  .long 0x6e1c2614                    // ins v20.s[3], v16.s[1]
  .long 0x4eb41e90                    // orr v16.16b, v20.16b, v20.16b
  .long 0x4e8778b4                    // zip2 v20.4s, v5.4s, v7.4s
  .long 0x4eb41e85                    // orr v5.16b, v20.16b, v20.16b
  .long 0x4e8538c6                    // zip1 v6.4s, v6.4s, v5.4s
  .long 0x6e0444c7                    // ins v7.s[0], v6.s[2]
  .long 0x6e0c64c7                    // ins v7.s[1], v6.s[3]
  .long 0x6e1424c7                    // ins v7.s[2], v6.s[1]
  .long 0x6e1c04c7                    // ins v7.s[3], v6.s[0]
  .long 0x4eb11e25                    // orr v5.16b, v17.16b, v17.16b
  .long 0x4eb01e06                    // orr v6.16b, v16.16b, v16.16b
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f345652                    // shl v18.4s, v18.4s, #20
  .long 0x6f344432                    // sri v18.4s, v1.4s, #12
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380472                    // ushr v18.4s, v3.4s, #8
  .long 0x4f385473                    // shl v19.4s, v3.4s, #24
  .long 0x4eb31e43                    // orr v3.16b, v18.16b, v19.16b
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f395652                    // shl v18.4s, v18.4s, #25
  .long 0x6f394432                    // sri v18.4s, v1.4s, #7
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x6e046414                    // ins v20.s[0], v0.s[3]
  .long 0x6e0c0414                    // ins v20.s[1], v0.s[0]
  .long 0x6e142414                    // ins v20.s[2], v0.s[1]
  .long 0x6e1c4414                    // ins v20.s[3], v0.s[2]
  .long 0x4eb41e80                    // orr v0.16b, v20.16b, v20.16b
  .long 0x6e044474                    // ins v20.s[0], v3.s[2]
  .long 0x6e0c6474                    // ins v20.s[1], v3.s[3]
  .long 0x6e140474                    // ins v20.s[2], v3.s[0]
  .long 0x6e1c2474                    // ins v20.s[3], v3.s[1]
  .long 0x4eb41e83                    // orr v3.16b, v20.16b, v20.16b
  .long 0x6e042454                    // ins v20.s[0], v2.s[1]
  .long 0x6e0c4454                    // ins v20.s[1], v2.s[2]
  .long 0x6e146454                    // ins v20.s[2], v2.s[3]
  .long 0x6e1c0454                    // ins v20.s[3], v2.s[0]
  .long 0x4eb41e82                    // orr v2.16b, v20.16b, v20.16b
  .long 0x4ea68400                    // add v0.4s, v0.4s, v6.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f345652                    // shl v18.4s, v18.4s, #20
  .long 0x6f344432                    // sri v18.4s, v1.4s, #12
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x4ea78400                    // add v0.4s, v0.4s, v7.4s
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6f380472                    // ushr v18.4s, v3.4s, #8
  .long 0x4f385473                    // shl v19.4s, v3.4s, #24
  .long 0x4eb31e43                    // orr v3.16b, v18.16b, v19.16b
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea11c32                    // orr v18.16b, v1.16b, v1.16b
  .long 0x4f395652                    // shl v18.4s, v18.4s, #25
  .long 0x6f394432                    // sri v18.4s, v1.4s, #7
  .long 0x4eb21e41                    // orr v1.16b, v18.16b, v18.16b
  .long 0x6e042414                    // ins v20.s[0], v0.s[1]
  .long 0x6e0c4414                    // ins v20.s[1], v0.s[2]
  .long 0x6e146414                    // ins v20.s[2], v0.s[3]
  .long 0x6e1c0414                    // ins v20.s[3], v0.s[0]
  .long 0x4eb41e80                    // orr v0.16b, v20.16b, v20.16b
  .long 0x6e044474                    // ins v20.s[0], v3.s[2]
  .long 0x6e0c6474                    // ins v20.s[1], v3.s[3]
  .long 0x6e140474                    // ins v20.s[2], v3.s[0]
  .long 0x6e1c2474                    // ins v20.s[3], v3.s[1]
  .long 0x4eb41e83                    // orr v3.16b, v20.16b, v20.16b
  .long 0x6e046454                    // ins v20.s[0], v2.s[3]
  .long 0x6e0c0454                    // ins v20.s[1], v2.s[0]
  .long 0x6e142454                    // ins v20.s[2], v2.s[1]
  .long 0x6e1c4454                    // ins v20.s[3], v2.s[2]
  .long 0x4eb41e82                    // orr v2.16b, v20.16b, v20.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0x6e301c42                    // eor v2.16b, v2.16b, v16.16b
  .long 0x6e311c63                    // eor v3.16b, v3.16b, v17.16b
  .long 0xad000400                    // stp q0, q1, [x0]
  .long 0xad010c02                    // stp q2, q3, [x0, #32]
  add sp, sp, #128
  ret
