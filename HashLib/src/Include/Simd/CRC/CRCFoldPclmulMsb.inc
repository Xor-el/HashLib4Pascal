// SSE2 + SSSE3 + PCLMULQDQ CRC folding + Barrett reduction for non-reflected
// (MSB-first) CRCs with width 8..64.
// PCLMULQDQ instructions are db-encoded for broad assembler compatibility.
//
// Function signature (included after SimdProc4Begin.inc):
//   function CRC_Fold_Pclmul_Msb(AData: PByte; ALength: UInt32;
//     AState: Pointer; AConstants: Pointer): UInt64;
//
// Register mapping (MS x64 ABI after prologue):
//   rcx = AData, edx = ALength (>= 64), r8 = AState, r9 = AConstants
//   AState: [0..7] = initial CRC pre-shifted left by (64 - Width), [8..15] = 0.
//   AConstants layout (TCRCFoldConstants):
//     [0..15]  = Fold_4x128
//     [16..31] = Fold_1x128
//     [32..47] = Barrett
//     [48..63] = Fold_8x128 (unused by this path)
//     [64..79] = BswapMask
//     [80..87] = CrcBits
//     [88..95] = BarrettShift
//   Returns: final CRC in RAX.
//
// Reference: Linux kernel crc-pclmul-template.S by Eric Biggers (Google).
//
// pclmulqdq xmm_dst, xmm_src, imm8 (register-register, no REX for xmm0-7):
//   66 0F 3A 44 ModRM imm8
// ModRM for reg-reg: 11_dst_src
//   xmm0=000 xmm1=001 xmm2=010 xmm3=011 xmm4=100
//   xmm5=101 xmm6=110 xmm7=111
// pshufb xmm_dst, xmm_src (SSSE3):
//   66 0F 38 00 ModRM

  // --- Pre-load constants ---
  movdqu xmm6, dqword ptr [r9 + 64]   // BswapMask into xmm6 (kept throughout)
  movdqu xmm7, dqword ptr [r9]        // fold_4x128

  // --- Load first 64 bytes with byte-swap ---
  movdqu xmm0, dqword ptr [rcx]
  db $66, $0F, $38, $00, $C6                   // pshufb xmm0, xmm6
  movdqu xmm1, dqword ptr [rcx + 16]
  db $66, $0F, $38, $00, $CE                   // pshufb xmm1, xmm6
  movdqu xmm2, dqword ptr [rcx + 32]
  db $66, $0F, $38, $00, $D6                   // pshufb xmm2, xmm6
  movdqu xmm3, dqword ptr [rcx + 48]
  db $66, $0F, $38, $00, $DE                   // pshufb xmm3, xmm6

  // XOR pre-shifted CRC into the HIGH qword of xmm0 (MSB-first placement)
  movq xmm4, qword ptr [r8]
  pslldq xmm4, 8
  pxor xmm0, xmm4

  add rcx, 64
  sub edx, 64

  // --- Main fold-by-4 loop ---
  cmp edx, 64
  jb @fold4_done

@fold4_loop:
  // Fold xmm0
  movdqa xmm4, xmm0
  db $66, $0F, $3A, $44, $C7, $00              // pclmulqdq xmm0, xmm7, $00
  db $66, $0F, $3A, $44, $E7, $11              // pclmulqdq xmm4, xmm7, $11
  pxor xmm0, xmm4
  movdqu xmm5, dqword ptr [rcx]
  db $66, $0F, $38, $00, $EE                   // pshufb xmm5, xmm6
  pxor xmm0, xmm5

  // Fold xmm1
  movdqa xmm4, xmm1
  db $66, $0F, $3A, $44, $CF, $00              // pclmulqdq xmm1, xmm7, $00
  db $66, $0F, $3A, $44, $E7, $11              // pclmulqdq xmm4, xmm7, $11
  pxor xmm1, xmm4
  movdqu xmm5, dqword ptr [rcx + 16]
  db $66, $0F, $38, $00, $EE                   // pshufb xmm5, xmm6
  pxor xmm1, xmm5

  // Fold xmm2
  movdqa xmm4, xmm2
  db $66, $0F, $3A, $44, $D7, $00              // pclmulqdq xmm2, xmm7, $00
  db $66, $0F, $3A, $44, $E7, $11              // pclmulqdq xmm4, xmm7, $11
  pxor xmm2, xmm4
  movdqu xmm5, dqword ptr [rcx + 32]
  db $66, $0F, $38, $00, $EE                   // pshufb xmm5, xmm6
  pxor xmm2, xmm5

  // Fold xmm3
  movdqa xmm4, xmm3
  db $66, $0F, $3A, $44, $DF, $00              // pclmulqdq xmm3, xmm7, $00
  db $66, $0F, $3A, $44, $E7, $11              // pclmulqdq xmm4, xmm7, $11
  pxor xmm3, xmm4
  movdqu xmm5, dqword ptr [rcx + 48]
  db $66, $0F, $38, $00, $EE                   // pshufb xmm5, xmm6
  pxor xmm3, xmm5

  add rcx, 64
  sub edx, 64
  cmp edx, 64
  jae @fold4_loop

@fold4_done:
  // --- Fold 4 accumulators to 1 using fold_1x128 (reload into xmm7) ---
  movdqu xmm7, dqword ptr [r9 + 16]   // fold_1x128

  // xmm0 = fold(xmm0) XOR xmm1
  movdqa xmm4, xmm0
  db $66, $0F, $3A, $44, $C7, $00              // pclmulqdq xmm0, xmm7, $00
  db $66, $0F, $3A, $44, $E7, $11              // pclmulqdq xmm4, xmm7, $11
  pxor xmm0, xmm4
  pxor xmm0, xmm1

  // xmm0 = fold(xmm0) XOR xmm2
  movdqa xmm4, xmm0
  db $66, $0F, $3A, $44, $C7, $00              // pclmulqdq xmm0, xmm7, $00
  db $66, $0F, $3A, $44, $E7, $11              // pclmulqdq xmm4, xmm7, $11
  pxor xmm0, xmm4
  pxor xmm0, xmm2

  // xmm0 = fold(xmm0) XOR xmm3
  movdqa xmm4, xmm0
  db $66, $0F, $3A, $44, $C7, $00              // pclmulqdq xmm0, xmm7, $00
  db $66, $0F, $3A, $44, $E7, $11              // pclmulqdq xmm4, xmm7, $11
  pxor xmm0, xmm4
  pxor xmm0, xmm3

  // --- Fold remaining 16-byte blocks ---
  cmp edx, 16
  jb @fold1_done

@fold1_loop:
  movdqa xmm4, xmm0
  db $66, $0F, $3A, $44, $C7, $00              // pclmulqdq xmm0, xmm7, $00
  db $66, $0F, $3A, $44, $E7, $11              // pclmulqdq xmm4, xmm7, $11
  pxor xmm0, xmm4
  movdqu xmm5, dqword ptr [rcx]
  db $66, $0F, $38, $00, $EE                   // pshufb xmm5, xmm6
  pxor xmm0, xmm5
  add rcx, 16
  sub edx, 16
  cmp edx, 16
  jae @fold1_loop

@fold1_done:
  // =================================================================
  // MSB Barrett reduction: 128-bit xmm0 -> CRC in rax
  // Computes x^n * A mod G via two Barrett rounds, each on one 64-bit
  // half.  Per Linux kernel crc-pclmul-template.S (Eric Biggers).
  //
  //   Round 1: crc := x^n * A_H mod G
  //   Merge:   A_L := x^(64-n)*crc + A_L
  //   Round 2: crc := x^n * A_L mod G  (= x^n * A mod G)
  //
  // Barrett[0] = mu_lo = floor(x^(64+n)/G) - x^64
  // Barrett[1] = G  (for CRC-64: poly without x^64)
  // BarrettShift = 64 - n  (at [r9 + 88])
  // =================================================================

  movdqu xmm6, dqword ptr [r9 + 32]            // xmm6 = [G : mu_lo]

  // --- Round 1: Barrett on A_H ---
  movdqa xmm1, xmm0
  db $66, $0F, $3A, $44, $CE, $01              // pclmulqdq xmm1, xmm6, $01
  pxor xmm1, xmm0                              // xmm1.hi = tmp
  db $66, $0F, $3A, $44, $CE, $11              // pclmulqdq xmm1, xmm6, $11

  // Merge: crc1 in xmm1.lo bits 0..n-1; shift left by (64-n) and XOR
  movq xmm2, qword ptr [r9 + 88]
  psllq xmm1, xmm2
  pxor xmm0, xmm1

  // --- Round 2: Barrett on modified A_L ---
  movdqa xmm1, xmm0
  db $66, $0F, $3A, $44, $CE, $00              // pclmulqdq xmm1, xmm6, $00
  pshufd xmm0, xmm0, $4E                        // swap hi/lo qwords
  pxor xmm0, xmm1                              // xmm0.hi = tmp2
  db $66, $0F, $3A, $44, $C6, $11              // pclmulqdq xmm0, xmm6, $11

  // movq rax, xmm0: 66 48 0F 7E C0
  db $66, $48, $0F, $7E, $C0
