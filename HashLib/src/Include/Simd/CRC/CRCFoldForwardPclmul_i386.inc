// SSE2 + SSSE3 + PCLMULQDQ implementation of CRC folding + Barrett
// reduction for non-reflected (MSB-first) CRCs with width 8..64 (IA-32).
// Fold-by-4 only: the fold-by-8 upper path of the x86-64 kernel needs
// xmm8-xmm11, which IA-32 does not have. All byte sequences are verbatim
// from CRCFoldForwardPclmul_x86_64.inc (xmm0-7 forms carry no REX prefix
// and encode identically on IA-32).
// ABI (after HlpSimdProc4Begin_i386.inc): ebx = AData, esi = ALength
//   (>= 16), edi = AState, eax = Ctx (PCRCFoldRuntimeCtx; FoldConstants
//   at +0).
//   AState: pointer to the initial CRC pre-shifted left by (64 - Width)
//   as one UInt64. Returns the final CRC UInt64 in edx:eax (low qword
//   of xmm0).
//   Ctx: [+0] Fold_4x128, [+16] Fold_1x128, [+32] Barrett, [+64] BswapMask,
//        [+80] CrcBits, [+88] BarrettShift.
// PCLMULQDQ/pshufb instructions are db-encoded for broad assembler
// compatibility. Encoding notes:
//   pclmulqdq xmm_dst, xmm_src, imm8: 66 0F 3A 44 ModRM imm8
//   pshufb    xmm_dst, xmm_src:       66 0F 38 00 ModRM
//   ModRM = 11_dst_src.
// Reference: Linux kernel crc-pclmul-template.S by Eric Biggers (Google),
// HashLib CRCFoldForwardPclmul_x86_64.inc.

  push ebp
  mov ebp, eax                        // Ctx

  // BswapMask is always needed (kept in xmm6 throughout)
  movdqu xmm6, oword ptr [ebp + 64]   // BswapMask

  cmp esi, 64
  jae @large_input

  // --- Small input (16..63 bytes): load 1 block with byte-swap ---
  movdqu xmm7, oword ptr [ebp + 16]   // fold_1x128
  movdqu xmm0, oword ptr [ebx]
  db $66, $0F, $38, $00, $C6                   // pshufb xmm0, xmm6
  movq xmm4, qword ptr [edi]
  pslldq xmm4, 8
  pxor xmm0, xmm4
  add ebx, 16
  sub esi, 16
  jmp @fold1_check

@large_input:
  // --- Large input (>= 64 bytes): load 4 blocks with byte-swap ---
  movdqu xmm7, oword ptr [ebp]        // fold_4x128

  movdqu xmm0, oword ptr [ebx]
  db $66, $0F, $38, $00, $C6                   // pshufb xmm0, xmm6
  movdqu xmm1, oword ptr [ebx + 16]
  db $66, $0F, $38, $00, $CE                   // pshufb xmm1, xmm6
  movdqu xmm2, oword ptr [ebx + 32]
  db $66, $0F, $38, $00, $D6                   // pshufb xmm2, xmm6
  movdqu xmm3, oword ptr [ebx + 48]
  db $66, $0F, $38, $00, $DE                   // pshufb xmm3, xmm6

  movq xmm4, qword ptr [edi]
  pslldq xmm4, 8
  pxor xmm0, xmm4

  add ebx, 64
  sub esi, 64

  // --- Main fold-by-4 loop ---
  cmp esi, 64
  jb @fold4_done

@fold4_loop:
  // Fold xmm0
  movdqa xmm4, xmm0
  db $66, $0F, $3A, $44, $C7, $00              // pclmulqdq xmm0, xmm7, $00
  db $66, $0F, $3A, $44, $E7, $11              // pclmulqdq xmm4, xmm7, $11
  pxor xmm0, xmm4
  movdqu xmm5, oword ptr [ebx]
  db $66, $0F, $38, $00, $EE                   // pshufb xmm5, xmm6
  pxor xmm0, xmm5

  // Fold xmm1
  movdqa xmm4, xmm1
  db $66, $0F, $3A, $44, $CF, $00              // pclmulqdq xmm1, xmm7, $00
  db $66, $0F, $3A, $44, $E7, $11              // pclmulqdq xmm4, xmm7, $11
  pxor xmm1, xmm4
  movdqu xmm5, oword ptr [ebx + 16]
  db $66, $0F, $38, $00, $EE                   // pshufb xmm5, xmm6
  pxor xmm1, xmm5

  // Fold xmm2
  movdqa xmm4, xmm2
  db $66, $0F, $3A, $44, $D7, $00              // pclmulqdq xmm2, xmm7, $00
  db $66, $0F, $3A, $44, $E7, $11              // pclmulqdq xmm4, xmm7, $11
  pxor xmm2, xmm4
  movdqu xmm5, oword ptr [ebx + 32]
  db $66, $0F, $38, $00, $EE                   // pshufb xmm5, xmm6
  pxor xmm2, xmm5

  // Fold xmm3
  movdqa xmm4, xmm3
  db $66, $0F, $3A, $44, $DF, $00              // pclmulqdq xmm3, xmm7, $00
  db $66, $0F, $3A, $44, $E7, $11              // pclmulqdq xmm4, xmm7, $11
  pxor xmm3, xmm4
  movdqu xmm5, oword ptr [ebx + 48]
  db $66, $0F, $38, $00, $EE                   // pshufb xmm5, xmm6
  pxor xmm3, xmm5

  add ebx, 64
  sub esi, 64
  cmp esi, 64
  jae @fold4_loop

@fold4_done:
  // --- Fold 4 accumulators to 1 using fold_1x128 (reload into xmm7) ---
  movdqu xmm7, oword ptr [ebp + 16]   // fold_1x128

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
@fold1_check:
  cmp esi, 16
  jb @fold1_done

@fold1_loop:
  movdqa xmm4, xmm0
  db $66, $0F, $3A, $44, $C7, $00              // pclmulqdq xmm0, xmm7, $00
  db $66, $0F, $3A, $44, $E7, $11              // pclmulqdq xmm4, xmm7, $11
  pxor xmm0, xmm4
  movdqu xmm5, oword ptr [ebx]
  db $66, $0F, $38, $00, $EE                   // pshufb xmm5, xmm6
  pxor xmm0, xmm5
  add ebx, 16
  sub esi, 16
  cmp esi, 16
  jae @fold1_loop

@fold1_done:
  // =================================================================
  // MSB Barrett reduction: 128-bit xmm0 -> CRC in edx:eax
  // Two Barrett rounds, each on one 64-bit half; per Linux kernel
  // crc-pclmul-template.S (Eric Biggers). xmm6 = [G : mu_lo].
  // =================================================================

  movdqu xmm6, oword ptr [ebp + 32]            // xmm6 = [G : mu_lo]

  // --- Round 1: Barrett on A_H ---
  movdqa xmm1, xmm0
  db $66, $0F, $3A, $44, $CE, $01              // pclmulqdq xmm1, xmm6, $01
  pxor xmm1, xmm0                              // xmm1.hi = tmp
  db $66, $0F, $3A, $44, $CE, $11              // pclmulqdq xmm1, xmm6, $11

  // Merge: crc1 in xmm1.lo bits 0..n-1; shift left by (64-n) and XOR
  movq xmm2, qword ptr [ebp + 88]
  psllq xmm1, xmm2
  pxor xmm0, xmm1

  // --- Round 2: Barrett on modified A_L ---
  movdqa xmm1, xmm0
  db $66, $0F, $3A, $44, $CE, $00              // pclmulqdq xmm1, xmm6, $00
  pshufd xmm0, xmm0, $4E                        // swap hi/lo qwords
  pxor xmm0, xmm1                              // xmm0.hi = tmp2
  db $66, $0F, $3A, $44, $C6, $11              // pclmulqdq xmm0, xmm6, $11

  // Low qword of xmm0 -> edx:eax
  movd eax, xmm0
  psrldq xmm0, 4
  movd edx, xmm0

  pop ebp
  pop edi
  pop esi
  pop ebx
