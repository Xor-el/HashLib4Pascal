// SSE2 + PCLMULQDQ CRC folding + Barrett reduction for reflected (LSB-first)
// CRCs with width 8..64 (IA-32). CRC-64 uses a special Barrett path for the
// 65-bit G. Fold-by-4 only: the fold-by-8 upper path of the x86-64 kernel
// needs xmm8-11, which IA-32 does not have.
// PCLMULQDQ instructions are db-encoded for broad assembler compatibility;
// all byte sequences are verbatim from CRCFoldReflectedPclmul_x86_64.inc
// (xmm0-7 forms carry no REX prefix and encode identically on IA-32).
//
// After HlpSimdProc4Begin_i386: ebx = AData, esi = ALength (>= 16),
//   edi = AState, eax = Ctx (PCRCFoldRuntimeCtx; FoldConstants at +0).
//   AState: pointer to the initial CRC (reflected) as one UInt64.
//   Ctx: [+0] Fold_4x128, [+16] Fold_1x128, [+32] Barrett, [+80] CrcBits.
// Result UInt64 in edx:eax (high qword of xmm0).
//
// pclmulqdq xmm_dst, xmm_src, imm8 (register-register):
//   66 0F 3A 44 ModRM imm8; ModRM = 11_dst_src.

  push ebp
  mov ebp, eax                        // Ctx

  // fold_1x128 is always needed (fold-by-1 loop and Barrett step 1)
  movdqu xmm7, oword ptr [ebp + 16]   // fold_1x128

  cmp esi, 64
  jae @large_input

  // --- Small input (16..63 bytes): load 1 block ---
  movdqu xmm0, oword ptr [ebx]
  movq xmm4, qword ptr [edi]
  pxor xmm0, xmm4
  add ebx, 16
  sub esi, 16
  jmp @fold1_check

@large_input:
  // --- Large input (>= 64 bytes): load 4 blocks ---
  movdqu xmm6, oword ptr [ebp]        // fold_4x128

  movdqu xmm0, oword ptr [ebx]
  movdqu xmm1, oword ptr [ebx + 16]
  movdqu xmm2, oword ptr [ebx + 32]
  movdqu xmm3, oword ptr [ebx + 48]

  movq xmm4, qword ptr [edi]
  pxor xmm0, xmm4

  add ebx, 64
  sub esi, 64

  // --- Main fold-by-4 loop ---
  cmp esi, 64
  jb @fold4_done

@fold4_loop:
  // Fold xmm0
  movdqa xmm4, xmm0
  db $66, $0F, $3A, $44, $C6, $00              // pclmulqdq xmm0, xmm6, $00
  db $66, $0F, $3A, $44, $E6, $11              // pclmulqdq xmm4, xmm6, $11
  pxor xmm0, xmm4
  movdqu xmm5, oword ptr [ebx]
  pxor xmm0, xmm5

  // Fold xmm1
  movdqa xmm4, xmm1
  db $66, $0F, $3A, $44, $CE, $00              // pclmulqdq xmm1, xmm6, $00
  db $66, $0F, $3A, $44, $E6, $11              // pclmulqdq xmm4, xmm6, $11
  pxor xmm1, xmm4
  movdqu xmm5, oword ptr [ebx + 16]
  pxor xmm1, xmm5

  // Fold xmm2
  movdqa xmm4, xmm2
  db $66, $0F, $3A, $44, $D6, $00              // pclmulqdq xmm2, xmm6, $00
  db $66, $0F, $3A, $44, $E6, $11              // pclmulqdq xmm4, xmm6, $11
  pxor xmm2, xmm4
  movdqu xmm5, oword ptr [ebx + 32]
  pxor xmm2, xmm5

  // Fold xmm3
  movdqa xmm4, xmm3
  db $66, $0F, $3A, $44, $DE, $00              // pclmulqdq xmm3, xmm6, $00
  db $66, $0F, $3A, $44, $E6, $11              // pclmulqdq xmm4, xmm6, $11
  pxor xmm3, xmm4
  movdqu xmm5, oword ptr [ebx + 48]
  pxor xmm3, xmm5

  add ebx, 64
  sub esi, 64
  cmp esi, 64
  jae @fold4_loop

@fold4_done:
  // --- Fold 4 accumulators to 1 using fold_1x128 (xmm7) ---

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
  pxor xmm0, xmm5
  add ebx, 16
  sub esi, 16
  cmp esi, 16
  jae @fold1_loop

@fold1_done:
  // =================================================================
  // Final reduction: 128-bit xmm0 -> CRC in edx:eax
  // Following Linux kernel crc-pclmul-template.S Barrett reduction.
  // =================================================================

  // Step 1: Multiply by x^n and reduce 128 bits to 64+n bits.
  movdqa xmm1, xmm0
  db $66, $0F, $3A, $44, $CF, $10              // pclmulqdq xmm1, xmm7, $10
  psrldq xmm0, 8                               // xmm0 = {0, A_hi}
  pxor xmm0, xmm1                              // xmm0 = t0 (64+n bits)

  // Step 2: Barrett reduction.
  movdqu xmm6, oword ptr [ebp + 32]

  // t1 = clmul(t0.lo, barrett[0])  =>  q = floor(t0 / G)
  movdqa xmm1, xmm0
  db $66, $0F, $3A, $44, $CE, $00              // pclmulqdq xmm1, xmm6, $00

  // Check if CRC-64: G is 65-bit, needs split multiplication
  // (CrcBits <= 64, so the low dword suffices)
  cmp dword ptr [ebp + 80], 64
  je @barrett_64

  // Standard Barrett (width < 64): single pclmulqdq covers full G
  db $66, $0F, $3A, $44, $CE, $10              // pclmulqdq xmm1, xmm6, $10
  pxor xmm0, xmm1
  jmp @extract_crc

@barrett_64:
  // CRC-64 Barrett: G is 65-bit, split into 64-bit pclmulqdq + x^0 correction.
  movdqa xmm2, xmm1                            // save q
  db $66, $0F, $3A, $44, $CE, $10              // pclmulqdq xmm1, xmm6, $10
  db $66, $0F, $6C, $D2                        // punpcklqdq xmm2, xmm2 {q.lo, q.lo}
  pxor xmm0, xmm1
  pxor xmm0, xmm2

@extract_crc:
  // High qword of xmm0 -> edx:eax
  psrldq xmm0, 8
  movd eax, xmm0
  psrldq xmm0, 4
  movd edx, xmm0

  pop ebp
  pop edi
  pop esi
  pop ebx
