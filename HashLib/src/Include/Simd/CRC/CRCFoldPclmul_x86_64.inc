// SSE2 + PCLMULQDQ CRC folding + Barrett reduction for reflected (LSB-first)
// CRCs with width 8..64. CRC-64 uses a special Barrett path for the 65-bit G.
// PCLMULQDQ instructions are db-encoded for broad assembler compatibility.
//
// Function signature (included after SimdProc4Begin_x86_64.inc):
//   function CRC_Fold_Pclmul(AData: PByte; ALength: UInt32;
//     AState: Pointer; AConstants: Pointer): UInt64;
//
// Register mapping (MS x64 ABI after prologue):
//   rcx = AData, edx = ALength (>= 16), r8 = AState, r9 = AConstants
//   AState: [0..7] = initial CRC (reflected), [8..15] = 0.
//   AConstants layout (TCRCFoldConstants):
//     [0..15]  = Fold_4x128
//     [16..31] = Fold_1x128
//     [32..47] = Barrett
//     [48..63] = Fold_8x128 (unused by this path)
//     [64..79] = BswapMask  (unused by this path)
//     [80..87] = CrcBits
//   Returns: final CRC in RAX.
//
// Reference: Linux kernel crc-pclmul-template.S by Eric Biggers (Google).
//
// pclmulqdq xmm_dst, xmm_src, imm8 (register-register, no REX for xmm0-7):
//   66 0F 3A 44 ModRM imm8
// ModRM for reg-reg: 11_dst_src
//   xmm0=000 xmm1=001 xmm2=010 xmm3=011 xmm4=100
//   xmm5=101 xmm6=110 xmm7=111

  // fold_1x128 is always needed (fold-by-1 loop and Barrett step 1)
  movdqu xmm7, dqword ptr [r9 + 16]   // fold_1x128

  cmp edx, 64
  jae @large_input

  // --- Small input (16..63 bytes): load 1 block ---
  movdqu xmm0, dqword ptr [rcx]
  movq xmm4, qword ptr [r8]
  pxor xmm0, xmm4
  add rcx, 16
  sub edx, 16
  jmp @fold1_check

@large_input:
  // --- Large input (>= 64 bytes): load 4 blocks ---
  movdqu xmm6, dqword ptr [r9]        // fold_4x128

  movdqu xmm0, dqword ptr [rcx]
  movdqu xmm1, dqword ptr [rcx + 16]
  movdqu xmm2, dqword ptr [rcx + 32]
  movdqu xmm3, dqword ptr [rcx + 48]

  movq xmm4, qword ptr [r8]
  pxor xmm0, xmm4

  add rcx, 64
  sub edx, 64

  // --- Main fold-by-4 loop ---
  cmp edx, 64
  jb @fold4_done

@fold4_loop:
  // Fold xmm0
  movdqa xmm4, xmm0
  db $66, $0F, $3A, $44, $C6, $00              // pclmulqdq xmm0, xmm6, $00
  db $66, $0F, $3A, $44, $E6, $11              // pclmulqdq xmm4, xmm6, $11
  pxor xmm0, xmm4
  movdqu xmm5, dqword ptr [rcx]
  pxor xmm0, xmm5

  // Fold xmm1
  movdqa xmm4, xmm1
  db $66, $0F, $3A, $44, $CE, $00              // pclmulqdq xmm1, xmm6, $00
  db $66, $0F, $3A, $44, $E6, $11              // pclmulqdq xmm4, xmm6, $11
  pxor xmm1, xmm4
  movdqu xmm5, dqword ptr [rcx + 16]
  pxor xmm1, xmm5

  // Fold xmm2
  movdqa xmm4, xmm2
  db $66, $0F, $3A, $44, $D6, $00              // pclmulqdq xmm2, xmm6, $00
  db $66, $0F, $3A, $44, $E6, $11              // pclmulqdq xmm4, xmm6, $11
  pxor xmm2, xmm4
  movdqu xmm5, dqword ptr [rcx + 32]
  pxor xmm2, xmm5

  // Fold xmm3
  movdqa xmm4, xmm3
  db $66, $0F, $3A, $44, $DE, $00              // pclmulqdq xmm3, xmm6, $00
  db $66, $0F, $3A, $44, $E6, $11              // pclmulqdq xmm4, xmm6, $11
  pxor xmm3, xmm4
  movdqu xmm5, dqword ptr [rcx + 48]
  pxor xmm3, xmm5

  add rcx, 64
  sub edx, 64
  cmp edx, 64
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
  cmp edx, 16
  jb @fold1_done

@fold1_loop:
  movdqa xmm4, xmm0
  db $66, $0F, $3A, $44, $C7, $00              // pclmulqdq xmm0, xmm7, $00
  db $66, $0F, $3A, $44, $E7, $11              // pclmulqdq xmm4, xmm7, $11
  pxor xmm0, xmm4
  movdqu xmm5, dqword ptr [rcx]
  pxor xmm0, xmm5
  add rcx, 16
  sub edx, 16
  cmp edx, 16
  jae @fold1_loop

@fold1_done:
  // =================================================================
  // Final reduction: 128-bit xmm0 -> CRC in rax
  // Following Linux kernel crc-pclmul-template.S Barrett reduction.
  // =================================================================

  // Step 1: Multiply by x^n and reduce 128 bits to 64+n bits.
  //   t0 = ((x^(64+n) mod G) * floor(A / x^64)) + (x^n * (A mod x^64))
  // The fold_1x128 LO64_TERMS constant (xmm7 high qword) encodes
  // (x^(128+k) mod G) * x^(64-n) which makes the low (64-n) bits of
  // the product zero. Selecting it via $10 = clmul(xmm0.lo, xmm7.hi).

  movdqa xmm1, xmm0
  db $66, $0F, $3A, $44, $CF, $10              // pclmulqdq xmm1, xmm7, $10
  psrldq xmm0, 8                               // xmm0 = {0, A_hi}
  pxor xmm0, xmm1                              // xmm0 = t0 (64+n bits)

  // Step 2: Barrett reduction.
  // Load Barrett constants into xmm6:
  //   xmm6.lo = bitreflect(floor(x^(63+n)/G), 64)
  //   xmm6.hi:
  //     n < 64: bitreflect((G - x^n) * x^(64-n-1), 64)
  //     n = 64: bitreflect(((G - x^n) - x^0) / x, 64)
  movdqu xmm6, dqword ptr [r9 + 32]

  // t1 = clmul(t0.lo, barrett[0])  =>  q = floor(t0 / G)
  movdqa xmm1, xmm0
  db $66, $0F, $3A, $44, $CE, $00              // pclmulqdq xmm1, xmm6, $00

  // Check if CRC-64: G is 65-bit, needs split multiplication
  cmp qword ptr [r9 + 80], 64
  je @barrett_64

  // Standard Barrett (width < 64): single pclmulqdq covers full G
  db $66, $0F, $3A, $44, $CE, $10              // pclmulqdq xmm1, xmm6, $10
  pxor xmm0, xmm1
  jmp @extract_crc

@barrett_64:
  // CRC-64 Barrett: G is 65-bit, split into 64-bit pclmulqdq + x^0 correction.
  // Barrett[1] stores ((G - x^64) - x^0) / x; the x^0 term is handled
  // separately by duplicating q.lo and XORing it into the result.
  movdqa xmm2, xmm1                           // save q
  db $66, $0F, $3A, $44, $CE, $10              // pclmulqdq xmm1, xmm6, $10
  // punpcklqdq xmm2, xmm2: 66 0F 6C D2
  db $66, $0F, $6C, $D2                        // xmm2 = {q.lo, q.lo}
  pxor xmm0, xmm1
  pxor xmm0, xmm2

@extract_crc:
  // Extract high qword (bits 64..127) into rax.
  // pextrq rax, xmm0, 1: 66 48 0F 3A 16 C0 01
  db $66, $48, $0F, $3A, $16, $C0, $01
