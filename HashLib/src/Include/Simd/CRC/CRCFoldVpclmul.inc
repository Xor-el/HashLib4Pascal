// AVX2 + VPCLMULQDQ CRC folding + Barrett reduction for reflected (LSB-first)
// CRCs with width 8..32 (CRC-64 requires a separate path).
// AVX2/VPCLMULQDQ instructions are db-encoded for broad assembler compatibility.
//
// Function signature (included after SimdProc4Begin.inc):
//   function CRC_Fold_Vpclmul(AData: PByte; ALength: UInt32;
//     AState: Pointer; AConstants: Pointer): UInt64;
//
// Register mapping (MS x64 ABI after prologue):
//   rcx = AData, edx = ALength (>= 64), r8 = AState, r9 = AConstants
//   AState: [0..7] = initial CRC (reflected), [8..15] = 0.
//   AConstants layout (TCRCFoldConstants):
//     [0..15]  = Fold_4x128  (stride 512)
//     [16..31] = Fold_1x128  (stride 128)
//     [32..47] = Barrett
//     [48..63] = Fold_8x128  (stride 1024)
//   Returns: final CRC in RAX.
//
// Reference: zlib-ng crc32_pclmulqdq_tpl.h (256-bit VPCLMULQDQ path)
// and Linux kernel crc-pclmul-template.S by Eric Biggers (Barrett reduction).
//
// VEX byte layout reference:
//   2-byte: C5 [R.vvvv.L.pp]
//   3-byte: C4 [R.X.B.mmmmm] [W.vvvv.L.pp]

  cmp edx, 128
  jb @xmm_path

  // ===== YMM PATH (>= 128 bytes) =====

  // Broadcast Fold_8x128 (stride 1024) into ymm6
  db $C4, $C2, $7D, $5A, $71, $30             // vbroadcasti128 ymm6, [r9 + 48]

  // Load first 128 bytes into ymm0..ymm3
  db $C5, $FE, $6F, $01                       // vmovdqu ymm0, [rcx]
  db $C5, $FE, $6F, $49, $20                  // vmovdqu ymm1, [rcx + 32]
  db $C5, $FE, $6F, $51, $40                  // vmovdqu ymm2, [rcx + 64]
  db $C5, $FE, $6F, $59, $60                  // vmovdqu ymm3, [rcx + 96]

  // XOR initial CRC into low 64 bits of ymm0
  db $C4, $C1, $7A, $7E, $20                  // vmovq xmm4, [r8]
  db $C5, $FD, $EF, $C4                       // vpxor ymm0, ymm0, ymm4

  add rcx, 128
  sub edx, 128

  // --- Main fold-by-8 loop (4 ymm accumulators, 128 bytes per iteration) ---
  cmp edx, 128
  jb @ymm_done

@ymm_loop:
  // Fold ymm0
  db $C4, $E3, $7D, $44, $E6, $11             // vpclmulqdq ymm4, ymm0, ymm6, $11
  db $C4, $E3, $7D, $44, $C6, $00             // vpclmulqdq ymm0, ymm0, ymm6, $00
  db $C5, $FD, $EF, $C4                       // vpxor ymm0, ymm0, ymm4
  db $C5, $FE, $6F, $29                       // vmovdqu ymm5, [rcx]
  db $C5, $FD, $EF, $C5                       // vpxor ymm0, ymm0, ymm5

  // Fold ymm1
  db $C4, $E3, $75, $44, $E6, $11             // vpclmulqdq ymm4, ymm1, ymm6, $11
  db $C4, $E3, $75, $44, $CE, $00             // vpclmulqdq ymm1, ymm1, ymm6, $00
  db $C5, $F5, $EF, $CC                       // vpxor ymm1, ymm1, ymm4
  db $C5, $FE, $6F, $69, $20                  // vmovdqu ymm5, [rcx + 32]
  db $C5, $F5, $EF, $CD                       // vpxor ymm1, ymm1, ymm5

  // Fold ymm2
  db $C4, $E3, $6D, $44, $E6, $11             // vpclmulqdq ymm4, ymm2, ymm6, $11
  db $C4, $E3, $6D, $44, $D6, $00             // vpclmulqdq ymm2, ymm2, ymm6, $00
  db $C5, $ED, $EF, $D4                       // vpxor ymm2, ymm2, ymm4
  db $C5, $FE, $6F, $69, $40                  // vmovdqu ymm5, [rcx + 64]
  db $C5, $ED, $EF, $D5                       // vpxor ymm2, ymm2, ymm5

  // Fold ymm3
  db $C4, $E3, $65, $44, $E6, $11             // vpclmulqdq ymm4, ymm3, ymm6, $11
  db $C4, $E3, $65, $44, $DE, $00             // vpclmulqdq ymm3, ymm3, ymm6, $00
  db $C5, $E5, $EF, $DC                       // vpxor ymm3, ymm3, ymm4
  db $C5, $FE, $6F, $69, $60                  // vmovdqu ymm5, [rcx + 96]
  db $C5, $E5, $EF, $DD                       // vpxor ymm3, ymm3, ymm5

  add rcx, 128
  sub edx, 128
  cmp edx, 128
  jae @ymm_loop

@ymm_done:
  // --- Reduce 4 ymm -> 2 ymm using Fold_4x128 (stride 512) ---
  db $C4, $C2, $7D, $5A, $31                  // vbroadcasti128 ymm6, [r9]

  // ymm0 = fold(ymm0) XOR ymm2
  db $C4, $E3, $7D, $44, $E6, $11             // vpclmulqdq ymm4, ymm0, ymm6, $11
  db $C4, $E3, $7D, $44, $C6, $00             // vpclmulqdq ymm0, ymm0, ymm6, $00
  db $C5, $FD, $EF, $C4                       // vpxor ymm0, ymm0, ymm4
  db $C5, $FD, $EF, $C2                       // vpxor ymm0, ymm0, ymm2

  // ymm1 = fold(ymm1) XOR ymm3
  db $C4, $E3, $75, $44, $E6, $11             // vpclmulqdq ymm4, ymm1, ymm6, $11
  db $C4, $E3, $75, $44, $CE, $00             // vpclmulqdq ymm1, ymm1, ymm6, $00
  db $C5, $F5, $EF, $CC                       // vpxor ymm1, ymm1, ymm4
  db $C5, $F5, $EF, $CB                       // vpxor ymm1, ymm1, ymm3

  // --- Extract 4 xmm from 2 ymm ---
  // ymm0 = [result0 | result1], ymm1 = [result2 | result3]
  db $C5, $F9, $6F, $D1                       // vmovdqa xmm2, xmm1       (save low of ymm1 = result2)
  db $C4, $E3, $7D, $39, $CB, $01             // vextracti128 xmm3, ymm1, 1 (high of ymm1 = result3)
  db $C4, $E3, $7D, $39, $C1, $01             // vextracti128 xmm1, ymm0, 1 (high of ymm0 = result1)
  // xmm0 = low(ymm0) = result0 (untouched)

  db $C5, $F8, $77                             // vzeroupper
  jmp @fold4to1

@xmm_path:
  // ===== XMM PATH (64..127 bytes) =====

  // Load first 64 bytes
  db $C5, $FA, $6F, $01                       // vmovdqu xmm0, [rcx]
  db $C5, $FA, $6F, $49, $10                  // vmovdqu xmm1, [rcx + 16]
  db $C5, $FA, $6F, $51, $20                  // vmovdqu xmm2, [rcx + 32]
  db $C5, $FA, $6F, $59, $30                  // vmovdqu xmm3, [rcx + 48]

  // XOR initial CRC into low 64 bits of xmm0
  db $C4, $C1, $7A, $7E, $20                  // vmovq xmm4, [r8]
  db $C5, $F9, $EF, $C4                       // vpxor xmm0, xmm0, xmm4

  add rcx, 64
  sub edx, 64

@fold4to1:
  // ===== FOLD 4 XMM -> 1 XMM using Fold_1x128 (stride 128) =====
  db $C4, $C1, $7A, $6F, $79, $10             // vmovdqu xmm7, [r9 + 16]

  // xmm0 = fold(xmm0) XOR xmm1
  db $C4, $E3, $79, $44, $E7, $11             // vpclmulqdq xmm4, xmm0, xmm7, $11
  db $C4, $E3, $79, $44, $C7, $00             // vpclmulqdq xmm0, xmm0, xmm7, $00
  db $C5, $F9, $EF, $C4                       // vpxor xmm0, xmm0, xmm4
  db $C5, $F9, $EF, $C1                       // vpxor xmm0, xmm0, xmm1

  // xmm0 = fold(xmm0) XOR xmm2
  db $C4, $E3, $79, $44, $E7, $11             // vpclmulqdq xmm4, xmm0, xmm7, $11
  db $C4, $E3, $79, $44, $C7, $00             // vpclmulqdq xmm0, xmm0, xmm7, $00
  db $C5, $F9, $EF, $C4                       // vpxor xmm0, xmm0, xmm4
  db $C5, $F9, $EF, $C2                       // vpxor xmm0, xmm0, xmm2

  // xmm0 = fold(xmm0) XOR xmm3
  db $C4, $E3, $79, $44, $E7, $11             // vpclmulqdq xmm4, xmm0, xmm7, $11
  db $C4, $E3, $79, $44, $C7, $00             // vpclmulqdq xmm0, xmm0, xmm7, $00
  db $C5, $F9, $EF, $C4                       // vpxor xmm0, xmm0, xmm4
  db $C5, $F9, $EF, $C3                       // vpxor xmm0, xmm0, xmm3

  // ===== FOLD REMAINING 16-BYTE BLOCKS =====
  cmp edx, 16
  jb @tail_done

@tail_loop:
  db $C4, $E3, $79, $44, $E7, $11             // vpclmulqdq xmm4, xmm0, xmm7, $11
  db $C4, $E3, $79, $44, $C7, $00             // vpclmulqdq xmm0, xmm0, xmm7, $00
  db $C5, $F9, $EF, $C4                       // vpxor xmm0, xmm0, xmm4
  db $C5, $FA, $6F, $29                       // vmovdqu xmm5, [rcx]
  db $C5, $F9, $EF, $C5                       // vpxor xmm0, xmm0, xmm5
  add rcx, 16
  sub edx, 16
  cmp edx, 16
  jae @tail_loop

@tail_done:
  // =================================================================
  // Final reduction: 128-bit xmm0 -> CRC in rax
  // Following Linux kernel crc-pclmul-template.S Barrett reduction.
  // =================================================================

  // Step 1: Multiply by x^n and reduce 128 bits to 64+n bits.
  db $C4, $E3, $79, $44, $CF, $10             // vpclmulqdq xmm1, xmm0, xmm7, $10
  db $C5, $F9, $73, $D8, $08                  // vpsrldq xmm0, xmm0, 8
  db $C5, $F9, $EF, $C1                       // vpxor xmm0, xmm0, xmm1

  // Step 2: Barrett reduction.
  db $C4, $C1, $7A, $6F, $71, $20             // vmovdqu xmm6, [r9 + 32]
  db $C4, $E3, $79, $44, $CE, $00             // vpclmulqdq xmm1, xmm0, xmm6, $00
  db $C4, $E3, $71, $44, $CE, $10             // vpclmulqdq xmm1, xmm1, xmm6, $10
  db $C5, $F9, $EF, $C1                       // vpxor xmm0, xmm0, xmm1

  // Extract high qword (bits 64..127) into rax and return.
  db $C5, $F8, $77                             // vzeroupper
  db $C4, $E3, $F9, $16, $C0, $01             // vpextrq rax, xmm0, 1
