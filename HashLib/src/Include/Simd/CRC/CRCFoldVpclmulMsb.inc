// AVX2 + VPCLMULQDQ CRC folding + Barrett reduction for non-reflected
// (MSB-first) CRCs with width 8..64.
// AVX2/VPCLMULQDQ/SSSE3 instructions are db-encoded for broad assembler
// compatibility.
//
// Function signature (included after SimdProc4Begin.inc):
//   function CRC_Fold_Vpclmul_Msb(AData: PByte; ALength: UInt32;
//     AState: Pointer; AConstants: Pointer): UInt64;
//
// Register mapping (MS x64 ABI after prologue):
//   rcx = AData, edx = ALength (>= 16), r8 = AState, r9 = AConstants
//   AState: [0..7] = initial CRC pre-shifted left by (64 - Width), [8..15] = 0.
//   AConstants layout (TCRCFoldConstants):
//     [0..15]  = Fold_4x128  (stride 512)
//     [16..31] = Fold_1x128  (stride 128)
//     [32..47] = Barrett
//     [48..63] = Fold_8x128  (stride 1024)
//     [64..79] = BswapMask
//     [80..87] = CrcBits
//     [88..95] = BarrettShift
//   Returns: final CRC in RAX.
//
// Reference: Linux kernel crc-pclmul-template.S by Eric Biggers (Google).
//
// VEX byte layout reference:
//   2-byte: C5 [R.vvvv.L.pp]
//   3-byte: C4 [R.X.B.mmmmm] [W.vvvv.L.pp]

  cmp edx, 128
  jb @xmm_path

  // ===== YMM PATH (>= 128 bytes) =====

  // Broadcast BswapMask into ymm5 (kept throughout ymm path)
  db $C4, $C2, $7D, $5A, $69, $40             // vbroadcasti128 ymm5, [r9 + 64]

  // Broadcast Fold_8x128 (stride 1024) into ymm6
  db $C4, $C2, $7D, $5A, $71, $30             // vbroadcasti128 ymm6, [r9 + 48]

  // Load first 128 bytes into ymm0..ymm3 and byte-swap
  db $C5, $FE, $6F, $01                       // vmovdqu ymm0, [rcx]
  db $C4, $E2, $7D, $00, $C5                  // vpshufb ymm0, ymm0, ymm5
  db $C5, $FE, $6F, $49, $20                  // vmovdqu ymm1, [rcx + 32]
  db $C4, $E2, $75, $00, $CD                  // vpshufb ymm1, ymm1, ymm5
  db $C5, $FE, $6F, $51, $40                  // vmovdqu ymm2, [rcx + 64]
  db $C4, $E2, $6D, $00, $D5                  // vpshufb ymm2, ymm2, ymm5
  db $C5, $FE, $6F, $59, $60                  // vmovdqu ymm3, [rcx + 96]
  db $C4, $E2, $65, $00, $DD                  // vpshufb ymm3, ymm3, ymm5

  // XOR pre-shifted CRC into HIGH qword of first lane of ymm0
  db $C4, $C1, $7A, $7E, $20                  // vmovq xmm4, [r8]
  db $C5, $D9, $73, $FC, $08                  // vpslldq xmm4, xmm4, 8
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
  db $C5, $FE, $6F, $39                       // vmovdqu ymm7, [rcx]
  db $C4, $E2, $45, $00, $FD                  // vpshufb ymm7, ymm7, ymm5
  db $C5, $FD, $EF, $C7                       // vpxor ymm0, ymm0, ymm7

  // Fold ymm1
  db $C4, $E3, $75, $44, $E6, $11             // vpclmulqdq ymm4, ymm1, ymm6, $11
  db $C4, $E3, $75, $44, $CE, $00             // vpclmulqdq ymm1, ymm1, ymm6, $00
  db $C5, $F5, $EF, $CC                       // vpxor ymm1, ymm1, ymm4
  db $C5, $FE, $6F, $79, $20                  // vmovdqu ymm7, [rcx + 32]
  db $C4, $E2, $45, $00, $FD                  // vpshufb ymm7, ymm7, ymm5
  db $C5, $F5, $EF, $CF                       // vpxor ymm1, ymm1, ymm7

  // Fold ymm2
  db $C4, $E3, $6D, $44, $E6, $11             // vpclmulqdq ymm4, ymm2, ymm6, $11
  db $C4, $E3, $6D, $44, $D6, $00             // vpclmulqdq ymm2, ymm2, ymm6, $00
  db $C5, $ED, $EF, $D4                       // vpxor ymm2, ymm2, ymm4
  db $C5, $FE, $6F, $79, $40                  // vmovdqu ymm7, [rcx + 64]
  db $C4, $E2, $45, $00, $FD                  // vpshufb ymm7, ymm7, ymm5
  db $C5, $ED, $EF, $D7                       // vpxor ymm2, ymm2, ymm7

  // Fold ymm3
  db $C4, $E3, $65, $44, $E6, $11             // vpclmulqdq ymm4, ymm3, ymm6, $11
  db $C4, $E3, $65, $44, $DE, $00             // vpclmulqdq ymm3, ymm3, ymm6, $00
  db $C5, $E5, $EF, $DC                       // vpxor ymm3, ymm3, ymm4
  db $C5, $FE, $6F, $79, $60                  // vmovdqu ymm7, [rcx + 96]
  db $C4, $E2, $45, $00, $FD                  // vpshufb ymm7, ymm7, ymm5
  db $C5, $E5, $EF, $DF                       // vpxor ymm3, ymm3, ymm7

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
  db $C5, $F9, $6F, $D1                       // vmovdqa xmm2, xmm1       (low of ymm1)
  db $C4, $E3, $7D, $39, $CB, $01             // vextracti128 xmm3, ymm1, 1
  db $C4, $E3, $7D, $39, $C1, $01             // vextracti128 xmm1, ymm0, 1

  db $C5, $F8, $77                             // vzeroupper
  jmp @fold4to1

@xmm_path:
  // ===== XMM PATH (16..127 bytes) =====

  // Load BswapMask into xmm5
  db $C4, $C1, $7A, $6F, $69, $40             // vmovdqu xmm5, [r9 + 64]

  cmp edx, 64
  jae @xmm_large

  // --- Small input (16..63 bytes): load 1 block with byte-swap ---
  db $C5, $FA, $6F, $01                       // vmovdqu xmm0, [rcx]
  db $C4, $E2, $79, $00, $C5                  // vpshufb xmm0, xmm0, xmm5
  db $C4, $C1, $7A, $7E, $20                  // vmovq xmm4, [r8]
  db $C5, $D9, $73, $FC, $08                  // vpslldq xmm4, xmm4, 8
  db $C5, $F9, $EF, $C4                       // vpxor xmm0, xmm0, xmm4
  add rcx, 16
  sub edx, 16
  db $C4, $C1, $7A, $6F, $79, $10             // vmovdqu xmm7, [r9 + 16]
  jmp @tail_check

@xmm_large:
  // --- Large input (64..127 bytes): load 4 blocks with byte-swap ---
  db $C5, $FA, $6F, $01                       // vmovdqu xmm0, [rcx]
  db $C4, $E2, $79, $00, $C5                  // vpshufb xmm0, xmm0, xmm5
  db $C5, $FA, $6F, $49, $10                  // vmovdqu xmm1, [rcx + 16]
  db $C4, $E2, $71, $00, $CD                  // vpshufb xmm1, xmm1, xmm5
  db $C5, $FA, $6F, $51, $20                  // vmovdqu xmm2, [rcx + 32]
  db $C4, $E2, $69, $00, $D5                  // vpshufb xmm2, xmm2, xmm5
  db $C5, $FA, $6F, $59, $30                  // vmovdqu xmm3, [rcx + 48]
  db $C4, $E2, $61, $00, $DD                  // vpshufb xmm3, xmm3, xmm5

  db $C4, $C1, $7A, $7E, $20                  // vmovq xmm4, [r8]
  db $C5, $D9, $73, $FC, $08                  // vpslldq xmm4, xmm4, 8
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
@tail_check:
  cmp edx, 16
  jb @tail_done

@tail_loop:
  db $C4, $E3, $79, $44, $E7, $11             // vpclmulqdq xmm4, xmm0, xmm7, $11
  db $C4, $E3, $79, $44, $C7, $00             // vpclmulqdq xmm0, xmm0, xmm7, $00
  db $C5, $F9, $EF, $C4                       // vpxor xmm0, xmm0, xmm4
  db $C5, $FA, $6F, $31                       // vmovdqu xmm6, [rcx]
  db $C4, $E2, $49, $00, $F5                  // vpshufb xmm6, xmm6, xmm5
  db $C5, $F9, $EF, $C6                       // vpxor xmm0, xmm0, xmm6
  add rcx, 16
  sub edx, 16
  cmp edx, 16
  jae @tail_loop

@tail_done:
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

  db $C4, $C1, $7A, $6F, $71, $20             // vmovdqu xmm6, [r9 + 32]

  // --- Round 1: Barrett on A_H ---
  db $C5, $F9, $6F, $C8                       // vmovdqa xmm1, xmm0
  db $C4, $E3, $71, $44, $CE, $01             // vpclmulqdq xmm1, xmm1, xmm6, $01
  db $C5, $F1, $EF, $C8                       // vpxor xmm1, xmm1, xmm0
  db $C4, $E3, $71, $44, $CE, $11             // vpclmulqdq xmm1, xmm1, xmm6, $11

  // Merge: crc1 in xmm1.lo bits 0..n-1; shift left by (64-n) and XOR
  db $C4, $C1, $7A, $7E, $51, $58             // vmovq xmm2, [r9 + 88]
  db $C5, $F1, $F3, $CA                       // vpsllq xmm1, xmm1, xmm2
  db $C5, $F9, $EF, $C1                       // vpxor xmm0, xmm0, xmm1

  // --- Round 2: Barrett on modified A_L ---
  db $C5, $F9, $6F, $C8                       // vmovdqa xmm1, xmm0
  db $C4, $E3, $71, $44, $CE, $00             // vpclmulqdq xmm1, xmm1, xmm6, $00
  db $C5, $F9, $70, $C0, $4E                  // vpshufd xmm0, xmm0, $4E
  db $C5, $F9, $EF, $C1                       // vpxor xmm0, xmm0, xmm1
  db $C4, $E3, $79, $44, $C6, $11             // vpclmulqdq xmm0, xmm0, xmm6, $11

  // Extract low qword into rax and return
  db $C5, $F8, $77                             // vzeroupper
  // movq rax, xmm0: 66 48 0F 7E C0
  db $66, $48, $0F, $7E, $C0
