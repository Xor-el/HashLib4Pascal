// AVX2 implementation of XXH3_accumulate_512 (IA-32; fully unrolled,
// 2 x 32-byte chunks). Same structure as XXH3Acc512Avx2_x86_64.inc.
// IA-32: after HlpSimdProc3Begin_i386 - ebx = acc, esi = input, edi = secret
//   (parallel to MS x64 ABI: rcx, rdx, r8).
// Uses only volatile registers: ymm0-ymm3.
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.
// Reference: official xxHash C - XXH3_accumulate_512_avx2 in xxhash.h,
// HashLib XXH3Acc512Avx2_x86_64.inc.

  // --- Chunk 0: acc[0..3], input[0..31], secret[0..31] ---
  db $C5, $FE, $6F, $03                         // vmovdqu ymm0, yword [ebx]
  db $C5, $FE, $6F, $0E                         // vmovdqu ymm1, yword [esi]
  db $C5, $FE, $6F, $17                         // vmovdqu ymm2, yword [edi]
  db $C5, $ED, $EF, $D1                         // vpxor  ymm2, ymm2, ymm1
  db $C5, $E5, $73, $D2, $20                    // vpsrlq ymm3, ymm2, $20
  db $C5, $ED, $F4, $D3                         // vpmuludq ymm2, ymm2, ymm3
  db $C5, $FD, $70, $C9, $4E                    // vpshufd ymm1, ymm1, $4E
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C2                         // vpaddq ymm0, ymm0, ymm2
  db $C5, $FE, $7F, $03                         // vmovdqu yword [ebx], ymm0

  // --- Chunk 1: acc[4..7], input[32..63], secret[32..63] ---
  db $C5, $FE, $6F, $43, $20                    // vmovdqu ymm0, yword [ebx + $20]
  db $C5, $FE, $6F, $4E, $20                    // vmovdqu ymm1, yword [esi + $20]
  db $C5, $FE, $6F, $57, $20                    // vmovdqu ymm2, yword [edi + $20]
  db $C5, $ED, $EF, $D1                         // vpxor  ymm2, ymm2, ymm1
  db $C5, $E5, $73, $D2, $20                    // vpsrlq ymm3, ymm2, $20
  db $C5, $ED, $F4, $D3                         // vpmuludq ymm2, ymm2, ymm3
  db $C5, $FD, $70, $C9, $4E                    // vpshufd ymm1, ymm1, $4E
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C2                         // vpaddq ymm0, ymm0, ymm2
  db $C5, $FE, $7F, $43, $20                    // vmovdqu yword [ebx + $20], ymm0

  db $C5, $F8, $77                              // vzeroupper
  pop    edi
  pop    esi
  pop    ebx
