// AVX2 implementation of XXH3_scrambleAcc (fully unrolled, 2 x 32-byte
// chunks; IA-32). Same structure as XXH3ScrambleAvx2_x86_64.inc.
// ABI (after HlpSimdProc2Begin_i386.inc): ebx = acc ptr, esi = secret ptr.
// Saves: none (uses ymm0-ymm4 and eax only; all volatile on IA-32).
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.
// Reference: official xxHash C - XXH3_scrambleAcc_avx2 in xxhash.h,
// HashLib XXH3ScrambleAvx2_x86_64.inc.

  // Broadcast XXH_PRIME32_1 ($9E3779B1) to all dword lanes of ymm4
  mov    eax, $9E3779B1
  db $C5, $F9, $6E, $E0                         // vmovd  xmm4, eax
  db $C4, $E2, $7D, $58, $E4                    // vpbroadcastd ymm4, xmm4

  // --- Chunk 0: acc[0..3], secret[0..31] ---
  db $C5, $FE, $6F, $03                         // vmovdqu ymm0, yword [ebx]
  db $C5, $F5, $73, $D0, $2F                    // vpsrlq ymm1, ymm0, $2F
  db $C5, $FD, $EF, $C1                         // vpxor  ymm0, ymm0, ymm1
  db $C5, $FE, $6F, $0E                         // vmovdqu ymm1, yword [esi]
  db $C5, $FD, $EF, $C1                         // vpxor  ymm0, ymm0, ymm1
  // Multiply 64-bit lanes by PRIME32_1
  db $C5, $F5, $73, $D0, $20                    // vpsrlq ymm1, ymm0, $20
  db $C5, $FD, $F4, $D4                         // vpmuludq ymm2, ymm0, ymm4
  db $C5, $F5, $F4, $CC                         // vpmuludq ymm1, ymm1, ymm4
  db $C5, $F5, $73, $F1, $20                    // vpsllq ymm1, ymm1, $20
  db $C5, $ED, $D4, $C1                         // vpaddq ymm0, ymm2, ymm1
  db $C5, $FE, $7F, $03                         // vmovdqu yword [ebx], ymm0

  // --- Chunk 1: acc[4..7], secret[32..63] ---
  db $C5, $FE, $6F, $43, $20                    // vmovdqu ymm0, yword [ebx + $20]
  db $C5, $F5, $73, $D0, $2F                    // vpsrlq ymm1, ymm0, $2F
  db $C5, $FD, $EF, $C1                         // vpxor  ymm0, ymm0, ymm1
  db $C5, $FE, $6F, $4E, $20                    // vmovdqu ymm1, yword [esi + $20]
  db $C5, $FD, $EF, $C1                         // vpxor  ymm0, ymm0, ymm1
  db $C5, $F5, $73, $D0, $20                    // vpsrlq ymm1, ymm0, $20
  db $C5, $FD, $F4, $D4                         // vpmuludq ymm2, ymm0, ymm4
  db $C5, $F5, $F4, $CC                         // vpmuludq ymm1, ymm1, ymm4
  db $C5, $F5, $73, $F1, $20                    // vpsllq ymm1, ymm1, $20
  db $C5, $ED, $D4, $C1                         // vpaddq ymm0, ymm2, ymm1
  db $C5, $FE, $7F, $43, $20                    // vmovdqu yword [ebx + $20], ymm0

  db $C5, $F8, $77                              // vzeroupper
  pop    esi
  pop    ebx
