// AVX2 implementation of XXH3_accumulate_512 (fully unrolled, 2 x 32-byte chunks).
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.
// Expects MS x64 ABI: rcx = acc ptr, rdx = input ptr, r8 = secret ptr.
// Uses only volatile registers: ymm0-ymm4.
// Reference: official xxHash C - XXH3_accumulate_512_avx2 in xxhash.h

  // --- Chunk 0: acc[0..3], input[0..31], secret[0..31] ---
  db $C5, $FE, $6F, $01                         // vmovdqu ymm0, yword [rcx]
  db $C5, $FE, $6F, $0A                         // vmovdqu ymm1, yword [rdx]
  db $C4, $C1, $7E, $6F, $10                    // vmovdqu ymm2, yword [r8]
  db $C5, $ED, $EF, $D1                         // vpxor ymm2, ymm2, ymm1
  db $C5, $E5, $73, $D2, $20                    // vpsrlq ymm3, ymm2, 32
  db $C5, $ED, $F4, $D3                         // vpmuludq ymm2, ymm2, ymm3
  db $C5, $FD, $70, $C9, $4E                    // vpshufd ymm1, ymm1, $4E
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C2                         // vpaddq ymm0, ymm0, ymm2
  db $C5, $FE, $7F, $01                         // vmovdqu yword [rcx], ymm0

  // --- Chunk 1: acc[4..7], input[32..63], secret[32..63] ---
  db $C5, $FE, $6F, $41, $20                    // vmovdqu ymm0, yword [rcx + $20]
  db $C5, $FE, $6F, $4A, $20                    // vmovdqu ymm1, yword [rdx + $20]
  db $C4, $C1, $7E, $6F, $50, $20               // vmovdqu ymm2, yword [r8 + $20]
  db $C5, $ED, $EF, $D1                         // vpxor ymm2, ymm2, ymm1
  db $C5, $E5, $73, $D2, $20                    // vpsrlq ymm3, ymm2, 32
  db $C5, $ED, $F4, $D3                         // vpmuludq ymm2, ymm2, ymm3
  db $C5, $FD, $70, $C9, $4E                    // vpshufd ymm1, ymm1, $4E
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C2                         // vpaddq ymm0, ymm0, ymm2
  db $C5, $FE, $7F, $41, $20                    // vmovdqu yword [rcx + $20], ymm0

  db $C5, $F8, $77                              // vzeroupper
