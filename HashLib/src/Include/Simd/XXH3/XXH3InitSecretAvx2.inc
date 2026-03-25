// AVX2 implementation of XXH3_initCustomSecret (fully unrolled, 6 x 32-byte chunks).
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.
// Expects MS x64 ABI: rcx = customSecret ptr, rdx = defaultSecret ptr, r8 = seed (UInt64).
// Uses only volatile registers: ymm0-ymm2, rax.
// Reference: official xxHash C - XXH3_initCustomSecret_avx2 in xxhash.h

  // Build seed vector ymm0 = [seed, -seed, seed, -seed]
  db $C4, $C1, $F9, $6E, $C0                    // vmovq xmm0, r8
  mov rax, r8
  neg rax
  db $C4, $E1, $F9, $6E, $C8                    // vmovq xmm1, rax
  db $C5, $F9, $6C, $C1                         // vpunpcklqdq xmm0, xmm0, xmm1
  db $C4, $E3, $7D, $38, $C0, $01               // vinserti128 ymm0, ymm0, xmm0, 1

  // Block 0
  db $C5, $FE, $6F, $0A                         // vmovdqu ymm1, yword [rdx]
  db $C5, $F5, $D4, $C8                         // vpaddq ymm1, ymm1, ymm0
  db $C5, $FE, $7F, $09                         // vmovdqu yword [rcx], ymm1

  // Block 1
  db $C5, $FE, $6F, $4A, $20                    // vmovdqu ymm1, yword [rdx + $20]
  db $C5, $F5, $D4, $C8                         // vpaddq ymm1, ymm1, ymm0
  db $C5, $FE, $7F, $49, $20                    // vmovdqu yword [rcx + $20], ymm1

  // Block 2
  db $C5, $FE, $6F, $4A, $40                    // vmovdqu ymm1, yword [rdx + $40]
  db $C5, $F5, $D4, $C8                         // vpaddq ymm1, ymm1, ymm0
  db $C5, $FE, $7F, $49, $40                    // vmovdqu yword [rcx + $40], ymm1

  // Block 3
  db $C5, $FE, $6F, $4A, $60                    // vmovdqu ymm1, yword [rdx + $60]
  db $C5, $F5, $D4, $C8                         // vpaddq ymm1, ymm1, ymm0
  db $C5, $FE, $7F, $49, $60                    // vmovdqu yword [rcx + $60], ymm1

  // Block 4
  db $C5, $FE, $6F, $8A, $80, $00, $00, $00     // vmovdqu ymm1, yword [rdx + $80]
  db $C5, $F5, $D4, $C8                         // vpaddq ymm1, ymm1, ymm0
  db $C5, $FE, $7F, $89, $80, $00, $00, $00     // vmovdqu yword [rcx + $80], ymm1

  // Block 5
  db $C5, $FE, $6F, $8A, $A0, $00, $00, $00     // vmovdqu ymm1, yword [rdx + $A0]
  db $C5, $F5, $D4, $C8                         // vpaddq ymm1, ymm1, ymm0
  db $C5, $FE, $7F, $89, $A0, $00, $00, $00     // vmovdqu yword [rcx + $A0], ymm1

  db $C5, $F8, $77                              // vzeroupper
