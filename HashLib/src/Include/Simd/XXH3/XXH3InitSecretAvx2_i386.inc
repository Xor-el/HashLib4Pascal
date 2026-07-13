// AVX2 implementation of XXH3_initCustomSecret (fully unrolled, 6 x
// 32-byte chunks; IA-32). Same structure as XXH3InitSecretAvx2_x86_64.inc;
// the x86_64 version's vmovq xmm, r64 seed transfers (not encodable in
// 32-bit mode) become the SSE2 i386 sibling's push/vmovq-from-stack
// pattern, with the negation done in 32-bit halves (not/not + add/adc
// carry).
// ABI (after HlpSimdProc3Begin_i386.inc): ebx = customSecret ptr,
//   esi = defaultSecret ptr, edi = seed ptr (PUInt64).
// Saves: none (uses ymm0-ymm1, eax, ecx, edx; edi reused; all volatile on
//   IA-32).
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.
// Reference: official xxHash C - XXH3_initCustomSecret_avx2 in xxhash.h,
// HashLib XXH3InitSecretAvx2_x86_64.inc.

  // Build seed vector ymm0 = [seed, -seed, seed, -seed]
  mov    eax, dword ptr [edi]
  mov    edx, dword ptr [edi + $4]

  push   edx
  push   eax
  db $C5, $FA, $7E, $04, $24                    // vmovq  xmm0, qword [esp]
  add    esp, $8

  mov    ecx, eax
  mov    edi, edx
  not    ecx
  not    edi
  add    ecx, $1
  adc    edi, $0
  push   edi
  push   ecx
  db $C5, $FA, $7E, $0C, $24                    // vmovq  xmm1, qword [esp]
  add    esp, $8
  db $C5, $F9, $6C, $C1                         // vpunpcklqdq xmm0, xmm0, xmm1
  db $C4, $E3, $7D, $38, $C0, $01               // vinserti128 ymm0, ymm0, xmm0, $1

  // Block 0
  db $C5, $FE, $6F, $0E                         // vmovdqu ymm1, yword [esi]
  db $C5, $F5, $D4, $C8                         // vpaddq ymm1, ymm1, ymm0
  db $C5, $FE, $7F, $0B                         // vmovdqu yword [ebx], ymm1

  // Block 1
  db $C5, $FE, $6F, $4E, $20                    // vmovdqu ymm1, yword [esi + $20]
  db $C5, $F5, $D4, $C8                         // vpaddq ymm1, ymm1, ymm0
  db $C5, $FE, $7F, $4B, $20                    // vmovdqu yword [ebx + $20], ymm1

  // Block 2
  db $C5, $FE, $6F, $4E, $40                    // vmovdqu ymm1, yword [esi + $40]
  db $C5, $F5, $D4, $C8                         // vpaddq ymm1, ymm1, ymm0
  db $C5, $FE, $7F, $4B, $40                    // vmovdqu yword [ebx + $40], ymm1

  // Block 3
  db $C5, $FE, $6F, $4E, $60                    // vmovdqu ymm1, yword [esi + $60]
  db $C5, $F5, $D4, $C8                         // vpaddq ymm1, ymm1, ymm0
  db $C5, $FE, $7F, $4B, $60                    // vmovdqu yword [ebx + $60], ymm1

  // Block 4
  db $C5, $FE, $6F, $8E, $80, $00, $00, $00     // vmovdqu ymm1, yword [esi + $80]
  db $C5, $F5, $D4, $C8                         // vpaddq ymm1, ymm1, ymm0
  db $C5, $FE, $7F, $8B, $80, $00, $00, $00     // vmovdqu yword [ebx + $80], ymm1

  // Block 5
  db $C5, $FE, $6F, $8E, $A0, $00, $00, $00     // vmovdqu ymm1, yword [esi + $A0]
  db $C5, $F5, $D4, $C8                         // vpaddq ymm1, ymm1, ymm0
  db $C5, $FE, $7F, $8B, $A0, $00, $00, $00     // vmovdqu yword [ebx + $A0], ymm1

  db $C5, $F8, $77                              // vzeroupper
  pop    edi
  pop    esi
  pop    ebx
