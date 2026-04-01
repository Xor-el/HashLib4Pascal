// AVX2 implementation of Adler-32 block processing.
// Expects MS x64 ABI: rcx = data ptr, edx = num_blocks, r8 = sums ptr, r9 = constants ptr.
// ASums layout: [SumA: UInt32, SumB: UInt32].
// Constants layout: [weights: 32B, ones_16: 32B] at offsets 0 and 32.
// Processes num_blocks x 32-byte blocks. Does NOT apply mod 65521 (caller does it).
// Uses ymm0-ymm5 only (all volatile on Windows x64, no saves needed).
// Weights and ones are reloaded from memory each iteration to avoid
// using non-volatile ymm registers.
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.

  // Zero register
  db $C5, $E5, $EF, $DB                         // vpxor ymm3, ymm3, ymm3

  // Load initial sums
  mov eax, dword [r8]
  mov r10d, dword [r8 + 4]
  mov r11d, edx

  // v_ps = [SumA * num_blocks, 0, 0, 0]
  imul edx, eax
  db $C5, $F9, $6E, $D2                         // vmovd xmm2, edx

  // v_s2 = [SumB, 0, 0, 0]
  db $C4, $C1, $79, $6E, $CA                    // vmovd xmm1, r10d

  // v_s1 = 0
  db $C5, $F9, $EF, $C0                         // vpxor xmm0, xmm0, xmm0

@loop:
  db $C5, $ED, $FE, $D0                         // vpaddd ymm2, ymm2, ymm0

  // Load 32 data bytes
  db $C5, $FE, $6F, $21                         // vmovdqu ymm4, yword [rcx]

  // Byte sum for s1
  db $C5, $DD, $F6, $EB                         // vpsadbw ymm5, ymm4, ymm3
  db $C5, $FD, $FE, $C5                         // vpaddd ymm0, ymm0, ymm5

  // Weighted sum for s2
  db $C4, $C1, $7E, $6F, $29                    // vmovdqu ymm5, yword [r9]
  db $C4, $E2, $5D, $04, $E5                    // vpmaddubsw ymm4, ymm4, ymm5
  db $C4, $C1, $7E, $6F, $69, $20              // vmovdqu ymm5, yword [r9 + 32]
  db $C5, $DD, $F5, $E5                         // vpmaddwd ymm4, ymm4, ymm5
  db $C5, $F5, $FE, $CC                         // vpaddd ymm1, ymm1, ymm4

  add rcx, 32
  dec r11d
  jnz @loop

  // v_s2 += v_ps * 32
  db $C5, $ED, $72, $F2, $05                    // vpslld ymm2, ymm2, 5
  db $C5, $F5, $FE, $CA                         // vpaddd ymm1, ymm1, ymm2

  // Horizontal reduce v_s1: extract high 128 + 128-bit hsum
  db $C4, $E3, $7D, $39, $C5, $01              // vextracti128 xmm5, ymm0, 1
  db $C5, $F9, $FE, $C5                         // vpaddd xmm0, xmm0, xmm5
  db $C5, $F9, $70, $E8, $B1                    // vpshufd xmm5, xmm0, $B1
  db $C5, $F9, $FE, $C5                         // vpaddd xmm0, xmm0, xmm5
  db $C5, $F9, $70, $E8, $4E                    // vpshufd xmm5, xmm0, $4E
  db $C5, $F9, $FE, $C5                         // vpaddd xmm0, xmm0, xmm5
  db $C5, $F9, $7E, $C2                         // vmovd edx, xmm0
  add eax, edx

  // Horizontal reduce v_s2: extract high 128 + 128-bit hsum
  db $C4, $E3, $7D, $39, $CD, $01              // vextracti128 xmm5, ymm1, 1
  db $C5, $F1, $FE, $CD                         // vpaddd xmm1, xmm1, xmm5
  db $C5, $F9, $70, $E9, $B1                    // vpshufd xmm5, xmm1, $B1
  db $C5, $F1, $FE, $CD                         // vpaddd xmm1, xmm1, xmm5
  db $C5, $F9, $70, $E9, $4E                    // vpshufd xmm5, xmm1, $4E
  db $C5, $F1, $FE, $CD                         // vpaddd xmm1, xmm1, xmm5
  db $C4, $C1, $79, $7E, $CA                    // vmovd r10d, xmm1

  // Store results
  mov dword [r8], eax
  mov dword [r8 + 4], r10d

  db $C5, $F8, $77                              // vzeroupper
