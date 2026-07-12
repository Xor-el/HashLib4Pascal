// AVX2 implementation of Adler-32 block processing (IA-32; 256-bit ymm
// integer ops work in 32-bit mode - only ymm0-7 exist, which this kernel
// fits). Same structure as Adler32BlocksAvx2_x86_64.inc.
// IA-32: after HlpSimdProc4Begin_i386 - ebx = data ptr, esi = num_blocks,
//   edi = sums ptr, eax = constants ptr (moved to ecx at entry; eax then
//   accumulates SumA). SumB rides xmm1 end-to-end via vmovd memory forms.
// ASums layout: [SumA: UInt32, SumB: UInt32].
// Constants layout: [weights: 32B, ones_16: 32B] at offsets 0 and 32.
// Processes num_blocks x 32-byte blocks. Does NOT apply mod 65521 (caller does it).
// Uses ymm0-ymm5 only (all volatile on IA-32; no saves needed).
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.
// Reference: Chromium zlib adler32_simd.c, HashLib Adler32BlocksAvx2_x86_64.inc.

  mov    ecx, eax
  db $C5, $E5, $EF, $DB                         // vpxor  ymm3, ymm3, ymm3
  mov    eax, dword ptr [edi]
  db $C5, $F9, $6E, $4F, $04                    // vmovd  xmm1, dword [edi + $4]
  mov    edx, esi
  imul   edx, eax
  db $C5, $F9, $6E, $D2                         // vmovd  xmm2, edx
  db $C5, $F9, $EF, $C0                         // vpxor  xmm0, xmm0, xmm0

@loop:
  db $C5, $ED, $FE, $D0                         // vpaddd ymm2, ymm2, ymm0
  db $C5, $FE, $6F, $23                         // vmovdqu ymm4, yword [ebx]
  db $C5, $DD, $F6, $EB                         // vpsadbw ymm5, ymm4, ymm3
  db $C5, $FD, $FE, $C5                         // vpaddd ymm0, ymm0, ymm5
  db $C5, $FE, $6F, $29                         // vmovdqu ymm5, yword [ecx]
  db $C4, $E2, $5D, $04, $E5                    // vpmaddubsw ymm4, ymm4, ymm5
  db $C5, $FE, $6F, $69, $20                    // vmovdqu ymm5, yword [ecx + $20]
  db $C5, $DD, $F5, $E5                         // vpmaddwd ymm4, ymm4, ymm5
  db $C5, $F5, $FE, $CC                         // vpaddd ymm1, ymm1, ymm4
  add    ebx, $20
  dec    esi
  jnz @loop
  db $C5, $ED, $72, $F2, $05                    // vpslld ymm2, ymm2, $5
  db $C5, $F5, $FE, $CA                         // vpaddd ymm1, ymm1, ymm2
  db $C4, $E3, $7D, $39, $C5, $01               // vextracti128 xmm5, ymm0, $1
  db $C5, $F9, $FE, $C5                         // vpaddd xmm0, xmm0, xmm5
  db $C5, $F9, $70, $E8, $B1                    // vpshufd xmm5, xmm0, $B1
  db $C5, $F9, $FE, $C5                         // vpaddd xmm0, xmm0, xmm5
  db $C5, $F9, $70, $E8, $4E                    // vpshufd xmm5, xmm0, $4E
  db $C5, $F9, $FE, $C5                         // vpaddd xmm0, xmm0, xmm5
  db $C5, $F9, $7E, $C2                         // vmovd  edx, xmm0
  add    eax, edx
  db $C4, $E3, $7D, $39, $CD, $01               // vextracti128 xmm5, ymm1, $1
  db $C5, $F1, $FE, $CD                         // vpaddd xmm1, xmm1, xmm5
  db $C5, $F9, $70, $E9, $B1                    // vpshufd xmm5, xmm1, $B1
  db $C5, $F1, $FE, $CD                         // vpaddd xmm1, xmm1, xmm5
  db $C5, $F9, $70, $E9, $4E                    // vpshufd xmm5, xmm1, $4E
  db $C5, $F1, $FE, $CD                         // vpaddd xmm1, xmm1, xmm5
  mov    dword ptr [edi], eax
  db $C5, $F9, $7E, $4F, $04                    // vmovd  dword [edi + $4], xmm1
  db $C5, $F8, $77                              // vzeroupper
  pop    edi
  pop    esi
  pop    ebx
