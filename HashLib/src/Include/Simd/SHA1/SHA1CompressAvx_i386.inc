// AVX (VEX-128) implementation of SHA-1 compress (SIMD schedule; IA-32);
// the Avx name states the ISA requirement: VEX-128 encodings only - there
// is no i386 AVX2 SHA-1 upstream. The 3-operand VEX forms eliminate the
// SSSE3 kernel's register-copy movdqa traffic in the interleaved message
// schedule. The four round constants and the byte-swap mask are read from
// K_SHA1_Doubled at a 32-byte stride (VEX memory operands are read
// unaligned, so the Pascal const needs no special alignment) and spilled
// to the local frame like the original; the original's PIC table setup and
// stack-argument reads are replaced by the shared-prologue registers.
// ABI (after HlpSimdProc4Begin_i386.inc): ebx = state ptr, esi = data ptr,
//   edi = numblocks, eax = K_SHA1_Doubled ptr.
// Frame: the prologue pushes ebx/esi/edi; ebp is pushed here, giving the
//   4-deep frame the original epilogue unwinds via its saved-esp slot.
// AVX instructions are db-encoded for broad assembler compatibility.
// Reference: OpenSSL CRYPTOGAMS sha1-586.pl (AVX function).

  push   ebp
  mov    ebp, eax
  db $C5, $FC, $77                                // vzeroall
  db $C5, $FA, $6F, $7D, $00                      // vmovdqu xmm7, oword [ebp + $0]
  db $C5, $FA, $6F, $45, $20                      // vmovdqu xmm0, oword [ebp + $20]
  db $C5, $FA, $6F, $4D, $40                      // vmovdqu xmm1, oword [ebp + $40]
  db $C5, $FA, $6F, $55, $60                      // vmovdqu xmm2, oword [ebp + $60]
  db $C5, $FA, $6F, $B5, $80, $00, $00, $00       // vmovdqu xmm6, oword [ebp + $80]
  mov    edx, edi
  mov    edi, ebx
  mov    ebp, esi
  mov    esi, esp
  sub    esp, $D0
  and    esp, $FFFFFFC0
  db $C5, $F9, $7F, $44, $24, $70                 // vmovdqa oword [esp + $70], xmm0
  db $C5, $F9, $7F, $8C, $24, $80, $00, $00, $00  // vmovdqa oword [esp + $80], xmm1
  db $C5, $F9, $7F, $94, $24, $90, $00, $00, $00  // vmovdqa oword [esp + $90], xmm2
  shl    edx, $6
  db $C5, $F9, $7F, $BC, $24, $A0, $00, $00, $00  // vmovdqa oword [esp + $A0], xmm7
  add    edx, ebp
  db $C5, $F9, $7F, $B4, $24, $B0, $00, $00, $00  // vmovdqa oword [esp + $B0], xmm6
  add    ebp, $40
  mov    dword ptr [esp + $C0], edi
  mov    dword ptr [esp + $C4], ebp
  mov    dword ptr [esp + $C8], edx
  mov    dword ptr [esp + $CC], esi
  mov    eax, dword ptr [edi]
  mov    ebx, dword ptr [edi + $4]
  mov    ecx, dword ptr [edi + $8]
  mov    edx, dword ptr [edi + $C]
  mov    edi, dword ptr [edi + $10]
  mov    esi, ebx
  db $C5, $FA, $6F, $45, $C0                      // vmovdqu xmm0, oword [ebp - $40]
  db $C5, $FA, $6F, $4D, $D0                      // vmovdqu xmm1, oword [ebp - $30]
  db $C5, $FA, $6F, $55, $E0                      // vmovdqu xmm2, oword [ebp - $20]
  db $C5, $FA, $6F, $5D, $F0                      // vmovdqu xmm3, oword [ebp - $10]
  db $C4, $E2, $79, $00, $C6                      // vpshufb xmm0, xmm0, xmm6
  db $C4, $E2, $71, $00, $CE                      // vpshufb xmm1, xmm1, xmm6
  db $C4, $E2, $69, $00, $D6                      // vpshufb xmm2, xmm2, xmm6
  db $C5, $F9, $7F, $7C, $24, $60                 // vmovdqa oword [esp + $60], xmm7
  db $C4, $E2, $61, $00, $DE                      // vpshufb xmm3, xmm3, xmm6
  db $C5, $F9, $FE, $E7                           // vpaddd xmm4, xmm0, xmm7
  db $C5, $F1, $FE, $EF                           // vpaddd xmm5, xmm1, xmm7
  db $C5, $E9, $FE, $F7                           // vpaddd xmm6, xmm2, xmm7
  db $C5, $F9, $7F, $24, $24                      // vmovdqa oword [esp], xmm4
  mov    ebp, ecx
  db $C5, $F9, $7F, $6C, $24, $10                 // vmovdqa oword [esp + $10], xmm5
  xor    ebp, edx
  db $C5, $F9, $7F, $74, $24, $20                 // vmovdqa oword [esp + $20], xmm6
  and    esi, ebp
  jmp @loop_009

@loop_009:
  shrd   ebx, ebx, $2
  xor    esi, edx
  db $C4, $E3, $71, $0F, $E0, $08                 // vpalignr xmm4, xmm1, xmm0, $8
  mov    ebp, eax
  add    edi, dword ptr [esp]
  db $C5, $C1, $FE, $FB                           // vpaddd xmm7, xmm7, xmm3
  db $C5, $F9, $7F, $44, $24, $40                 // vmovdqa oword [esp + $40], xmm0
  xor    ebx, ecx
  shld   eax, eax, $5
  db $C5, $C9, $73, $DB, $04                      // vpsrldq xmm6, xmm3, $4
  add    edi, esi
  and    ebp, ebx
  db $C5, $D9, $EF, $E0                           // vpxor  xmm4, xmm4, xmm0
  xor    ebx, ecx
  add    edi, eax
  db $C5, $C9, $EF, $F2                           // vpxor  xmm6, xmm6, xmm2
  shrd   eax, eax, $7
  xor    ebp, ecx
  db $C5, $F9, $7F, $7C, $24, $30                 // vmovdqa oword [esp + $30], xmm7
  mov    esi, edi
  add    edx, dword ptr [esp + $4]
  db $C5, $D9, $EF, $E6                           // vpxor  xmm4, xmm4, xmm6
  xor    eax, ebx
  shld   edi, edi, $5
  add    edx, ebp
  and    esi, eax
  db $C5, $C9, $72, $D4, $1F                      // vpsrld xmm6, xmm4, $1F
  xor    eax, ebx
  add    edx, edi
  shrd   edi, edi, $7
  xor    esi, ebx
  db $C5, $F9, $73, $FC, $0C                      // vpslldq xmm0, xmm4, $C
  db $C5, $D9, $FE, $E4                           // vpaddd xmm4, xmm4, xmm4
  mov    ebp, edx
  add    ecx, dword ptr [esp + $8]
  xor    edi, eax
  shld   edx, edx, $5
  db $C5, $C1, $72, $D0, $1E                      // vpsrld xmm7, xmm0, $1E
  db $C5, $D9, $EB, $E6                           // vpor   xmm4, xmm4, xmm6
  add    ecx, esi
  and    ebp, edi
  xor    edi, eax
  add    ecx, edx
  db $C5, $F9, $72, $F0, $02                      // vpslld xmm0, xmm0, $2
  shrd   edx, edx, $7
  xor    ebp, eax
  db $C5, $D9, $EF, $E7                           // vpxor  xmm4, xmm4, xmm7
  mov    esi, ecx
  add    ebx, dword ptr [esp + $C]
  xor    edx, edi
  shld   ecx, ecx, $5
  db $C5, $D9, $EF, $E0                           // vpxor  xmm4, xmm4, xmm0
  add    ebx, ebp
  and    esi, edx
  db $C5, $F9, $6F, $44, $24, $60                 // vmovdqa xmm0, oword [esp + $60]
  xor    edx, edi
  add    ebx, ecx
  shrd   ecx, ecx, $7
  xor    esi, edi
  db $C4, $E3, $69, $0F, $E9, $08                 // vpalignr xmm5, xmm2, xmm1, $8
  mov    ebp, ebx
  add    eax, dword ptr [esp + $10]
  db $C5, $F9, $FE, $C4                           // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $7F, $4C, $24, $50                 // vmovdqa oword [esp + $50], xmm1
  xor    ecx, edx
  shld   ebx, ebx, $5
  db $C5, $C1, $73, $DC, $04                      // vpsrldq xmm7, xmm4, $4
  add    eax, esi
  and    ebp, ecx
  db $C5, $D1, $EF, $E9                           // vpxor  xmm5, xmm5, xmm1
  xor    ecx, edx
  add    eax, ebx
  db $C5, $C1, $EF, $FB                           // vpxor  xmm7, xmm7, xmm3
  shrd   ebx, ebx, $7
  xor    ebp, edx
  db $C5, $F9, $7F, $04, $24                      // vmovdqa oword [esp], xmm0
  mov    esi, eax
  add    edi, dword ptr [esp + $14]
  db $C5, $D1, $EF, $EF                           // vpxor  xmm5, xmm5, xmm7
  xor    ebx, ecx
  shld   eax, eax, $5
  add    edi, ebp
  and    esi, ebx
  db $C5, $C1, $72, $D5, $1F                      // vpsrld xmm7, xmm5, $1F
  xor    ebx, ecx
  add    edi, eax
  shrd   eax, eax, $7
  xor    esi, ecx
  db $C5, $F1, $73, $FD, $0C                      // vpslldq xmm1, xmm5, $C
  db $C5, $D1, $FE, $ED                           // vpaddd xmm5, xmm5, xmm5
  mov    ebp, edi
  add    edx, dword ptr [esp + $18]
  xor    eax, ebx
  shld   edi, edi, $5
  db $C5, $F9, $72, $D1, $1E                      // vpsrld xmm0, xmm1, $1E
  db $C5, $D1, $EB, $EF                           // vpor   xmm5, xmm5, xmm7
  add    edx, esi
  and    ebp, eax
  xor    eax, ebx
  add    edx, edi
  db $C5, $F1, $72, $F1, $02                      // vpslld xmm1, xmm1, $2
  shrd   edi, edi, $7
  xor    ebp, ebx
  db $C5, $D1, $EF, $E8                           // vpxor  xmm5, xmm5, xmm0
  mov    esi, edx
  add    ecx, dword ptr [esp + $1C]
  xor    edi, eax
  shld   edx, edx, $5
  db $C5, $D1, $EF, $E9                           // vpxor  xmm5, xmm5, xmm1
  add    ecx, ebp
  and    esi, edi
  db $C5, $F9, $6F, $4C, $24, $70                 // vmovdqa xmm1, oword [esp + $70]
  xor    edi, eax
  add    ecx, edx
  shrd   edx, edx, $7
  xor    esi, eax
  db $C4, $E3, $61, $0F, $F2, $08                 // vpalignr xmm6, xmm3, xmm2, $8
  mov    ebp, ecx
  add    ebx, dword ptr [esp + $20]
  db $C5, $F1, $FE, $CD                           // vpaddd xmm1, xmm1, xmm5
  db $C5, $F9, $7F, $54, $24, $60                 // vmovdqa oword [esp + $60], xmm2
  xor    edx, edi
  shld   ecx, ecx, $5
  db $C5, $F9, $73, $DD, $04                      // vpsrldq xmm0, xmm5, $4
  add    ebx, esi
  and    ebp, edx
  db $C5, $C9, $EF, $F2                           // vpxor  xmm6, xmm6, xmm2
  xor    edx, edi
  add    ebx, ecx
  db $C5, $F9, $EF, $C4                           // vpxor  xmm0, xmm0, xmm4
  shrd   ecx, ecx, $7
  xor    ebp, edi
  db $C5, $F9, $7F, $4C, $24, $10                 // vmovdqa oword [esp + $10], xmm1
  mov    esi, ebx
  add    eax, dword ptr [esp + $24]
  db $C5, $C9, $EF, $F0                           // vpxor  xmm6, xmm6, xmm0
  xor    ecx, edx
  shld   ebx, ebx, $5
  add    eax, ebp
  and    esi, ecx
  db $C5, $F9, $72, $D6, $1F                      // vpsrld xmm0, xmm6, $1F
  xor    ecx, edx
  add    eax, ebx
  shrd   ebx, ebx, $7
  xor    esi, edx
  db $C5, $E9, $73, $FE, $0C                      // vpslldq xmm2, xmm6, $C
  db $C5, $C9, $FE, $F6                           // vpaddd xmm6, xmm6, xmm6
  mov    ebp, eax
  add    edi, dword ptr [esp + $28]
  xor    ebx, ecx
  shld   eax, eax, $5
  db $C5, $F1, $72, $D2, $1E                      // vpsrld xmm1, xmm2, $1E
  db $C5, $C9, $EB, $F0                           // vpor   xmm6, xmm6, xmm0
  add    edi, esi
  and    ebp, ebx
  xor    ebx, ecx
  add    edi, eax
  db $C5, $E9, $72, $F2, $02                      // vpslld xmm2, xmm2, $2
  db $C5, $F9, $6F, $44, $24, $40                 // vmovdqa xmm0, oword [esp + $40]
  shrd   eax, eax, $7
  xor    ebp, ecx
  db $C5, $C9, $EF, $F1                           // vpxor  xmm6, xmm6, xmm1
  mov    esi, edi
  add    edx, dword ptr [esp + $2C]
  xor    eax, ebx
  shld   edi, edi, $5
  db $C5, $C9, $EF, $F2                           // vpxor  xmm6, xmm6, xmm2
  add    edx, ebp
  and    esi, eax
  db $C5, $F9, $6F, $54, $24, $70                 // vmovdqa xmm2, oword [esp + $70]
  xor    eax, ebx
  add    edx, edi
  shrd   edi, edi, $7
  xor    esi, ebx
  db $C4, $E3, $59, $0F, $FB, $08                 // vpalignr xmm7, xmm4, xmm3, $8
  mov    ebp, edx
  add    ecx, dword ptr [esp + $30]
  db $C5, $E9, $FE, $D6                           // vpaddd xmm2, xmm2, xmm6
  db $C5, $F9, $7F, $5C, $24, $40                 // vmovdqa oword [esp + $40], xmm3
  xor    edi, eax
  shld   edx, edx, $5
  db $C5, $F1, $73, $DE, $04                      // vpsrldq xmm1, xmm6, $4
  add    ecx, esi
  and    ebp, edi
  db $C5, $C1, $EF, $FB                           // vpxor  xmm7, xmm7, xmm3
  xor    edi, eax
  add    ecx, edx
  db $C5, $F1, $EF, $CD                           // vpxor  xmm1, xmm1, xmm5
  shrd   edx, edx, $7
  xor    ebp, eax
  db $C5, $F9, $7F, $54, $24, $20                 // vmovdqa oword [esp + $20], xmm2
  mov    esi, ecx
  add    ebx, dword ptr [esp + $34]
  db $C5, $C1, $EF, $F9                           // vpxor  xmm7, xmm7, xmm1
  xor    edx, edi
  shld   ecx, ecx, $5
  add    ebx, ebp
  and    esi, edx
  db $C5, $F1, $72, $D7, $1F                      // vpsrld xmm1, xmm7, $1F
  xor    edx, edi
  add    ebx, ecx
  shrd   ecx, ecx, $7
  xor    esi, edi
  db $C5, $E1, $73, $FF, $0C                      // vpslldq xmm3, xmm7, $C
  db $C5, $C1, $FE, $FF                           // vpaddd xmm7, xmm7, xmm7
  mov    ebp, ebx
  add    eax, dword ptr [esp + $38]
  xor    ecx, edx
  shld   ebx, ebx, $5
  db $C5, $E9, $72, $D3, $1E                      // vpsrld xmm2, xmm3, $1E
  db $C5, $C1, $EB, $F9                           // vpor   xmm7, xmm7, xmm1
  add    eax, esi
  and    ebp, ecx
  xor    ecx, edx
  add    eax, ebx
  db $C5, $E1, $72, $F3, $02                      // vpslld xmm3, xmm3, $2
  db $C5, $F9, $6F, $4C, $24, $50                 // vmovdqa xmm1, oword [esp + $50]
  shrd   ebx, ebx, $7
  xor    ebp, edx
  db $C5, $C1, $EF, $FA                           // vpxor  xmm7, xmm7, xmm2
  mov    esi, eax
  add    edi, dword ptr [esp + $3C]
  xor    ebx, ecx
  shld   eax, eax, $5
  db $C5, $C1, $EF, $FB                           // vpxor  xmm7, xmm7, xmm3
  add    edi, ebp
  and    esi, ebx
  db $C5, $F9, $6F, $5C, $24, $70                 // vmovdqa xmm3, oword [esp + $70]
  xor    ebx, ecx
  add    edi, eax
  db $C4, $E3, $41, $0F, $D6, $08                 // vpalignr xmm2, xmm7, xmm6, $8
  db $C5, $F9, $EF, $C4                           // vpxor  xmm0, xmm0, xmm4
  shrd   eax, eax, $7
  xor    esi, ecx
  mov    ebp, edi
  add    edx, dword ptr [esp]
  db $C5, $F9, $EF, $C1                           // vpxor  xmm0, xmm0, xmm1
  db $C5, $F9, $7F, $64, $24, $50                 // vmovdqa oword [esp + $50], xmm4
  xor    eax, ebx
  shld   edi, edi, $5
  db $C5, $F9, $6F, $E3                           // vmovdqa xmm4, xmm3
  db $C5, $E1, $FE, $DF                           // vpaddd xmm3, xmm3, xmm7
  add    edx, esi
  and    ebp, eax
  db $C5, $F9, $EF, $C2                           // vpxor  xmm0, xmm0, xmm2
  xor    eax, ebx
  add    edx, edi
  shrd   edi, edi, $7
  xor    ebp, ebx
  db $C5, $E9, $72, $D0, $1E                      // vpsrld xmm2, xmm0, $1E
  db $C5, $F9, $7F, $5C, $24, $30                 // vmovdqa oword [esp + $30], xmm3
  mov    esi, edx
  add    ecx, dword ptr [esp + $4]
  xor    edi, eax
  shld   edx, edx, $5
  db $C5, $F9, $72, $F0, $02                      // vpslld xmm0, xmm0, $2
  add    ecx, ebp
  and    esi, edi
  xor    edi, eax
  add    ecx, edx
  shrd   edx, edx, $7
  xor    esi, eax
  mov    ebp, ecx
  add    ebx, dword ptr [esp + $8]
  db $C5, $F9, $EB, $C2                           // vpor   xmm0, xmm0, xmm2
  xor    edx, edi
  shld   ecx, ecx, $5
  db $C5, $F9, $6F, $54, $24, $60                 // vmovdqa xmm2, oword [esp + $60]
  add    ebx, esi
  and    ebp, edx
  xor    edx, edi
  add    ebx, ecx
  add    eax, dword ptr [esp + $C]
  xor    ebp, edi
  mov    esi, ebx
  shld   ebx, ebx, $5
  add    eax, ebp
  xor    esi, edx
  shrd   ecx, ecx, $7
  add    eax, ebx
  db $C4, $E3, $79, $0F, $DF, $08                 // vpalignr xmm3, xmm0, xmm7, $8
  db $C5, $F1, $EF, $CD                           // vpxor  xmm1, xmm1, xmm5
  add    edi, dword ptr [esp + $10]
  xor    esi, ecx
  mov    ebp, eax
  shld   eax, eax, $5
  db $C5, $F1, $EF, $CA                           // vpxor  xmm1, xmm1, xmm2
  db $C5, $F9, $7F, $6C, $24, $60                 // vmovdqa oword [esp + $60], xmm5
  add    edi, esi
  xor    ebp, ecx
  db $C5, $F9, $6F, $EC                           // vmovdqa xmm5, xmm4
  db $C5, $D9, $FE, $E0                           // vpaddd xmm4, xmm4, xmm0
  shrd   ebx, ebx, $7
  add    edi, eax
  db $C5, $F1, $EF, $CB                           // vpxor  xmm1, xmm1, xmm3
  add    edx, dword ptr [esp + $14]
  xor    ebp, ebx
  mov    esi, edi
  shld   edi, edi, $5
  db $C5, $E1, $72, $D1, $1E                      // vpsrld xmm3, xmm1, $1E
  db $C5, $F9, $7F, $24, $24                      // vmovdqa oword [esp], xmm4
  add    edx, ebp
  xor    esi, ebx
  shrd   eax, eax, $7
  add    edx, edi
  db $C5, $F1, $72, $F1, $02                      // vpslld xmm1, xmm1, $2
  add    ecx, dword ptr [esp + $18]
  xor    esi, eax
  mov    ebp, edx
  shld   edx, edx, $5
  add    ecx, esi
  xor    ebp, eax
  shrd   edi, edi, $7
  add    ecx, edx
  db $C5, $F1, $EB, $CB                           // vpor   xmm1, xmm1, xmm3
  add    ebx, dword ptr [esp + $1C]
  xor    ebp, edi
  db $C5, $F9, $6F, $5C, $24, $40                 // vmovdqa xmm3, oword [esp + $40]
  mov    esi, ecx
  shld   ecx, ecx, $5
  add    ebx, ebp
  xor    esi, edi
  shrd   edx, edx, $7
  add    ebx, ecx
  db $C4, $E3, $71, $0F, $E0, $08                 // vpalignr xmm4, xmm1, xmm0, $8
  db $C5, $E9, $EF, $D6                           // vpxor  xmm2, xmm2, xmm6
  add    eax, dword ptr [esp + $20]
  xor    esi, edx
  mov    ebp, ebx
  shld   ebx, ebx, $5
  db $C5, $E9, $EF, $D3                           // vpxor  xmm2, xmm2, xmm3
  db $C5, $F9, $7F, $74, $24, $40                 // vmovdqa oword [esp + $40], xmm6
  add    eax, esi
  xor    ebp, edx
  db $C5, $F9, $6F, $B4, $24, $80, $00, $00, $00  // vmovdqa xmm6, oword [esp + $80]
  db $C5, $D1, $FE, $E9                           // vpaddd xmm5, xmm5, xmm1
  shrd   ecx, ecx, $7
  add    eax, ebx
  db $C5, $E9, $EF, $D4                           // vpxor  xmm2, xmm2, xmm4
  add    edi, dword ptr [esp + $24]
  xor    ebp, ecx
  mov    esi, eax
  shld   eax, eax, $5
  db $C5, $D9, $72, $D2, $1E                      // vpsrld xmm4, xmm2, $1E
  db $C5, $F9, $7F, $6C, $24, $10                 // vmovdqa oword [esp + $10], xmm5
  add    edi, ebp
  xor    esi, ecx
  shrd   ebx, ebx, $7
  add    edi, eax
  db $C5, $E9, $72, $F2, $02                      // vpslld xmm2, xmm2, $2
  add    edx, dword ptr [esp + $28]
  xor    esi, ebx
  mov    ebp, edi
  shld   edi, edi, $5
  add    edx, esi
  xor    ebp, ebx
  shrd   eax, eax, $7
  add    edx, edi
  db $C5, $E9, $EB, $D4                           // vpor   xmm2, xmm2, xmm4
  add    ecx, dword ptr [esp + $2C]
  xor    ebp, eax
  db $C5, $F9, $6F, $64, $24, $50                 // vmovdqa xmm4, oword [esp + $50]
  mov    esi, edx
  shld   edx, edx, $5
  add    ecx, ebp
  xor    esi, eax
  shrd   edi, edi, $7
  add    ecx, edx
  db $C4, $E3, $69, $0F, $E9, $08                 // vpalignr xmm5, xmm2, xmm1, $8
  db $C5, $E1, $EF, $DF                           // vpxor  xmm3, xmm3, xmm7
  add    ebx, dword ptr [esp + $30]
  xor    esi, edi
  mov    ebp, ecx
  shld   ecx, ecx, $5
  db $C5, $E1, $EF, $DC                           // vpxor  xmm3, xmm3, xmm4
  db $C5, $F9, $7F, $7C, $24, $50                 // vmovdqa oword [esp + $50], xmm7
  add    ebx, esi
  xor    ebp, edi
  db $C5, $F9, $6F, $FE                           // vmovdqa xmm7, xmm6
  db $C5, $C9, $FE, $F2                           // vpaddd xmm6, xmm6, xmm2
  shrd   edx, edx, $7
  add    ebx, ecx
  db $C5, $E1, $EF, $DD                           // vpxor  xmm3, xmm3, xmm5
  add    eax, dword ptr [esp + $34]
  xor    ebp, edx
  mov    esi, ebx
  shld   ebx, ebx, $5
  db $C5, $D1, $72, $D3, $1E                      // vpsrld xmm5, xmm3, $1E
  db $C5, $F9, $7F, $74, $24, $20                 // vmovdqa oword [esp + $20], xmm6
  add    eax, ebp
  xor    esi, edx
  shrd   ecx, ecx, $7
  add    eax, ebx
  db $C5, $E1, $72, $F3, $02                      // vpslld xmm3, xmm3, $2
  add    edi, dword ptr [esp + $38]
  xor    esi, ecx
  mov    ebp, eax
  shld   eax, eax, $5
  add    edi, esi
  xor    ebp, ecx
  shrd   ebx, ebx, $7
  add    edi, eax
  db $C5, $E1, $EB, $DD                           // vpor   xmm3, xmm3, xmm5
  add    edx, dword ptr [esp + $3C]
  xor    ebp, ebx
  db $C5, $F9, $6F, $6C, $24, $60                 // vmovdqa xmm5, oword [esp + $60]
  mov    esi, edi
  shld   edi, edi, $5
  add    edx, ebp
  xor    esi, ebx
  shrd   eax, eax, $7
  add    edx, edi
  db $C4, $E3, $61, $0F, $F2, $08                 // vpalignr xmm6, xmm3, xmm2, $8
  db $C5, $D9, $EF, $E0                           // vpxor  xmm4, xmm4, xmm0
  add    ecx, dword ptr [esp]
  xor    esi, eax
  mov    ebp, edx
  shld   edx, edx, $5
  db $C5, $D9, $EF, $E5                           // vpxor  xmm4, xmm4, xmm5
  db $C5, $F9, $7F, $44, $24, $60                 // vmovdqa oword [esp + $60], xmm0
  add    ecx, esi
  xor    ebp, eax
  db $C5, $F9, $6F, $C7                           // vmovdqa xmm0, xmm7
  db $C5, $C1, $FE, $FB                           // vpaddd xmm7, xmm7, xmm3
  shrd   edi, edi, $7
  add    ecx, edx
  db $C5, $D9, $EF, $E6                           // vpxor  xmm4, xmm4, xmm6
  add    ebx, dword ptr [esp + $4]
  xor    ebp, edi
  mov    esi, ecx
  shld   ecx, ecx, $5
  db $C5, $C9, $72, $D4, $1E                      // vpsrld xmm6, xmm4, $1E
  db $C5, $F9, $7F, $7C, $24, $30                 // vmovdqa oword [esp + $30], xmm7
  add    ebx, ebp
  xor    esi, edi
  shrd   edx, edx, $7
  add    ebx, ecx
  db $C5, $D9, $72, $F4, $02                      // vpslld xmm4, xmm4, $2
  add    eax, dword ptr [esp + $8]
  xor    esi, edx
  mov    ebp, ebx
  shld   ebx, ebx, $5
  add    eax, esi
  xor    ebp, edx
  shrd   ecx, ecx, $7
  add    eax, ebx
  db $C5, $D9, $EB, $E6                           // vpor   xmm4, xmm4, xmm6
  add    edi, dword ptr [esp + $C]
  xor    ebp, ecx
  db $C5, $F9, $6F, $74, $24, $40                 // vmovdqa xmm6, oword [esp + $40]
  mov    esi, eax
  shld   eax, eax, $5
  add    edi, ebp
  xor    esi, ecx
  shrd   ebx, ebx, $7
  add    edi, eax
  db $C4, $E3, $59, $0F, $FB, $08                 // vpalignr xmm7, xmm4, xmm3, $8
  db $C5, $D1, $EF, $E9                           // vpxor  xmm5, xmm5, xmm1
  add    edx, dword ptr [esp + $10]
  xor    esi, ebx
  mov    ebp, edi
  shld   edi, edi, $5
  db $C5, $D1, $EF, $EE                           // vpxor  xmm5, xmm5, xmm6
  db $C5, $F9, $7F, $4C, $24, $40                 // vmovdqa oword [esp + $40], xmm1
  add    edx, esi
  xor    ebp, ebx
  db $C5, $F9, $6F, $C8                           // vmovdqa xmm1, xmm0
  db $C5, $F9, $FE, $C4                           // vpaddd xmm0, xmm0, xmm4
  shrd   eax, eax, $7
  add    edx, edi
  db $C5, $D1, $EF, $EF                           // vpxor  xmm5, xmm5, xmm7
  add    ecx, dword ptr [esp + $14]
  xor    ebp, eax
  mov    esi, edx
  shld   edx, edx, $5
  db $C5, $C1, $72, $D5, $1E                      // vpsrld xmm7, xmm5, $1E
  db $C5, $F9, $7F, $04, $24                      // vmovdqa oword [esp], xmm0
  add    ecx, ebp
  xor    esi, eax
  shrd   edi, edi, $7
  add    ecx, edx
  db $C5, $D1, $72, $F5, $02                      // vpslld xmm5, xmm5, $2
  add    ebx, dword ptr [esp + $18]
  xor    esi, edi
  mov    ebp, ecx
  shld   ecx, ecx, $5
  add    ebx, esi
  xor    ebp, edi
  shrd   edx, edx, $7
  add    ebx, ecx
  db $C5, $D1, $EB, $EF                           // vpor   xmm5, xmm5, xmm7
  add    eax, dword ptr [esp + $1C]
  db $C5, $F9, $6F, $7C, $24, $50                 // vmovdqa xmm7, oword [esp + $50]
  shrd   ecx, ecx, $7
  mov    esi, ebx
  xor    ebp, edx
  shld   ebx, ebx, $5
  add    eax, ebp
  xor    esi, ecx
  xor    ecx, edx
  add    eax, ebx
  db $C4, $E3, $51, $0F, $C4, $08                 // vpalignr xmm0, xmm5, xmm4, $8
  db $C5, $C9, $EF, $F2                           // vpxor  xmm6, xmm6, xmm2
  add    edi, dword ptr [esp + $20]
  and    esi, ecx
  xor    ecx, edx
  shrd   ebx, ebx, $7
  db $C5, $C9, $EF, $F7                           // vpxor  xmm6, xmm6, xmm7
  db $C5, $F9, $7F, $54, $24, $50                 // vmovdqa oword [esp + $50], xmm2
  mov    ebp, eax
  xor    esi, ecx
  db $C5, $F9, $6F, $D1                           // vmovdqa xmm2, xmm1
  db $C5, $F1, $FE, $CD                           // vpaddd xmm1, xmm1, xmm5
  shld   eax, eax, $5
  add    edi, esi
  db $C5, $C9, $EF, $F0                           // vpxor  xmm6, xmm6, xmm0
  xor    ebp, ebx
  xor    ebx, ecx
  add    edi, eax
  add    edx, dword ptr [esp + $24]
  db $C5, $F9, $72, $D6, $1E                      // vpsrld xmm0, xmm6, $1E
  db $C5, $F9, $7F, $4C, $24, $10                 // vmovdqa oword [esp + $10], xmm1
  and    ebp, ebx
  xor    ebx, ecx
  shrd   eax, eax, $7
  mov    esi, edi
  db $C5, $C9, $72, $F6, $02                      // vpslld xmm6, xmm6, $2
  xor    ebp, ebx
  shld   edi, edi, $5
  add    edx, ebp
  xor    esi, eax
  xor    eax, ebx
  add    edx, edi
  add    ecx, dword ptr [esp + $28]
  and    esi, eax
  db $C5, $C9, $EB, $F0                           // vpor   xmm6, xmm6, xmm0
  xor    eax, ebx
  shrd   edi, edi, $7
  db $C5, $F9, $6F, $44, $24, $60                 // vmovdqa xmm0, oword [esp + $60]
  mov    ebp, edx
  xor    esi, eax
  shld   edx, edx, $5
  add    ecx, esi
  xor    ebp, edi
  xor    edi, eax
  add    ecx, edx
  add    ebx, dword ptr [esp + $2C]
  and    ebp, edi
  xor    edi, eax
  shrd   edx, edx, $7
  mov    esi, ecx
  xor    ebp, edi
  shld   ecx, ecx, $5
  add    ebx, ebp
  xor    esi, edx
  xor    edx, edi
  add    ebx, ecx
  db $C4, $E3, $49, $0F, $CD, $08                 // vpalignr xmm1, xmm6, xmm5, $8
  db $C5, $C1, $EF, $FB                           // vpxor  xmm7, xmm7, xmm3
  add    eax, dword ptr [esp + $30]
  and    esi, edx
  xor    edx, edi
  shrd   ecx, ecx, $7
  db $C5, $C1, $EF, $F8                           // vpxor  xmm7, xmm7, xmm0
  db $C5, $F9, $7F, $5C, $24, $60                 // vmovdqa oword [esp + $60], xmm3
  mov    ebp, ebx
  xor    esi, edx
  db $C5, $F9, $6F, $9C, $24, $90, $00, $00, $00  // vmovdqa xmm3, oword [esp + $90]
  db $C5, $E9, $FE, $D6                           // vpaddd xmm2, xmm2, xmm6
  shld   ebx, ebx, $5
  add    eax, esi
  db $C5, $C1, $EF, $F9                           // vpxor  xmm7, xmm7, xmm1
  xor    ebp, ecx
  xor    ecx, edx
  add    eax, ebx
  add    edi, dword ptr [esp + $34]
  db $C5, $F1, $72, $D7, $1E                      // vpsrld xmm1, xmm7, $1E
  db $C5, $F9, $7F, $54, $24, $20                 // vmovdqa oword [esp + $20], xmm2
  and    ebp, ecx
  xor    ecx, edx
  shrd   ebx, ebx, $7
  mov    esi, eax
  db $C5, $C1, $72, $F7, $02                      // vpslld xmm7, xmm7, $2
  xor    ebp, ecx
  shld   eax, eax, $5
  add    edi, ebp
  xor    esi, ebx
  xor    ebx, ecx
  add    edi, eax
  add    edx, dword ptr [esp + $38]
  and    esi, ebx
  db $C5, $C1, $EB, $F9                           // vpor   xmm7, xmm7, xmm1
  xor    ebx, ecx
  shrd   eax, eax, $7
  db $C5, $F9, $6F, $4C, $24, $40                 // vmovdqa xmm1, oword [esp + $40]
  mov    ebp, edi
  xor    esi, ebx
  shld   edi, edi, $5
  add    edx, esi
  xor    ebp, eax
  xor    eax, ebx
  add    edx, edi
  add    ecx, dword ptr [esp + $3C]
  and    ebp, eax
  xor    eax, ebx
  shrd   edi, edi, $7
  mov    esi, edx
  xor    ebp, eax
  shld   edx, edx, $5
  add    ecx, ebp
  xor    esi, edi
  xor    edi, eax
  add    ecx, edx
  db $C4, $E3, $41, $0F, $D6, $08                 // vpalignr xmm2, xmm7, xmm6, $8
  db $C5, $F9, $EF, $C4                           // vpxor  xmm0, xmm0, xmm4
  add    ebx, dword ptr [esp]
  and    esi, edi
  xor    edi, eax
  shrd   edx, edx, $7
  db $C5, $F9, $EF, $C1                           // vpxor  xmm0, xmm0, xmm1
  db $C5, $F9, $7F, $64, $24, $40                 // vmovdqa oword [esp + $40], xmm4
  mov    ebp, ecx
  xor    esi, edi
  db $C5, $F9, $6F, $E3                           // vmovdqa xmm4, xmm3
  db $C5, $E1, $FE, $DF                           // vpaddd xmm3, xmm3, xmm7
  shld   ecx, ecx, $5
  add    ebx, esi
  db $C5, $F9, $EF, $C2                           // vpxor  xmm0, xmm0, xmm2
  xor    ebp, edx
  xor    edx, edi
  add    ebx, ecx
  add    eax, dword ptr [esp + $4]
  db $C5, $E9, $72, $D0, $1E                      // vpsrld xmm2, xmm0, $1E
  db $C5, $F9, $7F, $5C, $24, $30                 // vmovdqa oword [esp + $30], xmm3
  and    ebp, edx
  xor    edx, edi
  shrd   ecx, ecx, $7
  mov    esi, ebx
  db $C5, $F9, $72, $F0, $02                      // vpslld xmm0, xmm0, $2
  xor    ebp, edx
  shld   ebx, ebx, $5
  add    eax, ebp
  xor    esi, ecx
  xor    ecx, edx
  add    eax, ebx
  add    edi, dword ptr [esp + $8]
  and    esi, ecx
  db $C5, $F9, $EB, $C2                           // vpor   xmm0, xmm0, xmm2
  xor    ecx, edx
  shrd   ebx, ebx, $7
  db $C5, $F9, $6F, $54, $24, $50                 // vmovdqa xmm2, oword [esp + $50]
  mov    ebp, eax
  xor    esi, ecx
  shld   eax, eax, $5
  add    edi, esi
  xor    ebp, ebx
  xor    ebx, ecx
  add    edi, eax
  add    edx, dword ptr [esp + $C]
  and    ebp, ebx
  xor    ebx, ecx
  shrd   eax, eax, $7
  mov    esi, edi
  xor    ebp, ebx
  shld   edi, edi, $5
  add    edx, ebp
  xor    esi, eax
  xor    eax, ebx
  add    edx, edi
  db $C4, $E3, $79, $0F, $DF, $08                 // vpalignr xmm3, xmm0, xmm7, $8
  db $C5, $F1, $EF, $CD                           // vpxor  xmm1, xmm1, xmm5
  add    ecx, dword ptr [esp + $10]
  and    esi, eax
  xor    eax, ebx
  shrd   edi, edi, $7
  db $C5, $F1, $EF, $CA                           // vpxor  xmm1, xmm1, xmm2
  db $C5, $F9, $7F, $6C, $24, $50                 // vmovdqa oword [esp + $50], xmm5
  mov    ebp, edx
  xor    esi, eax
  db $C5, $F9, $6F, $EC                           // vmovdqa xmm5, xmm4
  db $C5, $D9, $FE, $E0                           // vpaddd xmm4, xmm4, xmm0
  shld   edx, edx, $5
  add    ecx, esi
  db $C5, $F1, $EF, $CB                           // vpxor  xmm1, xmm1, xmm3
  xor    ebp, edi
  xor    edi, eax
  add    ecx, edx
  add    ebx, dword ptr [esp + $14]
  db $C5, $E1, $72, $D1, $1E                      // vpsrld xmm3, xmm1, $1E
  db $C5, $F9, $7F, $24, $24                      // vmovdqa oword [esp], xmm4
  and    ebp, edi
  xor    edi, eax
  shrd   edx, edx, $7
  mov    esi, ecx
  db $C5, $F1, $72, $F1, $02                      // vpslld xmm1, xmm1, $2
  xor    ebp, edi
  shld   ecx, ecx, $5
  add    ebx, ebp
  xor    esi, edx
  xor    edx, edi
  add    ebx, ecx
  add    eax, dword ptr [esp + $18]
  and    esi, edx
  db $C5, $F1, $EB, $CB                           // vpor   xmm1, xmm1, xmm3
  xor    edx, edi
  shrd   ecx, ecx, $7
  db $C5, $F9, $6F, $5C, $24, $60                 // vmovdqa xmm3, oword [esp + $60]
  mov    ebp, ebx
  xor    esi, edx
  shld   ebx, ebx, $5
  add    eax, esi
  xor    ebp, ecx
  xor    ecx, edx
  add    eax, ebx
  add    edi, dword ptr [esp + $1C]
  and    ebp, ecx
  xor    ecx, edx
  shrd   ebx, ebx, $7
  mov    esi, eax
  xor    ebp, ecx
  shld   eax, eax, $5
  add    edi, ebp
  xor    esi, ebx
  xor    ebx, ecx
  add    edi, eax
  db $C4, $E3, $71, $0F, $E0, $08                 // vpalignr xmm4, xmm1, xmm0, $8
  db $C5, $E9, $EF, $D6                           // vpxor  xmm2, xmm2, xmm6
  add    edx, dword ptr [esp + $20]
  and    esi, ebx
  xor    ebx, ecx
  shrd   eax, eax, $7
  db $C5, $E9, $EF, $D3                           // vpxor  xmm2, xmm2, xmm3
  db $C5, $F9, $7F, $74, $24, $60                 // vmovdqa oword [esp + $60], xmm6
  mov    ebp, edi
  xor    esi, ebx
  db $C5, $F9, $6F, $F5                           // vmovdqa xmm6, xmm5
  db $C5, $D1, $FE, $E9                           // vpaddd xmm5, xmm5, xmm1
  shld   edi, edi, $5
  add    edx, esi
  db $C5, $E9, $EF, $D4                           // vpxor  xmm2, xmm2, xmm4
  xor    ebp, eax
  xor    eax, ebx
  add    edx, edi
  add    ecx, dword ptr [esp + $24]
  db $C5, $D9, $72, $D2, $1E                      // vpsrld xmm4, xmm2, $1E
  db $C5, $F9, $7F, $6C, $24, $10                 // vmovdqa oword [esp + $10], xmm5
  and    ebp, eax
  xor    eax, ebx
  shrd   edi, edi, $7
  mov    esi, edx
  db $C5, $E9, $72, $F2, $02                      // vpslld xmm2, xmm2, $2
  xor    ebp, eax
  shld   edx, edx, $5
  add    ecx, ebp
  xor    esi, edi
  xor    edi, eax
  add    ecx, edx
  add    ebx, dword ptr [esp + $28]
  and    esi, edi
  db $C5, $E9, $EB, $D4                           // vpor   xmm2, xmm2, xmm4
  xor    edi, eax
  shrd   edx, edx, $7
  db $C5, $F9, $6F, $64, $24, $40                 // vmovdqa xmm4, oword [esp + $40]
  mov    ebp, ecx
  xor    esi, edi
  shld   ecx, ecx, $5
  add    ebx, esi
  xor    ebp, edx
  xor    edx, edi
  add    ebx, ecx
  add    eax, dword ptr [esp + $2C]
  and    ebp, edx
  xor    edx, edi
  shrd   ecx, ecx, $7
  mov    esi, ebx
  xor    ebp, edx
  shld   ebx, ebx, $5
  add    eax, ebp
  xor    esi, edx
  add    eax, ebx
  db $C4, $E3, $69, $0F, $E9, $08                 // vpalignr xmm5, xmm2, xmm1, $8
  db $C5, $E1, $EF, $DF                           // vpxor  xmm3, xmm3, xmm7
  add    edi, dword ptr [esp + $30]
  xor    esi, ecx
  mov    ebp, eax
  shld   eax, eax, $5
  db $C5, $E1, $EF, $DC                           // vpxor  xmm3, xmm3, xmm4
  db $C5, $F9, $7F, $7C, $24, $40                 // vmovdqa oword [esp + $40], xmm7
  add    edi, esi
  xor    ebp, ecx
  db $C5, $F9, $6F, $FE                           // vmovdqa xmm7, xmm6
  db $C5, $C9, $FE, $F2                           // vpaddd xmm6, xmm6, xmm2
  shrd   ebx, ebx, $7
  add    edi, eax
  db $C5, $E1, $EF, $DD                           // vpxor  xmm3, xmm3, xmm5
  add    edx, dword ptr [esp + $34]
  xor    ebp, ebx
  mov    esi, edi
  shld   edi, edi, $5
  db $C5, $D1, $72, $D3, $1E                      // vpsrld xmm5, xmm3, $1E
  db $C5, $F9, $7F, $74, $24, $20                 // vmovdqa oword [esp + $20], xmm6
  add    edx, ebp
  xor    esi, ebx
  shrd   eax, eax, $7
  add    edx, edi
  db $C5, $E1, $72, $F3, $02                      // vpslld xmm3, xmm3, $2
  add    ecx, dword ptr [esp + $38]
  xor    esi, eax
  mov    ebp, edx
  shld   edx, edx, $5
  add    ecx, esi
  xor    ebp, eax
  shrd   edi, edi, $7
  add    ecx, edx
  db $C5, $E1, $EB, $DD                           // vpor   xmm3, xmm3, xmm5
  add    ebx, dword ptr [esp + $3C]
  xor    ebp, edi
  mov    esi, ecx
  shld   ecx, ecx, $5
  add    ebx, ebp
  xor    esi, edi
  shrd   edx, edx, $7
  add    ebx, ecx
  add    eax, dword ptr [esp]
  db $C5, $C1, $FE, $FB                           // vpaddd xmm7, xmm7, xmm3
  xor    esi, edx
  mov    ebp, ebx
  shld   ebx, ebx, $5
  add    eax, esi
  db $C5, $F9, $7F, $7C, $24, $30                 // vmovdqa oword [esp + $30], xmm7
  xor    ebp, edx
  shrd   ecx, ecx, $7
  add    eax, ebx
  add    edi, dword ptr [esp + $4]
  xor    ebp, ecx
  mov    esi, eax
  shld   eax, eax, $5
  add    edi, ebp
  xor    esi, ecx
  shrd   ebx, ebx, $7
  add    edi, eax
  add    edx, dword ptr [esp + $8]
  xor    esi, ebx
  mov    ebp, edi
  shld   edi, edi, $5
  add    edx, esi
  xor    ebp, ebx
  shrd   eax, eax, $7
  add    edx, edi
  add    ecx, dword ptr [esp + $C]
  xor    ebp, eax
  mov    esi, edx
  shld   edx, edx, $5
  add    ecx, ebp
  xor    esi, eax
  shrd   edi, edi, $7
  add    ecx, edx
  mov    ebp, dword ptr [esp + $C4]
  cmp    ebp, dword ptr [esp + $C8]
  je @done_010
  db $C5, $F9, $6F, $BC, $24, $A0, $00, $00, $00  // vmovdqa xmm7, oword [esp + $A0]
  db $C5, $F9, $6F, $B4, $24, $B0, $00, $00, $00  // vmovdqa xmm6, oword [esp + $B0]
  db $C5, $FA, $6F, $45, $00                      // vmovdqu xmm0, oword [ebp + $0]
  db $C5, $FA, $6F, $4D, $10                      // vmovdqu xmm1, oword [ebp + $10]
  db $C5, $FA, $6F, $55, $20                      // vmovdqu xmm2, oword [ebp + $20]
  db $C5, $FA, $6F, $5D, $30                      // vmovdqu xmm3, oword [ebp + $30]
  add    ebp, $40
  db $C4, $E2, $79, $00, $C6                      // vpshufb xmm0, xmm0, xmm6
  mov    dword ptr [esp + $C4], ebp
  db $C5, $F9, $7F, $7C, $24, $60                 // vmovdqa oword [esp + $60], xmm7
  add    ebx, dword ptr [esp + $10]
  xor    esi, edi
  db $C4, $E2, $71, $00, $CE                      // vpshufb xmm1, xmm1, xmm6
  mov    ebp, ecx
  shld   ecx, ecx, $5
  db $C5, $F9, $FE, $E7                           // vpaddd xmm4, xmm0, xmm7
  add    ebx, esi
  xor    ebp, edi
  shrd   edx, edx, $7
  add    ebx, ecx
  db $C5, $F9, $7F, $24, $24                      // vmovdqa oword [esp], xmm4
  add    eax, dword ptr [esp + $14]
  xor    ebp, edx
  mov    esi, ebx
  shld   ebx, ebx, $5
  add    eax, ebp
  xor    esi, edx
  shrd   ecx, ecx, $7
  add    eax, ebx
  add    edi, dword ptr [esp + $18]
  xor    esi, ecx
  mov    ebp, eax
  shld   eax, eax, $5
  add    edi, esi
  xor    ebp, ecx
  shrd   ebx, ebx, $7
  add    edi, eax
  add    edx, dword ptr [esp + $1C]
  xor    ebp, ebx
  mov    esi, edi
  shld   edi, edi, $5
  add    edx, ebp
  xor    esi, ebx
  shrd   eax, eax, $7
  add    edx, edi
  add    ecx, dword ptr [esp + $20]
  xor    esi, eax
  db $C4, $E2, $69, $00, $D6                      // vpshufb xmm2, xmm2, xmm6
  mov    ebp, edx
  shld   edx, edx, $5
  db $C5, $F1, $FE, $EF                           // vpaddd xmm5, xmm1, xmm7
  add    ecx, esi
  xor    ebp, eax
  shrd   edi, edi, $7
  add    ecx, edx
  db $C5, $F9, $7F, $6C, $24, $10                 // vmovdqa oword [esp + $10], xmm5
  add    ebx, dword ptr [esp + $24]
  xor    ebp, edi
  mov    esi, ecx
  shld   ecx, ecx, $5
  add    ebx, ebp
  xor    esi, edi
  shrd   edx, edx, $7
  add    ebx, ecx
  add    eax, dword ptr [esp + $28]
  xor    esi, edx
  mov    ebp, ebx
  shld   ebx, ebx, $5
  add    eax, esi
  xor    ebp, edx
  shrd   ecx, ecx, $7
  add    eax, ebx
  add    edi, dword ptr [esp + $2C]
  xor    ebp, ecx
  mov    esi, eax
  shld   eax, eax, $5
  add    edi, ebp
  xor    esi, ecx
  shrd   ebx, ebx, $7
  add    edi, eax
  add    edx, dword ptr [esp + $30]
  xor    esi, ebx
  db $C4, $E2, $61, $00, $DE                      // vpshufb xmm3, xmm3, xmm6
  mov    ebp, edi
  shld   edi, edi, $5
  db $C5, $E9, $FE, $F7                           // vpaddd xmm6, xmm2, xmm7
  add    edx, esi
  xor    ebp, ebx
  shrd   eax, eax, $7
  add    edx, edi
  db $C5, $F9, $7F, $74, $24, $20                 // vmovdqa oword [esp + $20], xmm6
  add    ecx, dword ptr [esp + $34]
  xor    ebp, eax
  mov    esi, edx
  shld   edx, edx, $5
  add    ecx, ebp
  xor    esi, eax
  shrd   edi, edi, $7
  add    ecx, edx
  add    ebx, dword ptr [esp + $38]
  xor    esi, edi
  mov    ebp, ecx
  shld   ecx, ecx, $5
  add    ebx, esi
  xor    ebp, edi
  shrd   edx, edx, $7
  add    ebx, ecx
  add    eax, dword ptr [esp + $3C]
  xor    ebp, edx
  mov    esi, ebx
  shld   ebx, ebx, $5
  add    eax, ebp
  shrd   ecx, ecx, $7
  add    eax, ebx
  mov    ebp, dword ptr [esp + $C0]
  add    eax, dword ptr [ebp + $0]
  add    esi, dword ptr [ebp + $4]
  add    ecx, dword ptr [ebp + $8]
  mov    dword ptr [ebp + $0], eax
  add    edx, dword ptr [ebp + $C]
  mov    dword ptr [ebp + $4], esi
  add    edi, dword ptr [ebp + $10]
  mov    ebx, ecx
  mov    dword ptr [ebp + $8], ecx
  xor    ebx, edx
  mov    dword ptr [ebp + $C], edx
  mov    dword ptr [ebp + $10], edi
  mov    ebp, esi
  and    esi, ebx
  mov    ebx, ebp
  jmp @loop_009

@done_010:
  add    ebx, dword ptr [esp + $10]
  xor    esi, edi
  mov    ebp, ecx
  shld   ecx, ecx, $5
  add    ebx, esi
  xor    ebp, edi
  shrd   edx, edx, $7
  add    ebx, ecx
  add    eax, dword ptr [esp + $14]
  xor    ebp, edx
  mov    esi, ebx
  shld   ebx, ebx, $5
  add    eax, ebp
  xor    esi, edx
  shrd   ecx, ecx, $7
  add    eax, ebx
  add    edi, dword ptr [esp + $18]
  xor    esi, ecx
  mov    ebp, eax
  shld   eax, eax, $5
  add    edi, esi
  xor    ebp, ecx
  shrd   ebx, ebx, $7
  add    edi, eax
  add    edx, dword ptr [esp + $1C]
  xor    ebp, ebx
  mov    esi, edi
  shld   edi, edi, $5
  add    edx, ebp
  xor    esi, ebx
  shrd   eax, eax, $7
  add    edx, edi
  add    ecx, dword ptr [esp + $20]
  xor    esi, eax
  mov    ebp, edx
  shld   edx, edx, $5
  add    ecx, esi
  xor    ebp, eax
  shrd   edi, edi, $7
  add    ecx, edx
  add    ebx, dword ptr [esp + $24]
  xor    ebp, edi
  mov    esi, ecx
  shld   ecx, ecx, $5
  add    ebx, ebp
  xor    esi, edi
  shrd   edx, edx, $7
  add    ebx, ecx
  add    eax, dword ptr [esp + $28]
  xor    esi, edx
  mov    ebp, ebx
  shld   ebx, ebx, $5
  add    eax, esi
  xor    ebp, edx
  shrd   ecx, ecx, $7
  add    eax, ebx
  add    edi, dword ptr [esp + $2C]
  xor    ebp, ecx
  mov    esi, eax
  shld   eax, eax, $5
  add    edi, ebp
  xor    esi, ecx
  shrd   ebx, ebx, $7
  add    edi, eax
  add    edx, dword ptr [esp + $30]
  xor    esi, ebx
  mov    ebp, edi
  shld   edi, edi, $5
  add    edx, esi
  xor    ebp, ebx
  shrd   eax, eax, $7
  add    edx, edi
  add    ecx, dword ptr [esp + $34]
  xor    ebp, eax
  mov    esi, edx
  shld   edx, edx, $5
  add    ecx, ebp
  xor    esi, eax
  shrd   edi, edi, $7
  add    ecx, edx
  add    ebx, dword ptr [esp + $38]
  xor    esi, edi
  mov    ebp, ecx
  shld   ecx, ecx, $5
  add    ebx, esi
  xor    ebp, edi
  shrd   edx, edx, $7
  add    ebx, ecx
  add    eax, dword ptr [esp + $3C]
  xor    ebp, edx
  mov    esi, ebx
  shld   ebx, ebx, $5
  add    eax, ebp
  shrd   ecx, ecx, $7
  add    eax, ebx
  db $C5, $FC, $77                                // vzeroall
  mov    ebp, dword ptr [esp + $C0]
  add    eax, dword ptr [ebp + $0]
  mov    esp, dword ptr [esp + $CC]
  add    esi, dword ptr [ebp + $4]
  add    ecx, dword ptr [ebp + $8]
  mov    dword ptr [ebp + $0], eax
  add    edx, dword ptr [ebp + $C]
  mov    dword ptr [ebp + $4], esi
  add    edi, dword ptr [ebp + $10]
  mov    dword ptr [ebp + $8], ecx
  mov    dword ptr [ebp + $C], edx
  mov    dword ptr [ebp + $10], edi
  pop    ebp
  pop    edi
  pop    esi
  pop    ebx
