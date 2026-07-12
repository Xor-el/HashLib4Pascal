// SHA-256 AVX SIMD-schedule implementation (IA-32). VEX-128 (AVX1)
// instructions only - there is no i386 AVX2 SHA-256 upstream - dispatched at
// the AVX2 tier (every AVX2 CPU has AVX1; AVX1-only CPUs fall to the SSSE3
// tier). The 3-operand VEX forms eliminate the SSSE3 kernel's register-copy
// movdqa traffic; the byte-swap mask stays resident in xmm7. All VEX
// instructions are db-encoded for broad assembler compatibility.
// K256 is read from K256_Doubled at a 32-byte stride (the walk and offsets
// are doubled relative to the original; VEX memory operands are read
// unaligned, so the Pascal const needs no special alignment).
// Reference: OpenSSL CRYPTOGAMS sha256-586.pl (AVX section).
// Expects (after HlpSimdProc4Begin_i386): ebx = state, esi = data,
//   edi = numblocks, eax = K256_Doubled ptr. HlpSimdProc4Begin pushes
//   ebx/esi/edi; ebp is pushed here as the K walk pointer. Frame and slot
//   layout (ctx@96/data@100/end@104/savedsp@108) mirror the SSE2/SSSE3
//   siblings.

  push   ebp
  mov    ebp, eax
  mov    eax, edi
  mov    edi, esi
  mov    esi, ebx
  mov    ebx, esp
  sub    esp, $10
  and    esp, $FFFFFFC0
  shl    eax, $6
  add    eax, edi
  mov    dword ptr [esp], esi
  mov    dword ptr [esp + $4], edi
  mov    dword ptr [esp + $8], eax
  mov    dword ptr [esp + $C], ebx
  lea    esp, [esp - $60]
  db $C5, $FC, $77                                // vzeroall
  mov    eax, dword ptr [esi]
  mov    ebx, dword ptr [esi + $4]
  mov    ecx, dword ptr [esi + $8]
  mov    edi, dword ptr [esi + $C]
  mov    dword ptr [esp + $4], ebx
  xor    ebx, ecx
  mov    dword ptr [esp + $8], ecx
  mov    dword ptr [esp + $C], edi
  mov    edx, dword ptr [esi + $10]
  mov    edi, dword ptr [esi + $14]
  mov    ecx, dword ptr [esi + $18]
  mov    esi, dword ptr [esi + $1C]
  mov    dword ptr [esp + $14], edi
  mov    edi, dword ptr [esp + $64]
  mov    dword ptr [esp + $18], ecx
  mov    dword ptr [esp + $1C], esi
  db $C5, $FA, $6F, $BD, $00, $02, $00, $00       // vmovdqu xmm7, oword [ebp + $200]
  jmp @grand_avx_014

@grand_avx_014:
  db $C5, $FA, $6F, $07                           // vmovdqu xmm0, oword [edi]
  db $C5, $FA, $6F, $4F, $10                      // vmovdqu xmm1, oword [edi + $10]
  db $C5, $FA, $6F, $57, $20                      // vmovdqu xmm2, oword [edi + $20]
  db $C5, $FA, $6F, $5F, $30                      // vmovdqu xmm3, oword [edi + $30]
  add    edi, $40
  db $C4, $E2, $79, $00, $C7                      // vpshufb xmm0, xmm0, xmm7
  mov    dword ptr [esp + $64], edi
  db $C4, $E2, $71, $00, $CF                      // vpshufb xmm1, xmm1, xmm7
  db $C4, $E2, $69, $00, $D7                      // vpshufb xmm2, xmm2, xmm7
  db $C5, $F9, $FE, $65, $00                      // vpaddd xmm4, xmm0, oword [ebp + $0]
  db $C4, $E2, $61, $00, $DF                      // vpshufb xmm3, xmm3, xmm7
  db $C5, $F1, $FE, $6D, $20                      // vpaddd xmm5, xmm1, oword [ebp + $20]
  db $C5, $E9, $FE, $75, $40                      // vpaddd xmm6, xmm2, oword [ebp + $40]
  db $C5, $E1, $FE, $7D, $60                      // vpaddd xmm7, xmm3, oword [ebp + $60]
  db $C5, $F9, $7F, $64, $24, $20                 // vmovdqa oword [esp + $20], xmm4
  db $C5, $F9, $7F, $6C, $24, $30                 // vmovdqa oword [esp + $30], xmm5
  db $C5, $F9, $7F, $74, $24, $40                 // vmovdqa oword [esp + $40], xmm6
  db $C5, $F9, $7F, $7C, $24, $50                 // vmovdqa oword [esp + $50], xmm7
  jmp @avx_00_47_015

@avx_00_47_015:
  add    ebp, $80
  db $C4, $E3, $71, $0F, $E0, $04                 // vpalignr xmm4, xmm1, xmm0, $4
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $14]
  db $C4, $E3, $61, $0F, $FA, $04                 // vpalignr xmm7, xmm3, xmm2, $4
  xor    edx, ecx
  mov    edi, dword ptr [esp + $18]
  xor    esi, edi
  db $C5, $C9, $72, $D4, $07                      // vpsrld xmm6, xmm4, $7
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $10], ecx
  db $C5, $F9, $FE, $C7                           // vpaddd xmm0, xmm0, xmm7
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  db $C5, $C1, $72, $D4, $03                      // vpsrld xmm7, xmm4, $3
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword ptr [esp + $4]
  db $C5, $D1, $72, $F4, $0E                      // vpslld xmm5, xmm4, $E
  mov    esi, eax
  shrd   ecx, ecx, $9
  mov    dword ptr [esp], eax
  db $C5, $C1, $EF, $E6                           // vpxor  xmm4, xmm7, xmm6
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword ptr [esp + $1C]
  db $C5, $F9, $70, $FB, $FA                      // vpshufd xmm7, xmm3, $FA
  shrd   ecx, ecx, $B
  and    ebx, eax
  xor    ecx, esi
  db $C5, $C9, $72, $D6, $0B                      // vpsrld xmm6, xmm6, $B
  add    edx, dword ptr [esp + $20]
  xor    ebx, edi
  shrd   ecx, ecx, $2
  db $C5, $D9, $EF, $E5                           // vpxor  xmm4, xmm4, xmm5
  add    ebx, edx
  add    edx, dword ptr [esp + $C]
  add    ebx, ecx
  db $C5, $D1, $72, $F5, $0B                      // vpslld xmm5, xmm5, $B
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $10]
  db $C5, $D9, $EF, $E6                           // vpxor  xmm4, xmm4, xmm6
  xor    edx, ecx
  mov    edi, dword ptr [esp + $14]
  xor    esi, edi
  db $C5, $C9, $72, $D7, $0A                      // vpsrld xmm6, xmm7, $A
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $C], ecx
  db $C5, $D9, $EF, $E5                           // vpxor  xmm4, xmm4, xmm5
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  db $C5, $D1, $73, $D7, $11                      // vpsrlq xmm5, xmm7, $11
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword ptr [esp]
  db $C5, $F9, $FE, $C4                           // vpaddd xmm0, xmm0, xmm4
  mov    esi, ebx
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $1C], ebx
  db $C5, $C9, $EF, $F5                           // vpxor  xmm6, xmm6, xmm5
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword ptr [esp + $18]
  db $C5, $C1, $73, $D7, $13                      // vpsrlq xmm7, xmm7, $13
  shrd   ecx, ecx, $B
  and    eax, ebx
  xor    ecx, esi
  db $C5, $C9, $EF, $F7                           // vpxor  xmm6, xmm6, xmm7
  add    edx, dword ptr [esp + $24]
  xor    eax, edi
  shrd   ecx, ecx, $2
  db $C5, $F9, $70, $FE, $84                      // vpshufd xmm7, xmm6, $84
  add    eax, edx
  add    edx, dword ptr [esp + $8]
  add    eax, ecx
  db $C5, $C1, $73, $DF, $08                      // vpsrldq xmm7, xmm7, $8
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $C]
  db $C5, $F9, $FE, $C7                           // vpaddd xmm0, xmm0, xmm7
  xor    edx, ecx
  mov    edi, dword ptr [esp + $10]
  xor    esi, edi
  db $C5, $F9, $70, $F8, $50                      // vpshufd xmm7, xmm0, $50
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $8], ecx
  db $C5, $C9, $72, $D7, $0A                      // vpsrld xmm6, xmm7, $A
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  db $C5, $D1, $73, $D7, $11                      // vpsrlq xmm5, xmm7, $11
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword ptr [esp + $1C]
  db $C5, $C9, $EF, $F5                           // vpxor  xmm6, xmm6, xmm5
  mov    esi, eax
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $18], eax
  db $C5, $C1, $73, $D7, $13                      // vpsrlq xmm7, xmm7, $13
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword ptr [esp + $14]
  db $C5, $C9, $EF, $F7                           // vpxor  xmm6, xmm6, xmm7
  shrd   ecx, ecx, $B
  and    ebx, eax
  xor    ecx, esi
  db $C5, $F9, $70, $FE, $E8                      // vpshufd xmm7, xmm6, $E8
  add    edx, dword ptr [esp + $28]
  xor    ebx, edi
  shrd   ecx, ecx, $2
  db $C5, $C1, $73, $FF, $08                      // vpslldq xmm7, xmm7, $8
  add    ebx, edx
  add    edx, dword ptr [esp + $4]
  add    ebx, ecx
  db $C5, $F9, $FE, $C7                           // vpaddd xmm0, xmm0, xmm7
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $8]
  db $C5, $F9, $FE, $75, $00                      // vpaddd xmm6, xmm0, oword [ebp + $0]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $C]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $4], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword ptr [esp + $18]
  mov    esi, ebx
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $14], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword ptr [esp + $10]
  shrd   ecx, ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword ptr [esp + $2C]
  xor    eax, edi
  shrd   ecx, ecx, $2
  add    eax, edx
  add    edx, dword ptr [esp]
  add    eax, ecx
  db $C5, $F9, $7F, $74, $24, $20                 // vmovdqa oword [esp + $20], xmm6
  db $C4, $E3, $69, $0F, $E1, $04                 // vpalignr xmm4, xmm2, xmm1, $4
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $4]
  db $C4, $E3, $79, $0F, $FB, $04                 // vpalignr xmm7, xmm0, xmm3, $4
  xor    edx, ecx
  mov    edi, dword ptr [esp + $8]
  xor    esi, edi
  db $C5, $C9, $72, $D4, $07                      // vpsrld xmm6, xmm4, $7
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp], ecx
  db $C5, $F1, $FE, $CF                           // vpaddd xmm1, xmm1, xmm7
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  db $C5, $C1, $72, $D4, $03                      // vpsrld xmm7, xmm4, $3
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword ptr [esp + $14]
  db $C5, $D1, $72, $F4, $0E                      // vpslld xmm5, xmm4, $E
  mov    esi, eax
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $10], eax
  db $C5, $C1, $EF, $E6                           // vpxor  xmm4, xmm7, xmm6
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword ptr [esp + $C]
  db $C5, $F9, $70, $F8, $FA                      // vpshufd xmm7, xmm0, $FA
  shrd   ecx, ecx, $B
  and    ebx, eax
  xor    ecx, esi
  db $C5, $C9, $72, $D6, $0B                      // vpsrld xmm6, xmm6, $B
  add    edx, dword ptr [esp + $30]
  xor    ebx, edi
  shrd   ecx, ecx, $2
  db $C5, $D9, $EF, $E5                           // vpxor  xmm4, xmm4, xmm5
  add    ebx, edx
  add    edx, dword ptr [esp + $1C]
  add    ebx, ecx
  db $C5, $D1, $72, $F5, $0B                      // vpslld xmm5, xmm5, $B
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp]
  db $C5, $D9, $EF, $E6                           // vpxor  xmm4, xmm4, xmm6
  xor    edx, ecx
  mov    edi, dword ptr [esp + $4]
  xor    esi, edi
  db $C5, $C9, $72, $D7, $0A                      // vpsrld xmm6, xmm7, $A
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $1C], ecx
  db $C5, $D9, $EF, $E5                           // vpxor  xmm4, xmm4, xmm5
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  db $C5, $D1, $73, $D7, $11                      // vpsrlq xmm5, xmm7, $11
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword ptr [esp + $10]
  db $C5, $F1, $FE, $CC                           // vpaddd xmm1, xmm1, xmm4
  mov    esi, ebx
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $C], ebx
  db $C5, $C9, $EF, $F5                           // vpxor  xmm6, xmm6, xmm5
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword ptr [esp + $8]
  db $C5, $C1, $73, $D7, $13                      // vpsrlq xmm7, xmm7, $13
  shrd   ecx, ecx, $B
  and    eax, ebx
  xor    ecx, esi
  db $C5, $C9, $EF, $F7                           // vpxor  xmm6, xmm6, xmm7
  add    edx, dword ptr [esp + $34]
  xor    eax, edi
  shrd   ecx, ecx, $2
  db $C5, $F9, $70, $FE, $84                      // vpshufd xmm7, xmm6, $84
  add    eax, edx
  add    edx, dword ptr [esp + $18]
  add    eax, ecx
  db $C5, $C1, $73, $DF, $08                      // vpsrldq xmm7, xmm7, $8
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $1C]
  db $C5, $F1, $FE, $CF                           // vpaddd xmm1, xmm1, xmm7
  xor    edx, ecx
  mov    edi, dword ptr [esp]
  xor    esi, edi
  db $C5, $F9, $70, $F9, $50                      // vpshufd xmm7, xmm1, $50
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $18], ecx
  db $C5, $C9, $72, $D7, $0A                      // vpsrld xmm6, xmm7, $A
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  db $C5, $D1, $73, $D7, $11                      // vpsrlq xmm5, xmm7, $11
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword ptr [esp + $C]
  db $C5, $C9, $EF, $F5                           // vpxor  xmm6, xmm6, xmm5
  mov    esi, eax
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $8], eax
  db $C5, $C1, $73, $D7, $13                      // vpsrlq xmm7, xmm7, $13
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword ptr [esp + $4]
  db $C5, $C9, $EF, $F7                           // vpxor  xmm6, xmm6, xmm7
  shrd   ecx, ecx, $B
  and    ebx, eax
  xor    ecx, esi
  db $C5, $F9, $70, $FE, $E8                      // vpshufd xmm7, xmm6, $E8
  add    edx, dword ptr [esp + $38]
  xor    ebx, edi
  shrd   ecx, ecx, $2
  db $C5, $C1, $73, $FF, $08                      // vpslldq xmm7, xmm7, $8
  add    ebx, edx
  add    edx, dword ptr [esp + $14]
  add    ebx, ecx
  db $C5, $F1, $FE, $CF                           // vpaddd xmm1, xmm1, xmm7
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $18]
  db $C5, $F1, $FE, $75, $20                      // vpaddd xmm6, xmm1, oword [ebp + $20]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $1C]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $14], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword ptr [esp + $8]
  mov    esi, ebx
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $4], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword ptr [esp]
  shrd   ecx, ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword ptr [esp + $3C]
  xor    eax, edi
  shrd   ecx, ecx, $2
  add    eax, edx
  add    edx, dword ptr [esp + $10]
  add    eax, ecx
  db $C5, $F9, $7F, $74, $24, $30                 // vmovdqa oword [esp + $30], xmm6
  db $C4, $E3, $61, $0F, $E2, $04                 // vpalignr xmm4, xmm3, xmm2, $4
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $14]
  db $C4, $E3, $71, $0F, $F8, $04                 // vpalignr xmm7, xmm1, xmm0, $4
  xor    edx, ecx
  mov    edi, dword ptr [esp + $18]
  xor    esi, edi
  db $C5, $C9, $72, $D4, $07                      // vpsrld xmm6, xmm4, $7
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $10], ecx
  db $C5, $E9, $FE, $D7                           // vpaddd xmm2, xmm2, xmm7
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  db $C5, $C1, $72, $D4, $03                      // vpsrld xmm7, xmm4, $3
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword ptr [esp + $4]
  db $C5, $D1, $72, $F4, $0E                      // vpslld xmm5, xmm4, $E
  mov    esi, eax
  shrd   ecx, ecx, $9
  mov    dword ptr [esp], eax
  db $C5, $C1, $EF, $E6                           // vpxor  xmm4, xmm7, xmm6
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword ptr [esp + $1C]
  db $C5, $F9, $70, $F9, $FA                      // vpshufd xmm7, xmm1, $FA
  shrd   ecx, ecx, $B
  and    ebx, eax
  xor    ecx, esi
  db $C5, $C9, $72, $D6, $0B                      // vpsrld xmm6, xmm6, $B
  add    edx, dword ptr [esp + $40]
  xor    ebx, edi
  shrd   ecx, ecx, $2
  db $C5, $D9, $EF, $E5                           // vpxor  xmm4, xmm4, xmm5
  add    ebx, edx
  add    edx, dword ptr [esp + $C]
  add    ebx, ecx
  db $C5, $D1, $72, $F5, $0B                      // vpslld xmm5, xmm5, $B
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $10]
  db $C5, $D9, $EF, $E6                           // vpxor  xmm4, xmm4, xmm6
  xor    edx, ecx
  mov    edi, dword ptr [esp + $14]
  xor    esi, edi
  db $C5, $C9, $72, $D7, $0A                      // vpsrld xmm6, xmm7, $A
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $C], ecx
  db $C5, $D9, $EF, $E5                           // vpxor  xmm4, xmm4, xmm5
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  db $C5, $D1, $73, $D7, $11                      // vpsrlq xmm5, xmm7, $11
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword ptr [esp]
  db $C5, $E9, $FE, $D4                           // vpaddd xmm2, xmm2, xmm4
  mov    esi, ebx
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $1C], ebx
  db $C5, $C9, $EF, $F5                           // vpxor  xmm6, xmm6, xmm5
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword ptr [esp + $18]
  db $C5, $C1, $73, $D7, $13                      // vpsrlq xmm7, xmm7, $13
  shrd   ecx, ecx, $B
  and    eax, ebx
  xor    ecx, esi
  db $C5, $C9, $EF, $F7                           // vpxor  xmm6, xmm6, xmm7
  add    edx, dword ptr [esp + $44]
  xor    eax, edi
  shrd   ecx, ecx, $2
  db $C5, $F9, $70, $FE, $84                      // vpshufd xmm7, xmm6, $84
  add    eax, edx
  add    edx, dword ptr [esp + $8]
  add    eax, ecx
  db $C5, $C1, $73, $DF, $08                      // vpsrldq xmm7, xmm7, $8
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $C]
  db $C5, $E9, $FE, $D7                           // vpaddd xmm2, xmm2, xmm7
  xor    edx, ecx
  mov    edi, dword ptr [esp + $10]
  xor    esi, edi
  db $C5, $F9, $70, $FA, $50                      // vpshufd xmm7, xmm2, $50
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $8], ecx
  db $C5, $C9, $72, $D7, $0A                      // vpsrld xmm6, xmm7, $A
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  db $C5, $D1, $73, $D7, $11                      // vpsrlq xmm5, xmm7, $11
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword ptr [esp + $1C]
  db $C5, $C9, $EF, $F5                           // vpxor  xmm6, xmm6, xmm5
  mov    esi, eax
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $18], eax
  db $C5, $C1, $73, $D7, $13                      // vpsrlq xmm7, xmm7, $13
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword ptr [esp + $14]
  db $C5, $C9, $EF, $F7                           // vpxor  xmm6, xmm6, xmm7
  shrd   ecx, ecx, $B
  and    ebx, eax
  xor    ecx, esi
  db $C5, $F9, $70, $FE, $E8                      // vpshufd xmm7, xmm6, $E8
  add    edx, dword ptr [esp + $48]
  xor    ebx, edi
  shrd   ecx, ecx, $2
  db $C5, $C1, $73, $FF, $08                      // vpslldq xmm7, xmm7, $8
  add    ebx, edx
  add    edx, dword ptr [esp + $4]
  add    ebx, ecx
  db $C5, $E9, $FE, $D7                           // vpaddd xmm2, xmm2, xmm7
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $8]
  db $C5, $E9, $FE, $75, $40                      // vpaddd xmm6, xmm2, oword [ebp + $40]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $C]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $4], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword ptr [esp + $18]
  mov    esi, ebx
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $14], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword ptr [esp + $10]
  shrd   ecx, ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword ptr [esp + $4C]
  xor    eax, edi
  shrd   ecx, ecx, $2
  add    eax, edx
  add    edx, dword ptr [esp]
  add    eax, ecx
  db $C5, $F9, $7F, $74, $24, $40                 // vmovdqa oword [esp + $40], xmm6
  db $C4, $E3, $79, $0F, $E3, $04                 // vpalignr xmm4, xmm0, xmm3, $4
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $4]
  db $C4, $E3, $69, $0F, $F9, $04                 // vpalignr xmm7, xmm2, xmm1, $4
  xor    edx, ecx
  mov    edi, dword ptr [esp + $8]
  xor    esi, edi
  db $C5, $C9, $72, $D4, $07                      // vpsrld xmm6, xmm4, $7
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp], ecx
  db $C5, $E1, $FE, $DF                           // vpaddd xmm3, xmm3, xmm7
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  db $C5, $C1, $72, $D4, $03                      // vpsrld xmm7, xmm4, $3
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword ptr [esp + $14]
  db $C5, $D1, $72, $F4, $0E                      // vpslld xmm5, xmm4, $E
  mov    esi, eax
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $10], eax
  db $C5, $C1, $EF, $E6                           // vpxor  xmm4, xmm7, xmm6
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword ptr [esp + $C]
  db $C5, $F9, $70, $FA, $FA                      // vpshufd xmm7, xmm2, $FA
  shrd   ecx, ecx, $B
  and    ebx, eax
  xor    ecx, esi
  db $C5, $C9, $72, $D6, $0B                      // vpsrld xmm6, xmm6, $B
  add    edx, dword ptr [esp + $50]
  xor    ebx, edi
  shrd   ecx, ecx, $2
  db $C5, $D9, $EF, $E5                           // vpxor  xmm4, xmm4, xmm5
  add    ebx, edx
  add    edx, dword ptr [esp + $1C]
  add    ebx, ecx
  db $C5, $D1, $72, $F5, $0B                      // vpslld xmm5, xmm5, $B
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp]
  db $C5, $D9, $EF, $E6                           // vpxor  xmm4, xmm4, xmm6
  xor    edx, ecx
  mov    edi, dword ptr [esp + $4]
  xor    esi, edi
  db $C5, $C9, $72, $D7, $0A                      // vpsrld xmm6, xmm7, $A
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $1C], ecx
  db $C5, $D9, $EF, $E5                           // vpxor  xmm4, xmm4, xmm5
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  db $C5, $D1, $73, $D7, $11                      // vpsrlq xmm5, xmm7, $11
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword ptr [esp + $10]
  db $C5, $E1, $FE, $DC                           // vpaddd xmm3, xmm3, xmm4
  mov    esi, ebx
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $C], ebx
  db $C5, $C9, $EF, $F5                           // vpxor  xmm6, xmm6, xmm5
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword ptr [esp + $8]
  db $C5, $C1, $73, $D7, $13                      // vpsrlq xmm7, xmm7, $13
  shrd   ecx, ecx, $B
  and    eax, ebx
  xor    ecx, esi
  db $C5, $C9, $EF, $F7                           // vpxor  xmm6, xmm6, xmm7
  add    edx, dword ptr [esp + $54]
  xor    eax, edi
  shrd   ecx, ecx, $2
  db $C5, $F9, $70, $FE, $84                      // vpshufd xmm7, xmm6, $84
  add    eax, edx
  add    edx, dword ptr [esp + $18]
  add    eax, ecx
  db $C5, $C1, $73, $DF, $08                      // vpsrldq xmm7, xmm7, $8
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $1C]
  db $C5, $E1, $FE, $DF                           // vpaddd xmm3, xmm3, xmm7
  xor    edx, ecx
  mov    edi, dword ptr [esp]
  xor    esi, edi
  db $C5, $F9, $70, $FB, $50                      // vpshufd xmm7, xmm3, $50
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $18], ecx
  db $C5, $C9, $72, $D7, $0A                      // vpsrld xmm6, xmm7, $A
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  db $C5, $D1, $73, $D7, $11                      // vpsrlq xmm5, xmm7, $11
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword ptr [esp + $C]
  db $C5, $C9, $EF, $F5                           // vpxor  xmm6, xmm6, xmm5
  mov    esi, eax
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $8], eax
  db $C5, $C1, $73, $D7, $13                      // vpsrlq xmm7, xmm7, $13
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword ptr [esp + $4]
  db $C5, $C9, $EF, $F7                           // vpxor  xmm6, xmm6, xmm7
  shrd   ecx, ecx, $B
  and    ebx, eax
  xor    ecx, esi
  db $C5, $F9, $70, $FE, $E8                      // vpshufd xmm7, xmm6, $E8
  add    edx, dword ptr [esp + $58]
  xor    ebx, edi
  shrd   ecx, ecx, $2
  db $C5, $C1, $73, $FF, $08                      // vpslldq xmm7, xmm7, $8
  add    ebx, edx
  add    edx, dword ptr [esp + $14]
  add    ebx, ecx
  db $C5, $E1, $FE, $DF                           // vpaddd xmm3, xmm3, xmm7
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $18]
  db $C5, $E1, $FE, $75, $60                      // vpaddd xmm6, xmm3, oword [ebp + $60]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $1C]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $14], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword ptr [esp + $8]
  mov    esi, ebx
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $4], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword ptr [esp]
  shrd   ecx, ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword ptr [esp + $5C]
  xor    eax, edi
  shrd   ecx, ecx, $2
  add    eax, edx
  add    edx, dword ptr [esp + $10]
  add    eax, ecx
  db $C5, $F9, $7F, $74, $24, $50                 // vmovdqa oword [esp + $50], xmm6
  cmp    dword ptr [ebp + $80], $10203
  jne @avx_00_47_015
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $14]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $18]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $10], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword ptr [esp + $4]
  mov    esi, eax
  shrd   ecx, ecx, $9
  mov    dword ptr [esp], eax
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword ptr [esp + $1C]
  shrd   ecx, ecx, $B
  and    ebx, eax
  xor    ecx, esi
  add    edx, dword ptr [esp + $20]
  xor    ebx, edi
  shrd   ecx, ecx, $2
  add    ebx, edx
  add    edx, dword ptr [esp + $C]
  add    ebx, ecx
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $10]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $14]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $C], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword ptr [esp]
  mov    esi, ebx
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $1C], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword ptr [esp + $18]
  shrd   ecx, ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword ptr [esp + $24]
  xor    eax, edi
  shrd   ecx, ecx, $2
  add    eax, edx
  add    edx, dword ptr [esp + $8]
  add    eax, ecx
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $C]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $10]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $8], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword ptr [esp + $1C]
  mov    esi, eax
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $18], eax
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword ptr [esp + $14]
  shrd   ecx, ecx, $B
  and    ebx, eax
  xor    ecx, esi
  add    edx, dword ptr [esp + $28]
  xor    ebx, edi
  shrd   ecx, ecx, $2
  add    ebx, edx
  add    edx, dword ptr [esp + $4]
  add    ebx, ecx
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $8]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $C]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $4], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword ptr [esp + $18]
  mov    esi, ebx
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $14], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword ptr [esp + $10]
  shrd   ecx, ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword ptr [esp + $2C]
  xor    eax, edi
  shrd   ecx, ecx, $2
  add    eax, edx
  add    edx, dword ptr [esp]
  add    eax, ecx
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $4]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $8]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword ptr [esp + $14]
  mov    esi, eax
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $10], eax
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword ptr [esp + $C]
  shrd   ecx, ecx, $B
  and    ebx, eax
  xor    ecx, esi
  add    edx, dword ptr [esp + $30]
  xor    ebx, edi
  shrd   ecx, ecx, $2
  add    ebx, edx
  add    edx, dword ptr [esp + $1C]
  add    ebx, ecx
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $4]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $1C], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword ptr [esp + $10]
  mov    esi, ebx
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $C], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword ptr [esp + $8]
  shrd   ecx, ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword ptr [esp + $34]
  xor    eax, edi
  shrd   ecx, ecx, $2
  add    eax, edx
  add    edx, dword ptr [esp + $18]
  add    eax, ecx
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $1C]
  xor    edx, ecx
  mov    edi, dword ptr [esp]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $18], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword ptr [esp + $C]
  mov    esi, eax
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $8], eax
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword ptr [esp + $4]
  shrd   ecx, ecx, $B
  and    ebx, eax
  xor    ecx, esi
  add    edx, dword ptr [esp + $38]
  xor    ebx, edi
  shrd   ecx, ecx, $2
  add    ebx, edx
  add    edx, dword ptr [esp + $14]
  add    ebx, ecx
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $18]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $1C]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $14], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword ptr [esp + $8]
  mov    esi, ebx
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $4], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword ptr [esp]
  shrd   ecx, ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword ptr [esp + $3C]
  xor    eax, edi
  shrd   ecx, ecx, $2
  add    eax, edx
  add    edx, dword ptr [esp + $10]
  add    eax, ecx
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $14]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $18]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $10], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword ptr [esp + $4]
  mov    esi, eax
  shrd   ecx, ecx, $9
  mov    dword ptr [esp], eax
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword ptr [esp + $1C]
  shrd   ecx, ecx, $B
  and    ebx, eax
  xor    ecx, esi
  add    edx, dword ptr [esp + $40]
  xor    ebx, edi
  shrd   ecx, ecx, $2
  add    ebx, edx
  add    edx, dword ptr [esp + $C]
  add    ebx, ecx
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $10]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $14]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $C], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword ptr [esp]
  mov    esi, ebx
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $1C], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword ptr [esp + $18]
  shrd   ecx, ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword ptr [esp + $44]
  xor    eax, edi
  shrd   ecx, ecx, $2
  add    eax, edx
  add    edx, dword ptr [esp + $8]
  add    eax, ecx
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $C]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $10]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $8], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword ptr [esp + $1C]
  mov    esi, eax
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $18], eax
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword ptr [esp + $14]
  shrd   ecx, ecx, $B
  and    ebx, eax
  xor    ecx, esi
  add    edx, dword ptr [esp + $48]
  xor    ebx, edi
  shrd   ecx, ecx, $2
  add    ebx, edx
  add    edx, dword ptr [esp + $4]
  add    ebx, ecx
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $8]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $C]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $4], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword ptr [esp + $18]
  mov    esi, ebx
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $14], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword ptr [esp + $10]
  shrd   ecx, ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword ptr [esp + $4C]
  xor    eax, edi
  shrd   ecx, ecx, $2
  add    eax, edx
  add    edx, dword ptr [esp]
  add    eax, ecx
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $4]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $8]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword ptr [esp + $14]
  mov    esi, eax
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $10], eax
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword ptr [esp + $C]
  shrd   ecx, ecx, $B
  and    ebx, eax
  xor    ecx, esi
  add    edx, dword ptr [esp + $50]
  xor    ebx, edi
  shrd   ecx, ecx, $2
  add    ebx, edx
  add    edx, dword ptr [esp + $1C]
  add    ebx, ecx
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $4]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $1C], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword ptr [esp + $10]
  mov    esi, ebx
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $C], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword ptr [esp + $8]
  shrd   ecx, ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword ptr [esp + $54]
  xor    eax, edi
  shrd   ecx, ecx, $2
  add    eax, edx
  add    edx, dword ptr [esp + $18]
  add    eax, ecx
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $1C]
  xor    edx, ecx
  mov    edi, dword ptr [esp]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $18], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword ptr [esp + $C]
  mov    esi, eax
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $8], eax
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword ptr [esp + $4]
  shrd   ecx, ecx, $B
  and    ebx, eax
  xor    ecx, esi
  add    edx, dword ptr [esp + $58]
  xor    ebx, edi
  shrd   ecx, ecx, $2
  add    ebx, edx
  add    edx, dword ptr [esp + $14]
  add    ebx, ecx
  mov    ecx, edx
  shrd   edx, edx, $E
  mov    esi, dword ptr [esp + $18]
  xor    edx, ecx
  mov    edi, dword ptr [esp + $1C]
  xor    esi, edi
  shrd   edx, edx, $5
  and    esi, ecx
  mov    dword ptr [esp + $14], ecx
  xor    edx, ecx
  xor    edi, esi
  shrd   edx, edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword ptr [esp + $8]
  mov    esi, ebx
  shrd   ecx, ecx, $9
  mov    dword ptr [esp + $4], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword ptr [esp]
  shrd   ecx, ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword ptr [esp + $5C]
  xor    eax, edi
  shrd   ecx, ecx, $2
  add    eax, edx
  add    edx, dword ptr [esp + $10]
  add    eax, ecx
  mov    esi, dword ptr [esp + $60]
  xor    ebx, edi
  mov    ecx, dword ptr [esp + $C]
  add    eax, dword ptr [esi]
  add    ebx, dword ptr [esi + $4]
  add    edi, dword ptr [esi + $8]
  add    ecx, dword ptr [esi + $C]
  mov    dword ptr [esi], eax
  mov    dword ptr [esi + $4], ebx
  mov    dword ptr [esi + $8], edi
  mov    dword ptr [esi + $C], ecx
  mov    dword ptr [esp + $4], ebx
  xor    ebx, edi
  mov    dword ptr [esp + $8], edi
  mov    dword ptr [esp + $C], ecx
  mov    edi, dword ptr [esp + $14]
  mov    ecx, dword ptr [esp + $18]
  add    edx, dword ptr [esi + $10]
  add    edi, dword ptr [esi + $14]
  add    ecx, dword ptr [esi + $18]
  mov    dword ptr [esi + $10], edx
  mov    dword ptr [esi + $14], edi
  mov    dword ptr [esp + $14], edi
  mov    edi, dword ptr [esp + $1C]
  mov    dword ptr [esi + $18], ecx
  add    edi, dword ptr [esi + $1C]
  mov    dword ptr [esp + $18], ecx
  mov    dword ptr [esi + $1C], edi
  mov    dword ptr [esp + $1C], edi
  mov    edi, dword ptr [esp + $64]
  db $C5, $FA, $6F, $BD, $80, $00, $00, $00       // vmovdqu xmm7, oword [ebp + $80]
  sub    ebp, $180
  cmp    edi, dword ptr [esp + $68]
  jb @grand_avx_014
  mov    esp, dword ptr [esp + $6C]
  db $C5, $FC, $77                                // vzeroall
  pop    ebp
  pop    edi
  pop    esi
  pop    ebx
