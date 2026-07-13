// SHA-NI implementation of SHA-256 compress (IA-32; Intel SHA Extensions
// work in 32-bit mode), with the unified function's common prologue
// reproduced by the same proven head as the SSE2/SSSE3/AVX siblings (slots
// ctx/data/end/savedsp; the section's sub $32 shifts them to 32/36/40/44).
// K256 is read from K256_Doubled at a 32-byte stride (bias and offsets
// doubled; read unaligned - Pascal consts have no alignment guarantee); the
// byte-swap mask sits at the doubled +512 (= biased +256).
// ABI (after HlpSimdProc4Begin_i386.inc): ebx = state ptr, esi = data ptr,
//   edi = numblocks, eax = K256_Doubled ptr.
// Frame: the prologue pushes ebx/esi/edi; ebp is pushed here as the K
//   pointer.
// SHA-NI and shuffle instructions are db-encoded for broad assembler
// compatibility.
// Reference: OpenSSL CRYPTOGAMS sha256-586.pl (shaext section).

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
  sub    esp, $20
  movdqu xmm1, oword ptr [esi]
  lea    ebp, [ebp + $100]
  movdqu xmm2, oword ptr [esi + $10]
  movdqu xmm7, oword ptr [ebp + $100]
  pshufd xmm0, xmm1, $1B
  pshufd xmm1, xmm1, $B1
  pshufd xmm2, xmm2, $1B
  db $66, $0F, $3A, $0F, $CA, $08                 // palignr xmm1, xmm2, $8
  db $66, $0F, $6C, $D0                           // punpcklqdq xmm2, xmm0
  jmp @loop_shaext_011

@loop_shaext_011:
  movdqu xmm3, oword ptr [edi]
  movdqu xmm4, oword ptr [edi + $10]
  movdqu xmm5, oword ptr [edi + $20]
  db $66, $0F, $38, $00, $DF                      // pshufb xmm3, xmm7
  movdqu xmm6, oword ptr [edi + $30]
  movdqa oword ptr [esp + $10], xmm2
  movdqu xmm0, oword ptr [ebp - $100]
  paddd  xmm0, xmm3
  db $66, $0F, $38, $00, $E7                      // pshufb xmm4, xmm7
  db $0F, $38, $CB, $D1                           // sha256rnds2 xmm2, xmm1, xmm0
  pshufd xmm0, xmm0, $E
  nop
  movdqa oword ptr [esp], xmm1
  db $0F, $38, $CB, $CA                           // sha256rnds2 xmm1, xmm2, xmm0
  movdqu xmm0, oword ptr [ebp - $E0]
  paddd  xmm0, xmm4
  db $66, $0F, $38, $00, $EF                      // pshufb xmm5, xmm7
  db $0F, $38, $CB, $D1                           // sha256rnds2 xmm2, xmm1, xmm0
  pshufd xmm0, xmm0, $E
  lea    edi, [edi + $40]
  db $0F, $38, $CC, $DC                           // sha256msg1 xmm3, xmm4
  db $0F, $38, $CB, $CA                           // sha256rnds2 xmm1, xmm2, xmm0
  movdqu xmm0, oword ptr [ebp - $C0]
  paddd  xmm0, xmm5
  db $66, $0F, $38, $00, $F7                      // pshufb xmm6, xmm7
  db $0F, $38, $CB, $D1                           // sha256rnds2 xmm2, xmm1, xmm0
  pshufd xmm0, xmm0, $E
  movdqa xmm7, xmm6
  db $66, $0F, $3A, $0F, $FD, $04                 // palignr xmm7, xmm5, $4
  nop
  paddd  xmm3, xmm7
  db $0F, $38, $CC, $E5                           // sha256msg1 xmm4, xmm5
  db $0F, $38, $CB, $CA                           // sha256rnds2 xmm1, xmm2, xmm0
  movdqu xmm0, oword ptr [ebp - $A0]
  paddd  xmm0, xmm6
  db $0F, $38, $CD, $DE                           // sha256msg2 xmm3, xmm6
  db $0F, $38, $CB, $D1                           // sha256rnds2 xmm2, xmm1, xmm0
  pshufd xmm0, xmm0, $E
  movdqa xmm7, xmm3
  db $66, $0F, $3A, $0F, $FE, $04                 // palignr xmm7, xmm6, $4
  nop
  paddd  xmm4, xmm7
  db $0F, $38, $CC, $EE                           // sha256msg1 xmm5, xmm6
  db $0F, $38, $CB, $CA                           // sha256rnds2 xmm1, xmm2, xmm0
  movdqu xmm0, oword ptr [ebp - $80]
  paddd  xmm0, xmm3
  db $0F, $38, $CD, $E3                           // sha256msg2 xmm4, xmm3
  db $0F, $38, $CB, $D1                           // sha256rnds2 xmm2, xmm1, xmm0
  pshufd xmm0, xmm0, $E
  movdqa xmm7, xmm4
  db $66, $0F, $3A, $0F, $FB, $04                 // palignr xmm7, xmm3, $4
  nop
  paddd  xmm5, xmm7
  db $0F, $38, $CC, $F3                           // sha256msg1 xmm6, xmm3
  db $0F, $38, $CB, $CA                           // sha256rnds2 xmm1, xmm2, xmm0
  movdqu xmm0, oword ptr [ebp - $60]
  paddd  xmm0, xmm4
  db $0F, $38, $CD, $EC                           // sha256msg2 xmm5, xmm4
  db $0F, $38, $CB, $D1                           // sha256rnds2 xmm2, xmm1, xmm0
  pshufd xmm0, xmm0, $E
  movdqa xmm7, xmm5
  db $66, $0F, $3A, $0F, $FC, $04                 // palignr xmm7, xmm4, $4
  nop
  paddd  xmm6, xmm7
  db $0F, $38, $CC, $DC                           // sha256msg1 xmm3, xmm4
  db $0F, $38, $CB, $CA                           // sha256rnds2 xmm1, xmm2, xmm0
  movdqu xmm0, oword ptr [ebp - $40]
  paddd  xmm0, xmm5
  db $0F, $38, $CD, $F5                           // sha256msg2 xmm6, xmm5
  db $0F, $38, $CB, $D1                           // sha256rnds2 xmm2, xmm1, xmm0
  pshufd xmm0, xmm0, $E
  movdqa xmm7, xmm6
  db $66, $0F, $3A, $0F, $FD, $04                 // palignr xmm7, xmm5, $4
  nop
  paddd  xmm3, xmm7
  db $0F, $38, $CC, $E5                           // sha256msg1 xmm4, xmm5
  db $0F, $38, $CB, $CA                           // sha256rnds2 xmm1, xmm2, xmm0
  movdqu xmm0, oword ptr [ebp - $20]
  paddd  xmm0, xmm6
  db $0F, $38, $CD, $DE                           // sha256msg2 xmm3, xmm6
  db $0F, $38, $CB, $D1                           // sha256rnds2 xmm2, xmm1, xmm0
  pshufd xmm0, xmm0, $E
  movdqa xmm7, xmm3
  db $66, $0F, $3A, $0F, $FE, $04                 // palignr xmm7, xmm6, $4
  nop
  paddd  xmm4, xmm7
  db $0F, $38, $CC, $EE                           // sha256msg1 xmm5, xmm6
  db $0F, $38, $CB, $CA                           // sha256rnds2 xmm1, xmm2, xmm0
  movdqu xmm0, oword ptr [ebp + $0]
  paddd  xmm0, xmm3
  db $0F, $38, $CD, $E3                           // sha256msg2 xmm4, xmm3
  db $0F, $38, $CB, $D1                           // sha256rnds2 xmm2, xmm1, xmm0
  pshufd xmm0, xmm0, $E
  movdqa xmm7, xmm4
  db $66, $0F, $3A, $0F, $FB, $04                 // palignr xmm7, xmm3, $4
  nop
  paddd  xmm5, xmm7
  db $0F, $38, $CC, $F3                           // sha256msg1 xmm6, xmm3
  db $0F, $38, $CB, $CA                           // sha256rnds2 xmm1, xmm2, xmm0
  movdqu xmm0, oword ptr [ebp + $20]
  paddd  xmm0, xmm4
  db $0F, $38, $CD, $EC                           // sha256msg2 xmm5, xmm4
  db $0F, $38, $CB, $D1                           // sha256rnds2 xmm2, xmm1, xmm0
  pshufd xmm0, xmm0, $E
  movdqa xmm7, xmm5
  db $66, $0F, $3A, $0F, $FC, $04                 // palignr xmm7, xmm4, $4
  nop
  paddd  xmm6, xmm7
  db $0F, $38, $CC, $DC                           // sha256msg1 xmm3, xmm4
  db $0F, $38, $CB, $CA                           // sha256rnds2 xmm1, xmm2, xmm0
  movdqu xmm0, oword ptr [ebp + $40]
  paddd  xmm0, xmm5
  db $0F, $38, $CD, $F5                           // sha256msg2 xmm6, xmm5
  db $0F, $38, $CB, $D1                           // sha256rnds2 xmm2, xmm1, xmm0
  pshufd xmm0, xmm0, $E
  movdqa xmm7, xmm6
  db $66, $0F, $3A, $0F, $FD, $04                 // palignr xmm7, xmm5, $4
  nop
  paddd  xmm3, xmm7
  db $0F, $38, $CC, $E5                           // sha256msg1 xmm4, xmm5
  db $0F, $38, $CB, $CA                           // sha256rnds2 xmm1, xmm2, xmm0
  movdqu xmm0, oword ptr [ebp + $60]
  paddd  xmm0, xmm6
  db $0F, $38, $CD, $DE                           // sha256msg2 xmm3, xmm6
  db $0F, $38, $CB, $D1                           // sha256rnds2 xmm2, xmm1, xmm0
  pshufd xmm0, xmm0, $E
  movdqa xmm7, xmm3
  db $66, $0F, $3A, $0F, $FE, $04                 // palignr xmm7, xmm6, $4
  nop
  paddd  xmm4, xmm7
  db $0F, $38, $CC, $EE                           // sha256msg1 xmm5, xmm6
  db $0F, $38, $CB, $CA                           // sha256rnds2 xmm1, xmm2, xmm0
  movdqu xmm0, oword ptr [ebp + $80]
  paddd  xmm0, xmm3
  db $0F, $38, $CD, $E3                           // sha256msg2 xmm4, xmm3
  db $0F, $38, $CB, $D1                           // sha256rnds2 xmm2, xmm1, xmm0
  pshufd xmm0, xmm0, $E
  movdqa xmm7, xmm4
  db $66, $0F, $3A, $0F, $FB, $04                 // palignr xmm7, xmm3, $4
  nop
  paddd  xmm5, xmm7
  db $0F, $38, $CC, $F3                           // sha256msg1 xmm6, xmm3
  db $0F, $38, $CB, $CA                           // sha256rnds2 xmm1, xmm2, xmm0
  movdqu xmm0, oword ptr [ebp + $A0]
  paddd  xmm0, xmm4
  db $0F, $38, $CD, $EC                           // sha256msg2 xmm5, xmm4
  db $0F, $38, $CB, $D1                           // sha256rnds2 xmm2, xmm1, xmm0
  pshufd xmm0, xmm0, $E
  movdqa xmm7, xmm5
  db $66, $0F, $3A, $0F, $FC, $04                 // palignr xmm7, xmm4, $4
  db $0F, $38, $CB, $CA                           // sha256rnds2 xmm1, xmm2, xmm0
  paddd  xmm6, xmm7
  movdqu xmm0, oword ptr [ebp + $C0]
  paddd  xmm0, xmm5
  db $0F, $38, $CB, $D1                           // sha256rnds2 xmm2, xmm1, xmm0
  pshufd xmm0, xmm0, $E
  db $0F, $38, $CD, $F5                           // sha256msg2 xmm6, xmm5
  movdqu xmm7, oword ptr [ebp + $100]
  db $0F, $38, $CB, $CA                           // sha256rnds2 xmm1, xmm2, xmm0
  movdqu xmm0, oword ptr [ebp + $E0]
  paddd  xmm0, xmm6
  nop
  db $0F, $38, $CB, $D1                           // sha256rnds2 xmm2, xmm1, xmm0
  pshufd xmm0, xmm0, $E
  cmp    eax, edi
  nop
  db $0F, $38, $CB, $CA                           // sha256rnds2 xmm1, xmm2, xmm0
  paddd  xmm2, oword ptr [esp + $10]
  paddd  xmm1, oword ptr [esp]
  jnz @loop_shaext_011
  pshufd xmm2, xmm2, $B1
  pshufd xmm7, xmm1, $1B
  pshufd xmm1, xmm1, $B1
  db $66, $0F, $6D, $CA                           // punpckhqdq xmm1, xmm2
  db $66, $0F, $3A, $0F, $D7, $08                 // palignr xmm2, xmm7, $8
  mov    esp, dword ptr [esp + $2C]
  movdqu oword ptr [esi], xmm1
  movdqu oword ptr [esi + $10], xmm2
  pop    ebp
  pop    edi
  pop    esi
  pop    ebx
