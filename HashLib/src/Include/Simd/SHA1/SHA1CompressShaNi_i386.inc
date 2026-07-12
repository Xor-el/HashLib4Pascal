// SHA-1 SHA-NI implementation (IA-32; Intel SHA Extensions work in 32-bit
// mode). The twenty sha1rnds4 steps carry their round constants as
// immediates; the only table read is the 16-byte flip mask, taken from
// K_SHA1_Doubled at +160 (byte-identical to the original's .LK_XX_XX+80; read
// unaligned - Pascal consts have no alignment guarantee). SHA-NI and shuffle
// instructions are db-encoded for broad assembler compatibility. The
// original's PIC table setup and stack-argument reads are replaced by the
// shared-prologue registers.
// Reference: OpenSSL CRYPTOGAMS sha1-586.pl (shaext function).
// Expects (after HlpSimdProc4Begin_i386): ebx = state, esi = data,
//   edi = numblocks, eax = K_SHA1_Doubled ptr. HlpSimdProc4Begin pushes
//   ebx/esi/edi; ebp is pushed here, giving the 4-deep frame the original
//   epilogue unwinds via its saved-esp register.

  push   ebp
  mov    ebp, eax
  mov    ecx, edi
  mov    edi, ebx
  mov    ebx, esp
  sub    esp, $20
  movdqu xmm0, oword ptr [edi]
  movd   xmm1, dword ptr [edi + $10]
  and    esp, $FFFFFFE0
  movdqu xmm3, oword ptr [ebp + $A0]
  movdqu xmm4, oword ptr [esi]
  pshufd xmm0, xmm0, $1B
  movdqu xmm5, oword ptr [esi + $10]
  pshufd xmm1, xmm1, $1B
  movdqu xmm6, oword ptr [esi + $20]
  db $66, $0F, $38, $00, $E3                      // pshufb xmm4, xmm3
  movdqu xmm7, oword ptr [esi + $30]
  db $66, $0F, $38, $00, $EB                      // pshufb xmm5, xmm3
  db $66, $0F, $38, $00, $F3                      // pshufb xmm6, xmm3
  db $66, $0F, $38, $00, $FB                      // pshufb xmm7, xmm3
  jmp @loop_shaext_004

@loop_shaext_004:
  dec    ecx
  lea    eax, [esi + $40]
  movdqa oword ptr [esp], xmm1
  paddd  xmm1, xmm4
  cmovne esi, eax
  movdqa oword ptr [esp + $10], xmm0
  db $0F, $38, $C9, $E5                           // sha1msg1 xmm4, xmm5
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $00                      // sha1rnds4 xmm0, xmm1, $0
  db $0F, $38, $C8, $D5                           // sha1nexte xmm2, xmm5
  pxor   xmm4, xmm6
  db $0F, $38, $C9, $EE                           // sha1msg1 xmm5, xmm6
  db $0F, $38, $CA, $E7                           // sha1msg2 xmm4, xmm7
  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $00                      // sha1rnds4 xmm0, xmm2, $0
  db $0F, $38, $C8, $CE                           // sha1nexte xmm1, xmm6
  pxor   xmm5, xmm7
  db $0F, $38, $CA, $EC                           // sha1msg2 xmm5, xmm4
  db $0F, $38, $C9, $F7                           // sha1msg1 xmm6, xmm7
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $00                      // sha1rnds4 xmm0, xmm1, $0
  db $0F, $38, $C8, $D7                           // sha1nexte xmm2, xmm7
  pxor   xmm6, xmm4
  db $0F, $38, $C9, $FC                           // sha1msg1 xmm7, xmm4
  db $0F, $38, $CA, $F5                           // sha1msg2 xmm6, xmm5
  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $00                      // sha1rnds4 xmm0, xmm2, $0
  db $0F, $38, $C8, $CC                           // sha1nexte xmm1, xmm4
  pxor   xmm7, xmm5
  db $0F, $38, $CA, $FE                           // sha1msg2 xmm7, xmm6
  db $0F, $38, $C9, $E5                           // sha1msg1 xmm4, xmm5
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $00                      // sha1rnds4 xmm0, xmm1, $0
  db $0F, $38, $C8, $D5                           // sha1nexte xmm2, xmm5
  pxor   xmm4, xmm6
  db $0F, $38, $C9, $EE                           // sha1msg1 xmm5, xmm6
  db $0F, $38, $CA, $E7                           // sha1msg2 xmm4, xmm7
  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $01                      // sha1rnds4 xmm0, xmm2, $1
  db $0F, $38, $C8, $CE                           // sha1nexte xmm1, xmm6
  pxor   xmm5, xmm7
  db $0F, $38, $CA, $EC                           // sha1msg2 xmm5, xmm4
  db $0F, $38, $C9, $F7                           // sha1msg1 xmm6, xmm7
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $01                      // sha1rnds4 xmm0, xmm1, $1
  db $0F, $38, $C8, $D7                           // sha1nexte xmm2, xmm7
  pxor   xmm6, xmm4
  db $0F, $38, $C9, $FC                           // sha1msg1 xmm7, xmm4
  db $0F, $38, $CA, $F5                           // sha1msg2 xmm6, xmm5
  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $01                      // sha1rnds4 xmm0, xmm2, $1
  db $0F, $38, $C8, $CC                           // sha1nexte xmm1, xmm4
  pxor   xmm7, xmm5
  db $0F, $38, $CA, $FE                           // sha1msg2 xmm7, xmm6
  db $0F, $38, $C9, $E5                           // sha1msg1 xmm4, xmm5
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $01                      // sha1rnds4 xmm0, xmm1, $1
  db $0F, $38, $C8, $D5                           // sha1nexte xmm2, xmm5
  pxor   xmm4, xmm6
  db $0F, $38, $C9, $EE                           // sha1msg1 xmm5, xmm6
  db $0F, $38, $CA, $E7                           // sha1msg2 xmm4, xmm7
  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $01                      // sha1rnds4 xmm0, xmm2, $1
  db $0F, $38, $C8, $CE                           // sha1nexte xmm1, xmm6
  pxor   xmm5, xmm7
  db $0F, $38, $CA, $EC                           // sha1msg2 xmm5, xmm4
  db $0F, $38, $C9, $F7                           // sha1msg1 xmm6, xmm7
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $02                      // sha1rnds4 xmm0, xmm1, $2
  db $0F, $38, $C8, $D7                           // sha1nexte xmm2, xmm7
  pxor   xmm6, xmm4
  db $0F, $38, $C9, $FC                           // sha1msg1 xmm7, xmm4
  db $0F, $38, $CA, $F5                           // sha1msg2 xmm6, xmm5
  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $02                      // sha1rnds4 xmm0, xmm2, $2
  db $0F, $38, $C8, $CC                           // sha1nexte xmm1, xmm4
  pxor   xmm7, xmm5
  db $0F, $38, $CA, $FE                           // sha1msg2 xmm7, xmm6
  db $0F, $38, $C9, $E5                           // sha1msg1 xmm4, xmm5
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $02                      // sha1rnds4 xmm0, xmm1, $2
  db $0F, $38, $C8, $D5                           // sha1nexte xmm2, xmm5
  pxor   xmm4, xmm6
  db $0F, $38, $C9, $EE                           // sha1msg1 xmm5, xmm6
  db $0F, $38, $CA, $E7                           // sha1msg2 xmm4, xmm7
  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $02                      // sha1rnds4 xmm0, xmm2, $2
  db $0F, $38, $C8, $CE                           // sha1nexte xmm1, xmm6
  pxor   xmm5, xmm7
  db $0F, $38, $CA, $EC                           // sha1msg2 xmm5, xmm4
  db $0F, $38, $C9, $F7                           // sha1msg1 xmm6, xmm7
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $02                      // sha1rnds4 xmm0, xmm1, $2
  db $0F, $38, $C8, $D7                           // sha1nexte xmm2, xmm7
  pxor   xmm6, xmm4
  db $0F, $38, $C9, $FC                           // sha1msg1 xmm7, xmm4
  db $0F, $38, $CA, $F5                           // sha1msg2 xmm6, xmm5
  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $03                      // sha1rnds4 xmm0, xmm2, $3
  db $0F, $38, $C8, $CC                           // sha1nexte xmm1, xmm4
  pxor   xmm7, xmm5
  db $0F, $38, $CA, $FE                           // sha1msg2 xmm7, xmm6
  movdqu xmm4, oword ptr [esi]
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $03                      // sha1rnds4 xmm0, xmm1, $3
  db $0F, $38, $C8, $D5                           // sha1nexte xmm2, xmm5
  movdqu xmm5, oword ptr [esi + $10]
  db $66, $0F, $38, $00, $E3                      // pshufb xmm4, xmm3
  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $03                      // sha1rnds4 xmm0, xmm2, $3
  db $0F, $38, $C8, $CE                           // sha1nexte xmm1, xmm6
  movdqu xmm6, oword ptr [esi + $20]
  db $66, $0F, $38, $00, $EB                      // pshufb xmm5, xmm3
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $03                      // sha1rnds4 xmm0, xmm1, $3
  db $0F, $38, $C8, $D7                           // sha1nexte xmm2, xmm7
  movdqu xmm7, oword ptr [esi + $30]
  db $66, $0F, $38, $00, $F3                      // pshufb xmm6, xmm3
  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $03                      // sha1rnds4 xmm0, xmm2, $3
  movdqa xmm2, oword ptr [esp]
  db $66, $0F, $38, $00, $FB                      // pshufb xmm7, xmm3
  db $0F, $38, $C8, $CA                           // sha1nexte xmm1, xmm2
  paddd  xmm0, oword ptr [esp + $10]
  jnz @loop_shaext_004
  pshufd xmm0, xmm0, $1B
  pshufd xmm1, xmm1, $1B
  movdqu oword ptr [edi], xmm0
  movd   dword ptr [edi + $10], xmm1
  mov    esp, ebx
  pop    ebp
  pop    edi
  pop    esi
  pop    ebx
