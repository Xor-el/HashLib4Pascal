// SSSE3 Adler-32 block processing (IA-32).
// After SimdProc4Begin_i386: ebx = AData, esi = ANumBlocks, edi = ASums, eax = AConstants.
// Constants: [weights_hi: 16B, weights_lo: 16B, ones_16: 16B] (48 bytes; same as x64 SSSE3).
// No xmm8 on IA-32: psadbw uses a copy in xmm5 (first half) or xmm4 (second half), then reload weights.
// Caller applies mod 65521.

  push eax

  mov ecx, esi
  mov eax, dword ptr [edi]
  mov esi, dword ptr [edi + 4]

  mov edx, ecx
  imul edx, eax
  movd xmm2, edx
  movd xmm1, esi
  pxor xmm0, xmm0
  pxor xmm3, xmm3

{$IFDEF MSWINDOWS}
  sub esp, 32
  movdqu oword ptr [esp], xmm6
  movdqu oword ptr [esp + $10], xmm7
  mov edx, dword ptr [esp + 32]
{$ELSE}
  mov edx, dword ptr [esp]
{$ENDIF}

  movdqu xmm4, oword ptr [edx]
  movdqu xmm5, oword ptr [edx + 16]
  movdqu xmm6, oword ptr [edx + 32]

@adler32_ssse3_loop:
  paddd xmm2, xmm0

  movdqu xmm7, oword ptr [ebx]
  movdqa xmm5, xmm7
  psadbw xmm5, xmm3
  paddd xmm0, xmm5
  movdqu xmm4, oword ptr [edx]
  movdqu xmm5, oword ptr [edx + 16]
  pmaddubsw xmm7, xmm4
  pmaddwd xmm7, xmm6
  paddd xmm1, xmm7

  movdqu xmm7, oword ptr [ebx + 16]
  movdqa xmm4, xmm7
  psadbw xmm4, xmm3
  paddd xmm0, xmm4
  movdqu xmm4, oword ptr [edx]
  movdqu xmm5, oword ptr [edx + 16]
  pmaddubsw xmm7, xmm5
  pmaddwd xmm7, xmm6
  paddd xmm1, xmm7

  add ebx, 32
  dec ecx
  jnz @adler32_ssse3_loop

  pslld xmm2, 5
  paddd xmm1, xmm2

  pshufd xmm7, xmm0, $B1
  paddd xmm0, xmm7
  pshufd xmm7, xmm0, $4E
  paddd xmm0, xmm7
  movd edx, xmm0
  add eax, edx

  pshufd xmm7, xmm1, $B1
  paddd xmm1, xmm7
  pshufd xmm7, xmm1, $4E
  paddd xmm1, xmm7
  movd esi, xmm1

  mov dword ptr [edi], eax
  mov dword ptr [edi + 4], esi

{$IFDEF MSWINDOWS}
  movdqu xmm6, oword ptr [esp]
  movdqu xmm7, oword ptr [esp + $10]
  add esp, 32
{$ENDIF}
  add esp, 4
  pop edi
  pop esi
  pop ebx
