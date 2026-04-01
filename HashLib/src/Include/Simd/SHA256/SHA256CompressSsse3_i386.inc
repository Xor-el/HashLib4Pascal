// SHA-256 SSSE3 implementation with SIMD message schedule (IA-32).
// After SimdProc4Begin_i386 — ebx = state, esi = data, edi = numblocks, eax = K256 ptr.
// Phase 1 matches SHA256CompressSsse3_x86_64.inc (pshufb, palignr); Phase 2 same GPR rounds as SSE2 i386.
// K256 layout: 64 UInt32 round constants (256 bytes), then BSWAP mask (16 bytes) at offset 256.
// Uses xmm0–xmm7. Non-volatile xmm6–xmm7 saved/restored on Windows (MSWINDOWS).
//
// Two-phase per block:
//   Phase 1 (SIMD): Compute W+K[0..63] using SSSE3 message schedule, store to stack
//   Phase 2 (GPR): Run 64 compression rounds reading W+K from stack
//
// Stack layout (sub esp, 376): same roles as x64; W+K via movdqu (ESP may be off 16-byte alignment).
// Scratch dwords at [esp+$4C]..[esp+$54] in the round loop only. Sigma1 uses register rotates only.

  sub esp, 376

{$IFDEF MSWINDOWS}
  movdqu oword ptr [esp], xmm6
  movdqu oword ptr [esp + $10], xmm7
{$ENDIF}
  mov [esp + $20], ebx
  mov [esp + $24], esi
  mov [esp + $28], edi
  mov [esp + $2C], eax
  mov [esp + $30], ebp

  test edi, edi
  jz @ssse3_256_done

@ssse3_256_block_loop:

  // ========== Phase 1: Message Schedule ==========

  mov ebx, [esp + $2C]
  mov esi, [esp + $24]
  lea ebp, [esp + $70]

  movdqu xmm7, oword ptr [ebx + $100]
  movdqu xmm0, oword ptr [esi]
  pshufb xmm0, xmm7
  movdqu xmm1, oword ptr [esi + $10]
  pshufb xmm1, xmm7
  movdqu xmm2, oword ptr [esi + $20]
  pshufb xmm2, xmm7
  movdqu xmm3, oword ptr [esi + $30]
  pshufb xmm3, xmm7

  movdqa xmm4, xmm0
  movdqu xmm5, oword ptr [ebx]
  paddd  xmm4, xmm5
  movdqu oword ptr [ebp], xmm4

  movdqa xmm4, xmm1
  movdqu xmm5, oword ptr [ebx + $10]
  paddd  xmm4, xmm5
  movdqu oword ptr [ebp + $10], xmm4

  movdqa xmm4, xmm2
  movdqu xmm5, oword ptr [ebx + $20]
  paddd  xmm4, xmm5
  movdqu oword ptr [ebp + $20], xmm4

  movdqa xmm4, xmm3
  movdqu xmm5, oword ptr [ebx + $30]
  paddd  xmm4, xmm5
  movdqu oword ptr [ebp + $30], xmm4

  add ebx, $40
  add ebp, $40
  mov ecx, 12

@ssse3_256_expand_loop:

  movdqa xmm4, xmm1
  palignr xmm4, xmm0, 4
  movdqa xmm5, xmm4
  movdqa xmm6, xmm4
  psrld  xmm4, 3
  psrld  xmm5, 7
  pslld  xmm6, 14
  pxor   xmm4, xmm5
  psrld  xmm5, 11
  pxor   xmm4, xmm6
  pslld  xmm6, 11
  pxor   xmm4, xmm5
  pxor   xmm4, xmm6

  paddd  xmm0, xmm4

  movdqa xmm4, xmm3
  palignr xmm4, xmm2, 4
  paddd  xmm0, xmm4

  movdqa xmm4, xmm3
  psrldq xmm4, 8
  movdqa xmm5, xmm4
  movdqa xmm6, xmm4
  psrld  xmm4, 10
  psrld  xmm5, 17
  pslld  xmm6, 13
  pxor   xmm4, xmm5
  psrld  xmm5, 2
  pxor   xmm4, xmm6
  pslld  xmm6, 2
  pxor   xmm4, xmm5
  pxor   xmm4, xmm6
  paddd  xmm0, xmm4

  movdqa xmm4, xmm0
  pslldq xmm4, 8
  movdqa xmm5, xmm4
  movdqa xmm6, xmm4
  psrld  xmm4, 10
  psrld  xmm5, 17
  pslld  xmm6, 13
  pxor   xmm4, xmm5
  psrld  xmm5, 2
  pxor   xmm4, xmm6
  pslld  xmm6, 2
  pxor   xmm4, xmm5
  pxor   xmm4, xmm6
  paddd  xmm0, xmm4

  movdqu xmm4, oword ptr [ebx]
  paddd  xmm4, xmm0
  movdqu oword ptr [ebp], xmm4

  movdqa xmm4, xmm0
  movdqa xmm0, xmm1
  movdqa xmm1, xmm2
  movdqa xmm2, xmm3
  movdqa xmm3, xmm4

  add ebx, $10
  add ebp, $10
  dec ecx
  jnz @ssse3_256_expand_loop

  // ========== Phase 2: 64 Compression Rounds ==========

  mov esi, [esp + $20]
  mov eax, [esi]
  mov ebx, [esi + $04]
  mov ecx, [esi + $08]
  mov edx, [esi + $0C]
  mov edi, [esi + $10]
  mov [esp + $34], edi
  mov edi, [esi + $14]
  mov [esp + $38], edi
  mov edi, [esi + $18]
  mov [esp + $3C], edi
  mov edi, [esi + $1C]
  mov [esp + $40], edi

  lea edi, [esp + $70 + $100]
  mov [esp + $44], edi
  lea ebp, [esp + $70]

@ssse3_256_round_loop:

  // Round 0: a=eax b=ebx c=ecx d=edx e=dword ptr [esp + $34] f=dword ptr [esp + $38] g=dword ptr [esp + $3C] h=dword ptr [esp + $40]
  mov esi, dword ptr [esp + $34]
  mov edi, dword ptr [esp + $34]
  ror esi, 6
  ror edi, 11
  xor esi, edi
  ror edi, 14
  xor esi, edi
  mov edi, dword ptr [esp + $38]
  xor edi, dword ptr [esp + $3C]
  and edi, dword ptr [esp + $34]
  xor edi, dword ptr [esp + $3C]
  add esi, dword ptr [esp + $40]
  add esi, edi
  add esi, dword ptr [ebp]
  add edx, esi
  mov dword ptr [esp + $4C], eax
  mov edi, dword ptr [esp + $4C]
  ror edi, 2
  mov eax, dword ptr [esp + $4C]
  ror eax, 13
  xor edi, eax
  mov eax, dword ptr [esp + $4C]
  ror eax, 22
  xor edi, eax
  add esi, edi
  mov eax, dword ptr [esp + $4C]
  mov dword ptr [esp + $40], eax
  and dword ptr [esp + $40], ebx
  mov edi, eax
  xor edi, ebx
  and edi, ecx
  xor dword ptr [esp + $40], edi
  add dword ptr [esp + $40], esi

  // Round 1: a=dword ptr [esp + $40] b=eax c=ebx d=ecx e=edx f=dword ptr [esp + $34] g=dword ptr [esp + $38] h=dword ptr [esp + $3C]
  mov esi, edx
  mov edi, edx
  ror esi, 6
  ror edi, 11
  xor esi, edi
  ror edi, 14
  xor esi, edi
  mov edi, dword ptr [esp + $34]
  xor edi, dword ptr [esp + $38]
  and edi, edx
  xor edi, dword ptr [esp + $38]
  add esi, dword ptr [esp + $3C]
  add esi, edi
  add esi, dword ptr [ebp + $04]
  add ecx, esi
  mov dword ptr [esp + $50], eax
  mov edi, dword ptr [esp + $40]
  mov dword ptr [esp + $3C], edi
  mov dword ptr [esp + $4C], edi
  mov edi, dword ptr [esp + $4C]
  ror edi, 2
  mov eax, dword ptr [esp + $4C]
  ror eax, 13
  xor edi, eax
  mov eax, dword ptr [esp + $4C]
  ror eax, 22
  xor edi, eax
  add esi, edi
  mov eax, dword ptr [esp + $50]
  mov edi, dword ptr [esp + $40]
  mov dword ptr [esp + $3C], edi
  and dword ptr [esp + $3C], eax
  xor edi, eax
  and edi, ebx
  xor dword ptr [esp + $3C], edi
  add dword ptr [esp + $3C], esi

  // Round 2: a=dword ptr [esp + $3C] b=dword ptr [esp + $40] c=eax d=ebx e=ecx f=edx g=dword ptr [esp + $34] h=dword ptr [esp + $38]
  mov esi, ecx
  mov edi, ecx
  ror esi, 6
  ror edi, 11
  xor esi, edi
  ror edi, 14
  xor esi, edi
  mov edi, edx
  xor edi, dword ptr [esp + $34]
  and edi, ecx
  xor edi, dword ptr [esp + $34]
  add esi, dword ptr [esp + $38]
  add esi, edi
  add esi, dword ptr [ebp + $08]
  add ebx, esi
  mov dword ptr [esp + $50], ebx
  mov dword ptr [esp + $54], eax
  mov edi, dword ptr [esp + $3C]
  mov dword ptr [esp + $38], edi
  mov dword ptr [esp + $4C], edi
  mov edi, dword ptr [esp + $4C]
  ror edi, 2
  mov eax, dword ptr [esp + $4C]
  ror eax, 13
  xor edi, eax
  mov eax, dword ptr [esp + $4C]
  ror eax, 22
  xor edi, eax
  add esi, edi
  mov eax, dword ptr [esp + $54]
  mov ebx, dword ptr [esp + $50]
  mov edi, dword ptr [esp + $3C]
  and edi, dword ptr [esp + $40]
  mov dword ptr [esp + $38], edi
  mov edi, dword ptr [esp + $3C]
  xor edi, dword ptr [esp + $40]
  and edi, eax
  xor dword ptr [esp + $38], edi
  add dword ptr [esp + $38], esi

  // Round 3: a=dword ptr [esp + $38] b=dword ptr [esp + $3C] c=dword ptr [esp + $40] d=eax e=ebx f=ecx g=edx h=dword ptr [esp + $34]
  mov esi, ebx
  mov edi, ebx
  ror esi, 6
  ror edi, 11
  xor esi, edi
  ror edi, 14
  xor esi, edi
  mov edi, ecx
  xor edi, edx
  and edi, ebx
  xor edi, edx
  add esi, dword ptr [esp + $34]
  add esi, edi
  add esi, dword ptr [ebp + $0C]
  add eax, esi
  mov dword ptr [esp + $50], eax
  mov dword ptr [esp + $54], ebx
  mov edi, dword ptr [esp + $38]
  mov dword ptr [esp + $34], edi
  mov dword ptr [esp + $4C], edi
  mov edi, dword ptr [esp + $4C]
  ror edi, 2
  mov eax, dword ptr [esp + $4C]
  ror eax, 13
  xor edi, eax
  mov eax, dword ptr [esp + $4C]
  ror eax, 22
  xor edi, eax
  add esi, edi
  mov eax, dword ptr [esp + $50]
  mov ebx, dword ptr [esp + $54]
  mov edi, dword ptr [esp + $38]
  and edi, dword ptr [esp + $3C]
  mov dword ptr [esp + $34], edi
  mov edi, dword ptr [esp + $38]
  xor edi, dword ptr [esp + $3C]
  and edi, dword ptr [esp + $40]
  xor dword ptr [esp + $34], edi
  add dword ptr [esp + $34], esi

  // Round 4: a=dword ptr [esp + $34] b=dword ptr [esp + $38] c=dword ptr [esp + $3C] d=dword ptr [esp + $40] e=eax f=ebx g=ecx h=edx
  mov esi, eax
  mov edi, eax
  ror esi, 6
  ror edi, 11
  xor esi, edi
  ror edi, 14
  xor esi, edi
  mov edi, ebx
  xor edi, ecx
  and edi, eax
  xor edi, ecx
  add esi, edx
  add esi, edi
  add esi, dword ptr [ebp + $10]
  add dword ptr [esp + $40], esi
  mov edi, dword ptr [esp + $34]
  mov edx, dword ptr [esp + $34]
  ror edi, 2
  ror edx, 13
  xor edi, edx
  ror edx, 9
  xor edi, edx
  add esi, edi
  mov edx, dword ptr [esp + $34]
  and edx, dword ptr [esp + $38]
  mov edi, dword ptr [esp + $34]
  xor edi, dword ptr [esp + $38]
  and edi, dword ptr [esp + $3C]
  xor edx, edi
  add edx, esi

  // Round 5: a=edx b=dword ptr [esp + $34] c=dword ptr [esp + $38] d=dword ptr [esp + $3C] e=dword ptr [esp + $40] f=eax g=ebx h=ecx
  mov esi, dword ptr [esp + $40]
  mov edi, dword ptr [esp + $40]
  ror esi, 6
  ror edi, 11
  xor esi, edi
  ror edi, 14
  xor esi, edi
  mov edi, eax
  xor edi, ebx
  and edi, dword ptr [esp + $40]
  xor edi, ebx
  add esi, ecx
  add esi, edi
  add esi, dword ptr [ebp + $14]
  add dword ptr [esp + $3C], esi
  mov edi, edx
  mov ecx, edx
  ror edi, 2
  ror ecx, 13
  xor edi, ecx
  ror ecx, 9
  xor edi, ecx
  add esi, edi
  mov ecx, edx
  and ecx, dword ptr [esp + $34]
  mov edi, edx
  xor edi, dword ptr [esp + $34]
  and edi, dword ptr [esp + $38]
  xor ecx, edi
  add ecx, esi

  // Round 6: a=ecx b=edx c=dword ptr [esp + $34] d=dword ptr [esp + $38] e=dword ptr [esp + $3C] f=dword ptr [esp + $40] g=eax h=ebx
  mov esi, dword ptr [esp + $3C]
  mov edi, dword ptr [esp + $3C]
  ror esi, 6
  ror edi, 11
  xor esi, edi
  ror edi, 14
  xor esi, edi
  mov edi, dword ptr [esp + $40]
  xor edi, eax
  and edi, dword ptr [esp + $3C]
  xor edi, eax
  add esi, ebx
  add esi, edi
  add esi, dword ptr [ebp + $18]
  add dword ptr [esp + $38], esi
  mov edi, ecx
  mov ebx, ecx
  ror edi, 2
  ror ebx, 13
  xor edi, ebx
  ror ebx, 9
  xor edi, ebx
  add esi, edi
  mov ebx, ecx
  and ebx, edx
  mov edi, ecx
  xor edi, edx
  and edi, dword ptr [esp + $34]
  xor ebx, edi
  add ebx, esi

  // Round 7: a=ebx b=ecx c=edx d=dword ptr [esp + $34] e=dword ptr [esp + $38] f=dword ptr [esp + $3C] g=dword ptr [esp + $40] h=eax
  mov esi, dword ptr [esp + $38]
  mov edi, dword ptr [esp + $38]
  ror esi, 6
  ror edi, 11
  xor esi, edi
  ror edi, 14
  xor esi, edi
  mov edi, dword ptr [esp + $3C]
  xor edi, dword ptr [esp + $40]
  and edi, dword ptr [esp + $38]
  xor edi, dword ptr [esp + $40]
  add esi, eax
  add esi, edi
  add esi, dword ptr [ebp + $1C]
  add dword ptr [esp + $34], esi
  mov edi, ebx
  mov eax, ebx
  ror edi, 2
  ror eax, 13
  xor edi, eax
  ror eax, 9
  xor edi, eax
  add esi, edi
  mov eax, ebx
  and eax, ecx
  mov edi, ebx
  xor edi, ecx
  and edi, edx
  xor eax, edi
  add eax, esi

  add ebp, $20
  cmp ebp, [esp + $44]
  jb @ssse3_256_round_loop

  // Add round results to state
  mov esi, [esp + $20]
  add dword ptr [esi], eax
  add dword ptr [esi + $04], ebx
  add dword ptr [esi + $08], ecx
  add dword ptr [esi + $0C], edx
  mov eax, dword ptr [esp + $34]
  add dword ptr [esi + $10], eax
  mov eax, dword ptr [esp + $38]
  add dword ptr [esi + $14], eax
  mov eax, dword ptr [esp + $3C]
  add dword ptr [esi + $18], eax
  mov eax, dword ptr [esp + $40]
  add dword ptr [esi + $1C], eax

  mov esi, [esp + $24]
  add esi, $40
  mov [esp + $24], esi
  dec dword ptr [esp + $28]
  jnz @ssse3_256_block_loop

@ssse3_256_done:

  mov ebp, [esp + $30]
{$IFDEF MSWINDOWS}
  movdqu xmm6, oword ptr [esp]
  movdqu xmm7, oword ptr [esp + $10]
{$ENDIF}
  add esp, 376
  pop edi
  pop esi
  pop ebx
