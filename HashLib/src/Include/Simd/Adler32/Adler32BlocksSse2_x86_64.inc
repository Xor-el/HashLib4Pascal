// SSE2 implementation of Adler-32 block processing.
// Expects MS x64 ABI: rcx = data ptr, edx = num_blocks, r8 = sums ptr, r9 = constants ptr.
// ASums layout: [SumA: UInt32, SumB: UInt32].
// Constants layout: [weights_hi: 16B, weights_lo: 16B] (only first 32 bytes used).
// Processes num_blocks x 32-byte blocks. Does NOT apply mod 65521 (caller does it).
// Uses xmm0-xmm9 (xmm6-xmm9 saved/restored on Windows).
//
// Emulates SSSE3 pmaddubsw via punpcklbw/punpckhbw + pmaddwd:
//   data bytes are zero-extended to i16, then multiplied with pre-widened
//   weight bytes via pmaddwd (SSE2), producing the same 4 x i32 weighted
//   sums per 16-byte half that pmaddubsw + pmaddwd would yield.

{$IFDEF MSWINDOWS}
  sub rsp, 64
  movdqu oword [rsp], xmm6
  movdqu oword [rsp + $10], xmm7
  movdqu oword [rsp + $20], xmm8
  movdqu oword [rsp + $30], xmm9
{$ENDIF}

  // Zero constant
  pxor xmm3, xmm3

  // Pre-widen weight bytes to i16 (done once, stored in xmm6-xmm9)
  movdqu xmm4, oword [r9]
  movdqa xmm6, xmm4
  punpcklbw xmm6, xmm3
  movdqa xmm7, xmm4
  punpckhbw xmm7, xmm3
  movdqu xmm5, oword [r9 + 16]
  movdqa xmm8, xmm5
  punpcklbw xmm8, xmm3
  movdqa xmm9, xmm5
  punpckhbw xmm9, xmm3

  // Load initial sums
  mov eax, dword [r8]
  mov r10d, dword [r8 + 4]
  mov r11d, edx

  // v_ps = [SumA * num_blocks, 0, 0, 0]
  imul edx, eax
  movd xmm2, edx

  // v_s2 = [SumB, 0, 0, 0], v_s1 = 0
  movd xmm1, r10d
  pxor xmm0, xmm0

@loop:
  paddd xmm2, xmm0

  // ---- First 16-byte half (weights_hi) ----
  movdqu xmm4, oword [rcx]
  movdqa xmm5, xmm4
  psadbw xmm5, xmm3
  paddd xmm0, xmm5

  movdqa xmm5, xmm4
  punpcklbw xmm5, xmm3
  punpckhbw xmm4, xmm3
  pmaddwd xmm5, xmm6
  pmaddwd xmm4, xmm7
  paddd xmm5, xmm4
  paddd xmm1, xmm5

  // ---- Second 16-byte half (weights_lo) ----
  movdqu xmm4, oword [rcx + 16]
  movdqa xmm5, xmm4
  psadbw xmm5, xmm3
  paddd xmm0, xmm5

  movdqa xmm5, xmm4
  punpcklbw xmm5, xmm3
  punpckhbw xmm4, xmm3
  pmaddwd xmm5, xmm8
  pmaddwd xmm4, xmm9
  paddd xmm5, xmm4
  paddd xmm1, xmm5

  add rcx, 32
  dec r11d
  jnz @loop

  // v_s2 += v_ps * 32
  pslld xmm2, 5
  paddd xmm1, xmm2

  // Horizontal reduce v_s1
  pshufd xmm4, xmm0, $B1
  paddd xmm0, xmm4
  pshufd xmm4, xmm0, $4E
  paddd xmm0, xmm4
  movd edx, xmm0
  add eax, edx

  // Horizontal reduce v_s2
  pshufd xmm4, xmm1, $B1
  paddd xmm1, xmm4
  pshufd xmm4, xmm1, $4E
  paddd xmm1, xmm4
  movd r10d, xmm1

  // Store results
  mov dword [r8], eax
  mov dword [r8 + 4], r10d

{$IFDEF MSWINDOWS}
  movdqu xmm6, oword [rsp]
  movdqu xmm7, oword [rsp + $10]
  movdqu xmm8, oword [rsp + $20]
  movdqu xmm9, oword [rsp + $30]
  add rsp, 64
{$ENDIF}
