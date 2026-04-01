// SSSE3 implementation of Adler-32 block processing.
// Expects MS x64 ABI: rcx = data ptr, edx = num_blocks, r8 = sums ptr, r9 = constants ptr.
// ASums layout: [SumA: UInt32, SumB: UInt32].
// Constants layout: [weights_hi: 16B, weights_lo: 16B, ones_16: 16B].
// Processes num_blocks x 32-byte blocks. Does NOT apply mod 65521 (caller does it).
// Uses xmm0-xmm8 (xmm6-xmm8 saved/restored on Windows).

{$IFDEF MSWINDOWS}
  sub rsp, 48
  movdqu oword [rsp], xmm6
  movdqu oword [rsp + $10], xmm7
  movdqu oword [rsp + $20], xmm8
{$ENDIF}

  // Load constants
  movdqu xmm4, oword [r9]
  movdqu xmm5, oword [r9 + 16]
  movdqu xmm6, oword [r9 + 32]
  pxor xmm3, xmm3

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
  movdqu xmm7, oword [rcx]
  movdqa xmm8, xmm7
  psadbw xmm8, xmm3
  paddd xmm0, xmm8

  pmaddubsw xmm7, xmm4
  pmaddwd xmm7, xmm6
  paddd xmm1, xmm7

  // ---- Second 16-byte half (weights_lo) ----
  movdqu xmm7, oword [rcx + 16]
  movdqa xmm8, xmm7
  psadbw xmm8, xmm3
  paddd xmm0, xmm8

  pmaddubsw xmm7, xmm5
  pmaddwd xmm7, xmm6
  paddd xmm1, xmm7

  add rcx, 32
  dec r11d
  jnz @loop

  // v_s2 += v_ps * 32
  pslld xmm2, 5
  paddd xmm1, xmm2

  // Horizontal reduce v_s1
  pshufd xmm7, xmm0, $B1
  paddd xmm0, xmm7
  pshufd xmm7, xmm0, $4E
  paddd xmm0, xmm7
  movd edx, xmm0
  add eax, edx

  // Horizontal reduce v_s2
  pshufd xmm7, xmm1, $B1
  paddd xmm1, xmm7
  pshufd xmm7, xmm1, $4E
  paddd xmm1, xmm7
  movd r10d, xmm1

  // Store results
  mov dword [r8], eax
  mov dword [r8 + 4], r10d

{$IFDEF MSWINDOWS}
  movdqu xmm6, oword [rsp]
  movdqu xmm7, oword [rsp + $10]
  movdqu xmm8, oword [rsp + $20]
  add rsp, 48
{$ENDIF}
