// SSE2 implementation of Adler-32 block processing (num_blocks x 32-byte blocks;
// IA-32). Does NOT apply mod 65521 (the caller does). Same SSE2 pmaddubsw
// emulation as Adler32BlocksSse2_x86_64.inc (punpcklbw/hbw + pmaddwd); x64
// keeps the widened weights in xmm6-xmm9, IA-32 only has xmm0-xmm7 so they
// live on the stack (4 x 16 bytes).
// ABI (after HlpSimdProc4Begin_i386.inc): ebx = data ptr, esi = num_blocks,
//   edi = sums ptr, eax = constants ptr.
//   Sums layout: [SumA: UInt32, SumB: UInt32].
//   Constants layout: [weights_hi: 16B, weights_lo: 16B] (32 bytes).
// Frame (sub esp, 96):
//   [esp +  0..15] = xmm6 save        [esp + 48..63] = w1 (weights_hi high)
//   [esp + 16..31] = xmm7 save        [esp + 64..79] = w2 (weights_lo low)
//   [esp + 32..47] = w0 (weights_hi low)  [esp + 80..95] = w3 (weights_lo high)
// Saves: xmm6-xmm7 saved/restored defensively (volatile on IA-32).
// Reference: Chromium zlib adler32_simd.c, HashLib Adler32BlocksSse2_x86_64.inc.

  // Preserve constants pointer (eax) before GPR reloads from ASums
  push eax

  mov ecx, esi                 // block counter
  mov eax, dword ptr [edi]     // SumA
  mov esi, dword ptr [edi + 4] // SumB

  mov edx, ecx
  imul edx, eax                // num_blocks * SumA
  movd xmm2, edx               // v_ps

  movd xmm1, esi               // v_s2 = [SumB, 0, 0, 0]
  pxor xmm0, xmm0              // v_s1 = 0
  pxor xmm3, xmm3              // zero for unpack / psadbw

  sub esp, 96
  movdqu oword ptr [esp], xmm6
  movdqu oword ptr [esp + $10], xmm7

  mov edx, dword ptr [esp + 96] // AConstants (above frame + push eax)
  movdqu xmm4, oword ptr [edx]
  movdqa xmm6, xmm4
  punpcklbw xmm6, xmm3
  movdqu oword ptr [esp + $20], xmm6 // w0
  movdqa xmm6, xmm4
  punpckhbw xmm6, xmm3
  movdqu oword ptr [esp + $30], xmm6 // w1
  movdqu xmm5, oword ptr [edx + 16]
  movdqa xmm6, xmm5
  punpcklbw xmm6, xmm3
  movdqu oword ptr [esp + $40], xmm6 // w2
  movdqa xmm6, xmm5
  punpckhbw xmm6, xmm3
  movdqu oword ptr [esp + $50], xmm6 // w3

@adler32_sse2_loop:
  paddd xmm2, xmm0

  // First 16 bytes (weights_hi)
  movdqu xmm4, oword ptr [ebx]
  movdqa xmm5, xmm4
  psadbw xmm5, xmm3
  paddd xmm0, xmm5

  movdqa xmm5, xmm4
  punpcklbw xmm5, xmm3
  punpckhbw xmm4, xmm3
  movdqu xmm6, oword ptr [esp + $20]
  movdqu xmm7, oword ptr [esp + $30]
  pmaddwd xmm5, xmm6
  pmaddwd xmm4, xmm7
  paddd xmm5, xmm4
  paddd xmm1, xmm5

  // Second 16 bytes (weights_lo)
  movdqu xmm4, oword ptr [ebx + 16]
  movdqa xmm5, xmm4
  psadbw xmm5, xmm3
  paddd xmm0, xmm5

  movdqa xmm5, xmm4
  punpcklbw xmm5, xmm3
  punpckhbw xmm4, xmm3
  movdqu xmm6, oword ptr [esp + $40]
  movdqu xmm7, oword ptr [esp + $50]
  pmaddwd xmm5, xmm6
  pmaddwd xmm4, xmm7
  paddd xmm5, xmm4
  paddd xmm1, xmm5

  add ebx, 32
  dec ecx
  jnz @adler32_sse2_loop

  pslld xmm2, 5
  paddd xmm1, xmm2

  pshufd xmm4, xmm0, $B1
  paddd xmm0, xmm4
  pshufd xmm4, xmm0, $4E
  paddd xmm0, xmm4
  movd edx, xmm0
  add eax, edx

  pshufd xmm4, xmm1, $B1
  paddd xmm1, xmm4
  pshufd xmm4, xmm1, $4E
  paddd xmm1, xmm4
  movd esi, xmm1

  mov dword ptr [edi], eax
  mov dword ptr [edi + 4], esi

  movdqu xmm6, oword ptr [esp]
  movdqu xmm7, oword ptr [esp + $10]
  add esp, 96
  add esp, 4                   // discard saved AConstants
  pop edi
  pop esi
  pop ebx
