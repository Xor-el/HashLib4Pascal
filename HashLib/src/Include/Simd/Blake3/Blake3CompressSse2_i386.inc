// SSE2 implementation of BLAKE3 compress (7 rounds with register-based message scheduling).
// Reference: BLAKE3-team/BLAKE3 official SSE2 implementation (blake3_sse2_x86-64_windows_msvc.asm).
// IA-32: after SimdProc4Begin_i386 — ebx = state, esi = msg, edi = CV, eax = counterflags ptr
//   (parallel to MS x64 ABI: rcx, rdx, r8, r9).
// Register map: xmm0 = a (v0-3), xmm1 = b (v4-7), xmm2 = c (v8-11), xmm3 = d (v12-15);
//   IA-32 uses xmm0–7 only — high-XMM temps from x64 are folded into xmm0/1/2 + stack spill;
//   rotations use xmm0 + [esp+$20].
// Rotations: rot16 via pshuflw+pshufhw; rot12/8/7 via pslld/psrld/por.
// Message scheduling / diagonalize: same strategy as x64 (blend emulation, pshufd), per sneves.

  sub esp, 120
  movdqu oword ptr [esp], xmm6
  movdqu oword ptr [esp + $10], xmm7
  mov dword ptr [esp + $30], eax

  mov eax, $6A09E667
  mov dword ptr [esp + $60], eax
  mov eax, $BB67AE85
  mov dword ptr [esp + $64], eax
  mov eax, $3C6EF372
  mov dword ptr [esp + $68], eax
  mov eax, $A54FF53A
  mov dword ptr [esp + $6C], eax
  movdqu xmm2, oword ptr [esp + $60]

  // Initialize state: a=CV[0..3], b=CV[4..7], c=IV[0..3], d=CounterFlags
  movdqu xmm0, oword ptr [edi]
  movdqu xmm1, oword ptr [edi + $10]
  // xmm2 = IV (loaded above); eax clobbered by IV stores — reload counterflags
  mov eax, dword ptr [esp + $30]
  movdqu xmm3, oword ptr [eax]

  // Load and reorder message into 4 register pairs for round structure.
  // After reorder: xmm4={m0,m2,m4,m6}, xmm5={m1,m3,m5,m7},
  //   xmm6={m14,m8,m10,m12} (rotated), xmm7={m15,m9,m11,m13} (rotated).
  movdqu oword ptr [esp + $20], xmm0
  movdqu xmm4, oword ptr [esi]
  movdqu xmm5, oword ptr [esi + $10]
  movdqa xmm0, xmm4
  shufps xmm4, xmm5, $88
  shufps xmm0, xmm5, $DD
  movdqa xmm5, xmm0

  movdqu xmm6, oword ptr [esi + $20]
  movdqu xmm7, oword ptr [esi + $30]
  movdqa xmm0, xmm6
  shufps xmm6, xmm7, $88
  pshufd xmm6, xmm6, $93
  shufps xmm0, xmm7, $DD
  pshufd xmm7, xmm0, $93
  movdqu xmm0, oword ptr [esp + $20]

  // ===== Round 0 =====

  // Column G1 (msg xmm4)
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  // Column G2 (msg xmm5)
  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  // Diagonalize
  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  // Diagonal G1 (msg xmm6)
  paddd xmm0, xmm6
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  // Diagonal G2 (msg xmm7)
  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  // Undiagonalize
  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 0->1 =====
  movdqu oword ptr [esp + $20], xmm0
  movdqu oword ptr [esp + $30], xmm1
  movdqu oword ptr [esp + $40], xmm2
  movdqa xmm0, xmm4
  shufps xmm0, xmm5, $D6
  pshufd xmm1, xmm4, $0F
  pshufd xmm4, xmm0, $39
  movdqa xmm0, xmm6
  shufps xmm0, xmm7, $FA
  shufps xmm1, xmm0, $D8
  pshufd xmm1, xmm1, $D8
  movdqa xmm0, xmm7
  punpcklqdq xmm0, xmm5
  movdqa xmm2, xmm0
  punpckhdq xmm2, xmm6
  shufps xmm0, xmm2, $C4
  pshufd xmm0, xmm0, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm1
  movdqa xmm6, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  movdqu xmm1, oword ptr [esp + $30]
  movdqu xmm2, oword ptr [esp + $40]

  // ===== Round 1 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  paddd xmm0, xmm6
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 1->2 =====
  movdqu oword ptr [esp + $20], xmm0
  movdqu oword ptr [esp + $30], xmm1
  movdqu oword ptr [esp + $40], xmm2
  movdqa xmm0, xmm4
  shufps xmm0, xmm5, $D6
  pshufd xmm1, xmm4, $0F
  pshufd xmm4, xmm0, $39
  movdqa xmm0, xmm6
  shufps xmm0, xmm7, $FA
  shufps xmm1, xmm0, $D8
  pshufd xmm1, xmm1, $D8
  movdqa xmm0, xmm7
  punpcklqdq xmm0, xmm5
  movdqa xmm2, xmm0
  punpckhdq xmm2, xmm6
  shufps xmm0, xmm2, $C4
  pshufd xmm0, xmm0, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm1
  movdqa xmm6, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  movdqu xmm1, oword ptr [esp + $30]
  movdqu xmm2, oword ptr [esp + $40]

  // ===== Round 2 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  paddd xmm0, xmm6
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 2->3 =====
  movdqu oword ptr [esp + $20], xmm0
  movdqu oword ptr [esp + $30], xmm1
  movdqu oword ptr [esp + $40], xmm2
  movdqa xmm0, xmm4
  shufps xmm0, xmm5, $D6
  pshufd xmm1, xmm4, $0F
  pshufd xmm4, xmm0, $39
  movdqa xmm0, xmm6
  shufps xmm0, xmm7, $FA
  shufps xmm1, xmm0, $D8
  pshufd xmm1, xmm1, $D8
  movdqa xmm0, xmm7
  punpcklqdq xmm0, xmm5
  movdqa xmm2, xmm0
  punpckhdq xmm2, xmm6
  shufps xmm0, xmm2, $C4
  pshufd xmm0, xmm0, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm1
  movdqa xmm6, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  movdqu xmm1, oword ptr [esp + $30]
  movdqu xmm2, oword ptr [esp + $40]

  // ===== Round 3 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  paddd xmm0, xmm6
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 3->4 =====
  movdqu oword ptr [esp + $20], xmm0
  movdqu oword ptr [esp + $30], xmm1
  movdqu oword ptr [esp + $40], xmm2
  movdqa xmm0, xmm4
  shufps xmm0, xmm5, $D6
  pshufd xmm1, xmm4, $0F
  pshufd xmm4, xmm0, $39
  movdqa xmm0, xmm6
  shufps xmm0, xmm7, $FA
  shufps xmm1, xmm0, $D8
  pshufd xmm1, xmm1, $D8
  movdqa xmm0, xmm7
  punpcklqdq xmm0, xmm5
  movdqa xmm2, xmm0
  punpckhdq xmm2, xmm6
  shufps xmm0, xmm2, $C4
  pshufd xmm0, xmm0, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm1
  movdqa xmm6, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  movdqu xmm1, oword ptr [esp + $30]
  movdqu xmm2, oword ptr [esp + $40]

  // ===== Round 4 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  paddd xmm0, xmm6
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 4->5 =====
  movdqu oword ptr [esp + $20], xmm0
  movdqu oword ptr [esp + $30], xmm1
  movdqu oword ptr [esp + $40], xmm2
  movdqa xmm0, xmm4
  shufps xmm0, xmm5, $D6
  pshufd xmm1, xmm4, $0F
  pshufd xmm4, xmm0, $39
  movdqa xmm0, xmm6
  shufps xmm0, xmm7, $FA
  shufps xmm1, xmm0, $D8
  pshufd xmm1, xmm1, $D8
  movdqa xmm0, xmm7
  punpcklqdq xmm0, xmm5
  movdqa xmm2, xmm0
  punpckhdq xmm2, xmm6
  shufps xmm0, xmm2, $C4
  pshufd xmm0, xmm0, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm1
  movdqa xmm6, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  movdqu xmm1, oword ptr [esp + $30]
  movdqu xmm2, oword ptr [esp + $40]

  // ===== Round 5 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  paddd xmm0, xmm6
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 5->6 =====
  movdqu oword ptr [esp + $20], xmm0
  movdqu oword ptr [esp + $30], xmm1
  movdqu oword ptr [esp + $40], xmm2
  movdqa xmm0, xmm4
  shufps xmm0, xmm5, $D6
  pshufd xmm1, xmm4, $0F
  pshufd xmm4, xmm0, $39
  movdqa xmm0, xmm6
  shufps xmm0, xmm7, $FA
  shufps xmm1, xmm0, $D8
  pshufd xmm1, xmm1, $D8
  movdqa xmm0, xmm7
  punpcklqdq xmm0, xmm5
  movdqa xmm2, xmm0
  punpckhdq xmm2, xmm6
  shufps xmm0, xmm2, $C4
  pshufd xmm0, xmm0, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm1
  movdqa xmm6, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  movdqu xmm1, oword ptr [esp + $30]
  movdqu xmm2, oword ptr [esp + $40]

  // ===== Round 6 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  paddd xmm0, xmm6
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Finalization =====
  // BLAKE3: state[0..7] = a,b XOR c,d; state[8..15] = c,d XOR CV
  pxor xmm0, xmm2
  pxor xmm1, xmm3
  movdqu xmm4, oword ptr [edi]
  movdqu xmm5, oword ptr [edi + $10]
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  // Store all 16 words
  movdqu oword ptr [ebx], xmm0
  movdqu oword ptr [ebx + $10], xmm1
  movdqu oword ptr [ebx + $20], xmm2
  movdqu oword ptr [ebx + $30], xmm3

  movdqu xmm6, oword ptr [esp]
  movdqu xmm7, oword ptr [esp + $10]
  add esp, 120
  pop edi
  pop esi
  pop ebx
