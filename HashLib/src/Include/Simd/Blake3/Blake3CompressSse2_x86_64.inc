// SSE2 implementation of BLAKE3 compress (7 rounds with register-based message scheduling).
// Reference: BLAKE3-team/BLAKE3 official SSE2 implementation (blake3_sse2_x86-64_windows_msvc.asm).
// Expects MS x64 ABI: rcx = state ptr, rdx = msg ptr, r8 = CV ptr, r9 = counterflags ptr.
// Register map: xmm0 = a (v0-3), xmm1 = b (v4-7), xmm2 = c (v8-11), xmm3 = d (v12-15),
//   xmm4 = m0 (col G1 msg), xmm5 = m1 (col G2 msg), xmm6 = m2 (diag G1 msg),
//   xmm7 = m3 (diag G2 msg), xmm8/xmm9 = temp (msg perm), xmm11/xmm14 = temp (rotations).
// Rotations: rot16 via pshuflw+pshufhw; rot12/8/7 via pslld/psrld/por.
// Message scheduling: all 16 words kept in xmm4-7, permuted between rounds using
//   shufps/pshufd (blend_0xCC emulated via shufps+pshufd, blend_0xC0 via punpckhdq+shufps).
// Diagonalize/Undiagonalize via pshufd (row1 unrotated, per sneves optimization).

{$IFDEF MSWINDOWS}
  sub rsp, 120
  movdqa oword [rsp], xmm6
  movdqa oword [rsp + $10], xmm7
  movdqa oword [rsp + $20], xmm8
  movdqa oword [rsp + $30], xmm9
  movdqa oword [rsp + $40], xmm11
  movdqa oword [rsp + $50], xmm14

  mov eax, $6A09E667
  mov dword ptr [rsp + $60], eax
  mov eax, $BB67AE85
  mov dword ptr [rsp + $64], eax
  mov eax, $3C6EF372
  mov dword ptr [rsp + $68], eax
  mov eax, $A54FF53A
  mov dword ptr [rsp + $6C], eax
  movdqa xmm2, oword [rsp + $60]
{$ELSE}
  sub rsp, 24

  mov eax, $6A09E667
  mov dword ptr [rsp], eax
  mov eax, $BB67AE85
  mov dword ptr [rsp + $04], eax
  mov eax, $3C6EF372
  mov dword ptr [rsp + $08], eax
  mov eax, $A54FF53A
  mov dword ptr [rsp + $0C], eax
  movdqa xmm2, oword [rsp]
{$ENDIF}

  // Initialize state: a=CV[0..3], b=CV[4..7], c=IV[0..3], d=CounterFlags
  movdqu xmm0, oword [r8]
  movdqu xmm1, oword [r8 + $10]
  // xmm2 = IV (loaded above)
  movdqu xmm3, oword [r9]

  // Load and reorder message into 4 register pairs for round structure.
  // After reorder: xmm4={m0,m2,m4,m6}, xmm5={m1,m3,m5,m7},
  //   xmm6={m14,m8,m10,m12} (rotated), xmm7={m15,m9,m11,m13} (rotated).
  movdqu xmm4, oword [rdx]
  movdqu xmm5, oword [rdx + $10]
  movdqa xmm8, xmm4
  shufps xmm4, xmm5, $88
  shufps xmm8, xmm5, $DD
  movdqa xmm5, xmm8

  movdqu xmm6, oword [rdx + $20]
  movdqu xmm7, oword [rdx + $30]
  movdqa xmm8, xmm6
  shufps xmm6, xmm7, $88
  pshufd xmm6, xmm6, $93
  shufps xmm8, xmm7, $DD
  pshufd xmm7, xmm8, $93

  // ===== Round 0 =====

  // Column G1 (msg xmm4)
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 20
  psrld xmm11, 12
  por xmm1, xmm11

  // Column G2 (msg xmm5)
  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqa xmm14, xmm3
  psrld xmm3, 8
  pslld xmm14, 24
  pxor xmm3, xmm14
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 25
  psrld xmm11, 7
  por xmm1, xmm11

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
  movdqa xmm11, xmm1
  pslld xmm1, 20
  psrld xmm11, 12
  por xmm1, xmm11

  // Diagonal G2 (msg xmm7)
  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqa xmm14, xmm3
  psrld xmm3, 8
  pslld xmm14, 24
  pxor xmm3, xmm14
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 25
  psrld xmm11, 7
  por xmm1, xmm11

  // Undiagonalize
  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 0->1 =====
  movdqa xmm8, xmm4
  shufps xmm8, xmm5, $D6
  pshufd xmm9, xmm4, $0F
  pshufd xmm4, xmm8, $39
  movdqa xmm8, xmm6
  shufps xmm8, xmm7, $FA
  shufps xmm9, xmm8, $D8
  pshufd xmm9, xmm9, $D8
  movdqa xmm8, xmm7
  punpcklqdq xmm8, xmm5
  movdqa xmm14, xmm8
  punpckhdq xmm14, xmm6
  shufps xmm8, xmm14, $C4
  pshufd xmm8, xmm8, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm9
  movdqa xmm6, xmm8

  // ===== Round 1 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 20
  psrld xmm11, 12
  por xmm1, xmm11

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqa xmm14, xmm3
  psrld xmm3, 8
  pslld xmm14, 24
  pxor xmm3, xmm14
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 25
  psrld xmm11, 7
  por xmm1, xmm11

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
  movdqa xmm11, xmm1
  pslld xmm1, 20
  psrld xmm11, 12
  por xmm1, xmm11

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqa xmm14, xmm3
  psrld xmm3, 8
  pslld xmm14, 24
  pxor xmm3, xmm14
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 25
  psrld xmm11, 7
  por xmm1, xmm11

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 1->2 =====
  movdqa xmm8, xmm4
  shufps xmm8, xmm5, $D6
  pshufd xmm9, xmm4, $0F
  pshufd xmm4, xmm8, $39
  movdqa xmm8, xmm6
  shufps xmm8, xmm7, $FA
  shufps xmm9, xmm8, $D8
  pshufd xmm9, xmm9, $D8
  movdqa xmm8, xmm7
  punpcklqdq xmm8, xmm5
  movdqa xmm14, xmm8
  punpckhdq xmm14, xmm6
  shufps xmm8, xmm14, $C4
  pshufd xmm8, xmm8, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm9
  movdqa xmm6, xmm8

  // ===== Round 2 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 20
  psrld xmm11, 12
  por xmm1, xmm11

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqa xmm14, xmm3
  psrld xmm3, 8
  pslld xmm14, 24
  pxor xmm3, xmm14
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 25
  psrld xmm11, 7
  por xmm1, xmm11

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
  movdqa xmm11, xmm1
  pslld xmm1, 20
  psrld xmm11, 12
  por xmm1, xmm11

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqa xmm14, xmm3
  psrld xmm3, 8
  pslld xmm14, 24
  pxor xmm3, xmm14
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 25
  psrld xmm11, 7
  por xmm1, xmm11

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 2->3 =====
  movdqa xmm8, xmm4
  shufps xmm8, xmm5, $D6
  pshufd xmm9, xmm4, $0F
  pshufd xmm4, xmm8, $39
  movdqa xmm8, xmm6
  shufps xmm8, xmm7, $FA
  shufps xmm9, xmm8, $D8
  pshufd xmm9, xmm9, $D8
  movdqa xmm8, xmm7
  punpcklqdq xmm8, xmm5
  movdqa xmm14, xmm8
  punpckhdq xmm14, xmm6
  shufps xmm8, xmm14, $C4
  pshufd xmm8, xmm8, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm9
  movdqa xmm6, xmm8

  // ===== Round 3 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 20
  psrld xmm11, 12
  por xmm1, xmm11

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqa xmm14, xmm3
  psrld xmm3, 8
  pslld xmm14, 24
  pxor xmm3, xmm14
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 25
  psrld xmm11, 7
  por xmm1, xmm11

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
  movdqa xmm11, xmm1
  pslld xmm1, 20
  psrld xmm11, 12
  por xmm1, xmm11

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqa xmm14, xmm3
  psrld xmm3, 8
  pslld xmm14, 24
  pxor xmm3, xmm14
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 25
  psrld xmm11, 7
  por xmm1, xmm11

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 3->4 =====
  movdqa xmm8, xmm4
  shufps xmm8, xmm5, $D6
  pshufd xmm9, xmm4, $0F
  pshufd xmm4, xmm8, $39
  movdqa xmm8, xmm6
  shufps xmm8, xmm7, $FA
  shufps xmm9, xmm8, $D8
  pshufd xmm9, xmm9, $D8
  movdqa xmm8, xmm7
  punpcklqdq xmm8, xmm5
  movdqa xmm14, xmm8
  punpckhdq xmm14, xmm6
  shufps xmm8, xmm14, $C4
  pshufd xmm8, xmm8, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm9
  movdqa xmm6, xmm8

  // ===== Round 4 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 20
  psrld xmm11, 12
  por xmm1, xmm11

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqa xmm14, xmm3
  psrld xmm3, 8
  pslld xmm14, 24
  pxor xmm3, xmm14
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 25
  psrld xmm11, 7
  por xmm1, xmm11

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
  movdqa xmm11, xmm1
  pslld xmm1, 20
  psrld xmm11, 12
  por xmm1, xmm11

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqa xmm14, xmm3
  psrld xmm3, 8
  pslld xmm14, 24
  pxor xmm3, xmm14
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 25
  psrld xmm11, 7
  por xmm1, xmm11

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 4->5 =====
  movdqa xmm8, xmm4
  shufps xmm8, xmm5, $D6
  pshufd xmm9, xmm4, $0F
  pshufd xmm4, xmm8, $39
  movdqa xmm8, xmm6
  shufps xmm8, xmm7, $FA
  shufps xmm9, xmm8, $D8
  pshufd xmm9, xmm9, $D8
  movdqa xmm8, xmm7
  punpcklqdq xmm8, xmm5
  movdqa xmm14, xmm8
  punpckhdq xmm14, xmm6
  shufps xmm8, xmm14, $C4
  pshufd xmm8, xmm8, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm9
  movdqa xmm6, xmm8

  // ===== Round 5 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 20
  psrld xmm11, 12
  por xmm1, xmm11

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqa xmm14, xmm3
  psrld xmm3, 8
  pslld xmm14, 24
  pxor xmm3, xmm14
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 25
  psrld xmm11, 7
  por xmm1, xmm11

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
  movdqa xmm11, xmm1
  pslld xmm1, 20
  psrld xmm11, 12
  por xmm1, xmm11

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqa xmm14, xmm3
  psrld xmm3, 8
  pslld xmm14, 24
  pxor xmm3, xmm14
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 25
  psrld xmm11, 7
  por xmm1, xmm11

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 5->6 =====
  movdqa xmm8, xmm4
  shufps xmm8, xmm5, $D6
  pshufd xmm9, xmm4, $0F
  pshufd xmm4, xmm8, $39
  movdqa xmm8, xmm6
  shufps xmm8, xmm7, $FA
  shufps xmm9, xmm8, $D8
  pshufd xmm9, xmm9, $D8
  movdqa xmm8, xmm7
  punpcklqdq xmm8, xmm5
  movdqa xmm14, xmm8
  punpckhdq xmm14, xmm6
  shufps xmm8, xmm14, $C4
  pshufd xmm8, xmm8, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm9
  movdqa xmm6, xmm8

  // ===== Round 6 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 20
  psrld xmm11, 12
  por xmm1, xmm11

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqa xmm14, xmm3
  psrld xmm3, 8
  pslld xmm14, 24
  pxor xmm3, xmm14
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 25
  psrld xmm11, 7
  por xmm1, xmm11

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
  movdqa xmm11, xmm1
  pslld xmm1, 20
  psrld xmm11, 12
  por xmm1, xmm11

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqa xmm14, xmm3
  psrld xmm3, 8
  pslld xmm14, 24
  pxor xmm3, xmm14
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm11, xmm1
  pslld xmm1, 25
  psrld xmm11, 7
  por xmm1, xmm11

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Finalization =====
  // BLAKE3: state[0..7] = a,b XOR c,d; state[8..15] = c,d XOR CV
  pxor xmm0, xmm2
  pxor xmm1, xmm3
  movdqu xmm4, oword [r8]
  movdqu xmm5, oword [r8 + $10]
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  // Store all 16 words
  movdqu oword [rcx], xmm0
  movdqu oword [rcx + $10], xmm1
  movdqu oword [rcx + $20], xmm2
  movdqu oword [rcx + $30], xmm3

{$IFDEF MSWINDOWS}
  movdqa xmm6, oword [rsp]
  movdqa xmm7, oword [rsp + $10]
  movdqa xmm8, oword [rsp + $20]
  movdqa xmm9, oword [rsp + $30]
  movdqa xmm11, oword [rsp + $40]
  movdqa xmm14, oword [rsp + $50]
  add rsp, 120
{$ELSE}
  add rsp, 24
{$ENDIF}
