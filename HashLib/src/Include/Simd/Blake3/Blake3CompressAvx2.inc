// AVX2 implementation of BLAKE3 compress (VEX-encoded 128-bit, 7 rounds with register-based
// message scheduling).
// Reference: BLAKE3-team/BLAKE3 official SSE2/AVX2 implementation.
// Expects MS x64 ABI: rcx = state ptr, rdx = msg ptr, r8 = CV ptr, r9 = counterflags ptr.
// Register map: xmm0 = a, xmm1 = b, xmm2 = c, xmm3 = d,
//   xmm4 = m0, xmm5 = m1, xmm6 = m2, xmm7 = m3, xmm8/xmm9 = temp, xmm11/xmm14 = temp.
// 3-operand VEX form eliminates movdqa copies needed in SSE2 rotations.
// Blend emulations use vshufps+vpshufd (blend_0xCC) and vpunpckhdq+vshufps (blend_0xC0),
// avoiding the need for mask constants.

{$IFDEF MSWINDOWS}
  sub rsp, 120
  vmovdqa oword [rsp], xmm6
  vmovdqa oword [rsp + $10], xmm7
  vmovdqa oword [rsp + $20], xmm8
  vmovdqa oword [rsp + $30], xmm9
  vmovdqa oword [rsp + $40], xmm11
  vmovdqa oword [rsp + $50], xmm14

  mov eax, $6A09E667
  mov dword ptr [rsp + $60], eax
  mov eax, $BB67AE85
  mov dword ptr [rsp + $64], eax
  mov eax, $3C6EF372
  mov dword ptr [rsp + $68], eax
  mov eax, $A54FF53A
  mov dword ptr [rsp + $6C], eax
  vmovdqa xmm2, oword [rsp + $60]
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
  vmovdqa xmm2, oword [rsp]
{$ENDIF}

  // Initialize state
  vmovdqu xmm0, oword [r8]
  vmovdqu xmm1, oword [r8 + $10]
  vmovdqu xmm3, oword [r9]

  // Load and reorder message
  vmovdqu xmm4, oword [rdx]
  vmovdqu xmm5, oword [rdx + $10]
  vmovdqa xmm8, xmm4
  vshufps xmm4, xmm4, xmm5, $88
  vshufps xmm8, xmm8, xmm5, $DD
  vmovdqa xmm5, xmm8

  vmovdqu xmm6, oword [rdx + $20]
  vmovdqu xmm7, oword [rdx + $30]
  vmovdqa xmm8, xmm6
  vshufps xmm6, xmm6, xmm7, $88
  vpshufd xmm6, xmm6, $93
  vshufps xmm8, xmm8, xmm7, $DD
  vpshufd xmm7, xmm8, $93

  // ===== Round 0 =====

  vpaddd xmm0, xmm0, xmm4
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpshuflw xmm3, xmm3, $B1
  vpshufhw xmm3, xmm3, $B1
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 20
  vpsrld xmm1, xmm1, 12
  vpor xmm1, xmm1, xmm11

  vpaddd xmm0, xmm0, xmm5
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpsrld xmm14, xmm3, 8
  vpslld xmm3, xmm3, 24
  vpxor xmm3, xmm3, xmm14
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 25
  vpsrld xmm1, xmm1, 7
  vpor xmm1, xmm1, xmm11

  vpshufd xmm0, xmm0, $93
  vpshufd xmm3, xmm3, $4E
  vpshufd xmm2, xmm2, $39

  vpaddd xmm0, xmm0, xmm6
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpshuflw xmm3, xmm3, $B1
  vpshufhw xmm3, xmm3, $B1
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 20
  vpsrld xmm1, xmm1, 12
  vpor xmm1, xmm1, xmm11

  vpaddd xmm0, xmm0, xmm7
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpsrld xmm14, xmm3, 8
  vpslld xmm3, xmm3, 24
  vpxor xmm3, xmm3, xmm14
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 25
  vpsrld xmm1, xmm1, 7
  vpor xmm1, xmm1, xmm11

  vpshufd xmm0, xmm0, $39
  vpshufd xmm3, xmm3, $4E
  vpshufd xmm2, xmm2, $93

  // ===== Message Permutation 0->1 =====
  vmovdqa xmm8, xmm4
  vshufps xmm8, xmm8, xmm5, $D6
  vpshufd xmm9, xmm4, $0F
  vpshufd xmm4, xmm8, $39
  vmovdqa xmm8, xmm6
  vshufps xmm8, xmm8, xmm7, $FA
  vshufps xmm9, xmm9, xmm8, $D8
  vpshufd xmm9, xmm9, $D8
  vmovdqa xmm8, xmm7
  vpunpcklqdq xmm8, xmm8, xmm5
  vmovdqa xmm14, xmm8
  vpunpckhdq xmm14, xmm14, xmm6
  vshufps xmm8, xmm8, xmm14, $C4
  vpshufd xmm8, xmm8, $78
  vpunpckhdq xmm5, xmm5, xmm7
  vpunpckldq xmm6, xmm6, xmm5
  vpshufd xmm7, xmm6, $1E
  vmovdqa xmm5, xmm9
  vmovdqa xmm6, xmm8

  // ===== Round 1 =====

  vpaddd xmm0, xmm0, xmm4
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpshuflw xmm3, xmm3, $B1
  vpshufhw xmm3, xmm3, $B1
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 20
  vpsrld xmm1, xmm1, 12
  vpor xmm1, xmm1, xmm11

  vpaddd xmm0, xmm0, xmm5
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpsrld xmm14, xmm3, 8
  vpslld xmm3, xmm3, 24
  vpxor xmm3, xmm3, xmm14
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 25
  vpsrld xmm1, xmm1, 7
  vpor xmm1, xmm1, xmm11

  vpshufd xmm0, xmm0, $93
  vpshufd xmm3, xmm3, $4E
  vpshufd xmm2, xmm2, $39

  vpaddd xmm0, xmm0, xmm6
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpshuflw xmm3, xmm3, $B1
  vpshufhw xmm3, xmm3, $B1
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 20
  vpsrld xmm1, xmm1, 12
  vpor xmm1, xmm1, xmm11

  vpaddd xmm0, xmm0, xmm7
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpsrld xmm14, xmm3, 8
  vpslld xmm3, xmm3, 24
  vpxor xmm3, xmm3, xmm14
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 25
  vpsrld xmm1, xmm1, 7
  vpor xmm1, xmm1, xmm11

  vpshufd xmm0, xmm0, $39
  vpshufd xmm3, xmm3, $4E
  vpshufd xmm2, xmm2, $93

  // ===== Message Permutation 1->2 =====
  vmovdqa xmm8, xmm4
  vshufps xmm8, xmm8, xmm5, $D6
  vpshufd xmm9, xmm4, $0F
  vpshufd xmm4, xmm8, $39
  vmovdqa xmm8, xmm6
  vshufps xmm8, xmm8, xmm7, $FA
  vshufps xmm9, xmm9, xmm8, $D8
  vpshufd xmm9, xmm9, $D8
  vmovdqa xmm8, xmm7
  vpunpcklqdq xmm8, xmm8, xmm5
  vmovdqa xmm14, xmm8
  vpunpckhdq xmm14, xmm14, xmm6
  vshufps xmm8, xmm8, xmm14, $C4
  vpshufd xmm8, xmm8, $78
  vpunpckhdq xmm5, xmm5, xmm7
  vpunpckldq xmm6, xmm6, xmm5
  vpshufd xmm7, xmm6, $1E
  vmovdqa xmm5, xmm9
  vmovdqa xmm6, xmm8

  // ===== Round 2 =====

  vpaddd xmm0, xmm0, xmm4
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpshuflw xmm3, xmm3, $B1
  vpshufhw xmm3, xmm3, $B1
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 20
  vpsrld xmm1, xmm1, 12
  vpor xmm1, xmm1, xmm11

  vpaddd xmm0, xmm0, xmm5
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpsrld xmm14, xmm3, 8
  vpslld xmm3, xmm3, 24
  vpxor xmm3, xmm3, xmm14
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 25
  vpsrld xmm1, xmm1, 7
  vpor xmm1, xmm1, xmm11

  vpshufd xmm0, xmm0, $93
  vpshufd xmm3, xmm3, $4E
  vpshufd xmm2, xmm2, $39

  vpaddd xmm0, xmm0, xmm6
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpshuflw xmm3, xmm3, $B1
  vpshufhw xmm3, xmm3, $B1
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 20
  vpsrld xmm1, xmm1, 12
  vpor xmm1, xmm1, xmm11

  vpaddd xmm0, xmm0, xmm7
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpsrld xmm14, xmm3, 8
  vpslld xmm3, xmm3, 24
  vpxor xmm3, xmm3, xmm14
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 25
  vpsrld xmm1, xmm1, 7
  vpor xmm1, xmm1, xmm11

  vpshufd xmm0, xmm0, $39
  vpshufd xmm3, xmm3, $4E
  vpshufd xmm2, xmm2, $93

  // ===== Message Permutation 2->3 =====
  vmovdqa xmm8, xmm4
  vshufps xmm8, xmm8, xmm5, $D6
  vpshufd xmm9, xmm4, $0F
  vpshufd xmm4, xmm8, $39
  vmovdqa xmm8, xmm6
  vshufps xmm8, xmm8, xmm7, $FA
  vshufps xmm9, xmm9, xmm8, $D8
  vpshufd xmm9, xmm9, $D8
  vmovdqa xmm8, xmm7
  vpunpcklqdq xmm8, xmm8, xmm5
  vmovdqa xmm14, xmm8
  vpunpckhdq xmm14, xmm14, xmm6
  vshufps xmm8, xmm8, xmm14, $C4
  vpshufd xmm8, xmm8, $78
  vpunpckhdq xmm5, xmm5, xmm7
  vpunpckldq xmm6, xmm6, xmm5
  vpshufd xmm7, xmm6, $1E
  vmovdqa xmm5, xmm9
  vmovdqa xmm6, xmm8

  // ===== Round 3 =====

  vpaddd xmm0, xmm0, xmm4
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpshuflw xmm3, xmm3, $B1
  vpshufhw xmm3, xmm3, $B1
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 20
  vpsrld xmm1, xmm1, 12
  vpor xmm1, xmm1, xmm11

  vpaddd xmm0, xmm0, xmm5
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpsrld xmm14, xmm3, 8
  vpslld xmm3, xmm3, 24
  vpxor xmm3, xmm3, xmm14
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 25
  vpsrld xmm1, xmm1, 7
  vpor xmm1, xmm1, xmm11

  vpshufd xmm0, xmm0, $93
  vpshufd xmm3, xmm3, $4E
  vpshufd xmm2, xmm2, $39

  vpaddd xmm0, xmm0, xmm6
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpshuflw xmm3, xmm3, $B1
  vpshufhw xmm3, xmm3, $B1
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 20
  vpsrld xmm1, xmm1, 12
  vpor xmm1, xmm1, xmm11

  vpaddd xmm0, xmm0, xmm7
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpsrld xmm14, xmm3, 8
  vpslld xmm3, xmm3, 24
  vpxor xmm3, xmm3, xmm14
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 25
  vpsrld xmm1, xmm1, 7
  vpor xmm1, xmm1, xmm11

  vpshufd xmm0, xmm0, $39
  vpshufd xmm3, xmm3, $4E
  vpshufd xmm2, xmm2, $93

  // ===== Message Permutation 3->4 =====
  vmovdqa xmm8, xmm4
  vshufps xmm8, xmm8, xmm5, $D6
  vpshufd xmm9, xmm4, $0F
  vpshufd xmm4, xmm8, $39
  vmovdqa xmm8, xmm6
  vshufps xmm8, xmm8, xmm7, $FA
  vshufps xmm9, xmm9, xmm8, $D8
  vpshufd xmm9, xmm9, $D8
  vmovdqa xmm8, xmm7
  vpunpcklqdq xmm8, xmm8, xmm5
  vmovdqa xmm14, xmm8
  vpunpckhdq xmm14, xmm14, xmm6
  vshufps xmm8, xmm8, xmm14, $C4
  vpshufd xmm8, xmm8, $78
  vpunpckhdq xmm5, xmm5, xmm7
  vpunpckldq xmm6, xmm6, xmm5
  vpshufd xmm7, xmm6, $1E
  vmovdqa xmm5, xmm9
  vmovdqa xmm6, xmm8

  // ===== Round 4 =====

  vpaddd xmm0, xmm0, xmm4
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpshuflw xmm3, xmm3, $B1
  vpshufhw xmm3, xmm3, $B1
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 20
  vpsrld xmm1, xmm1, 12
  vpor xmm1, xmm1, xmm11

  vpaddd xmm0, xmm0, xmm5
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpsrld xmm14, xmm3, 8
  vpslld xmm3, xmm3, 24
  vpxor xmm3, xmm3, xmm14
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 25
  vpsrld xmm1, xmm1, 7
  vpor xmm1, xmm1, xmm11

  vpshufd xmm0, xmm0, $93
  vpshufd xmm3, xmm3, $4E
  vpshufd xmm2, xmm2, $39

  vpaddd xmm0, xmm0, xmm6
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpshuflw xmm3, xmm3, $B1
  vpshufhw xmm3, xmm3, $B1
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 20
  vpsrld xmm1, xmm1, 12
  vpor xmm1, xmm1, xmm11

  vpaddd xmm0, xmm0, xmm7
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpsrld xmm14, xmm3, 8
  vpslld xmm3, xmm3, 24
  vpxor xmm3, xmm3, xmm14
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 25
  vpsrld xmm1, xmm1, 7
  vpor xmm1, xmm1, xmm11

  vpshufd xmm0, xmm0, $39
  vpshufd xmm3, xmm3, $4E
  vpshufd xmm2, xmm2, $93

  // ===== Message Permutation 4->5 =====
  vmovdqa xmm8, xmm4
  vshufps xmm8, xmm8, xmm5, $D6
  vpshufd xmm9, xmm4, $0F
  vpshufd xmm4, xmm8, $39
  vmovdqa xmm8, xmm6
  vshufps xmm8, xmm8, xmm7, $FA
  vshufps xmm9, xmm9, xmm8, $D8
  vpshufd xmm9, xmm9, $D8
  vmovdqa xmm8, xmm7
  vpunpcklqdq xmm8, xmm8, xmm5
  vmovdqa xmm14, xmm8
  vpunpckhdq xmm14, xmm14, xmm6
  vshufps xmm8, xmm8, xmm14, $C4
  vpshufd xmm8, xmm8, $78
  vpunpckhdq xmm5, xmm5, xmm7
  vpunpckldq xmm6, xmm6, xmm5
  vpshufd xmm7, xmm6, $1E
  vmovdqa xmm5, xmm9
  vmovdqa xmm6, xmm8

  // ===== Round 5 =====

  vpaddd xmm0, xmm0, xmm4
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpshuflw xmm3, xmm3, $B1
  vpshufhw xmm3, xmm3, $B1
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 20
  vpsrld xmm1, xmm1, 12
  vpor xmm1, xmm1, xmm11

  vpaddd xmm0, xmm0, xmm5
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpsrld xmm14, xmm3, 8
  vpslld xmm3, xmm3, 24
  vpxor xmm3, xmm3, xmm14
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 25
  vpsrld xmm1, xmm1, 7
  vpor xmm1, xmm1, xmm11

  vpshufd xmm0, xmm0, $93
  vpshufd xmm3, xmm3, $4E
  vpshufd xmm2, xmm2, $39

  vpaddd xmm0, xmm0, xmm6
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpshuflw xmm3, xmm3, $B1
  vpshufhw xmm3, xmm3, $B1
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 20
  vpsrld xmm1, xmm1, 12
  vpor xmm1, xmm1, xmm11

  vpaddd xmm0, xmm0, xmm7
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpsrld xmm14, xmm3, 8
  vpslld xmm3, xmm3, 24
  vpxor xmm3, xmm3, xmm14
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 25
  vpsrld xmm1, xmm1, 7
  vpor xmm1, xmm1, xmm11

  vpshufd xmm0, xmm0, $39
  vpshufd xmm3, xmm3, $4E
  vpshufd xmm2, xmm2, $93

  // ===== Message Permutation 5->6 =====
  vmovdqa xmm8, xmm4
  vshufps xmm8, xmm8, xmm5, $D6
  vpshufd xmm9, xmm4, $0F
  vpshufd xmm4, xmm8, $39
  vmovdqa xmm8, xmm6
  vshufps xmm8, xmm8, xmm7, $FA
  vshufps xmm9, xmm9, xmm8, $D8
  vpshufd xmm9, xmm9, $D8
  vmovdqa xmm8, xmm7
  vpunpcklqdq xmm8, xmm8, xmm5
  vmovdqa xmm14, xmm8
  vpunpckhdq xmm14, xmm14, xmm6
  vshufps xmm8, xmm8, xmm14, $C4
  vpshufd xmm8, xmm8, $78
  vpunpckhdq xmm5, xmm5, xmm7
  vpunpckldq xmm6, xmm6, xmm5
  vpshufd xmm7, xmm6, $1E
  vmovdqa xmm5, xmm9
  vmovdqa xmm6, xmm8

  // ===== Round 6 =====

  vpaddd xmm0, xmm0, xmm4
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpshuflw xmm3, xmm3, $B1
  vpshufhw xmm3, xmm3, $B1
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 20
  vpsrld xmm1, xmm1, 12
  vpor xmm1, xmm1, xmm11

  vpaddd xmm0, xmm0, xmm5
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpsrld xmm14, xmm3, 8
  vpslld xmm3, xmm3, 24
  vpxor xmm3, xmm3, xmm14
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 25
  vpsrld xmm1, xmm1, 7
  vpor xmm1, xmm1, xmm11

  vpshufd xmm0, xmm0, $93
  vpshufd xmm3, xmm3, $4E
  vpshufd xmm2, xmm2, $39

  vpaddd xmm0, xmm0, xmm6
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpshuflw xmm3, xmm3, $B1
  vpshufhw xmm3, xmm3, $B1
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 20
  vpsrld xmm1, xmm1, 12
  vpor xmm1, xmm1, xmm11

  vpaddd xmm0, xmm0, xmm7
  vpaddd xmm0, xmm0, xmm1
  vpxor xmm3, xmm3, xmm0
  vpsrld xmm14, xmm3, 8
  vpslld xmm3, xmm3, 24
  vpxor xmm3, xmm3, xmm14
  vpaddd xmm2, xmm2, xmm3
  vpxor xmm1, xmm1, xmm2
  vpslld xmm11, xmm1, 25
  vpsrld xmm1, xmm1, 7
  vpor xmm1, xmm1, xmm11

  vpshufd xmm0, xmm0, $39
  vpshufd xmm3, xmm3, $4E
  vpshufd xmm2, xmm2, $93

  // ===== Finalization =====
  vpxor xmm0, xmm0, xmm2
  vpxor xmm1, xmm1, xmm3
  vmovdqu xmm4, oword [r8]
  vmovdqu xmm5, oword [r8 + $10]
  vpxor xmm2, xmm2, xmm4
  vpxor xmm3, xmm3, xmm5

  vmovdqu oword [rcx], xmm0
  vmovdqu oword [rcx + $10], xmm1
  vmovdqu oword [rcx + $20], xmm2
  vmovdqu oword [rcx + $30], xmm3

{$IFDEF MSWINDOWS}
  vmovdqa xmm6, oword [rsp]
  vmovdqa xmm7, oword [rsp + $10]
  vmovdqa xmm8, oword [rsp + $20]
  vmovdqa xmm9, oword [rsp + $30]
  vmovdqa xmm11, oword [rsp + $40]
  vmovdqa xmm14, oword [rsp + $50]
  add rsp, 120
{$ELSE}
  add rsp, 24
{$ENDIF}
