// SSE2 implementation of BLAKE3 hash4: processes 4 independent chunks simultaneously.
// Reference: BLAKE3-team/BLAKE3 official SSE2 implementation (blake3_sse2.c / blake3_hash_many).
// Each XMM register holds the same 32-bit word from 4 different chunks (inter-chunk SIMD).
// 7 rounds per block fully unrolled; 16-block loop with branch for chunk start/end flags.
//
// After SimdProc6Begin.inc:
//   rcx = AInput, rdx = AKey, r8 = AOut,
//   r9 = ANumChunks, r10 = ACounter, r11 = AFlags
//
// Register map: xmm0-xmm7 = state v0-v7, xmm8-xmm11 = state v8-v11,
//   xmm12-xmm13 = temp, v12-v15 spilled to stack.
// GPR: rcx = input pointer, rbx = block counter (0..15), rbp = block byte offset.
// Message transpose: 4x4 via punpckldq/punpckhdq + punpcklqdq/punpckhqdq (pure SSE2).
// Rotations: rot16 via pshuflw+pshufhw; rot12/8/7 via pslld/psrld/por.

  push rbx
  push rbp

{$IFDEF MSWINDOWS}
  sub rsp, 712
  movdqa oword [rsp + 576], xmm6
  movdqa oword [rsp + 592], xmm7
  movdqa oword [rsp + 608], xmm8
  movdqa oword [rsp + 624], xmm9
  movdqa oword [rsp + 640], xmm10
  movdqa oword [rsp + 656], xmm11
  movdqa oword [rsp + 672], xmm12
  movdqa oword [rsp + 688], xmm13
{$ELSE}
  sub rsp, 584
{$ENDIF}

  mov qword ptr [rsp + 560], r8
  mov dword ptr [rsp + 568], r11d

  // Broadcast key words to CV registers
  movd xmm0, dword ptr [rdx + 0]
  pshufd xmm0, xmm0, 0
  movd xmm1, dword ptr [rdx + 4]
  pshufd xmm1, xmm1, 0
  movd xmm2, dword ptr [rdx + 8]
  pshufd xmm2, xmm2, 0
  movd xmm3, dword ptr [rdx + 12]
  pshufd xmm3, xmm3, 0
  movd xmm4, dword ptr [rdx + 16]
  pshufd xmm4, xmm4, 0
  movd xmm5, dword ptr [rdx + 20]
  pshufd xmm5, xmm5, 0
  movd xmm6, dword ptr [rdx + 24]
  pshufd xmm6, xmm6, 0
  movd xmm7, dword ptr [rdx + 28]
  pshufd xmm7, xmm7, 0

  // Save initial CV to stack
  movdqa oword [rsp + 320], xmm0
  movdqa oword [rsp + 336], xmm1
  movdqa oword [rsp + 352], xmm2
  movdqa oword [rsp + 368], xmm3
  movdqa oword [rsp + 384], xmm4
  movdqa oword [rsp + 400], xmm5
  movdqa oword [rsp + 416], xmm6
  movdqa oword [rsp + 432], xmm7

  // Build counter vectors (r10 = ACounter, 64-bit)
  mov rax, r10
  mov dword ptr [rsp + 448], eax
  shr rax, 32
  mov dword ptr [rsp + 464], eax
  lea rax, [r10 + 1]
  mov dword ptr [rsp + 452], eax
  shr rax, 32
  mov dword ptr [rsp + 468], eax
  lea rax, [r10 + 2]
  mov dword ptr [rsp + 456], eax
  shr rax, 32
  mov dword ptr [rsp + 472], eax
  lea rax, [r10 + 3]
  mov dword ptr [rsp + 460], eax
  shr rax, 32
  mov dword ptr [rsp + 476], eax

  // Pre-compute IV broadcast vectors
  mov eax, $6A09E667
  movd xmm12, eax
  pshufd xmm12, xmm12, 0
  movdqa oword [rsp + 480], xmm12
  mov eax, $BB67AE85
  movd xmm12, eax
  pshufd xmm12, xmm12, 0
  movdqa oword [rsp + 496], xmm12
  mov eax, $3C6EF372
  movd xmm12, eax
  pshufd xmm12, xmm12, 0
  movdqa oword [rsp + 512], xmm12
  mov eax, $A54FF53A
  movd xmm12, eax
  pshufd xmm12, xmm12, 0
  movdqa oword [rsp + 528], xmm12

  mov eax, 64
  movd xmm12, eax
  pshufd xmm12, xmm12, 0
  movdqa oword [rsp + 544], xmm12

  xor ebx, ebx
  xor ebp, ebp

@block_loop:

  // Transpose message for current block from 4 chunks
  // Words 0..3
  movdqu xmm0, oword [rcx + rbp + 0]
  movdqu xmm1, oword [rcx + rbp + 1024]
  movdqu xmm2, oword [rcx + rbp + 2048]
  movdqu xmm3, oword [rcx + rbp + 3072]
  movdqa xmm4, xmm0
  punpckldq xmm0, xmm1
  punpckhdq xmm4, xmm1
  movdqa xmm5, xmm2
  punpckldq xmm2, xmm3
  punpckhdq xmm5, xmm3
  movdqa xmm1, xmm0
  punpcklqdq xmm0, xmm2
  punpckhqdq xmm1, xmm2
  movdqa xmm3, xmm4
  punpcklqdq xmm4, xmm5
  punpckhqdq xmm3, xmm5
  movdqa oword [rsp + 0], xmm0
  movdqa oword [rsp + 16], xmm1
  movdqa oword [rsp + 32], xmm4
  movdqa oword [rsp + 48], xmm3

  // Words 4..7
  movdqu xmm0, oword [rcx + rbp + 16]
  movdqu xmm1, oword [rcx + rbp + 1040]
  movdqu xmm2, oword [rcx + rbp + 2064]
  movdqu xmm3, oword [rcx + rbp + 3088]
  movdqa xmm4, xmm0
  punpckldq xmm0, xmm1
  punpckhdq xmm4, xmm1
  movdqa xmm5, xmm2
  punpckldq xmm2, xmm3
  punpckhdq xmm5, xmm3
  movdqa xmm1, xmm0
  punpcklqdq xmm0, xmm2
  punpckhqdq xmm1, xmm2
  movdqa xmm3, xmm4
  punpcklqdq xmm4, xmm5
  punpckhqdq xmm3, xmm5
  movdqa oword [rsp + 64], xmm0
  movdqa oword [rsp + 80], xmm1
  movdqa oword [rsp + 96], xmm4
  movdqa oword [rsp + 112], xmm3

  // Words 8..11
  movdqu xmm0, oword [rcx + rbp + 32]
  movdqu xmm1, oword [rcx + rbp + 1056]
  movdqu xmm2, oword [rcx + rbp + 2080]
  movdqu xmm3, oword [rcx + rbp + 3104]
  movdqa xmm4, xmm0
  punpckldq xmm0, xmm1
  punpckhdq xmm4, xmm1
  movdqa xmm5, xmm2
  punpckldq xmm2, xmm3
  punpckhdq xmm5, xmm3
  movdqa xmm1, xmm0
  punpcklqdq xmm0, xmm2
  punpckhqdq xmm1, xmm2
  movdqa xmm3, xmm4
  punpcklqdq xmm4, xmm5
  punpckhqdq xmm3, xmm5
  movdqa oword [rsp + 128], xmm0
  movdqa oword [rsp + 144], xmm1
  movdqa oword [rsp + 160], xmm4
  movdqa oword [rsp + 176], xmm3

  // Words 12..15
  movdqu xmm0, oword [rcx + rbp + 48]
  movdqu xmm1, oword [rcx + rbp + 1072]
  movdqu xmm2, oword [rcx + rbp + 2096]
  movdqu xmm3, oword [rcx + rbp + 3120]
  movdqa xmm4, xmm0
  punpckldq xmm0, xmm1
  punpckhdq xmm4, xmm1
  movdqa xmm5, xmm2
  punpckldq xmm2, xmm3
  punpckhdq xmm5, xmm3
  movdqa xmm1, xmm0
  punpcklqdq xmm0, xmm2
  punpckhqdq xmm1, xmm2
  movdqa xmm3, xmm4
  punpcklqdq xmm4, xmm5
  punpckhqdq xmm3, xmm5
  movdqa oword [rsp + 192], xmm0
  movdqa oword [rsp + 208], xmm1
  movdqa oword [rsp + 224], xmm4
  movdqa oword [rsp + 240], xmm3

  // Initialize state: v0-v7 from CV, v8-v11 from IV
  movdqa xmm0, oword [rsp + 320]
  movdqa xmm1, oword [rsp + 336]
  movdqa xmm2, oword [rsp + 352]
  movdqa xmm3, oword [rsp + 368]
  movdqa xmm4, oword [rsp + 384]
  movdqa xmm5, oword [rsp + 400]
  movdqa xmm6, oword [rsp + 416]
  movdqa xmm7, oword [rsp + 432]
  movdqa xmm8, oword [rsp + 480]
  movdqa xmm9, oword [rsp + 496]
  movdqa xmm10, oword [rsp + 512]
  movdqa xmm11, oword [rsp + 528]

  // v12-v15: counter, block length, flags
  movdqa xmm12, oword [rsp + 448]
  movdqa oword [rsp + 256], xmm12
  movdqa xmm12, oword [rsp + 464]
  movdqa oword [rsp + 272], xmm12
  movdqa xmm12, oword [rsp + 544]
  movdqa oword [rsp + 288], xmm12

  // Compute per-block flags and broadcast
  mov eax, dword ptr [rsp + 568]
  cmp ebx, 0
  jne @h4_not_first
  or eax, 1
@h4_not_first:
  cmp ebx, 15
  jne @h4_not_last
  or eax, 2
@h4_not_last:
  movd xmm12, eax
  pshufd xmm12, xmm12, 0
  movdqa oword [rsp + 304], xmm12

  // === Round 0 ===
  // G col (0,4,8,12) m[0],m[1]
  movdqa xmm12, oword [rsp + 256]
  paddd xmm0, oword [rsp + 0]
  paddd xmm0, xmm4
  pxor xmm12, xmm0
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm8, xmm12
  pxor xmm4, xmm8
  movdqa xmm13, xmm4
  pslld xmm4, 20
  psrld xmm13, 12
  por xmm4, xmm13
  paddd xmm0, oword [rsp + 16]
  paddd xmm0, xmm4
  pxor xmm12, xmm0
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm8, xmm12
  movdqa oword [rsp + 256], xmm12
  pxor xmm4, xmm8
  movdqa xmm13, xmm4
  pslld xmm4, 25
  psrld xmm13, 7
  por xmm4, xmm13
  // G col (1,5,9,13) m[2],m[3]
  movdqa xmm12, oword [rsp + 272]
  paddd xmm1, oword [rsp + 32]
  paddd xmm1, xmm5
  pxor xmm12, xmm1
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm9, xmm12
  pxor xmm5, xmm9
  movdqa xmm13, xmm5
  pslld xmm5, 20
  psrld xmm13, 12
  por xmm5, xmm13
  paddd xmm1, oword [rsp + 48]
  paddd xmm1, xmm5
  pxor xmm12, xmm1
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm9, xmm12
  movdqa oword [rsp + 272], xmm12
  pxor xmm5, xmm9
  movdqa xmm13, xmm5
  pslld xmm5, 25
  psrld xmm13, 7
  por xmm5, xmm13
  // G col (2,6,10,14) m[4],m[5]
  movdqa xmm12, oword [rsp + 288]
  paddd xmm2, oword [rsp + 64]
  paddd xmm2, xmm6
  pxor xmm12, xmm2
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm10, xmm12
  pxor xmm6, xmm10
  movdqa xmm13, xmm6
  pslld xmm6, 20
  psrld xmm13, 12
  por xmm6, xmm13
  paddd xmm2, oword [rsp + 80]
  paddd xmm2, xmm6
  pxor xmm12, xmm2
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm10, xmm12
  movdqa oword [rsp + 288], xmm12
  pxor xmm6, xmm10
  movdqa xmm13, xmm6
  pslld xmm6, 25
  psrld xmm13, 7
  por xmm6, xmm13
  // G col (3,7,11,15) m[6],m[7]
  movdqa xmm12, oword [rsp + 304]
  paddd xmm3, oword [rsp + 96]
  paddd xmm3, xmm7
  pxor xmm12, xmm3
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm11, xmm12
  pxor xmm7, xmm11
  movdqa xmm13, xmm7
  pslld xmm7, 20
  psrld xmm13, 12
  por xmm7, xmm13
  paddd xmm3, oword [rsp + 112]
  paddd xmm3, xmm7
  pxor xmm12, xmm3
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm11, xmm12
  movdqa oword [rsp + 304], xmm12
  pxor xmm7, xmm11
  movdqa xmm13, xmm7
  pslld xmm7, 25
  psrld xmm13, 7
  por xmm7, xmm13
  // G diag (0,5,10,15) m[8],m[9]
  movdqa xmm12, oword [rsp + 304]
  paddd xmm0, oword [rsp + 128]
  paddd xmm0, xmm5
  pxor xmm12, xmm0
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm10, xmm12
  pxor xmm5, xmm10
  movdqa xmm13, xmm5
  pslld xmm5, 20
  psrld xmm13, 12
  por xmm5, xmm13
  paddd xmm0, oword [rsp + 144]
  paddd xmm0, xmm5
  pxor xmm12, xmm0
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm10, xmm12
  movdqa oword [rsp + 304], xmm12
  pxor xmm5, xmm10
  movdqa xmm13, xmm5
  pslld xmm5, 25
  psrld xmm13, 7
  por xmm5, xmm13
  // G diag (1,6,11,12) m[10],m[11]
  movdqa xmm12, oword [rsp + 256]
  paddd xmm1, oword [rsp + 160]
  paddd xmm1, xmm6
  pxor xmm12, xmm1
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm11, xmm12
  pxor xmm6, xmm11
  movdqa xmm13, xmm6
  pslld xmm6, 20
  psrld xmm13, 12
  por xmm6, xmm13
  paddd xmm1, oword [rsp + 176]
  paddd xmm1, xmm6
  pxor xmm12, xmm1
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm11, xmm12
  movdqa oword [rsp + 256], xmm12
  pxor xmm6, xmm11
  movdqa xmm13, xmm6
  pslld xmm6, 25
  psrld xmm13, 7
  por xmm6, xmm13
  // G diag (2,7,8,13) m[12],m[13]
  movdqa xmm12, oword [rsp + 272]
  paddd xmm2, oword [rsp + 192]
  paddd xmm2, xmm7
  pxor xmm12, xmm2
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm8, xmm12
  pxor xmm7, xmm8
  movdqa xmm13, xmm7
  pslld xmm7, 20
  psrld xmm13, 12
  por xmm7, xmm13
  paddd xmm2, oword [rsp + 208]
  paddd xmm2, xmm7
  pxor xmm12, xmm2
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm8, xmm12
  movdqa oword [rsp + 272], xmm12
  pxor xmm7, xmm8
  movdqa xmm13, xmm7
  pslld xmm7, 25
  psrld xmm13, 7
  por xmm7, xmm13
  // G diag (3,4,9,14) m[14],m[15]
  movdqa xmm12, oword [rsp + 288]
  paddd xmm3, oword [rsp + 224]
  paddd xmm3, xmm4
  pxor xmm12, xmm3
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm9, xmm12
  pxor xmm4, xmm9
  movdqa xmm13, xmm4
  pslld xmm4, 20
  psrld xmm13, 12
  por xmm4, xmm13
  paddd xmm3, oword [rsp + 240]
  paddd xmm3, xmm4
  pxor xmm12, xmm3
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm9, xmm12
  movdqa oword [rsp + 288], xmm12
  pxor xmm4, xmm9
  movdqa xmm13, xmm4
  pslld xmm4, 25
  psrld xmm13, 7
  por xmm4, xmm13

  // === Round 1 ===
  // G col (0,4,8,12) m[2],m[6]
  movdqa xmm12, oword [rsp + 256]
  paddd xmm0, oword [rsp + 32]
  paddd xmm0, xmm4
  pxor xmm12, xmm0
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm8, xmm12
  pxor xmm4, xmm8
  movdqa xmm13, xmm4
  pslld xmm4, 20
  psrld xmm13, 12
  por xmm4, xmm13
  paddd xmm0, oword [rsp + 96]
  paddd xmm0, xmm4
  pxor xmm12, xmm0
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm8, xmm12
  movdqa oword [rsp + 256], xmm12
  pxor xmm4, xmm8
  movdqa xmm13, xmm4
  pslld xmm4, 25
  psrld xmm13, 7
  por xmm4, xmm13
  // G col (1,5,9,13) m[3],m[10]
  movdqa xmm12, oword [rsp + 272]
  paddd xmm1, oword [rsp + 48]
  paddd xmm1, xmm5
  pxor xmm12, xmm1
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm9, xmm12
  pxor xmm5, xmm9
  movdqa xmm13, xmm5
  pslld xmm5, 20
  psrld xmm13, 12
  por xmm5, xmm13
  paddd xmm1, oword [rsp + 160]
  paddd xmm1, xmm5
  pxor xmm12, xmm1
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm9, xmm12
  movdqa oword [rsp + 272], xmm12
  pxor xmm5, xmm9
  movdqa xmm13, xmm5
  pslld xmm5, 25
  psrld xmm13, 7
  por xmm5, xmm13
  // G col (2,6,10,14) m[7],m[0]
  movdqa xmm12, oword [rsp + 288]
  paddd xmm2, oword [rsp + 112]
  paddd xmm2, xmm6
  pxor xmm12, xmm2
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm10, xmm12
  pxor xmm6, xmm10
  movdqa xmm13, xmm6
  pslld xmm6, 20
  psrld xmm13, 12
  por xmm6, xmm13
  paddd xmm2, oword [rsp + 0]
  paddd xmm2, xmm6
  pxor xmm12, xmm2
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm10, xmm12
  movdqa oword [rsp + 288], xmm12
  pxor xmm6, xmm10
  movdqa xmm13, xmm6
  pslld xmm6, 25
  psrld xmm13, 7
  por xmm6, xmm13
  // G col (3,7,11,15) m[4],m[13]
  movdqa xmm12, oword [rsp + 304]
  paddd xmm3, oword [rsp + 64]
  paddd xmm3, xmm7
  pxor xmm12, xmm3
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm11, xmm12
  pxor xmm7, xmm11
  movdqa xmm13, xmm7
  pslld xmm7, 20
  psrld xmm13, 12
  por xmm7, xmm13
  paddd xmm3, oword [rsp + 208]
  paddd xmm3, xmm7
  pxor xmm12, xmm3
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm11, xmm12
  movdqa oword [rsp + 304], xmm12
  pxor xmm7, xmm11
  movdqa xmm13, xmm7
  pslld xmm7, 25
  psrld xmm13, 7
  por xmm7, xmm13
  // G diag (0,5,10,15) m[1],m[11]
  movdqa xmm12, oword [rsp + 304]
  paddd xmm0, oword [rsp + 16]
  paddd xmm0, xmm5
  pxor xmm12, xmm0
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm10, xmm12
  pxor xmm5, xmm10
  movdqa xmm13, xmm5
  pslld xmm5, 20
  psrld xmm13, 12
  por xmm5, xmm13
  paddd xmm0, oword [rsp + 176]
  paddd xmm0, xmm5
  pxor xmm12, xmm0
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm10, xmm12
  movdqa oword [rsp + 304], xmm12
  pxor xmm5, xmm10
  movdqa xmm13, xmm5
  pslld xmm5, 25
  psrld xmm13, 7
  por xmm5, xmm13
  // G diag (1,6,11,12) m[12],m[5]
  movdqa xmm12, oword [rsp + 256]
  paddd xmm1, oword [rsp + 192]
  paddd xmm1, xmm6
  pxor xmm12, xmm1
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm11, xmm12
  pxor xmm6, xmm11
  movdqa xmm13, xmm6
  pslld xmm6, 20
  psrld xmm13, 12
  por xmm6, xmm13
  paddd xmm1, oword [rsp + 80]
  paddd xmm1, xmm6
  pxor xmm12, xmm1
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm11, xmm12
  movdqa oword [rsp + 256], xmm12
  pxor xmm6, xmm11
  movdqa xmm13, xmm6
  pslld xmm6, 25
  psrld xmm13, 7
  por xmm6, xmm13
  // G diag (2,7,8,13) m[9],m[14]
  movdqa xmm12, oword [rsp + 272]
  paddd xmm2, oword [rsp + 144]
  paddd xmm2, xmm7
  pxor xmm12, xmm2
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm8, xmm12
  pxor xmm7, xmm8
  movdqa xmm13, xmm7
  pslld xmm7, 20
  psrld xmm13, 12
  por xmm7, xmm13
  paddd xmm2, oword [rsp + 224]
  paddd xmm2, xmm7
  pxor xmm12, xmm2
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm8, xmm12
  movdqa oword [rsp + 272], xmm12
  pxor xmm7, xmm8
  movdqa xmm13, xmm7
  pslld xmm7, 25
  psrld xmm13, 7
  por xmm7, xmm13
  // G diag (3,4,9,14) m[15],m[8]
  movdqa xmm12, oword [rsp + 288]
  paddd xmm3, oword [rsp + 240]
  paddd xmm3, xmm4
  pxor xmm12, xmm3
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm9, xmm12
  pxor xmm4, xmm9
  movdqa xmm13, xmm4
  pslld xmm4, 20
  psrld xmm13, 12
  por xmm4, xmm13
  paddd xmm3, oword [rsp + 128]
  paddd xmm3, xmm4
  pxor xmm12, xmm3
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm9, xmm12
  movdqa oword [rsp + 288], xmm12
  pxor xmm4, xmm9
  movdqa xmm13, xmm4
  pslld xmm4, 25
  psrld xmm13, 7
  por xmm4, xmm13

  // === Round 2 ===
  // G col (0,4,8,12) m[3],m[4]
  movdqa xmm12, oword [rsp + 256]
  paddd xmm0, oword [rsp + 48]
  paddd xmm0, xmm4
  pxor xmm12, xmm0
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm8, xmm12
  pxor xmm4, xmm8
  movdqa xmm13, xmm4
  pslld xmm4, 20
  psrld xmm13, 12
  por xmm4, xmm13
  paddd xmm0, oword [rsp + 64]
  paddd xmm0, xmm4
  pxor xmm12, xmm0
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm8, xmm12
  movdqa oword [rsp + 256], xmm12
  pxor xmm4, xmm8
  movdqa xmm13, xmm4
  pslld xmm4, 25
  psrld xmm13, 7
  por xmm4, xmm13
  // G col (1,5,9,13) m[10],m[12]
  movdqa xmm12, oword [rsp + 272]
  paddd xmm1, oword [rsp + 160]
  paddd xmm1, xmm5
  pxor xmm12, xmm1
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm9, xmm12
  pxor xmm5, xmm9
  movdqa xmm13, xmm5
  pslld xmm5, 20
  psrld xmm13, 12
  por xmm5, xmm13
  paddd xmm1, oword [rsp + 192]
  paddd xmm1, xmm5
  pxor xmm12, xmm1
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm9, xmm12
  movdqa oword [rsp + 272], xmm12
  pxor xmm5, xmm9
  movdqa xmm13, xmm5
  pslld xmm5, 25
  psrld xmm13, 7
  por xmm5, xmm13
  // G col (2,6,10,14) m[13],m[2]
  movdqa xmm12, oword [rsp + 288]
  paddd xmm2, oword [rsp + 208]
  paddd xmm2, xmm6
  pxor xmm12, xmm2
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm10, xmm12
  pxor xmm6, xmm10
  movdqa xmm13, xmm6
  pslld xmm6, 20
  psrld xmm13, 12
  por xmm6, xmm13
  paddd xmm2, oword [rsp + 32]
  paddd xmm2, xmm6
  pxor xmm12, xmm2
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm10, xmm12
  movdqa oword [rsp + 288], xmm12
  pxor xmm6, xmm10
  movdqa xmm13, xmm6
  pslld xmm6, 25
  psrld xmm13, 7
  por xmm6, xmm13
  // G col (3,7,11,15) m[7],m[14]
  movdqa xmm12, oword [rsp + 304]
  paddd xmm3, oword [rsp + 112]
  paddd xmm3, xmm7
  pxor xmm12, xmm3
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm11, xmm12
  pxor xmm7, xmm11
  movdqa xmm13, xmm7
  pslld xmm7, 20
  psrld xmm13, 12
  por xmm7, xmm13
  paddd xmm3, oword [rsp + 224]
  paddd xmm3, xmm7
  pxor xmm12, xmm3
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm11, xmm12
  movdqa oword [rsp + 304], xmm12
  pxor xmm7, xmm11
  movdqa xmm13, xmm7
  pslld xmm7, 25
  psrld xmm13, 7
  por xmm7, xmm13
  // G diag (0,5,10,15) m[6],m[5]
  movdqa xmm12, oword [rsp + 304]
  paddd xmm0, oword [rsp + 96]
  paddd xmm0, xmm5
  pxor xmm12, xmm0
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm10, xmm12
  pxor xmm5, xmm10
  movdqa xmm13, xmm5
  pslld xmm5, 20
  psrld xmm13, 12
  por xmm5, xmm13
  paddd xmm0, oword [rsp + 80]
  paddd xmm0, xmm5
  pxor xmm12, xmm0
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm10, xmm12
  movdqa oword [rsp + 304], xmm12
  pxor xmm5, xmm10
  movdqa xmm13, xmm5
  pslld xmm5, 25
  psrld xmm13, 7
  por xmm5, xmm13
  // G diag (1,6,11,12) m[9],m[0]
  movdqa xmm12, oword [rsp + 256]
  paddd xmm1, oword [rsp + 144]
  paddd xmm1, xmm6
  pxor xmm12, xmm1
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm11, xmm12
  pxor xmm6, xmm11
  movdqa xmm13, xmm6
  pslld xmm6, 20
  psrld xmm13, 12
  por xmm6, xmm13
  paddd xmm1, oword [rsp + 0]
  paddd xmm1, xmm6
  pxor xmm12, xmm1
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm11, xmm12
  movdqa oword [rsp + 256], xmm12
  pxor xmm6, xmm11
  movdqa xmm13, xmm6
  pslld xmm6, 25
  psrld xmm13, 7
  por xmm6, xmm13
  // G diag (2,7,8,13) m[11],m[15]
  movdqa xmm12, oword [rsp + 272]
  paddd xmm2, oword [rsp + 176]
  paddd xmm2, xmm7
  pxor xmm12, xmm2
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm8, xmm12
  pxor xmm7, xmm8
  movdqa xmm13, xmm7
  pslld xmm7, 20
  psrld xmm13, 12
  por xmm7, xmm13
  paddd xmm2, oword [rsp + 240]
  paddd xmm2, xmm7
  pxor xmm12, xmm2
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm8, xmm12
  movdqa oword [rsp + 272], xmm12
  pxor xmm7, xmm8
  movdqa xmm13, xmm7
  pslld xmm7, 25
  psrld xmm13, 7
  por xmm7, xmm13
  // G diag (3,4,9,14) m[8],m[1]
  movdqa xmm12, oword [rsp + 288]
  paddd xmm3, oword [rsp + 128]
  paddd xmm3, xmm4
  pxor xmm12, xmm3
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm9, xmm12
  pxor xmm4, xmm9
  movdqa xmm13, xmm4
  pslld xmm4, 20
  psrld xmm13, 12
  por xmm4, xmm13
  paddd xmm3, oword [rsp + 16]
  paddd xmm3, xmm4
  pxor xmm12, xmm3
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm9, xmm12
  movdqa oword [rsp + 288], xmm12
  pxor xmm4, xmm9
  movdqa xmm13, xmm4
  pslld xmm4, 25
  psrld xmm13, 7
  por xmm4, xmm13

  // === Round 3 ===
  // G col (0,4,8,12) m[10],m[7]
  movdqa xmm12, oword [rsp + 256]
  paddd xmm0, oword [rsp + 160]
  paddd xmm0, xmm4
  pxor xmm12, xmm0
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm8, xmm12
  pxor xmm4, xmm8
  movdqa xmm13, xmm4
  pslld xmm4, 20
  psrld xmm13, 12
  por xmm4, xmm13
  paddd xmm0, oword [rsp + 112]
  paddd xmm0, xmm4
  pxor xmm12, xmm0
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm8, xmm12
  movdqa oword [rsp + 256], xmm12
  pxor xmm4, xmm8
  movdqa xmm13, xmm4
  pslld xmm4, 25
  psrld xmm13, 7
  por xmm4, xmm13
  // G col (1,5,9,13) m[12],m[9]
  movdqa xmm12, oword [rsp + 272]
  paddd xmm1, oword [rsp + 192]
  paddd xmm1, xmm5
  pxor xmm12, xmm1
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm9, xmm12
  pxor xmm5, xmm9
  movdqa xmm13, xmm5
  pslld xmm5, 20
  psrld xmm13, 12
  por xmm5, xmm13
  paddd xmm1, oword [rsp + 144]
  paddd xmm1, xmm5
  pxor xmm12, xmm1
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm9, xmm12
  movdqa oword [rsp + 272], xmm12
  pxor xmm5, xmm9
  movdqa xmm13, xmm5
  pslld xmm5, 25
  psrld xmm13, 7
  por xmm5, xmm13
  // G col (2,6,10,14) m[14],m[3]
  movdqa xmm12, oword [rsp + 288]
  paddd xmm2, oword [rsp + 224]
  paddd xmm2, xmm6
  pxor xmm12, xmm2
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm10, xmm12
  pxor xmm6, xmm10
  movdqa xmm13, xmm6
  pslld xmm6, 20
  psrld xmm13, 12
  por xmm6, xmm13
  paddd xmm2, oword [rsp + 48]
  paddd xmm2, xmm6
  pxor xmm12, xmm2
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm10, xmm12
  movdqa oword [rsp + 288], xmm12
  pxor xmm6, xmm10
  movdqa xmm13, xmm6
  pslld xmm6, 25
  psrld xmm13, 7
  por xmm6, xmm13
  // G col (3,7,11,15) m[13],m[15]
  movdqa xmm12, oword [rsp + 304]
  paddd xmm3, oword [rsp + 208]
  paddd xmm3, xmm7
  pxor xmm12, xmm3
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm11, xmm12
  pxor xmm7, xmm11
  movdqa xmm13, xmm7
  pslld xmm7, 20
  psrld xmm13, 12
  por xmm7, xmm13
  paddd xmm3, oword [rsp + 240]
  paddd xmm3, xmm7
  pxor xmm12, xmm3
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm11, xmm12
  movdqa oword [rsp + 304], xmm12
  pxor xmm7, xmm11
  movdqa xmm13, xmm7
  pslld xmm7, 25
  psrld xmm13, 7
  por xmm7, xmm13
  // G diag (0,5,10,15) m[4],m[0]
  movdqa xmm12, oword [rsp + 304]
  paddd xmm0, oword [rsp + 64]
  paddd xmm0, xmm5
  pxor xmm12, xmm0
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm10, xmm12
  pxor xmm5, xmm10
  movdqa xmm13, xmm5
  pslld xmm5, 20
  psrld xmm13, 12
  por xmm5, xmm13
  paddd xmm0, oword [rsp + 0]
  paddd xmm0, xmm5
  pxor xmm12, xmm0
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm10, xmm12
  movdqa oword [rsp + 304], xmm12
  pxor xmm5, xmm10
  movdqa xmm13, xmm5
  pslld xmm5, 25
  psrld xmm13, 7
  por xmm5, xmm13
  // G diag (1,6,11,12) m[11],m[2]
  movdqa xmm12, oword [rsp + 256]
  paddd xmm1, oword [rsp + 176]
  paddd xmm1, xmm6
  pxor xmm12, xmm1
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm11, xmm12
  pxor xmm6, xmm11
  movdqa xmm13, xmm6
  pslld xmm6, 20
  psrld xmm13, 12
  por xmm6, xmm13
  paddd xmm1, oword [rsp + 32]
  paddd xmm1, xmm6
  pxor xmm12, xmm1
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm11, xmm12
  movdqa oword [rsp + 256], xmm12
  pxor xmm6, xmm11
  movdqa xmm13, xmm6
  pslld xmm6, 25
  psrld xmm13, 7
  por xmm6, xmm13
  // G diag (2,7,8,13) m[5],m[8]
  movdqa xmm12, oword [rsp + 272]
  paddd xmm2, oword [rsp + 80]
  paddd xmm2, xmm7
  pxor xmm12, xmm2
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm8, xmm12
  pxor xmm7, xmm8
  movdqa xmm13, xmm7
  pslld xmm7, 20
  psrld xmm13, 12
  por xmm7, xmm13
  paddd xmm2, oword [rsp + 128]
  paddd xmm2, xmm7
  pxor xmm12, xmm2
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm8, xmm12
  movdqa oword [rsp + 272], xmm12
  pxor xmm7, xmm8
  movdqa xmm13, xmm7
  pslld xmm7, 25
  psrld xmm13, 7
  por xmm7, xmm13
  // G diag (3,4,9,14) m[1],m[6]
  movdqa xmm12, oword [rsp + 288]
  paddd xmm3, oword [rsp + 16]
  paddd xmm3, xmm4
  pxor xmm12, xmm3
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm9, xmm12
  pxor xmm4, xmm9
  movdqa xmm13, xmm4
  pslld xmm4, 20
  psrld xmm13, 12
  por xmm4, xmm13
  paddd xmm3, oword [rsp + 96]
  paddd xmm3, xmm4
  pxor xmm12, xmm3
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm9, xmm12
  movdqa oword [rsp + 288], xmm12
  pxor xmm4, xmm9
  movdqa xmm13, xmm4
  pslld xmm4, 25
  psrld xmm13, 7
  por xmm4, xmm13

  // === Round 4 ===
  // G col (0,4,8,12) m[12],m[13]
  movdqa xmm12, oword [rsp + 256]
  paddd xmm0, oword [rsp + 192]
  paddd xmm0, xmm4
  pxor xmm12, xmm0
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm8, xmm12
  pxor xmm4, xmm8
  movdqa xmm13, xmm4
  pslld xmm4, 20
  psrld xmm13, 12
  por xmm4, xmm13
  paddd xmm0, oword [rsp + 208]
  paddd xmm0, xmm4
  pxor xmm12, xmm0
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm8, xmm12
  movdqa oword [rsp + 256], xmm12
  pxor xmm4, xmm8
  movdqa xmm13, xmm4
  pslld xmm4, 25
  psrld xmm13, 7
  por xmm4, xmm13
  // G col (1,5,9,13) m[9],m[11]
  movdqa xmm12, oword [rsp + 272]
  paddd xmm1, oword [rsp + 144]
  paddd xmm1, xmm5
  pxor xmm12, xmm1
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm9, xmm12
  pxor xmm5, xmm9
  movdqa xmm13, xmm5
  pslld xmm5, 20
  psrld xmm13, 12
  por xmm5, xmm13
  paddd xmm1, oword [rsp + 176]
  paddd xmm1, xmm5
  pxor xmm12, xmm1
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm9, xmm12
  movdqa oword [rsp + 272], xmm12
  pxor xmm5, xmm9
  movdqa xmm13, xmm5
  pslld xmm5, 25
  psrld xmm13, 7
  por xmm5, xmm13
  // G col (2,6,10,14) m[15],m[10]
  movdqa xmm12, oword [rsp + 288]
  paddd xmm2, oword [rsp + 240]
  paddd xmm2, xmm6
  pxor xmm12, xmm2
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm10, xmm12
  pxor xmm6, xmm10
  movdqa xmm13, xmm6
  pslld xmm6, 20
  psrld xmm13, 12
  por xmm6, xmm13
  paddd xmm2, oword [rsp + 160]
  paddd xmm2, xmm6
  pxor xmm12, xmm2
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm10, xmm12
  movdqa oword [rsp + 288], xmm12
  pxor xmm6, xmm10
  movdqa xmm13, xmm6
  pslld xmm6, 25
  psrld xmm13, 7
  por xmm6, xmm13
  // G col (3,7,11,15) m[14],m[8]
  movdqa xmm12, oword [rsp + 304]
  paddd xmm3, oword [rsp + 224]
  paddd xmm3, xmm7
  pxor xmm12, xmm3
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm11, xmm12
  pxor xmm7, xmm11
  movdqa xmm13, xmm7
  pslld xmm7, 20
  psrld xmm13, 12
  por xmm7, xmm13
  paddd xmm3, oword [rsp + 128]
  paddd xmm3, xmm7
  pxor xmm12, xmm3
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm11, xmm12
  movdqa oword [rsp + 304], xmm12
  pxor xmm7, xmm11
  movdqa xmm13, xmm7
  pslld xmm7, 25
  psrld xmm13, 7
  por xmm7, xmm13
  // G diag (0,5,10,15) m[7],m[2]
  movdqa xmm12, oword [rsp + 304]
  paddd xmm0, oword [rsp + 112]
  paddd xmm0, xmm5
  pxor xmm12, xmm0
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm10, xmm12
  pxor xmm5, xmm10
  movdqa xmm13, xmm5
  pslld xmm5, 20
  psrld xmm13, 12
  por xmm5, xmm13
  paddd xmm0, oword [rsp + 32]
  paddd xmm0, xmm5
  pxor xmm12, xmm0
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm10, xmm12
  movdqa oword [rsp + 304], xmm12
  pxor xmm5, xmm10
  movdqa xmm13, xmm5
  pslld xmm5, 25
  psrld xmm13, 7
  por xmm5, xmm13
  // G diag (1,6,11,12) m[5],m[3]
  movdqa xmm12, oword [rsp + 256]
  paddd xmm1, oword [rsp + 80]
  paddd xmm1, xmm6
  pxor xmm12, xmm1
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm11, xmm12
  pxor xmm6, xmm11
  movdqa xmm13, xmm6
  pslld xmm6, 20
  psrld xmm13, 12
  por xmm6, xmm13
  paddd xmm1, oword [rsp + 48]
  paddd xmm1, xmm6
  pxor xmm12, xmm1
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm11, xmm12
  movdqa oword [rsp + 256], xmm12
  pxor xmm6, xmm11
  movdqa xmm13, xmm6
  pslld xmm6, 25
  psrld xmm13, 7
  por xmm6, xmm13
  // G diag (2,7,8,13) m[0],m[1]
  movdqa xmm12, oword [rsp + 272]
  paddd xmm2, oword [rsp + 0]
  paddd xmm2, xmm7
  pxor xmm12, xmm2
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm8, xmm12
  pxor xmm7, xmm8
  movdqa xmm13, xmm7
  pslld xmm7, 20
  psrld xmm13, 12
  por xmm7, xmm13
  paddd xmm2, oword [rsp + 16]
  paddd xmm2, xmm7
  pxor xmm12, xmm2
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm8, xmm12
  movdqa oword [rsp + 272], xmm12
  pxor xmm7, xmm8
  movdqa xmm13, xmm7
  pslld xmm7, 25
  psrld xmm13, 7
  por xmm7, xmm13
  // G diag (3,4,9,14) m[6],m[4]
  movdqa xmm12, oword [rsp + 288]
  paddd xmm3, oword [rsp + 96]
  paddd xmm3, xmm4
  pxor xmm12, xmm3
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm9, xmm12
  pxor xmm4, xmm9
  movdqa xmm13, xmm4
  pslld xmm4, 20
  psrld xmm13, 12
  por xmm4, xmm13
  paddd xmm3, oword [rsp + 64]
  paddd xmm3, xmm4
  pxor xmm12, xmm3
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm9, xmm12
  movdqa oword [rsp + 288], xmm12
  pxor xmm4, xmm9
  movdqa xmm13, xmm4
  pslld xmm4, 25
  psrld xmm13, 7
  por xmm4, xmm13

  // === Round 5 ===
  // G col (0,4,8,12) m[9],m[14]
  movdqa xmm12, oword [rsp + 256]
  paddd xmm0, oword [rsp + 144]
  paddd xmm0, xmm4
  pxor xmm12, xmm0
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm8, xmm12
  pxor xmm4, xmm8
  movdqa xmm13, xmm4
  pslld xmm4, 20
  psrld xmm13, 12
  por xmm4, xmm13
  paddd xmm0, oword [rsp + 224]
  paddd xmm0, xmm4
  pxor xmm12, xmm0
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm8, xmm12
  movdqa oword [rsp + 256], xmm12
  pxor xmm4, xmm8
  movdqa xmm13, xmm4
  pslld xmm4, 25
  psrld xmm13, 7
  por xmm4, xmm13
  // G col (1,5,9,13) m[11],m[5]
  movdqa xmm12, oword [rsp + 272]
  paddd xmm1, oword [rsp + 176]
  paddd xmm1, xmm5
  pxor xmm12, xmm1
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm9, xmm12
  pxor xmm5, xmm9
  movdqa xmm13, xmm5
  pslld xmm5, 20
  psrld xmm13, 12
  por xmm5, xmm13
  paddd xmm1, oword [rsp + 80]
  paddd xmm1, xmm5
  pxor xmm12, xmm1
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm9, xmm12
  movdqa oword [rsp + 272], xmm12
  pxor xmm5, xmm9
  movdqa xmm13, xmm5
  pslld xmm5, 25
  psrld xmm13, 7
  por xmm5, xmm13
  // G col (2,6,10,14) m[8],m[12]
  movdqa xmm12, oword [rsp + 288]
  paddd xmm2, oword [rsp + 128]
  paddd xmm2, xmm6
  pxor xmm12, xmm2
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm10, xmm12
  pxor xmm6, xmm10
  movdqa xmm13, xmm6
  pslld xmm6, 20
  psrld xmm13, 12
  por xmm6, xmm13
  paddd xmm2, oword [rsp + 192]
  paddd xmm2, xmm6
  pxor xmm12, xmm2
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm10, xmm12
  movdqa oword [rsp + 288], xmm12
  pxor xmm6, xmm10
  movdqa xmm13, xmm6
  pslld xmm6, 25
  psrld xmm13, 7
  por xmm6, xmm13
  // G col (3,7,11,15) m[15],m[1]
  movdqa xmm12, oword [rsp + 304]
  paddd xmm3, oword [rsp + 240]
  paddd xmm3, xmm7
  pxor xmm12, xmm3
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm11, xmm12
  pxor xmm7, xmm11
  movdqa xmm13, xmm7
  pslld xmm7, 20
  psrld xmm13, 12
  por xmm7, xmm13
  paddd xmm3, oword [rsp + 16]
  paddd xmm3, xmm7
  pxor xmm12, xmm3
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm11, xmm12
  movdqa oword [rsp + 304], xmm12
  pxor xmm7, xmm11
  movdqa xmm13, xmm7
  pslld xmm7, 25
  psrld xmm13, 7
  por xmm7, xmm13
  // G diag (0,5,10,15) m[13],m[3]
  movdqa xmm12, oword [rsp + 304]
  paddd xmm0, oword [rsp + 208]
  paddd xmm0, xmm5
  pxor xmm12, xmm0
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm10, xmm12
  pxor xmm5, xmm10
  movdqa xmm13, xmm5
  pslld xmm5, 20
  psrld xmm13, 12
  por xmm5, xmm13
  paddd xmm0, oword [rsp + 48]
  paddd xmm0, xmm5
  pxor xmm12, xmm0
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm10, xmm12
  movdqa oword [rsp + 304], xmm12
  pxor xmm5, xmm10
  movdqa xmm13, xmm5
  pslld xmm5, 25
  psrld xmm13, 7
  por xmm5, xmm13
  // G diag (1,6,11,12) m[0],m[10]
  movdqa xmm12, oword [rsp + 256]
  paddd xmm1, oword [rsp + 0]
  paddd xmm1, xmm6
  pxor xmm12, xmm1
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm11, xmm12
  pxor xmm6, xmm11
  movdqa xmm13, xmm6
  pslld xmm6, 20
  psrld xmm13, 12
  por xmm6, xmm13
  paddd xmm1, oword [rsp + 160]
  paddd xmm1, xmm6
  pxor xmm12, xmm1
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm11, xmm12
  movdqa oword [rsp + 256], xmm12
  pxor xmm6, xmm11
  movdqa xmm13, xmm6
  pslld xmm6, 25
  psrld xmm13, 7
  por xmm6, xmm13
  // G diag (2,7,8,13) m[2],m[6]
  movdqa xmm12, oword [rsp + 272]
  paddd xmm2, oword [rsp + 32]
  paddd xmm2, xmm7
  pxor xmm12, xmm2
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm8, xmm12
  pxor xmm7, xmm8
  movdqa xmm13, xmm7
  pslld xmm7, 20
  psrld xmm13, 12
  por xmm7, xmm13
  paddd xmm2, oword [rsp + 96]
  paddd xmm2, xmm7
  pxor xmm12, xmm2
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm8, xmm12
  movdqa oword [rsp + 272], xmm12
  pxor xmm7, xmm8
  movdqa xmm13, xmm7
  pslld xmm7, 25
  psrld xmm13, 7
  por xmm7, xmm13
  // G diag (3,4,9,14) m[4],m[7]
  movdqa xmm12, oword [rsp + 288]
  paddd xmm3, oword [rsp + 64]
  paddd xmm3, xmm4
  pxor xmm12, xmm3
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm9, xmm12
  pxor xmm4, xmm9
  movdqa xmm13, xmm4
  pslld xmm4, 20
  psrld xmm13, 12
  por xmm4, xmm13
  paddd xmm3, oword [rsp + 112]
  paddd xmm3, xmm4
  pxor xmm12, xmm3
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm9, xmm12
  movdqa oword [rsp + 288], xmm12
  pxor xmm4, xmm9
  movdqa xmm13, xmm4
  pslld xmm4, 25
  psrld xmm13, 7
  por xmm4, xmm13

  // === Round 6 ===
  // G col (0,4,8,12) m[11],m[15]
  movdqa xmm12, oword [rsp + 256]
  paddd xmm0, oword [rsp + 176]
  paddd xmm0, xmm4
  pxor xmm12, xmm0
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm8, xmm12
  pxor xmm4, xmm8
  movdqa xmm13, xmm4
  pslld xmm4, 20
  psrld xmm13, 12
  por xmm4, xmm13
  paddd xmm0, oword [rsp + 240]
  paddd xmm0, xmm4
  pxor xmm12, xmm0
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm8, xmm12
  movdqa oword [rsp + 256], xmm12
  pxor xmm4, xmm8
  movdqa xmm13, xmm4
  pslld xmm4, 25
  psrld xmm13, 7
  por xmm4, xmm13
  // G col (1,5,9,13) m[5],m[0]
  movdqa xmm12, oword [rsp + 272]
  paddd xmm1, oword [rsp + 80]
  paddd xmm1, xmm5
  pxor xmm12, xmm1
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm9, xmm12
  pxor xmm5, xmm9
  movdqa xmm13, xmm5
  pslld xmm5, 20
  psrld xmm13, 12
  por xmm5, xmm13
  paddd xmm1, oword [rsp + 0]
  paddd xmm1, xmm5
  pxor xmm12, xmm1
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm9, xmm12
  movdqa oword [rsp + 272], xmm12
  pxor xmm5, xmm9
  movdqa xmm13, xmm5
  pslld xmm5, 25
  psrld xmm13, 7
  por xmm5, xmm13
  // G col (2,6,10,14) m[1],m[9]
  movdqa xmm12, oword [rsp + 288]
  paddd xmm2, oword [rsp + 16]
  paddd xmm2, xmm6
  pxor xmm12, xmm2
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm10, xmm12
  pxor xmm6, xmm10
  movdqa xmm13, xmm6
  pslld xmm6, 20
  psrld xmm13, 12
  por xmm6, xmm13
  paddd xmm2, oword [rsp + 144]
  paddd xmm2, xmm6
  pxor xmm12, xmm2
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm10, xmm12
  movdqa oword [rsp + 288], xmm12
  pxor xmm6, xmm10
  movdqa xmm13, xmm6
  pslld xmm6, 25
  psrld xmm13, 7
  por xmm6, xmm13
  // G col (3,7,11,15) m[8],m[6]
  movdqa xmm12, oword [rsp + 304]
  paddd xmm3, oword [rsp + 128]
  paddd xmm3, xmm7
  pxor xmm12, xmm3
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm11, xmm12
  pxor xmm7, xmm11
  movdqa xmm13, xmm7
  pslld xmm7, 20
  psrld xmm13, 12
  por xmm7, xmm13
  paddd xmm3, oword [rsp + 96]
  paddd xmm3, xmm7
  pxor xmm12, xmm3
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm11, xmm12
  movdqa oword [rsp + 304], xmm12
  pxor xmm7, xmm11
  movdqa xmm13, xmm7
  pslld xmm7, 25
  psrld xmm13, 7
  por xmm7, xmm13
  // G diag (0,5,10,15) m[14],m[10]
  movdqa xmm12, oword [rsp + 304]
  paddd xmm0, oword [rsp + 224]
  paddd xmm0, xmm5
  pxor xmm12, xmm0
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm10, xmm12
  pxor xmm5, xmm10
  movdqa xmm13, xmm5
  pslld xmm5, 20
  psrld xmm13, 12
  por xmm5, xmm13
  paddd xmm0, oword [rsp + 160]
  paddd xmm0, xmm5
  pxor xmm12, xmm0
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm10, xmm12
  movdqa oword [rsp + 304], xmm12
  pxor xmm5, xmm10
  movdqa xmm13, xmm5
  pslld xmm5, 25
  psrld xmm13, 7
  por xmm5, xmm13
  // G diag (1,6,11,12) m[2],m[12]
  movdqa xmm12, oword [rsp + 256]
  paddd xmm1, oword [rsp + 32]
  paddd xmm1, xmm6
  pxor xmm12, xmm1
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm11, xmm12
  pxor xmm6, xmm11
  movdqa xmm13, xmm6
  pslld xmm6, 20
  psrld xmm13, 12
  por xmm6, xmm13
  paddd xmm1, oword [rsp + 192]
  paddd xmm1, xmm6
  pxor xmm12, xmm1
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm11, xmm12
  movdqa oword [rsp + 256], xmm12
  pxor xmm6, xmm11
  movdqa xmm13, xmm6
  pslld xmm6, 25
  psrld xmm13, 7
  por xmm6, xmm13
  // G diag (2,7,8,13) m[3],m[4]
  movdqa xmm12, oword [rsp + 272]
  paddd xmm2, oword [rsp + 48]
  paddd xmm2, xmm7
  pxor xmm12, xmm2
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm8, xmm12
  pxor xmm7, xmm8
  movdqa xmm13, xmm7
  pslld xmm7, 20
  psrld xmm13, 12
  por xmm7, xmm13
  paddd xmm2, oword [rsp + 64]
  paddd xmm2, xmm7
  pxor xmm12, xmm2
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm8, xmm12
  movdqa oword [rsp + 272], xmm12
  pxor xmm7, xmm8
  movdqa xmm13, xmm7
  pslld xmm7, 25
  psrld xmm13, 7
  por xmm7, xmm13
  // G diag (3,4,9,14) m[7],m[13]
  movdqa xmm12, oword [rsp + 288]
  paddd xmm3, oword [rsp + 112]
  paddd xmm3, xmm4
  pxor xmm12, xmm3
  pshuflw xmm12, xmm12, $B1
  pshufhw xmm12, xmm12, $B1
  paddd xmm9, xmm12
  pxor xmm4, xmm9
  movdqa xmm13, xmm4
  pslld xmm4, 20
  psrld xmm13, 12
  por xmm4, xmm13
  paddd xmm3, oword [rsp + 208]
  paddd xmm3, xmm4
  pxor xmm12, xmm3
  movdqa xmm13, xmm12
  psrld xmm12, 8
  pslld xmm13, 24
  por xmm12, xmm13
  paddd xmm9, xmm12
  movdqa oword [rsp + 288], xmm12
  pxor xmm4, xmm9
  movdqa xmm13, xmm4
  pslld xmm4, 25
  psrld xmm13, 7
  por xmm4, xmm13

  // Finalize: new_cv[i] = v[i] XOR v[i+8]
  pxor xmm0, xmm8
  pxor xmm1, xmm9
  pxor xmm2, xmm10
  pxor xmm3, xmm11
  movdqa xmm12, oword [rsp + 256]
  pxor xmm4, xmm12
  movdqa xmm12, oword [rsp + 272]
  pxor xmm5, xmm12
  movdqa xmm12, oword [rsp + 288]
  pxor xmm6, xmm12
  movdqa xmm12, oword [rsp + 304]
  pxor xmm7, xmm12

  // Store new CV
  movdqa oword [rsp + 320], xmm0
  movdqa oword [rsp + 336], xmm1
  movdqa oword [rsp + 352], xmm2
  movdqa oword [rsp + 368], xmm3
  movdqa oword [rsp + 384], xmm4
  movdqa oword [rsp + 400], xmm5
  movdqa oword [rsp + 416], xmm6
  movdqa oword [rsp + 432], xmm7

  add ebp, 64
  inc ebx
  cmp ebx, 16
  jb @block_loop

  // Output: transpose 4x8 CV back to per-chunk layout
  mov rax, qword ptr [rsp + 560]

  // Transpose words 0-3
  movdqa xmm0, oword [rsp + 320]
  movdqa xmm1, oword [rsp + 336]
  movdqa xmm2, oword [rsp + 352]
  movdqa xmm3, oword [rsp + 368]
  movdqa xmm4, xmm0
  punpckldq xmm0, xmm1
  punpckhdq xmm4, xmm1
  movdqa xmm5, xmm2
  punpckldq xmm2, xmm3
  punpckhdq xmm5, xmm3
  movdqa xmm1, xmm0
  punpcklqdq xmm0, xmm2
  punpckhqdq xmm1, xmm2
  movdqa xmm3, xmm4
  punpcklqdq xmm4, xmm5
  punpckhqdq xmm3, xmm5
  movdqu oword [rax], xmm0
  movdqu oword [rax + 32], xmm1
  movdqu oword [rax + 64], xmm4
  movdqu oword [rax + 96], xmm3

  // Transpose words 4-7
  movdqa xmm0, oword [rsp + 384]
  movdqa xmm1, oword [rsp + 400]
  movdqa xmm2, oword [rsp + 416]
  movdqa xmm3, oword [rsp + 432]
  movdqa xmm4, xmm0
  punpckldq xmm0, xmm1
  punpckhdq xmm4, xmm1
  movdqa xmm5, xmm2
  punpckldq xmm2, xmm3
  punpckhdq xmm5, xmm3
  movdqa xmm1, xmm0
  punpcklqdq xmm0, xmm2
  punpckhqdq xmm1, xmm2
  movdqa xmm3, xmm4
  punpcklqdq xmm4, xmm5
  punpckhqdq xmm3, xmm5
  movdqu oword [rax + 16], xmm0
  movdqu oword [rax + 48], xmm1
  movdqu oword [rax + 80], xmm4
  movdqu oword [rax + 112], xmm3

{$IFDEF MSWINDOWS}
  movdqa xmm6, oword [rsp + 576]
  movdqa xmm7, oword [rsp + 592]
  movdqa xmm8, oword [rsp + 608]
  movdqa xmm9, oword [rsp + 624]
  movdqa xmm10, oword [rsp + 640]
  movdqa xmm11, oword [rsp + 656]
  movdqa xmm12, oword [rsp + 672]
  movdqa xmm13, oword [rsp + 688]
  add rsp, 712
{$ELSE}
  add rsp, 584
{$ENDIF}

  pop rbp
  pop rbx
