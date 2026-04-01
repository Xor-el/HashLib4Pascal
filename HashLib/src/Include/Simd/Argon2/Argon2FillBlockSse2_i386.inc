// SSE2 implementation of Argon2 FillBlock.
// IA-32: after SimdProc4Begin_i386 — ebx, esi, edi, eax = Left, Right, Current, WithXor
//   (parallel to MS x64 ABI: rcx, rdx, r8, r9).
// Each pointer addresses 128 QWords (1024 bytes).
// Uses xmm0–xmm7 only. Non-volatile xmm6–xmm7 saved/restored on Windows (MSWINDOWS).
// Register map during G rounds: xmm0-1 = A(0..3), xmm2-3 = B(4..7),
//   xmm4-5 = C(8..11), xmm6-7 = D(12..15) / temps (same roles as x64, fewer XMM).
// IA-32 stack (sub esp, 2132): WithXor at [esp+2128]; spill slots [esp+2080],[esp+2096],[esp+2112];
//   R_buf at lea eax,[esp+32]; ECX = loop offset; EBX = Z_buf base after copy; EDI = Current.
// r8/r9 analogues (Current, WithXor) are not clobbered across loops. ARight and ACurrent may alias.
//
// Diagonalize/Undiagonalize use shufpd (see x64 header in Argon2FillBlockSse2_x86_64.inc).

  sub esp, 2132

  mov dword ptr [esp + 2128], eax

{$IFDEF MSWINDOWS}
  movdqu oword ptr [esp], xmm6
  movdqu oword ptr [esp + 16], xmm7
{$ENDIF}

  // =========================================================================
  // Step 1: Compute R_buf = Left XOR Right, store at [esp+32]
  // =========================================================================
  lea eax, [esp + 32]
  xor ecx, ecx
@xor_loop:
  movdqu xmm0, oword ptr [ebx + ecx]
  movdqu xmm1, oword ptr [esi + ecx]
  pxor xmm0, xmm1
  movdqu oword ptr [eax + ecx], xmm0
  add ecx, 16
  cmp ecx, 1024
  jb @xor_loop

  // =========================================================================
  // Step 2: Copy R_buf to Z_buf at [esp+1056]
  // =========================================================================
  lea ebx, [esp + 1056]
  xor ecx, ecx
@copy_loop:
  movdqu xmm0, oword ptr [eax + ecx]
  movdqu oword ptr [ebx + ecx], xmm0
  add ecx, 16
  cmp ecx, 1024
  jb @copy_loop

  // =========================================================================
  // Step 3: Column rounds on Z_buf (8 iterations, 16 QWords = 128 bytes each)
  // =========================================================================
  xor ecx, ecx

@col_loop:
  movdqu xmm0, oword ptr [ebx + ecx]
  movdqu xmm1, oword ptr [ebx + ecx + $10]
  movdqu xmm2, oword ptr [ebx + ecx + $20]
  movdqu xmm3, oword ptr [ebx + ecx + $30]
  movdqu xmm4, oword ptr [ebx + ecx + $40]
  movdqu xmm5, oword ptr [ebx + ecx + $50]
  movdqu xmm6, oword ptr [ebx + ecx + $60]
  movdqu xmm7, oword ptr [ebx + ecx + $70]

  // ----- Column G: G(A0,B0,C0,D0) || G(A1,B1,C1,D1) -----

  // fBlaMka(a, b): a = a + b + 2*lo32(a)*lo32(b)
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm0
  pmuludq xmm4, xmm2
  psllq xmm4, 1
  paddq xmm0, xmm2
  paddq xmm0, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm1
  pmuludq xmm5, xmm3
  psllq xmm5, 1
  paddq xmm1, xmm3
  paddq xmm1, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  // d = rotr64(d ^ a, 32)
  pxor xmm6, xmm0
  pshufd xmm6, xmm6, $B1
  pxor xmm7, xmm1
  pshufd xmm7, xmm7, $B1

  // fBlaMka(c, d)
  movdqu oword ptr [esp + 2080], xmm4
  pmuludq xmm4, xmm6
  psllq xmm4, 1
  movdqu oword ptr [esp + 2096], xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  paddq xmm4, xmm6
  movdqu oword ptr [esp + 2112], xmm2
  movdqu xmm2, oword ptr [esp + 2096]
  paddq xmm4, xmm2
  movdqu xmm2, oword ptr [esp + 2112]
  movdqu oword ptr [esp + 2080], xmm5
  pmuludq xmm5, xmm7
  psllq xmm5, 1
  movdqu oword ptr [esp + 2096], xmm5
  movdqu xmm5, oword ptr [esp + 2080]
  paddq xmm5, xmm7
  movdqu oword ptr [esp + 2112], xmm3
  movdqu xmm3, oword ptr [esp + 2096]
  paddq xmm5, xmm3
  movdqu xmm3, oword ptr [esp + 2112]

  // b = rotr64(b ^ c, 24)
  pxor xmm2, xmm4
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  pxor xmm3, xmm5
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm3
  psrlq xmm5, 24
  psllq xmm3, 40
  por xmm3, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  // fBlaMka(a, b)
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm0
  pmuludq xmm4, xmm2
  psllq xmm4, 1
  paddq xmm0, xmm2
  paddq xmm0, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm1
  pmuludq xmm5, xmm3
  psllq xmm5, 1
  paddq xmm1, xmm3
  paddq xmm1, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  // d = rotr64(d ^ a, 16)
  pxor xmm6, xmm0
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  pxor xmm7, xmm1
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm7
  psrlq xmm5, 16
  psllq xmm7, 48
  por xmm7, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  // fBlaMka(c, d)
  movdqu oword ptr [esp + 2080], xmm4
  pmuludq xmm4, xmm6
  psllq xmm4, 1
  movdqu oword ptr [esp + 2096], xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  paddq xmm4, xmm6
  movdqu oword ptr [esp + 2112], xmm2
  movdqu xmm2, oword ptr [esp + 2096]
  paddq xmm4, xmm2
  movdqu xmm2, oword ptr [esp + 2112]
  movdqu oword ptr [esp + 2080], xmm5
  pmuludq xmm5, xmm7
  psllq xmm5, 1
  movdqu oword ptr [esp + 2096], xmm5
  movdqu xmm5, oword ptr [esp + 2080]
  paddq xmm5, xmm7
  movdqu oword ptr [esp + 2112], xmm3
  movdqu xmm3, oword ptr [esp + 2096]
  paddq xmm5, xmm3
  movdqu xmm3, oword ptr [esp + 2112]

  // b = rotr64(b ^ c, 63)
  pxor xmm2, xmm4
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  pxor xmm3, xmm5
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm3
  psrlq xmm5, 63
  paddq xmm3, xmm3
  por xmm3, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  // ----- Diagonalize -----
  // B: rotate QWord positions left by 1
  //   B0=(v4,v5)->B0'=(v5,v6), B1=(v6,v7)->B1'=(v7,v4)
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm2
  shufpd xmm2, xmm3, 1
  shufpd xmm3, xmm4, 1
  movdqu xmm4, oword ptr [esp + 2080]

  // C: swap register pair c0<->c1
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  // D: rotate QWord positions right by 1
  //   D0=(v12,v13)->D0'=(v15,v12), D1=(v14,v15)->D1'=(v13,v14)
  //   shufpd produces results in swapped registers, so we swap afterwards
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm7
  shufpd xmm7, xmm6, 1
  shufpd xmm6, xmm4, 1
  movdqa xmm4, xmm6
  movdqa xmm6, xmm7
  movdqa xmm7, xmm4
  movdqu xmm4, oword ptr [esp + 2080]

  // ----- Diagonal G -----

  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm0
  pmuludq xmm4, xmm2
  psllq xmm4, 1
  paddq xmm0, xmm2
  paddq xmm0, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm1
  pmuludq xmm5, xmm3
  psllq xmm5, 1
  paddq xmm1, xmm3
  paddq xmm1, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  pxor xmm6, xmm0
  pshufd xmm6, xmm6, $B1
  pxor xmm7, xmm1
  pshufd xmm7, xmm7, $B1

  movdqu oword ptr [esp + 2080], xmm4
  pmuludq xmm4, xmm6
  psllq xmm4, 1
  movdqu oword ptr [esp + 2096], xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  paddq xmm4, xmm6
  movdqu oword ptr [esp + 2112], xmm2
  movdqu xmm2, oword ptr [esp + 2096]
  paddq xmm4, xmm2
  movdqu xmm2, oword ptr [esp + 2112]
  movdqu oword ptr [esp + 2080], xmm5
  pmuludq xmm5, xmm7
  psllq xmm5, 1
  movdqu oword ptr [esp + 2096], xmm5
  movdqu xmm5, oword ptr [esp + 2080]
  paddq xmm5, xmm7
  movdqu oword ptr [esp + 2112], xmm3
  movdqu xmm3, oword ptr [esp + 2096]
  paddq xmm5, xmm3
  movdqu xmm3, oword ptr [esp + 2112]

  pxor xmm2, xmm4
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  pxor xmm3, xmm5
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm3
  psrlq xmm5, 24
  psllq xmm3, 40
  por xmm3, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm0
  pmuludq xmm4, xmm2
  psllq xmm4, 1
  paddq xmm0, xmm2
  paddq xmm0, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm1
  pmuludq xmm5, xmm3
  psllq xmm5, 1
  paddq xmm1, xmm3
  paddq xmm1, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  pxor xmm6, xmm0
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  pxor xmm7, xmm1
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm7
  psrlq xmm5, 16
  psllq xmm7, 48
  por xmm7, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  movdqu oword ptr [esp + 2080], xmm4
  pmuludq xmm4, xmm6
  psllq xmm4, 1
  movdqu oword ptr [esp + 2096], xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  paddq xmm4, xmm6
  movdqu oword ptr [esp + 2112], xmm2
  movdqu xmm2, oword ptr [esp + 2096]
  paddq xmm4, xmm2
  movdqu xmm2, oword ptr [esp + 2112]
  movdqu oword ptr [esp + 2080], xmm5
  pmuludq xmm5, xmm7
  psllq xmm5, 1
  movdqu oword ptr [esp + 2096], xmm5
  movdqu xmm5, oword ptr [esp + 2080]
  paddq xmm5, xmm7
  movdqu oword ptr [esp + 2112], xmm3
  movdqu xmm3, oword ptr [esp + 2096]
  paddq xmm5, xmm3
  movdqu xmm3, oword ptr [esp + 2112]

  pxor xmm2, xmm4
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  pxor xmm3, xmm5
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm3
  psrlq xmm5, 63
  paddq xmm3, xmm3
  por xmm3, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  // ----- Undiagonalize -----
  // B: rotate QWord positions right by 1 (undo left-1)
  //   shufpd produces results in swapped registers, so we swap afterwards
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm3
  shufpd xmm3, xmm2, 1
  shufpd xmm2, xmm4, 1
  movdqa xmm4, xmm2
  movdqa xmm2, xmm3
  movdqa xmm3, xmm4
  movdqu xmm4, oword ptr [esp + 2080]

  // C: swap register pair (self-inverse)
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  // D: rotate QWord positions left by 1 (undo right-1)
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm6
  shufpd xmm6, xmm7, 1
  shufpd xmm7, xmm4, 1
  movdqu xmm4, oword ptr [esp + 2080]

  // ----- Store back to Z_buf -----
  movdqu oword ptr [ebx + ecx], xmm0
  movdqu oword ptr [ebx + ecx + $10], xmm1
  movdqu oword ptr [ebx + ecx + $20], xmm2
  movdqu oword ptr [ebx + ecx + $30], xmm3
  movdqu oword ptr [ebx + ecx + $40], xmm4
  movdqu oword ptr [ebx + ecx + $50], xmm5
  movdqu oword ptr [ebx + ecx + $60], xmm6
  movdqu oword ptr [ebx + ecx + $70], xmm7

  add ecx, 128
  cmp ecx, 1024
  jb @col_loop

  // =========================================================================
  // Step 4: Row rounds on Z_buf (8 iterations, stride-16 QWord access)
  // =========================================================================
  xor ecx, ecx

@row_loop:
  movdqu xmm0, oword ptr [ebx + ecx]
  movdqu xmm1, oword ptr [ebx + ecx + 128]
  movdqu xmm2, oword ptr [ebx + ecx + 256]
  movdqu xmm3, oword ptr [ebx + ecx + 384]
  movdqu xmm4, oword ptr [ebx + ecx + 512]
  movdqu xmm5, oword ptr [ebx + ecx + 640]
  movdqu xmm6, oword ptr [ebx + ecx + 768]
  movdqu xmm7, oword ptr [ebx + ecx + 896]

  // ----- Column G -----

  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm0
  pmuludq xmm4, xmm2
  psllq xmm4, 1
  paddq xmm0, xmm2
  paddq xmm0, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm1
  pmuludq xmm5, xmm3
  psllq xmm5, 1
  paddq xmm1, xmm3
  paddq xmm1, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  pxor xmm6, xmm0
  pshufd xmm6, xmm6, $B1
  pxor xmm7, xmm1
  pshufd xmm7, xmm7, $B1

  movdqu oword ptr [esp + 2080], xmm4
  pmuludq xmm4, xmm6
  psllq xmm4, 1
  movdqu oword ptr [esp + 2096], xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  paddq xmm4, xmm6
  movdqu oword ptr [esp + 2112], xmm2
  movdqu xmm2, oword ptr [esp + 2096]
  paddq xmm4, xmm2
  movdqu xmm2, oword ptr [esp + 2112]
  movdqu oword ptr [esp + 2080], xmm5
  pmuludq xmm5, xmm7
  psllq xmm5, 1
  movdqu oword ptr [esp + 2096], xmm5
  movdqu xmm5, oword ptr [esp + 2080]
  paddq xmm5, xmm7
  movdqu oword ptr [esp + 2112], xmm3
  movdqu xmm3, oword ptr [esp + 2096]
  paddq xmm5, xmm3
  movdqu xmm3, oword ptr [esp + 2112]

  pxor xmm2, xmm4
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  pxor xmm3, xmm5
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm3
  psrlq xmm5, 24
  psllq xmm3, 40
  por xmm3, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm0
  pmuludq xmm4, xmm2
  psllq xmm4, 1
  paddq xmm0, xmm2
  paddq xmm0, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm1
  pmuludq xmm5, xmm3
  psllq xmm5, 1
  paddq xmm1, xmm3
  paddq xmm1, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  pxor xmm6, xmm0
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  pxor xmm7, xmm1
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm7
  psrlq xmm5, 16
  psllq xmm7, 48
  por xmm7, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  movdqu oword ptr [esp + 2080], xmm4
  pmuludq xmm4, xmm6
  psllq xmm4, 1
  movdqu oword ptr [esp + 2096], xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  paddq xmm4, xmm6
  movdqu oword ptr [esp + 2112], xmm2
  movdqu xmm2, oword ptr [esp + 2096]
  paddq xmm4, xmm2
  movdqu xmm2, oword ptr [esp + 2112]
  movdqu oword ptr [esp + 2080], xmm5
  pmuludq xmm5, xmm7
  psllq xmm5, 1
  movdqu oword ptr [esp + 2096], xmm5
  movdqu xmm5, oword ptr [esp + 2080]
  paddq xmm5, xmm7
  movdqu oword ptr [esp + 2112], xmm3
  movdqu xmm3, oword ptr [esp + 2096]
  paddq xmm5, xmm3
  movdqu xmm3, oword ptr [esp + 2112]

  pxor xmm2, xmm4
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  pxor xmm3, xmm5
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm3
  psrlq xmm5, 63
  paddq xmm3, xmm3
  por xmm3, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  // ----- Diagonalize -----
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm2
  shufpd xmm2, xmm3, 1
  shufpd xmm3, xmm4, 1
  movdqu xmm4, oword ptr [esp + 2080]

  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm7
  shufpd xmm7, xmm6, 1
  shufpd xmm6, xmm4, 1
  movdqa xmm4, xmm6
  movdqa xmm6, xmm7
  movdqa xmm7, xmm4
  movdqu xmm4, oword ptr [esp + 2080]

  // ----- Diagonal G -----

  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm0
  pmuludq xmm4, xmm2
  psllq xmm4, 1
  paddq xmm0, xmm2
  paddq xmm0, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm1
  pmuludq xmm5, xmm3
  psllq xmm5, 1
  paddq xmm1, xmm3
  paddq xmm1, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  pxor xmm6, xmm0
  pshufd xmm6, xmm6, $B1
  pxor xmm7, xmm1
  pshufd xmm7, xmm7, $B1

  movdqu oword ptr [esp + 2080], xmm4
  pmuludq xmm4, xmm6
  psllq xmm4, 1
  movdqu oword ptr [esp + 2096], xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  paddq xmm4, xmm6
  movdqu oword ptr [esp + 2112], xmm2
  movdqu xmm2, oword ptr [esp + 2096]
  paddq xmm4, xmm2
  movdqu xmm2, oword ptr [esp + 2112]
  movdqu oword ptr [esp + 2080], xmm5
  pmuludq xmm5, xmm7
  psllq xmm5, 1
  movdqu oword ptr [esp + 2096], xmm5
  movdqu xmm5, oword ptr [esp + 2080]
  paddq xmm5, xmm7
  movdqu oword ptr [esp + 2112], xmm3
  movdqu xmm3, oword ptr [esp + 2096]
  paddq xmm5, xmm3
  movdqu xmm3, oword ptr [esp + 2112]

  pxor xmm2, xmm4
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  pxor xmm3, xmm5
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm3
  psrlq xmm5, 24
  psllq xmm3, 40
  por xmm3, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm0
  pmuludq xmm4, xmm2
  psllq xmm4, 1
  paddq xmm0, xmm2
  paddq xmm0, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm1
  pmuludq xmm5, xmm3
  psllq xmm5, 1
  paddq xmm1, xmm3
  paddq xmm1, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  pxor xmm6, xmm0
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  pxor xmm7, xmm1
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm7
  psrlq xmm5, 16
  psllq xmm7, 48
  por xmm7, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  movdqu oword ptr [esp + 2080], xmm4
  pmuludq xmm4, xmm6
  psllq xmm4, 1
  movdqu oword ptr [esp + 2096], xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  paddq xmm4, xmm6
  movdqu oword ptr [esp + 2112], xmm2
  movdqu xmm2, oword ptr [esp + 2096]
  paddq xmm4, xmm2
  movdqu xmm2, oword ptr [esp + 2112]
  movdqu oword ptr [esp + 2080], xmm5
  pmuludq xmm5, xmm7
  psllq xmm5, 1
  movdqu oword ptr [esp + 2096], xmm5
  movdqu xmm5, oword ptr [esp + 2080]
  paddq xmm5, xmm7
  movdqu oword ptr [esp + 2112], xmm3
  movdqu xmm3, oword ptr [esp + 2096]
  paddq xmm5, xmm3
  movdqu xmm3, oword ptr [esp + 2112]

  pxor xmm2, xmm4
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqu xmm4, oword ptr [esp + 2080]
  pxor xmm3, xmm5
  movdqu oword ptr [esp + 2080], xmm5
  movdqa xmm5, xmm3
  psrlq xmm5, 63
  paddq xmm3, xmm3
  por xmm3, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  // ----- Undiagonalize -----
  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm3
  shufpd xmm3, xmm2, 1
  shufpd xmm2, xmm4, 1
  movdqa xmm4, xmm2
  movdqa xmm2, xmm3
  movdqa xmm3, xmm4
  movdqu xmm4, oword ptr [esp + 2080]

  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm5
  movdqu xmm5, oword ptr [esp + 2080]

  movdqu oword ptr [esp + 2080], xmm4
  movdqa xmm4, xmm6
  shufpd xmm6, xmm7, 1
  shufpd xmm7, xmm4, 1
  movdqu xmm4, oword ptr [esp + 2080]

  // ----- Store back to Z_buf at stride offsets -----
  movdqu oword ptr [ebx + ecx], xmm0
  movdqu oword ptr [ebx + ecx + 128], xmm1
  movdqu oword ptr [ebx + ecx + 256], xmm2
  movdqu oword ptr [ebx + ecx + 384], xmm3
  movdqu oword ptr [ebx + ecx + 512], xmm4
  movdqu oword ptr [ebx + ecx + 640], xmm5
  movdqu oword ptr [ebx + ecx + 768], xmm6
  movdqu oword ptr [ebx + ecx + 896], xmm7

  add ecx, 16
  cmp ecx, 128
  jb @row_loop

  // =========================================================================
  // Step 5: Final XOR — Current = R_buf XOR Z_buf [XOR Current]
  // =========================================================================
  cmp dword ptr [esp + 2128], 0
  jnz @final_with_xor

  xor ecx, ecx
@final_noxor_loop:
  movdqu xmm0, oword ptr [eax + ecx]
  movdqu xmm1, oword ptr [ebx + ecx]
  pxor xmm0, xmm1
  movdqu oword ptr [edi + ecx], xmm0
  add ecx, 16
  cmp ecx, 1024
  jb @final_noxor_loop
  jmp @epilogue

@final_with_xor:
  xor ecx, ecx
@final_xor_loop:
  movdqu xmm0, oword ptr [eax + ecx]
  movdqu xmm1, oword ptr [ebx + ecx]
  movdqu xmm2, oword ptr [edi + ecx]
  pxor xmm0, xmm1
  pxor xmm0, xmm2
  movdqu oword ptr [edi + ecx], xmm0
  add ecx, 16
  cmp ecx, 1024
  jb @final_xor_loop

@epilogue:
{$IFDEF MSWINDOWS}
  movdqu xmm6, oword ptr [esp]
  movdqu xmm7, oword ptr [esp + 16]
{$ENDIF}

  add esp, 2132
  pop edi
  pop esi
  pop ebx
