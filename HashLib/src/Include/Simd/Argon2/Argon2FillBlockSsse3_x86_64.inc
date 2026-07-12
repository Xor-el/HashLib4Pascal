// SSSE3 implementation of Argon2 FillBlock; SSE2 sibling:
// Argon2FillBlockSse2_x86_64.inc. Unlike the SSE2 sibling, the byte-aligned
// rotations (rot24/rot16) are single pshufb (db-encoded for broad assembler
// compatibility) against masks resident in xmm10/xmm11; rot32 stays pshufd and
// rot63 stays shift+or (not byte-aligned).
// Expects MS x64 ABI (after HlpSimdProc5Begin): rcx = Left ptr, rdx = Right ptr,
//   r8 = Current ptr, r9 = WithXor (0 or 1), r10 = byte-rotation masks ptr
//   (see ARGON2_ROT_MASKS: rot24 at +0, rot16 at +32; read unaligned, so the
//   Pascal const needs no special alignment; consumed by the entry mask loads,
//   r10 is scratch afterwards).
// Each pointer addresses 128 QWords (1024 bytes).
// Uses xmm0-xmm11; xmm6-xmm11 are MS x64 non-volatile (saved/restored).
// Register map during G rounds: xmm0-1 = A(0..3), xmm2-3 = B(4..7),
//   xmm4-5 = C(8..11), xmm6-7 = D(12..15), xmm8-9 = temps,
//   xmm10 = rot24 mask, xmm11 = rot16 mask.
// Stack layout (sub rsp, 2120):
//   [rsp+0..63]     xmm6-9 save area
//   [rsp+64..1087]  R_buf (1024 bytes)
//   [rsp+1088..2111] Z_buf (1024 bytes)
//   [rsp+2112..2119] alignment padding
// r8 (Current) and r9 (WithXor) survive all loops (not clobbered).
// ARight and ACurrent may alias; R_buf buffering handles this.
//
// Diagonalize/Undiagonalize use shufpd to rotate QWord positions within
// register pairs. Right-rotates require a 3-movdqa swap since shufpd
// naturally places results in the opposite register for that direction.

  {$I ..\..\Include\Simd\Common\HlpSimdNonVolatileSave_x86_64.inc}

  // Load byte-rotation masks (resident for the whole kernel)
  db $F3, $45, $0F, $6F, $12                    // movdqu xmm10, oword [r10]
  db $F3, $45, $0F, $6F, $5A, $20               // movdqu xmm11, oword [r10 + $20]

  sub rsp, 2056

  // =========================================================================
  // Step 1: Compute R_buf = Left XOR Right, store at [rsp+64]
  // =========================================================================
  lea rax, [rsp]
  xor r10, r10
@xor_loop:
  movdqu xmm0, oword [rcx + r10]
  movdqu xmm1, oword [rdx + r10]
  pxor xmm0, xmm1
  movdqu oword [rax + r10], xmm0
  add r10, 16
  cmp r10, 1024
  jb @xor_loop

  // =========================================================================
  // Step 2: Copy R_buf to Z_buf at [rsp+1088]
  // =========================================================================
  lea r11, [rsp + 1024]
  xor r10, r10
@copy_loop:
  movdqu xmm0, oword [rax + r10]
  movdqu oword [r11 + r10], xmm0
  add r10, 16
  cmp r10, 1024
  jb @copy_loop

  // =========================================================================
  // Step 3: Column rounds on Z_buf (8 iterations, 16 QWords = 128 bytes each)
  // =========================================================================
  xor r10, r10

@col_loop:
  movdqu xmm0, oword [r11 + r10]
  movdqu xmm1, oword [r11 + r10 + $10]
  movdqu xmm2, oword [r11 + r10 + $20]
  movdqu xmm3, oword [r11 + r10 + $30]
  movdqu xmm4, oword [r11 + r10 + $40]
  movdqu xmm5, oword [r11 + r10 + $50]
  movdqu xmm6, oword [r11 + r10 + $60]
  movdqu xmm7, oword [r11 + r10 + $70]

  // ----- Column G: G(A0,B0,C0,D0) || G(A1,B1,C1,D1) -----

  // fBlaMka(a, b): a = a + b + 2*lo32(a)*lo32(b)
  movdqa xmm8, xmm0
  pmuludq xmm8, xmm2
  psllq xmm8, 1
  paddq xmm0, xmm2
  paddq xmm0, xmm8
  movdqa xmm9, xmm1
  pmuludq xmm9, xmm3
  psllq xmm9, 1
  paddq xmm1, xmm3
  paddq xmm1, xmm9

  // d = rotr64(d ^ a, 32)
  pxor xmm6, xmm0
  pshufd xmm6, xmm6, $B1
  pxor xmm7, xmm1
  pshufd xmm7, xmm7, $B1

  // fBlaMka(c, d)
  movdqa xmm8, xmm4
  pmuludq xmm8, xmm6
  psllq xmm8, 1
  paddq xmm4, xmm6
  paddq xmm4, xmm8
  movdqa xmm9, xmm5
  pmuludq xmm9, xmm7
  psllq xmm9, 1
  paddq xmm5, xmm7
  paddq xmm5, xmm9

  // b = rotr64(b ^ c, 24)
  pxor xmm2, xmm4
  db $66, $41, $0F, $38, $00, $D2               // pshufb xmm2, xmm10
  pxor xmm3, xmm5
  db $66, $41, $0F, $38, $00, $DA               // pshufb xmm3, xmm10

  // fBlaMka(a, b)
  movdqa xmm8, xmm0
  pmuludq xmm8, xmm2
  psllq xmm8, 1
  paddq xmm0, xmm2
  paddq xmm0, xmm8
  movdqa xmm9, xmm1
  pmuludq xmm9, xmm3
  psllq xmm9, 1
  paddq xmm1, xmm3
  paddq xmm1, xmm9

  // d = rotr64(d ^ a, 16)
  pxor xmm6, xmm0
  db $66, $41, $0F, $38, $00, $F3               // pshufb xmm6, xmm11
  pxor xmm7, xmm1
  db $66, $41, $0F, $38, $00, $FB               // pshufb xmm7, xmm11

  // fBlaMka(c, d)
  movdqa xmm8, xmm4
  pmuludq xmm8, xmm6
  psllq xmm8, 1
  paddq xmm4, xmm6
  paddq xmm4, xmm8
  movdqa xmm9, xmm5
  pmuludq xmm9, xmm7
  psllq xmm9, 1
  paddq xmm5, xmm7
  paddq xmm5, xmm9

  // b = rotr64(b ^ c, 63)
  pxor xmm2, xmm4
  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  pxor xmm3, xmm5
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // ----- Diagonalize -----
  // B: rotate QWord positions left by 1
  //   B0=(v4,v5)->B0'=(v5,v6), B1=(v6,v7)->B1'=(v7,v4)
  movdqa xmm8, xmm2
  shufpd xmm2, xmm3, 1
  shufpd xmm3, xmm8, 1

  // C: swap register pair c0<->c1
  movdqa xmm8, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm8

  // D: rotate QWord positions right by 1
  //   D0=(v12,v13)->D0'=(v15,v12), D1=(v14,v15)->D1'=(v13,v14)
  //   shufpd produces results in swapped registers, so we swap afterwards
  movdqa xmm8, xmm7
  shufpd xmm7, xmm6, 1
  shufpd xmm6, xmm8, 1
  movdqa xmm8, xmm6
  movdqa xmm6, xmm7
  movdqa xmm7, xmm8

  // ----- Diagonal G -----

  movdqa xmm8, xmm0
  pmuludq xmm8, xmm2
  psllq xmm8, 1
  paddq xmm0, xmm2
  paddq xmm0, xmm8
  movdqa xmm9, xmm1
  pmuludq xmm9, xmm3
  psllq xmm9, 1
  paddq xmm1, xmm3
  paddq xmm1, xmm9

  pxor xmm6, xmm0
  pshufd xmm6, xmm6, $B1
  pxor xmm7, xmm1
  pshufd xmm7, xmm7, $B1

  movdqa xmm8, xmm4
  pmuludq xmm8, xmm6
  psllq xmm8, 1
  paddq xmm4, xmm6
  paddq xmm4, xmm8
  movdqa xmm9, xmm5
  pmuludq xmm9, xmm7
  psllq xmm9, 1
  paddq xmm5, xmm7
  paddq xmm5, xmm9

  pxor xmm2, xmm4
  db $66, $41, $0F, $38, $00, $D2               // pshufb xmm2, xmm10
  pxor xmm3, xmm5
  db $66, $41, $0F, $38, $00, $DA               // pshufb xmm3, xmm10

  movdqa xmm8, xmm0
  pmuludq xmm8, xmm2
  psllq xmm8, 1
  paddq xmm0, xmm2
  paddq xmm0, xmm8
  movdqa xmm9, xmm1
  pmuludq xmm9, xmm3
  psllq xmm9, 1
  paddq xmm1, xmm3
  paddq xmm1, xmm9

  pxor xmm6, xmm0
  db $66, $41, $0F, $38, $00, $F3               // pshufb xmm6, xmm11
  pxor xmm7, xmm1
  db $66, $41, $0F, $38, $00, $FB               // pshufb xmm7, xmm11

  movdqa xmm8, xmm4
  pmuludq xmm8, xmm6
  psllq xmm8, 1
  paddq xmm4, xmm6
  paddq xmm4, xmm8
  movdqa xmm9, xmm5
  pmuludq xmm9, xmm7
  psllq xmm9, 1
  paddq xmm5, xmm7
  paddq xmm5, xmm9

  pxor xmm2, xmm4
  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  pxor xmm3, xmm5
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // ----- Undiagonalize -----
  // B: rotate QWord positions right by 1 (undo left-1)
  //   shufpd produces results in swapped registers, so we swap afterwards
  movdqa xmm8, xmm3
  shufpd xmm3, xmm2, 1
  shufpd xmm2, xmm8, 1
  movdqa xmm8, xmm2
  movdqa xmm2, xmm3
  movdqa xmm3, xmm8

  // C: swap register pair (self-inverse)
  movdqa xmm8, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm8

  // D: rotate QWord positions left by 1 (undo right-1)
  movdqa xmm8, xmm6
  shufpd xmm6, xmm7, 1
  shufpd xmm7, xmm8, 1

  // ----- Store back to Z_buf -----
  movdqu oword [r11 + r10], xmm0
  movdqu oword [r11 + r10 + $10], xmm1
  movdqu oword [r11 + r10 + $20], xmm2
  movdqu oword [r11 + r10 + $30], xmm3
  movdqu oword [r11 + r10 + $40], xmm4
  movdqu oword [r11 + r10 + $50], xmm5
  movdqu oword [r11 + r10 + $60], xmm6
  movdqu oword [r11 + r10 + $70], xmm7

  add r10, 128
  cmp r10, 1024
  jb @col_loop

  // =========================================================================
  // Step 4: Row rounds on Z_buf (8 iterations, stride-16 QWord access)
  // =========================================================================
  xor r10, r10

@row_loop:
  movdqu xmm0, oword [r11 + r10]
  movdqu xmm1, oword [r11 + r10 + 128]
  movdqu xmm2, oword [r11 + r10 + 256]
  movdqu xmm3, oword [r11 + r10 + 384]
  movdqu xmm4, oword [r11 + r10 + 512]
  movdqu xmm5, oword [r11 + r10 + 640]
  movdqu xmm6, oword [r11 + r10 + 768]
  movdqu xmm7, oword [r11 + r10 + 896]

  // ----- Column G -----

  movdqa xmm8, xmm0
  pmuludq xmm8, xmm2
  psllq xmm8, 1
  paddq xmm0, xmm2
  paddq xmm0, xmm8
  movdqa xmm9, xmm1
  pmuludq xmm9, xmm3
  psllq xmm9, 1
  paddq xmm1, xmm3
  paddq xmm1, xmm9

  pxor xmm6, xmm0
  pshufd xmm6, xmm6, $B1
  pxor xmm7, xmm1
  pshufd xmm7, xmm7, $B1

  movdqa xmm8, xmm4
  pmuludq xmm8, xmm6
  psllq xmm8, 1
  paddq xmm4, xmm6
  paddq xmm4, xmm8
  movdqa xmm9, xmm5
  pmuludq xmm9, xmm7
  psllq xmm9, 1
  paddq xmm5, xmm7
  paddq xmm5, xmm9

  pxor xmm2, xmm4
  db $66, $41, $0F, $38, $00, $D2               // pshufb xmm2, xmm10
  pxor xmm3, xmm5
  db $66, $41, $0F, $38, $00, $DA               // pshufb xmm3, xmm10

  movdqa xmm8, xmm0
  pmuludq xmm8, xmm2
  psllq xmm8, 1
  paddq xmm0, xmm2
  paddq xmm0, xmm8
  movdqa xmm9, xmm1
  pmuludq xmm9, xmm3
  psllq xmm9, 1
  paddq xmm1, xmm3
  paddq xmm1, xmm9

  pxor xmm6, xmm0
  db $66, $41, $0F, $38, $00, $F3               // pshufb xmm6, xmm11
  pxor xmm7, xmm1
  db $66, $41, $0F, $38, $00, $FB               // pshufb xmm7, xmm11

  movdqa xmm8, xmm4
  pmuludq xmm8, xmm6
  psllq xmm8, 1
  paddq xmm4, xmm6
  paddq xmm4, xmm8
  movdqa xmm9, xmm5
  pmuludq xmm9, xmm7
  psllq xmm9, 1
  paddq xmm5, xmm7
  paddq xmm5, xmm9

  pxor xmm2, xmm4
  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  pxor xmm3, xmm5
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // ----- Diagonalize -----
  movdqa xmm8, xmm2
  shufpd xmm2, xmm3, 1
  shufpd xmm3, xmm8, 1

  movdqa xmm8, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm8

  movdqa xmm8, xmm7
  shufpd xmm7, xmm6, 1
  shufpd xmm6, xmm8, 1
  movdqa xmm8, xmm6
  movdqa xmm6, xmm7
  movdqa xmm7, xmm8

  // ----- Diagonal G -----

  movdqa xmm8, xmm0
  pmuludq xmm8, xmm2
  psllq xmm8, 1
  paddq xmm0, xmm2
  paddq xmm0, xmm8
  movdqa xmm9, xmm1
  pmuludq xmm9, xmm3
  psllq xmm9, 1
  paddq xmm1, xmm3
  paddq xmm1, xmm9

  pxor xmm6, xmm0
  pshufd xmm6, xmm6, $B1
  pxor xmm7, xmm1
  pshufd xmm7, xmm7, $B1

  movdqa xmm8, xmm4
  pmuludq xmm8, xmm6
  psllq xmm8, 1
  paddq xmm4, xmm6
  paddq xmm4, xmm8
  movdqa xmm9, xmm5
  pmuludq xmm9, xmm7
  psllq xmm9, 1
  paddq xmm5, xmm7
  paddq xmm5, xmm9

  pxor xmm2, xmm4
  db $66, $41, $0F, $38, $00, $D2               // pshufb xmm2, xmm10
  pxor xmm3, xmm5
  db $66, $41, $0F, $38, $00, $DA               // pshufb xmm3, xmm10

  movdqa xmm8, xmm0
  pmuludq xmm8, xmm2
  psllq xmm8, 1
  paddq xmm0, xmm2
  paddq xmm0, xmm8
  movdqa xmm9, xmm1
  pmuludq xmm9, xmm3
  psllq xmm9, 1
  paddq xmm1, xmm3
  paddq xmm1, xmm9

  pxor xmm6, xmm0
  db $66, $41, $0F, $38, $00, $F3               // pshufb xmm6, xmm11
  pxor xmm7, xmm1
  db $66, $41, $0F, $38, $00, $FB               // pshufb xmm7, xmm11

  movdqa xmm8, xmm4
  pmuludq xmm8, xmm6
  psllq xmm8, 1
  paddq xmm4, xmm6
  paddq xmm4, xmm8
  movdqa xmm9, xmm5
  pmuludq xmm9, xmm7
  psllq xmm9, 1
  paddq xmm5, xmm7
  paddq xmm5, xmm9

  pxor xmm2, xmm4
  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  pxor xmm3, xmm5
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // ----- Undiagonalize -----
  movdqa xmm8, xmm3
  shufpd xmm3, xmm2, 1
  shufpd xmm2, xmm8, 1
  movdqa xmm8, xmm2
  movdqa xmm2, xmm3
  movdqa xmm3, xmm8

  movdqa xmm8, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm8

  movdqa xmm8, xmm6
  shufpd xmm6, xmm7, 1
  shufpd xmm7, xmm8, 1

  // ----- Store back to Z_buf at stride offsets -----
  movdqu oword [r11 + r10], xmm0
  movdqu oword [r11 + r10 + 128], xmm1
  movdqu oword [r11 + r10 + 256], xmm2
  movdqu oword [r11 + r10 + 384], xmm3
  movdqu oword [r11 + r10 + 512], xmm4
  movdqu oword [r11 + r10 + 640], xmm5
  movdqu oword [r11 + r10 + 768], xmm6
  movdqu oword [r11 + r10 + 896], xmm7

  add r10, 16
  cmp r10, 128
  jb @row_loop

  // =========================================================================
  // Step 5: Final XOR - Current = R_buf XOR Z_buf [XOR Current]
  // =========================================================================
  test r9, r9
  jnz @final_with_xor

  xor r10, r10
@final_noxor_loop:
  movdqu xmm0, oword [rax + r10]
  movdqu xmm1, oword [r11 + r10]
  pxor xmm0, xmm1
  movdqu oword [r8 + r10], xmm0
  add r10, 16
  cmp r10, 1024
  jb @final_noxor_loop
  jmp @epilogue

@final_with_xor:
  xor r10, r10
@final_xor_loop:
  movdqu xmm0, oword [rax + r10]
  movdqu xmm1, oword [r11 + r10]
  movdqu xmm2, oword [r8 + r10]
  pxor xmm0, xmm1
  pxor xmm0, xmm2
  movdqu oword [r8 + r10], xmm0
  add r10, 16
  cmp r10, 1024
  jb @final_xor_loop

@epilogue:
  add rsp, 2056

  {$I ..\..\Include\Simd\Common\HlpSimdNonVolatileRestore_x86_64.inc}
