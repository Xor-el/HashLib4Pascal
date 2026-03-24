// AVX2 implementation of Argon2 FillBlock.
// Expects MS x64 ABI: rcx = Left ptr, rdx = Right ptr, r8 = Current ptr, r9 = WithXor (0 or 1).
// Each pointer addresses 128 QWords (1024 bytes).
// Uses ymm0-ymm9. Non-volatile ymm6-ymm9 saved/restored on Windows.
// Register map during G rounds: ymm0 = A(v0..v3), ymm1 = B(v4..v7),
//   ymm2 = C(v8..v11), ymm3 = D(v12..v15), ymm4-ymm5 = temps.
// Stack layout (sub rsp, 2184):
//   [rsp+0..127]    ymm6-9 save area (Windows only, 4 * 32 = 128 bytes)
//   [rsp+128..1151] R_buf (1024 bytes)
//   [rsp+1152..2175] Z_buf (1024 bytes)
//   [rsp+2176..2183] alignment padding
// r8 (Current) and r9 (WithXor) survive all loops (not clobbered).
// ARight and ACurrent may alias; R_buf buffering handles this.
// Diagonalize/Undiagonalize via vpermq (cross-lane 64-bit permute).
// vzeroupper required before return.

  sub rsp, 2184

{$IFDEF MSWINDOWS}
  vmovdqu yword [rsp], ymm6
  vmovdqu yword [rsp + $20], ymm7
  vmovdqu yword [rsp + $40], ymm8
  vmovdqu yword [rsp + $60], ymm9
{$ENDIF}

  // =========================================================================
  // Step 1: Compute R_buf = Left XOR Right, store at [rsp+128]
  // =========================================================================
  lea rax, [rsp + 128]
  xor r10, r10
@xor_loop:
  vmovdqu ymm0, yword [rcx + r10]
  vpxor ymm0, ymm0, yword [rdx + r10]
  vmovdqu yword [rax + r10], ymm0
  add r10, 32
  cmp r10, 1024
  jb @xor_loop

  // =========================================================================
  // Step 2: Copy R_buf to Z_buf at [rsp+1152]
  // =========================================================================
  lea r11, [rsp + 1152]
  xor r10, r10
@copy_loop:
  vmovdqu ymm0, yword [rax + r10]
  vmovdqu yword [r11 + r10], ymm0
  add r10, 32
  cmp r10, 1024
  jb @copy_loop

  // =========================================================================
  // Step 3: Column rounds on Z_buf (8 iterations, 16 QWords = 128 bytes each)
  // =========================================================================
  // Each iteration: load 4 ywords (128 bytes) into ymm0-3 (A,B,C,D),
  // apply BLAKE2_ROUND_NOMSG (columns + diagonals), store back.
  xor r10, r10

@col_loop:
  vmovdqu ymm0, yword [r11 + r10]
  vmovdqu ymm1, yword [r11 + r10 + $20]
  vmovdqu ymm2, yword [r11 + r10 + $40]
  vmovdqu ymm3, yword [r11 + r10 + $60]

  // ----- Column G: G(A,B,C,D) across all 4 lanes -----

  // fBlaMka(a, b): a = a + b + 2*lo32(a)*lo32(b)
  vpmuludq ymm4, ymm0, ymm1
  vpsllq ymm4, ymm4, 1
  vpaddq ymm0, ymm0, ymm1
  vpaddq ymm0, ymm0, ymm4

  // d = rotr64(d ^ a, 32)
  vpxor ymm3, ymm3, ymm0
  vpshufd ymm3, ymm3, $B1

  // fBlaMka(c, d)
  vpmuludq ymm4, ymm2, ymm3
  vpsllq ymm4, ymm4, 1
  vpaddq ymm2, ymm2, ymm3
  vpaddq ymm2, ymm2, ymm4

  // b = rotr64(b ^ c, 24)
  vpxor ymm1, ymm1, ymm2
  vpsrlq ymm4, ymm1, 24
  vpsllq ymm1, ymm1, 40
  vpor ymm1, ymm1, ymm4

  // fBlaMka(a, b)
  vpmuludq ymm4, ymm0, ymm1
  vpsllq ymm4, ymm4, 1
  vpaddq ymm0, ymm0, ymm1
  vpaddq ymm0, ymm0, ymm4

  // d = rotr64(d ^ a, 16)
  vpxor ymm3, ymm3, ymm0
  vpsrlq ymm4, ymm3, 16
  vpsllq ymm3, ymm3, 48
  vpor ymm3, ymm3, ymm4

  // fBlaMka(c, d)
  vpmuludq ymm4, ymm2, ymm3
  vpsllq ymm4, ymm4, 1
  vpaddq ymm2, ymm2, ymm3
  vpaddq ymm2, ymm2, ymm4

  // b = rotr64(b ^ c, 63)
  vpxor ymm1, ymm1, ymm2
  vpsrlq ymm4, ymm1, 63
  vpaddq ymm1, ymm1, ymm1
  vpor ymm1, ymm1, ymm4

  // ----- Diagonalize -----
  // B: rotate left by 1 QWord position
  vpermq ymm1, ymm1, $39
  // C: swap halves (rotate by 2)
  vpermq ymm2, ymm2, $4E
  // D: rotate right by 1 QWord position
  vpermq ymm3, ymm3, $93

  // ----- Diagonal G -----

  vpmuludq ymm4, ymm0, ymm1
  vpsllq ymm4, ymm4, 1
  vpaddq ymm0, ymm0, ymm1
  vpaddq ymm0, ymm0, ymm4

  vpxor ymm3, ymm3, ymm0
  vpshufd ymm3, ymm3, $B1

  vpmuludq ymm4, ymm2, ymm3
  vpsllq ymm4, ymm4, 1
  vpaddq ymm2, ymm2, ymm3
  vpaddq ymm2, ymm2, ymm4

  vpxor ymm1, ymm1, ymm2
  vpsrlq ymm4, ymm1, 24
  vpsllq ymm1, ymm1, 40
  vpor ymm1, ymm1, ymm4

  vpmuludq ymm4, ymm0, ymm1
  vpsllq ymm4, ymm4, 1
  vpaddq ymm0, ymm0, ymm1
  vpaddq ymm0, ymm0, ymm4

  vpxor ymm3, ymm3, ymm0
  vpsrlq ymm4, ymm3, 16
  vpsllq ymm3, ymm3, 48
  vpor ymm3, ymm3, ymm4

  vpmuludq ymm4, ymm2, ymm3
  vpsllq ymm4, ymm4, 1
  vpaddq ymm2, ymm2, ymm3
  vpaddq ymm2, ymm2, ymm4

  vpxor ymm1, ymm1, ymm2
  vpsrlq ymm4, ymm1, 63
  vpaddq ymm1, ymm1, ymm1
  vpor ymm1, ymm1, ymm4

  // ----- Undiagonalize -----
  vpermq ymm1, ymm1, $93
  vpermq ymm2, ymm2, $4E
  vpermq ymm3, ymm3, $39

  // ----- Store back to Z_buf -----
  vmovdqu yword [r11 + r10], ymm0
  vmovdqu yword [r11 + r10 + $20], ymm1
  vmovdqu yword [r11 + r10 + $40], ymm2
  vmovdqu yword [r11 + r10 + $60], ymm3

  add r10, 128
  cmp r10, 1024
  jb @col_loop

  // =========================================================================
  // Step 4: Row rounds on Z_buf (8 iterations, stride-16 QWord access)
  // =========================================================================
  // Row i: Z[2i,2i+1, 2i+16,2i+17, 2i+32,2i+33, 2i+48,2i+49,
  //          2i+64,2i+65, 2i+80,2i+81, 2i+96,2i+97, 2i+112,2i+113]
  // Load via vmovdqu xmm + vinserti128 to gather non-contiguous pairs.
  // Stride between pairs = 128 bytes.
  // ymm0 = A = (Z[2i..2i+1], Z[2i+16..2i+17])
  // ymm1 = B = (Z[2i+32..2i+33], Z[2i+48..2i+49])
  // ymm2 = C = (Z[2i+64..2i+65], Z[2i+80..2i+81])
  // ymm3 = D = (Z[2i+96..2i+97], Z[2i+112..2i+113])
  xor r10, r10

@row_loop:
  vmovdqu xmm0, oword [r11 + r10]
  vinserti128 ymm0, ymm0, oword [r11 + r10 + 128], 1
  vmovdqu xmm1, oword [r11 + r10 + 256]
  vinserti128 ymm1, ymm1, oword [r11 + r10 + 384], 1
  vmovdqu xmm2, oword [r11 + r10 + 512]
  vinserti128 ymm2, ymm2, oword [r11 + r10 + 640], 1
  vmovdqu xmm3, oword [r11 + r10 + 768]
  vinserti128 ymm3, ymm3, oword [r11 + r10 + 896], 1

  // ----- Column G -----

  vpmuludq ymm4, ymm0, ymm1
  vpsllq ymm4, ymm4, 1
  vpaddq ymm0, ymm0, ymm1
  vpaddq ymm0, ymm0, ymm4

  vpxor ymm3, ymm3, ymm0
  vpshufd ymm3, ymm3, $B1

  vpmuludq ymm4, ymm2, ymm3
  vpsllq ymm4, ymm4, 1
  vpaddq ymm2, ymm2, ymm3
  vpaddq ymm2, ymm2, ymm4

  vpxor ymm1, ymm1, ymm2
  vpsrlq ymm4, ymm1, 24
  vpsllq ymm1, ymm1, 40
  vpor ymm1, ymm1, ymm4

  vpmuludq ymm4, ymm0, ymm1
  vpsllq ymm4, ymm4, 1
  vpaddq ymm0, ymm0, ymm1
  vpaddq ymm0, ymm0, ymm4

  vpxor ymm3, ymm3, ymm0
  vpsrlq ymm4, ymm3, 16
  vpsllq ymm3, ymm3, 48
  vpor ymm3, ymm3, ymm4

  vpmuludq ymm4, ymm2, ymm3
  vpsllq ymm4, ymm4, 1
  vpaddq ymm2, ymm2, ymm3
  vpaddq ymm2, ymm2, ymm4

  vpxor ymm1, ymm1, ymm2
  vpsrlq ymm4, ymm1, 63
  vpaddq ymm1, ymm1, ymm1
  vpor ymm1, ymm1, ymm4

  // ----- Diagonalize -----
  vpermq ymm1, ymm1, $39
  vpermq ymm2, ymm2, $4E
  vpermq ymm3, ymm3, $93

  // ----- Diagonal G -----

  vpmuludq ymm4, ymm0, ymm1
  vpsllq ymm4, ymm4, 1
  vpaddq ymm0, ymm0, ymm1
  vpaddq ymm0, ymm0, ymm4

  vpxor ymm3, ymm3, ymm0
  vpshufd ymm3, ymm3, $B1

  vpmuludq ymm4, ymm2, ymm3
  vpsllq ymm4, ymm4, 1
  vpaddq ymm2, ymm2, ymm3
  vpaddq ymm2, ymm2, ymm4

  vpxor ymm1, ymm1, ymm2
  vpsrlq ymm4, ymm1, 24
  vpsllq ymm1, ymm1, 40
  vpor ymm1, ymm1, ymm4

  vpmuludq ymm4, ymm0, ymm1
  vpsllq ymm4, ymm4, 1
  vpaddq ymm0, ymm0, ymm1
  vpaddq ymm0, ymm0, ymm4

  vpxor ymm3, ymm3, ymm0
  vpsrlq ymm4, ymm3, 16
  vpsllq ymm3, ymm3, 48
  vpor ymm3, ymm3, ymm4

  vpmuludq ymm4, ymm2, ymm3
  vpsllq ymm4, ymm4, 1
  vpaddq ymm2, ymm2, ymm3
  vpaddq ymm2, ymm2, ymm4

  vpxor ymm1, ymm1, ymm2
  vpsrlq ymm4, ymm1, 63
  vpaddq ymm1, ymm1, ymm1
  vpor ymm1, ymm1, ymm4

  // ----- Undiagonalize -----
  vpermq ymm1, ymm1, $93
  vpermq ymm2, ymm2, $4E
  vpermq ymm3, ymm3, $39

  // ----- Store back to Z_buf (scatter to stride offsets) -----
  vmovdqu oword [r11 + r10], xmm0
  vextracti128 oword [r11 + r10 + 128], ymm0, 1
  vmovdqu oword [r11 + r10 + 256], xmm1
  vextracti128 oword [r11 + r10 + 384], ymm1, 1
  vmovdqu oword [r11 + r10 + 512], xmm2
  vextracti128 oword [r11 + r10 + 640], ymm2, 1
  vmovdqu oword [r11 + r10 + 768], xmm3
  vextracti128 oword [r11 + r10 + 896], ymm3, 1

  add r10, 16
  cmp r10, 128
  jb @row_loop

  // =========================================================================
  // Step 5: Final XOR — Current = R_buf XOR Z_buf [XOR Current]
  // =========================================================================
  test r9, r9
  jnz @final_with_xor

  xor r10, r10
@final_noxor_loop:
  vmovdqu ymm0, yword [rax + r10]
  vpxor ymm0, ymm0, yword [r11 + r10]
  vmovdqu yword [r8 + r10], ymm0
  add r10, 32
  cmp r10, 1024
  jb @final_noxor_loop
  jmp @epilogue

@final_with_xor:
  xor r10, r10
@final_xor_loop:
  vmovdqu ymm0, yword [rax + r10]
  vpxor ymm0, ymm0, yword [r11 + r10]
  vpxor ymm0, ymm0, yword [r8 + r10]
  vmovdqu yword [r8 + r10], ymm0
  add r10, 32
  cmp r10, 1024
  jb @final_xor_loop

@epilogue:
{$IFDEF MSWINDOWS}
  vmovdqu ymm6, yword [rsp]
  vmovdqu ymm7, yword [rsp + $20]
  vmovdqu ymm8, yword [rsp + $40]
  vmovdqu ymm9, yword [rsp + $60]
{$ENDIF}

  add rsp, 2184
  vzeroupper
