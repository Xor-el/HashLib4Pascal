// AVX2 implementation of BLAKE3 compress (VEX-encoded 128-bit, 7 rounds with register-based
// message scheduling).
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.
// Reference: BLAKE3-team/BLAKE3 official SSE2/AVX2 implementation.
// Expects MS x64 ABI: rcx = state ptr, rdx = msg ptr, r8 = CV ptr, r9 = counterflags ptr.
// Register map: xmm0 = a, xmm1 = b, xmm2 = c, xmm3 = d,
//   xmm4 = m0, xmm5 = m1, xmm6 = m2, xmm7 = m3, xmm8/xmm9 = temp, xmm11/xmm14 = temp.
// 3-operand VEX form eliminates movdqa copies needed in SSE2 rotations.
// Blend emulations use vshufps+vpshufd (blend_0xCC) and vpunpckhdq+vshufps (blend_0xC0),
// avoiding the need for mask constants.

{$IFDEF MSWINDOWS}
  sub rsp, 120
  db $C5, $F9, $7F, $34, $24                    // vmovdqa oword [rsp], xmm6
  db $C5, $F9, $7F, $7C, $24, $10               // vmovdqa oword [rsp + $10], xmm7
  db $C5, $79, $7F, $44, $24, $20               // vmovdqa oword [rsp + $20], xmm8
  db $C5, $79, $7F, $4C, $24, $30               // vmovdqa oword [rsp + $30], xmm9
  db $C5, $79, $7F, $5C, $24, $40               // vmovdqa oword [rsp + $40], xmm11
  db $C5, $79, $7F, $74, $24, $50               // vmovdqa oword [rsp + $50], xmm14

  mov eax, $6A09E667
  mov dword ptr [rsp + $60], eax
  mov eax, $BB67AE85
  mov dword ptr [rsp + $64], eax
  mov eax, $3C6EF372
  mov dword ptr [rsp + $68], eax
  mov eax, $A54FF53A
  mov dword ptr [rsp + $6C], eax
  db $C5, $F9, $6F, $54, $24, $60               // vmovdqa xmm2, oword [rsp + $60]
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
  db $C5, $F9, $6F, $14, $24                    // vmovdqa xmm2, oword [rsp]
{$ENDIF}

  // Initialize state
  db $C4, $C1, $7A, $6F, $00                    // vmovdqu xmm0, oword [r8]
  db $C4, $C1, $7A, $6F, $48, $10               // vmovdqu xmm1, oword [r8 + $10]
  db $C4, $C1, $7A, $6F, $19                    // vmovdqu xmm3, oword [r9]

  // Load and reorder message
  db $C5, $FA, $6F, $22                         // vmovdqu xmm4, oword [rdx]
  db $C5, $FA, $6F, $6A, $10                    // vmovdqu xmm5, oword [rdx + $10]
  db $C5, $79, $6F, $C4                         // vmovdqa xmm8, xmm4
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $38, $C6, $C5, $DD                    // vshufps xmm8, xmm8, xmm5, $DD
  db $C5, $79, $7F, $C5                         // vmovdqa xmm5, xmm8

  db $C5, $FA, $6F, $72, $20                    // vmovdqu xmm6, oword [rdx + $20]
  db $C5, $FA, $6F, $7A, $30                    // vmovdqu xmm7, oword [rdx + $30]
  db $C5, $79, $6F, $C6                         // vmovdqa xmm8, xmm6
  db $C5, $C8, $C6, $F7, $88                    // vshufps xmm6, xmm6, xmm7, $88
  db $C5, $F9, $70, $F6, $93                    // vpshufd xmm6, xmm6, $93
  db $C5, $38, $C6, $C7, $DD                    // vshufps xmm8, xmm8, xmm7, $DD
  db $C4, $C1, $79, $70, $F8, $93               // vpshufd xmm7, xmm8, $93

  // ===== Round 0 =====

  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $FB, $70, $DB, $B1                    // vpshuflw xmm3, xmm3, $B1
  db $C5, $FA, $70, $DB, $B1                    // vpshufhw xmm3, xmm3, $B1
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $14                    // vpslld xmm11, xmm1, 20
  db $C5, $F1, $72, $D1, $0C                    // vpsrld xmm1, xmm1, 12
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $FE, $C5                         // vpaddd xmm0, xmm0, xmm5
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $89, $72, $D3, $08                    // vpsrld xmm14, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C4, $C1, $61, $EF, $DE                    // vpxor xmm3, xmm3, xmm14
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $19                    // vpslld xmm11, xmm1, 25
  db $C5, $F1, $72, $D1, $07                    // vpsrld xmm1, xmm1, 7
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  db $C5, $F9, $FE, $C6                         // vpaddd xmm0, xmm0, xmm6
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $FB, $70, $DB, $B1                    // vpshuflw xmm3, xmm3, $B1
  db $C5, $FA, $70, $DB, $B1                    // vpshufhw xmm3, xmm3, $B1
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $14                    // vpslld xmm11, xmm1, 20
  db $C5, $F1, $72, $D1, $0C                    // vpsrld xmm1, xmm1, 12
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $FE, $C7                         // vpaddd xmm0, xmm0, xmm7
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $89, $72, $D3, $08                    // vpsrld xmm14, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C4, $C1, $61, $EF, $DE                    // vpxor xmm3, xmm3, xmm14
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $19                    // vpslld xmm11, xmm1, 25
  db $C5, $F1, $72, $D1, $07                    // vpsrld xmm1, xmm1, 7
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Message Permutation 0->1 =====
  db $C5, $79, $6F, $C4                         // vmovdqa xmm8, xmm4
  db $C5, $38, $C6, $C5, $D6                    // vshufps xmm8, xmm8, xmm5, $D6
  db $C5, $79, $70, $CC, $0F                    // vpshufd xmm9, xmm4, $0F
  db $C4, $C1, $79, $70, $E0, $39               // vpshufd xmm4, xmm8, $39
  db $C5, $79, $6F, $C6                         // vmovdqa xmm8, xmm6
  db $C5, $38, $C6, $C7, $FA                    // vshufps xmm8, xmm8, xmm7, $FA
  db $C4, $41, $30, $C6, $C8, $D8               // vshufps xmm9, xmm9, xmm8, $D8
  db $C4, $41, $79, $70, $C9, $D8               // vpshufd xmm9, xmm9, $D8
  db $C5, $79, $6F, $C7                         // vmovdqa xmm8, xmm7
  db $C5, $39, $6C, $C5                         // vpunpcklqdq xmm8, xmm8, xmm5
  db $C4, $41, $79, $6F, $F0                    // vmovdqa xmm14, xmm8
  db $C5, $09, $6A, $F6                         // vpunpckhdq xmm14, xmm14, xmm6
  db $C4, $41, $38, $C6, $C6, $C4               // vshufps xmm8, xmm8, xmm14, $C4
  db $C4, $41, $79, $70, $C0, $78               // vpshufd xmm8, xmm8, $78
  db $C5, $D1, $6A, $EF                         // vpunpckhdq xmm5, xmm5, xmm7
  db $C5, $C9, $62, $F5                         // vpunpckldq xmm6, xmm6, xmm5
  db $C5, $F9, $70, $FE, $1E                    // vpshufd xmm7, xmm6, $1E
  db $C5, $79, $7F, $CD                         // vmovdqa xmm5, xmm9
  db $C5, $79, $7F, $C6                         // vmovdqa xmm6, xmm8

  // ===== Round 1 =====

  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $FB, $70, $DB, $B1                    // vpshuflw xmm3, xmm3, $B1
  db $C5, $FA, $70, $DB, $B1                    // vpshufhw xmm3, xmm3, $B1
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $14                    // vpslld xmm11, xmm1, 20
  db $C5, $F1, $72, $D1, $0C                    // vpsrld xmm1, xmm1, 12
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $FE, $C5                         // vpaddd xmm0, xmm0, xmm5
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $89, $72, $D3, $08                    // vpsrld xmm14, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C4, $C1, $61, $EF, $DE                    // vpxor xmm3, xmm3, xmm14
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $19                    // vpslld xmm11, xmm1, 25
  db $C5, $F1, $72, $D1, $07                    // vpsrld xmm1, xmm1, 7
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  db $C5, $F9, $FE, $C6                         // vpaddd xmm0, xmm0, xmm6
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $FB, $70, $DB, $B1                    // vpshuflw xmm3, xmm3, $B1
  db $C5, $FA, $70, $DB, $B1                    // vpshufhw xmm3, xmm3, $B1
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $14                    // vpslld xmm11, xmm1, 20
  db $C5, $F1, $72, $D1, $0C                    // vpsrld xmm1, xmm1, 12
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $FE, $C7                         // vpaddd xmm0, xmm0, xmm7
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $89, $72, $D3, $08                    // vpsrld xmm14, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C4, $C1, $61, $EF, $DE                    // vpxor xmm3, xmm3, xmm14
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $19                    // vpslld xmm11, xmm1, 25
  db $C5, $F1, $72, $D1, $07                    // vpsrld xmm1, xmm1, 7
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Message Permutation 1->2 =====
  db $C5, $79, $6F, $C4                         // vmovdqa xmm8, xmm4
  db $C5, $38, $C6, $C5, $D6                    // vshufps xmm8, xmm8, xmm5, $D6
  db $C5, $79, $70, $CC, $0F                    // vpshufd xmm9, xmm4, $0F
  db $C4, $C1, $79, $70, $E0, $39               // vpshufd xmm4, xmm8, $39
  db $C5, $79, $6F, $C6                         // vmovdqa xmm8, xmm6
  db $C5, $38, $C6, $C7, $FA                    // vshufps xmm8, xmm8, xmm7, $FA
  db $C4, $41, $30, $C6, $C8, $D8               // vshufps xmm9, xmm9, xmm8, $D8
  db $C4, $41, $79, $70, $C9, $D8               // vpshufd xmm9, xmm9, $D8
  db $C5, $79, $6F, $C7                         // vmovdqa xmm8, xmm7
  db $C5, $39, $6C, $C5                         // vpunpcklqdq xmm8, xmm8, xmm5
  db $C4, $41, $79, $6F, $F0                    // vmovdqa xmm14, xmm8
  db $C5, $09, $6A, $F6                         // vpunpckhdq xmm14, xmm14, xmm6
  db $C4, $41, $38, $C6, $C6, $C4               // vshufps xmm8, xmm8, xmm14, $C4
  db $C4, $41, $79, $70, $C0, $78               // vpshufd xmm8, xmm8, $78
  db $C5, $D1, $6A, $EF                         // vpunpckhdq xmm5, xmm5, xmm7
  db $C5, $C9, $62, $F5                         // vpunpckldq xmm6, xmm6, xmm5
  db $C5, $F9, $70, $FE, $1E                    // vpshufd xmm7, xmm6, $1E
  db $C5, $79, $7F, $CD                         // vmovdqa xmm5, xmm9
  db $C5, $79, $7F, $C6                         // vmovdqa xmm6, xmm8

  // ===== Round 2 =====

  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $FB, $70, $DB, $B1                    // vpshuflw xmm3, xmm3, $B1
  db $C5, $FA, $70, $DB, $B1                    // vpshufhw xmm3, xmm3, $B1
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $14                    // vpslld xmm11, xmm1, 20
  db $C5, $F1, $72, $D1, $0C                    // vpsrld xmm1, xmm1, 12
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $FE, $C5                         // vpaddd xmm0, xmm0, xmm5
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $89, $72, $D3, $08                    // vpsrld xmm14, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C4, $C1, $61, $EF, $DE                    // vpxor xmm3, xmm3, xmm14
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $19                    // vpslld xmm11, xmm1, 25
  db $C5, $F1, $72, $D1, $07                    // vpsrld xmm1, xmm1, 7
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  db $C5, $F9, $FE, $C6                         // vpaddd xmm0, xmm0, xmm6
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $FB, $70, $DB, $B1                    // vpshuflw xmm3, xmm3, $B1
  db $C5, $FA, $70, $DB, $B1                    // vpshufhw xmm3, xmm3, $B1
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $14                    // vpslld xmm11, xmm1, 20
  db $C5, $F1, $72, $D1, $0C                    // vpsrld xmm1, xmm1, 12
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $FE, $C7                         // vpaddd xmm0, xmm0, xmm7
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $89, $72, $D3, $08                    // vpsrld xmm14, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C4, $C1, $61, $EF, $DE                    // vpxor xmm3, xmm3, xmm14
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $19                    // vpslld xmm11, xmm1, 25
  db $C5, $F1, $72, $D1, $07                    // vpsrld xmm1, xmm1, 7
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Message Permutation 2->3 =====
  db $C5, $79, $6F, $C4                         // vmovdqa xmm8, xmm4
  db $C5, $38, $C6, $C5, $D6                    // vshufps xmm8, xmm8, xmm5, $D6
  db $C5, $79, $70, $CC, $0F                    // vpshufd xmm9, xmm4, $0F
  db $C4, $C1, $79, $70, $E0, $39               // vpshufd xmm4, xmm8, $39
  db $C5, $79, $6F, $C6                         // vmovdqa xmm8, xmm6
  db $C5, $38, $C6, $C7, $FA                    // vshufps xmm8, xmm8, xmm7, $FA
  db $C4, $41, $30, $C6, $C8, $D8               // vshufps xmm9, xmm9, xmm8, $D8
  db $C4, $41, $79, $70, $C9, $D8               // vpshufd xmm9, xmm9, $D8
  db $C5, $79, $6F, $C7                         // vmovdqa xmm8, xmm7
  db $C5, $39, $6C, $C5                         // vpunpcklqdq xmm8, xmm8, xmm5
  db $C4, $41, $79, $6F, $F0                    // vmovdqa xmm14, xmm8
  db $C5, $09, $6A, $F6                         // vpunpckhdq xmm14, xmm14, xmm6
  db $C4, $41, $38, $C6, $C6, $C4               // vshufps xmm8, xmm8, xmm14, $C4
  db $C4, $41, $79, $70, $C0, $78               // vpshufd xmm8, xmm8, $78
  db $C5, $D1, $6A, $EF                         // vpunpckhdq xmm5, xmm5, xmm7
  db $C5, $C9, $62, $F5                         // vpunpckldq xmm6, xmm6, xmm5
  db $C5, $F9, $70, $FE, $1E                    // vpshufd xmm7, xmm6, $1E
  db $C5, $79, $7F, $CD                         // vmovdqa xmm5, xmm9
  db $C5, $79, $7F, $C6                         // vmovdqa xmm6, xmm8

  // ===== Round 3 =====

  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $FB, $70, $DB, $B1                    // vpshuflw xmm3, xmm3, $B1
  db $C5, $FA, $70, $DB, $B1                    // vpshufhw xmm3, xmm3, $B1
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $14                    // vpslld xmm11, xmm1, 20
  db $C5, $F1, $72, $D1, $0C                    // vpsrld xmm1, xmm1, 12
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $FE, $C5                         // vpaddd xmm0, xmm0, xmm5
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $89, $72, $D3, $08                    // vpsrld xmm14, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C4, $C1, $61, $EF, $DE                    // vpxor xmm3, xmm3, xmm14
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $19                    // vpslld xmm11, xmm1, 25
  db $C5, $F1, $72, $D1, $07                    // vpsrld xmm1, xmm1, 7
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  db $C5, $F9, $FE, $C6                         // vpaddd xmm0, xmm0, xmm6
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $FB, $70, $DB, $B1                    // vpshuflw xmm3, xmm3, $B1
  db $C5, $FA, $70, $DB, $B1                    // vpshufhw xmm3, xmm3, $B1
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $14                    // vpslld xmm11, xmm1, 20
  db $C5, $F1, $72, $D1, $0C                    // vpsrld xmm1, xmm1, 12
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $FE, $C7                         // vpaddd xmm0, xmm0, xmm7
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $89, $72, $D3, $08                    // vpsrld xmm14, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C4, $C1, $61, $EF, $DE                    // vpxor xmm3, xmm3, xmm14
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $19                    // vpslld xmm11, xmm1, 25
  db $C5, $F1, $72, $D1, $07                    // vpsrld xmm1, xmm1, 7
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Message Permutation 3->4 =====
  db $C5, $79, $6F, $C4                         // vmovdqa xmm8, xmm4
  db $C5, $38, $C6, $C5, $D6                    // vshufps xmm8, xmm8, xmm5, $D6
  db $C5, $79, $70, $CC, $0F                    // vpshufd xmm9, xmm4, $0F
  db $C4, $C1, $79, $70, $E0, $39               // vpshufd xmm4, xmm8, $39
  db $C5, $79, $6F, $C6                         // vmovdqa xmm8, xmm6
  db $C5, $38, $C6, $C7, $FA                    // vshufps xmm8, xmm8, xmm7, $FA
  db $C4, $41, $30, $C6, $C8, $D8               // vshufps xmm9, xmm9, xmm8, $D8
  db $C4, $41, $79, $70, $C9, $D8               // vpshufd xmm9, xmm9, $D8
  db $C5, $79, $6F, $C7                         // vmovdqa xmm8, xmm7
  db $C5, $39, $6C, $C5                         // vpunpcklqdq xmm8, xmm8, xmm5
  db $C4, $41, $79, $6F, $F0                    // vmovdqa xmm14, xmm8
  db $C5, $09, $6A, $F6                         // vpunpckhdq xmm14, xmm14, xmm6
  db $C4, $41, $38, $C6, $C6, $C4               // vshufps xmm8, xmm8, xmm14, $C4
  db $C4, $41, $79, $70, $C0, $78               // vpshufd xmm8, xmm8, $78
  db $C5, $D1, $6A, $EF                         // vpunpckhdq xmm5, xmm5, xmm7
  db $C5, $C9, $62, $F5                         // vpunpckldq xmm6, xmm6, xmm5
  db $C5, $F9, $70, $FE, $1E                    // vpshufd xmm7, xmm6, $1E
  db $C5, $79, $7F, $CD                         // vmovdqa xmm5, xmm9
  db $C5, $79, $7F, $C6                         // vmovdqa xmm6, xmm8

  // ===== Round 4 =====

  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $FB, $70, $DB, $B1                    // vpshuflw xmm3, xmm3, $B1
  db $C5, $FA, $70, $DB, $B1                    // vpshufhw xmm3, xmm3, $B1
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $14                    // vpslld xmm11, xmm1, 20
  db $C5, $F1, $72, $D1, $0C                    // vpsrld xmm1, xmm1, 12
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $FE, $C5                         // vpaddd xmm0, xmm0, xmm5
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $89, $72, $D3, $08                    // vpsrld xmm14, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C4, $C1, $61, $EF, $DE                    // vpxor xmm3, xmm3, xmm14
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $19                    // vpslld xmm11, xmm1, 25
  db $C5, $F1, $72, $D1, $07                    // vpsrld xmm1, xmm1, 7
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  db $C5, $F9, $FE, $C6                         // vpaddd xmm0, xmm0, xmm6
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $FB, $70, $DB, $B1                    // vpshuflw xmm3, xmm3, $B1
  db $C5, $FA, $70, $DB, $B1                    // vpshufhw xmm3, xmm3, $B1
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $14                    // vpslld xmm11, xmm1, 20
  db $C5, $F1, $72, $D1, $0C                    // vpsrld xmm1, xmm1, 12
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $FE, $C7                         // vpaddd xmm0, xmm0, xmm7
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $89, $72, $D3, $08                    // vpsrld xmm14, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C4, $C1, $61, $EF, $DE                    // vpxor xmm3, xmm3, xmm14
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $19                    // vpslld xmm11, xmm1, 25
  db $C5, $F1, $72, $D1, $07                    // vpsrld xmm1, xmm1, 7
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Message Permutation 4->5 =====
  db $C5, $79, $6F, $C4                         // vmovdqa xmm8, xmm4
  db $C5, $38, $C6, $C5, $D6                    // vshufps xmm8, xmm8, xmm5, $D6
  db $C5, $79, $70, $CC, $0F                    // vpshufd xmm9, xmm4, $0F
  db $C4, $C1, $79, $70, $E0, $39               // vpshufd xmm4, xmm8, $39
  db $C5, $79, $6F, $C6                         // vmovdqa xmm8, xmm6
  db $C5, $38, $C6, $C7, $FA                    // vshufps xmm8, xmm8, xmm7, $FA
  db $C4, $41, $30, $C6, $C8, $D8               // vshufps xmm9, xmm9, xmm8, $D8
  db $C4, $41, $79, $70, $C9, $D8               // vpshufd xmm9, xmm9, $D8
  db $C5, $79, $6F, $C7                         // vmovdqa xmm8, xmm7
  db $C5, $39, $6C, $C5                         // vpunpcklqdq xmm8, xmm8, xmm5
  db $C4, $41, $79, $6F, $F0                    // vmovdqa xmm14, xmm8
  db $C5, $09, $6A, $F6                         // vpunpckhdq xmm14, xmm14, xmm6
  db $C4, $41, $38, $C6, $C6, $C4               // vshufps xmm8, xmm8, xmm14, $C4
  db $C4, $41, $79, $70, $C0, $78               // vpshufd xmm8, xmm8, $78
  db $C5, $D1, $6A, $EF                         // vpunpckhdq xmm5, xmm5, xmm7
  db $C5, $C9, $62, $F5                         // vpunpckldq xmm6, xmm6, xmm5
  db $C5, $F9, $70, $FE, $1E                    // vpshufd xmm7, xmm6, $1E
  db $C5, $79, $7F, $CD                         // vmovdqa xmm5, xmm9
  db $C5, $79, $7F, $C6                         // vmovdqa xmm6, xmm8

  // ===== Round 5 =====

  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $FB, $70, $DB, $B1                    // vpshuflw xmm3, xmm3, $B1
  db $C5, $FA, $70, $DB, $B1                    // vpshufhw xmm3, xmm3, $B1
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $14                    // vpslld xmm11, xmm1, 20
  db $C5, $F1, $72, $D1, $0C                    // vpsrld xmm1, xmm1, 12
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $FE, $C5                         // vpaddd xmm0, xmm0, xmm5
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $89, $72, $D3, $08                    // vpsrld xmm14, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C4, $C1, $61, $EF, $DE                    // vpxor xmm3, xmm3, xmm14
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $19                    // vpslld xmm11, xmm1, 25
  db $C5, $F1, $72, $D1, $07                    // vpsrld xmm1, xmm1, 7
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  db $C5, $F9, $FE, $C6                         // vpaddd xmm0, xmm0, xmm6
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $FB, $70, $DB, $B1                    // vpshuflw xmm3, xmm3, $B1
  db $C5, $FA, $70, $DB, $B1                    // vpshufhw xmm3, xmm3, $B1
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $14                    // vpslld xmm11, xmm1, 20
  db $C5, $F1, $72, $D1, $0C                    // vpsrld xmm1, xmm1, 12
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $FE, $C7                         // vpaddd xmm0, xmm0, xmm7
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $89, $72, $D3, $08                    // vpsrld xmm14, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C4, $C1, $61, $EF, $DE                    // vpxor xmm3, xmm3, xmm14
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $19                    // vpslld xmm11, xmm1, 25
  db $C5, $F1, $72, $D1, $07                    // vpsrld xmm1, xmm1, 7
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Message Permutation 5->6 =====
  db $C5, $79, $6F, $C4                         // vmovdqa xmm8, xmm4
  db $C5, $38, $C6, $C5, $D6                    // vshufps xmm8, xmm8, xmm5, $D6
  db $C5, $79, $70, $CC, $0F                    // vpshufd xmm9, xmm4, $0F
  db $C4, $C1, $79, $70, $E0, $39               // vpshufd xmm4, xmm8, $39
  db $C5, $79, $6F, $C6                         // vmovdqa xmm8, xmm6
  db $C5, $38, $C6, $C7, $FA                    // vshufps xmm8, xmm8, xmm7, $FA
  db $C4, $41, $30, $C6, $C8, $D8               // vshufps xmm9, xmm9, xmm8, $D8
  db $C4, $41, $79, $70, $C9, $D8               // vpshufd xmm9, xmm9, $D8
  db $C5, $79, $6F, $C7                         // vmovdqa xmm8, xmm7
  db $C5, $39, $6C, $C5                         // vpunpcklqdq xmm8, xmm8, xmm5
  db $C4, $41, $79, $6F, $F0                    // vmovdqa xmm14, xmm8
  db $C5, $09, $6A, $F6                         // vpunpckhdq xmm14, xmm14, xmm6
  db $C4, $41, $38, $C6, $C6, $C4               // vshufps xmm8, xmm8, xmm14, $C4
  db $C4, $41, $79, $70, $C0, $78               // vpshufd xmm8, xmm8, $78
  db $C5, $D1, $6A, $EF                         // vpunpckhdq xmm5, xmm5, xmm7
  db $C5, $C9, $62, $F5                         // vpunpckldq xmm6, xmm6, xmm5
  db $C5, $F9, $70, $FE, $1E                    // vpshufd xmm7, xmm6, $1E
  db $C5, $79, $7F, $CD                         // vmovdqa xmm5, xmm9
  db $C5, $79, $7F, $C6                         // vmovdqa xmm6, xmm8

  // ===== Round 6 =====

  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $FB, $70, $DB, $B1                    // vpshuflw xmm3, xmm3, $B1
  db $C5, $FA, $70, $DB, $B1                    // vpshufhw xmm3, xmm3, $B1
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $14                    // vpslld xmm11, xmm1, 20
  db $C5, $F1, $72, $D1, $0C                    // vpsrld xmm1, xmm1, 12
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $FE, $C5                         // vpaddd xmm0, xmm0, xmm5
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $89, $72, $D3, $08                    // vpsrld xmm14, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C4, $C1, $61, $EF, $DE                    // vpxor xmm3, xmm3, xmm14
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $19                    // vpslld xmm11, xmm1, 25
  db $C5, $F1, $72, $D1, $07                    // vpsrld xmm1, xmm1, 7
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  db $C5, $F9, $FE, $C6                         // vpaddd xmm0, xmm0, xmm6
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $FB, $70, $DB, $B1                    // vpshuflw xmm3, xmm3, $B1
  db $C5, $FA, $70, $DB, $B1                    // vpshufhw xmm3, xmm3, $B1
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $14                    // vpslld xmm11, xmm1, 20
  db $C5, $F1, $72, $D1, $0C                    // vpsrld xmm1, xmm1, 12
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $FE, $C7                         // vpaddd xmm0, xmm0, xmm7
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $89, $72, $D3, $08                    // vpsrld xmm14, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C4, $C1, $61, $EF, $DE                    // vpxor xmm3, xmm3, xmm14
  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $A1, $72, $F1, $19                    // vpslld xmm11, xmm1, 25
  db $C5, $F1, $72, $D1, $07                    // vpsrld xmm1, xmm1, 7
  db $C4, $C1, $71, $EB, $CB                    // vpor xmm1, xmm1, xmm11

  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Finalization =====
  db $C5, $F9, $EF, $C2                         // vpxor xmm0, xmm0, xmm2
  db $C5, $F1, $EF, $CB                         // vpxor xmm1, xmm1, xmm3
  db $C4, $C1, $7A, $6F, $20                    // vmovdqu xmm4, oword [r8]
  db $C4, $C1, $7A, $6F, $68, $10               // vmovdqu xmm5, oword [r8 + $10]
  db $C5, $E9, $EF, $D4                         // vpxor xmm2, xmm2, xmm4
  db $C5, $E1, $EF, $DD                         // vpxor xmm3, xmm3, xmm5

  db $C5, $FA, $7F, $01                         // vmovdqu oword [rcx], xmm0
  db $C5, $FA, $7F, $49, $10                    // vmovdqu oword [rcx + $10], xmm1
  db $C5, $FA, $7F, $51, $20                    // vmovdqu oword [rcx + $20], xmm2
  db $C5, $FA, $7F, $59, $30                    // vmovdqu oword [rcx + $30], xmm3

{$IFDEF MSWINDOWS}
  db $C5, $F9, $6F, $34, $24                    // vmovdqa xmm6, oword [rsp]
  db $C5, $F9, $6F, $7C, $24, $10               // vmovdqa xmm7, oword [rsp + $10]
  db $C5, $79, $6F, $44, $24, $20               // vmovdqa xmm8, oword [rsp + $20]
  db $C5, $79, $6F, $4C, $24, $30               // vmovdqa xmm9, oword [rsp + $30]
  db $C5, $79, $6F, $5C, $24, $40               // vmovdqa xmm11, oword [rsp + $40]
  db $C5, $79, $6F, $74, $24, $50               // vmovdqa xmm14, oword [rsp + $50]
  add rsp, 120
{$ELSE}
  add rsp, 24
{$ENDIF}
