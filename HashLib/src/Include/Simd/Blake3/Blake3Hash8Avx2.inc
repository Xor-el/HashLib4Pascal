// AVX2 implementation of BLAKE3 hash8: processes 8 independent chunks simultaneously.
// Reference: BLAKE3-team/BLAKE3 official AVX2 implementation (blake3_avx2.c / blake3_hash_many).
// Each YMM register holds the same 32-bit word from 8 different chunks (inter-chunk SIMD).
// All VEX instructions are db-encoded for broad assembler compatibility.
// 7 rounds per block fully unrolled; 16-block loop with branch for chunk start/end flags.
//
// After SimdProc6Begin.inc:
//   rcx = AInput, rdx = AKey, r8 = AOut,
//   r9 = ANumChunks, r10 = ACounter, r11 = AFlags
//
// Register map: ymm0-ymm7 = state v0-v7, ymm8-ymm11 = state v8-v11,
//   ymm12-ymm13 = temp, v12-v15 spilled to stack.
// GPR: rcx = input pointer, rbx = block counter (0..15), rbp = block byte offset.
// Message transpose: chunks paired (0+4, 1+5, ...) via vinserti128, then per-lane 4x4.
// Output transpose: full 8x8 via vperm2i128 + vpunpckl/hdq + vpunpcklq/hqdq.
// 3-operand VEX form eliminates movdqa copies needed in SSE2 rotations.
// Stack 32-byte aligned via "and rsp, -32" for YMM movdqu stores.

  push rbx
  push rbp
  push r12

  mov r12, rsp
  and rsp, -32

{$IFDEF MSWINDOWS}
  sub rsp, 1280
  db $C5, $FA, $7F, $B4, $24, $80, $04, $00, $00 // vmovdqu [rsp+1152], xmm6
  db $C5, $FA, $7F, $BC, $24, $90, $04, $00, $00 // vmovdqu [rsp+1168], xmm7
  db $C5, $7A, $7F, $84, $24, $A0, $04, $00, $00 // vmovdqu [rsp+1184], xmm8
  db $C5, $7A, $7F, $8C, $24, $B0, $04, $00, $00 // vmovdqu [rsp+1200], xmm9
  db $C5, $7A, $7F, $94, $24, $C0, $04, $00, $00 // vmovdqu [rsp+1216], xmm10
  db $C5, $7A, $7F, $9C, $24, $D0, $04, $00, $00 // vmovdqu [rsp+1232], xmm11
  db $C5, $7A, $7F, $A4, $24, $E0, $04, $00, $00 // vmovdqu [rsp+1248], xmm12
  db $C5, $7A, $7F, $AC, $24, $F0, $04, $00, $00 // vmovdqu [rsp+1264], xmm13
{$ELSE}
  sub rsp, 1152
{$ENDIF}

  mov qword ptr [rsp + 1136], r12
  mov qword ptr [rsp + 1120], r8
  mov dword ptr [rsp + 1128], r11d

  // Broadcast key words to CV registers
  db $C4, $E2, $7D, $58, $02                 // vpbroadcastd ymm0, [rdx+0]
  db $C4, $E2, $7D, $58, $4A, $04            // vpbroadcastd ymm1, [rdx+4]
  db $C4, $E2, $7D, $58, $52, $08            // vpbroadcastd ymm2, [rdx+8]
  db $C4, $E2, $7D, $58, $5A, $0C            // vpbroadcastd ymm3, [rdx+12]
  db $C4, $E2, $7D, $58, $62, $10            // vpbroadcastd ymm4, [rdx+16]
  db $C4, $E2, $7D, $58, $6A, $14            // vpbroadcastd ymm5, [rdx+20]
  db $C4, $E2, $7D, $58, $72, $18            // vpbroadcastd ymm6, [rdx+24]
  db $C4, $E2, $7D, $58, $7A, $1C            // vpbroadcastd ymm7, [rdx+28]

  // Save initial CV to stack
  db $C5, $FE, $7F, $84, $24, $80, $02, $00, $00 // vmovdqu [rsp+640], ymm0
  db $C5, $FE, $7F, $8C, $24, $A0, $02, $00, $00 // vmovdqu [rsp+672], ymm1
  db $C5, $FE, $7F, $94, $24, $C0, $02, $00, $00 // vmovdqu [rsp+704], ymm2
  db $C5, $FE, $7F, $9C, $24, $E0, $02, $00, $00 // vmovdqu [rsp+736], ymm3
  db $C5, $FE, $7F, $A4, $24, $00, $03, $00, $00 // vmovdqu [rsp+768], ymm4
  db $C5, $FE, $7F, $AC, $24, $20, $03, $00, $00 // vmovdqu [rsp+800], ymm5
  db $C5, $FE, $7F, $B4, $24, $40, $03, $00, $00 // vmovdqu [rsp+832], ymm6
  db $C5, $FE, $7F, $BC, $24, $60, $03, $00, $00 // vmovdqu [rsp+864], ymm7

  // Build counter vectors (r10 = ACounter, 64-bit)
  mov rax, r10
  mov dword ptr [rsp + 896], eax
  shr rax, 32
  mov dword ptr [rsp + 928], eax
  lea rax, [r10 + 1]
  mov dword ptr [rsp + 900], eax
  shr rax, 32
  mov dword ptr [rsp + 932], eax
  lea rax, [r10 + 2]
  mov dword ptr [rsp + 904], eax
  shr rax, 32
  mov dword ptr [rsp + 936], eax
  lea rax, [r10 + 3]
  mov dword ptr [rsp + 908], eax
  shr rax, 32
  mov dword ptr [rsp + 940], eax
  lea rax, [r10 + 4]
  mov dword ptr [rsp + 912], eax
  shr rax, 32
  mov dword ptr [rsp + 944], eax
  lea rax, [r10 + 5]
  mov dword ptr [rsp + 916], eax
  shr rax, 32
  mov dword ptr [rsp + 948], eax
  lea rax, [r10 + 6]
  mov dword ptr [rsp + 920], eax
  shr rax, 32
  mov dword ptr [rsp + 952], eax
  lea rax, [r10 + 7]
  mov dword ptr [rsp + 924], eax
  shr rax, 32
  mov dword ptr [rsp + 956], eax

  // Pre-compute IV broadcast vectors
  mov eax, $6A09E667
  db $C5, $79, $6E, $E0                      // vmovd xmm12, eax
  db $C4, $42, $7D, $58, $E4                 // vpbroadcastd ymm12, xmm12
  db $C5, $7E, $7F, $A4, $24, $C0, $03, $00, $00 // vmovdqu [rsp+960], ymm12
  mov eax, $BB67AE85
  db $C5, $79, $6E, $E0                      // vmovd xmm12, eax
  db $C4, $42, $7D, $58, $E4                 // vpbroadcastd ymm12, xmm12
  db $C5, $7E, $7F, $A4, $24, $E0, $03, $00, $00 // vmovdqu [rsp+992], ymm12
  mov eax, $3C6EF372
  db $C5, $79, $6E, $E0                      // vmovd xmm12, eax
  db $C4, $42, $7D, $58, $E4                 // vpbroadcastd ymm12, xmm12
  db $C5, $7E, $7F, $A4, $24, $00, $04, $00, $00 // vmovdqu [rsp+1024], ymm12
  mov eax, $A54FF53A
  db $C5, $79, $6E, $E0                      // vmovd xmm12, eax
  db $C4, $42, $7D, $58, $E4                 // vpbroadcastd ymm12, xmm12
  db $C5, $7E, $7F, $A4, $24, $20, $04, $00, $00 // vmovdqu [rsp+1056], ymm12

  mov eax, 64
  db $C5, $79, $6E, $E0                      // vmovd xmm12, eax
  db $C4, $42, $7D, $58, $E4                 // vpbroadcastd ymm12, xmm12
  db $C5, $7E, $7F, $A4, $24, $40, $04, $00, $00 // vmovdqu [rsp+1088], ymm12

  xor ebx, ebx
  xor ebp, ebp

@block_loop:

  // Transpose message for current block from 8 chunks
  // Words 0..3
  db $C5, $FA, $6F, $04, $29                 // vmovdqu xmm0, [rcx+rbp+0]
  db $C4, $E3, $7D, $38, $84, $29, $00, $10, $00, $00, $01 // vinserti128 ymm0, ymm0, [rcx+rbp+4096], 1
  db $C5, $FA, $6F, $8C, $29, $00, $04, $00, $00 // vmovdqu xmm1, [rcx+rbp+1024]
  db $C4, $E3, $75, $38, $8C, $29, $00, $14, $00, $00, $01 // vinserti128 ymm1, ymm1, [rcx+rbp+5120], 1
  db $C5, $FA, $6F, $94, $29, $00, $08, $00, $00 // vmovdqu xmm2, [rcx+rbp+2048]
  db $C4, $E3, $6D, $38, $94, $29, $00, $18, $00, $00, $01 // vinserti128 ymm2, ymm2, [rcx+rbp+6144], 1
  db $C5, $FA, $6F, $9C, $29, $00, $0C, $00, $00 // vmovdqu xmm3, [rcx+rbp+3072]
  db $C4, $E3, $65, $38, $9C, $29, $00, $1C, $00, $00, $01 // vinserti128 ymm3, ymm3, [rcx+rbp+7168], 1
  db $C5, $FD, $62, $E1                      // vpunpckldq ymm4, ymm0, ymm1
  db $C5, $FD, $6A, $E9                      // vpunpckhdq ymm5, ymm0, ymm1
  db $C5, $ED, $62, $F3                      // vpunpckldq ymm6, ymm2, ymm3
  db $C5, $ED, $6A, $FB                      // vpunpckhdq ymm7, ymm2, ymm3
  db $C5, $DD, $6C, $C6                      // vpunpcklqdq ymm0, ymm4, ymm6
  db $C5, $DD, $6D, $CE                      // vpunpckhqdq ymm1, ymm4, ymm6
  db $C5, $D5, $6C, $D7                      // vpunpcklqdq ymm2, ymm5, ymm7
  db $C5, $D5, $6D, $DF                      // vpunpckhqdq ymm3, ymm5, ymm7
  db $C5, $FE, $7F, $04, $24                 // vmovdqu [rsp+0], ymm0
  db $C5, $FE, $7F, $4C, $24, $20            // vmovdqu [rsp+32], ymm1
  db $C5, $FE, $7F, $54, $24, $40            // vmovdqu [rsp+64], ymm2
  db $C5, $FE, $7F, $5C, $24, $60            // vmovdqu [rsp+96], ymm3

  // Words 4..7
  db $C5, $FA, $6F, $44, $29, $10            // vmovdqu xmm0, [rcx+rbp+16]
  db $C4, $E3, $7D, $38, $84, $29, $10, $10, $00, $00, $01 // vinserti128 ymm0, ymm0, [rcx+rbp+4112], 1
  db $C5, $FA, $6F, $8C, $29, $10, $04, $00, $00 // vmovdqu xmm1, [rcx+rbp+1040]
  db $C4, $E3, $75, $38, $8C, $29, $10, $14, $00, $00, $01 // vinserti128 ymm1, ymm1, [rcx+rbp+5136], 1
  db $C5, $FA, $6F, $94, $29, $10, $08, $00, $00 // vmovdqu xmm2, [rcx+rbp+2064]
  db $C4, $E3, $6D, $38, $94, $29, $10, $18, $00, $00, $01 // vinserti128 ymm2, ymm2, [rcx+rbp+6160], 1
  db $C5, $FA, $6F, $9C, $29, $10, $0C, $00, $00 // vmovdqu xmm3, [rcx+rbp+3088]
  db $C4, $E3, $65, $38, $9C, $29, $10, $1C, $00, $00, $01 // vinserti128 ymm3, ymm3, [rcx+rbp+7184], 1
  db $C5, $FD, $62, $E1                      // vpunpckldq ymm4, ymm0, ymm1
  db $C5, $FD, $6A, $E9                      // vpunpckhdq ymm5, ymm0, ymm1
  db $C5, $ED, $62, $F3                      // vpunpckldq ymm6, ymm2, ymm3
  db $C5, $ED, $6A, $FB                      // vpunpckhdq ymm7, ymm2, ymm3
  db $C5, $DD, $6C, $C6                      // vpunpcklqdq ymm0, ymm4, ymm6
  db $C5, $DD, $6D, $CE                      // vpunpckhqdq ymm1, ymm4, ymm6
  db $C5, $D5, $6C, $D7                      // vpunpcklqdq ymm2, ymm5, ymm7
  db $C5, $D5, $6D, $DF                      // vpunpckhqdq ymm3, ymm5, ymm7
  db $C5, $FE, $7F, $84, $24, $80, $00, $00, $00 // vmovdqu [rsp+128], ymm0
  db $C5, $FE, $7F, $8C, $24, $A0, $00, $00, $00 // vmovdqu [rsp+160], ymm1
  db $C5, $FE, $7F, $94, $24, $C0, $00, $00, $00 // vmovdqu [rsp+192], ymm2
  db $C5, $FE, $7F, $9C, $24, $E0, $00, $00, $00 // vmovdqu [rsp+224], ymm3

  // Words 8..11
  db $C5, $FA, $6F, $44, $29, $20            // vmovdqu xmm0, [rcx+rbp+32]
  db $C4, $E3, $7D, $38, $84, $29, $20, $10, $00, $00, $01 // vinserti128 ymm0, ymm0, [rcx+rbp+4128], 1
  db $C5, $FA, $6F, $8C, $29, $20, $04, $00, $00 // vmovdqu xmm1, [rcx+rbp+1056]
  db $C4, $E3, $75, $38, $8C, $29, $20, $14, $00, $00, $01 // vinserti128 ymm1, ymm1, [rcx+rbp+5152], 1
  db $C5, $FA, $6F, $94, $29, $20, $08, $00, $00 // vmovdqu xmm2, [rcx+rbp+2080]
  db $C4, $E3, $6D, $38, $94, $29, $20, $18, $00, $00, $01 // vinserti128 ymm2, ymm2, [rcx+rbp+6176], 1
  db $C5, $FA, $6F, $9C, $29, $20, $0C, $00, $00 // vmovdqu xmm3, [rcx+rbp+3104]
  db $C4, $E3, $65, $38, $9C, $29, $20, $1C, $00, $00, $01 // vinserti128 ymm3, ymm3, [rcx+rbp+7200], 1
  db $C5, $FD, $62, $E1                      // vpunpckldq ymm4, ymm0, ymm1
  db $C5, $FD, $6A, $E9                      // vpunpckhdq ymm5, ymm0, ymm1
  db $C5, $ED, $62, $F3                      // vpunpckldq ymm6, ymm2, ymm3
  db $C5, $ED, $6A, $FB                      // vpunpckhdq ymm7, ymm2, ymm3
  db $C5, $DD, $6C, $C6                      // vpunpcklqdq ymm0, ymm4, ymm6
  db $C5, $DD, $6D, $CE                      // vpunpckhqdq ymm1, ymm4, ymm6
  db $C5, $D5, $6C, $D7                      // vpunpcklqdq ymm2, ymm5, ymm7
  db $C5, $D5, $6D, $DF                      // vpunpckhqdq ymm3, ymm5, ymm7
  db $C5, $FE, $7F, $84, $24, $00, $01, $00, $00 // vmovdqu [rsp+256], ymm0
  db $C5, $FE, $7F, $8C, $24, $20, $01, $00, $00 // vmovdqu [rsp+288], ymm1
  db $C5, $FE, $7F, $94, $24, $40, $01, $00, $00 // vmovdqu [rsp+320], ymm2
  db $C5, $FE, $7F, $9C, $24, $60, $01, $00, $00 // vmovdqu [rsp+352], ymm3

  // Words 12..15
  db $C5, $FA, $6F, $44, $29, $30            // vmovdqu xmm0, [rcx+rbp+48]
  db $C4, $E3, $7D, $38, $84, $29, $30, $10, $00, $00, $01 // vinserti128 ymm0, ymm0, [rcx+rbp+4144], 1
  db $C5, $FA, $6F, $8C, $29, $30, $04, $00, $00 // vmovdqu xmm1, [rcx+rbp+1072]
  db $C4, $E3, $75, $38, $8C, $29, $30, $14, $00, $00, $01 // vinserti128 ymm1, ymm1, [rcx+rbp+5168], 1
  db $C5, $FA, $6F, $94, $29, $30, $08, $00, $00 // vmovdqu xmm2, [rcx+rbp+2096]
  db $C4, $E3, $6D, $38, $94, $29, $30, $18, $00, $00, $01 // vinserti128 ymm2, ymm2, [rcx+rbp+6192], 1
  db $C5, $FA, $6F, $9C, $29, $30, $0C, $00, $00 // vmovdqu xmm3, [rcx+rbp+3120]
  db $C4, $E3, $65, $38, $9C, $29, $30, $1C, $00, $00, $01 // vinserti128 ymm3, ymm3, [rcx+rbp+7216], 1
  db $C5, $FD, $62, $E1                      // vpunpckldq ymm4, ymm0, ymm1
  db $C5, $FD, $6A, $E9                      // vpunpckhdq ymm5, ymm0, ymm1
  db $C5, $ED, $62, $F3                      // vpunpckldq ymm6, ymm2, ymm3
  db $C5, $ED, $6A, $FB                      // vpunpckhdq ymm7, ymm2, ymm3
  db $C5, $DD, $6C, $C6                      // vpunpcklqdq ymm0, ymm4, ymm6
  db $C5, $DD, $6D, $CE                      // vpunpckhqdq ymm1, ymm4, ymm6
  db $C5, $D5, $6C, $D7                      // vpunpcklqdq ymm2, ymm5, ymm7
  db $C5, $D5, $6D, $DF                      // vpunpckhqdq ymm3, ymm5, ymm7
  db $C5, $FE, $7F, $84, $24, $80, $01, $00, $00 // vmovdqu [rsp+384], ymm0
  db $C5, $FE, $7F, $8C, $24, $A0, $01, $00, $00 // vmovdqu [rsp+416], ymm1
  db $C5, $FE, $7F, $94, $24, $C0, $01, $00, $00 // vmovdqu [rsp+448], ymm2
  db $C5, $FE, $7F, $9C, $24, $E0, $01, $00, $00 // vmovdqu [rsp+480], ymm3

  // Initialize state: v0-v7 from CV, v8-v11 from IV
  db $C5, $FE, $6F, $84, $24, $80, $02, $00, $00 // vmovdqu ymm0, [rsp+640]
  db $C5, $FE, $6F, $8C, $24, $A0, $02, $00, $00 // vmovdqu ymm1, [rsp+672]
  db $C5, $FE, $6F, $94, $24, $C0, $02, $00, $00 // vmovdqu ymm2, [rsp+704]
  db $C5, $FE, $6F, $9C, $24, $E0, $02, $00, $00 // vmovdqu ymm3, [rsp+736]
  db $C5, $FE, $6F, $A4, $24, $00, $03, $00, $00 // vmovdqu ymm4, [rsp+768]
  db $C5, $FE, $6F, $AC, $24, $20, $03, $00, $00 // vmovdqu ymm5, [rsp+800]
  db $C5, $FE, $6F, $B4, $24, $40, $03, $00, $00 // vmovdqu ymm6, [rsp+832]
  db $C5, $FE, $6F, $BC, $24, $60, $03, $00, $00 // vmovdqu ymm7, [rsp+864]
  db $C5, $7E, $6F, $84, $24, $C0, $03, $00, $00 // vmovdqu ymm8, [rsp+960]
  db $C5, $7E, $6F, $8C, $24, $E0, $03, $00, $00 // vmovdqu ymm9, [rsp+992]
  db $C5, $7E, $6F, $94, $24, $00, $04, $00, $00 // vmovdqu ymm10, [rsp+1024]
  db $C5, $7E, $6F, $9C, $24, $20, $04, $00, $00 // vmovdqu ymm11, [rsp+1056]

  // v12-v15: counter, block length, flags
  db $C5, $7E, $6F, $A4, $24, $80, $03, $00, $00 // vmovdqu ymm12, [rsp+896]
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00 // vmovdqu [rsp+512], ymm12
  db $C5, $7E, $6F, $A4, $24, $A0, $03, $00, $00 // vmovdqu ymm12, [rsp+928]
  db $C5, $7E, $7F, $A4, $24, $20, $02, $00, $00 // vmovdqu [rsp+544], ymm12
  db $C5, $7E, $6F, $A4, $24, $40, $04, $00, $00 // vmovdqu ymm12, [rsp+1088]
  db $C5, $7E, $7F, $A4, $24, $40, $02, $00, $00 // vmovdqu [rsp+576], ymm12

  // Compute per-block flags and broadcast
  mov eax, dword ptr [rsp + 1128]
  cmp ebx, 0
  jne @h8_not_first
  or eax, 1
@h8_not_first:
  cmp ebx, 15
  jne @h8_not_last
  or eax, 2
@h8_not_last:
  db $C5, $79, $6E, $E0                      // vmovd xmm12, eax
  db $C4, $42, $7D, $58, $E4                 // vpbroadcastd ymm12, xmm12
  db $C5, $7E, $7F, $A4, $24, $60, $02, $00, $00 // vmovdqu [rsp+608], ymm12

  // === Round 0 ===
  // G col (0,4,8,12) m[0],m[1]
  db $C5, $7E, $6F, $A4, $24, $00, $02, $00, $00 // vmovdqu ymm12, [rsp+512]
  db $C5, $FD, $FE, $04, $24                 // vpaddd ymm0, ymm0, [rsp+0]
  db $C5, $FD, $FE, $C4                      // vpaddd ymm0, ymm0, ymm4
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C4, $C1, $5D, $EF, $E0                 // vpxor ymm4, ymm4, ymm8
  db $C5, $95, $72, $D4, $0C                 // vpsrld ymm13, ymm4, 12
  db $C5, $DD, $72, $F4, $14                 // vpslld ymm4, ymm4, 20
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  db $C5, $FD, $FE, $44, $24, $20            // vpaddd ymm0, ymm0, [rsp+32]
  db $C5, $FD, $FE, $C4                      // vpaddd ymm0, ymm0, ymm4
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00 // vmovdqu [rsp+512], ymm12
  db $C4, $C1, $5D, $EF, $E0                 // vpxor ymm4, ymm4, ymm8
  db $C5, $95, $72, $D4, $07                 // vpsrld ymm13, ymm4, 7
  db $C5, $DD, $72, $F4, $19                 // vpslld ymm4, ymm4, 25
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  // G col (1,5,9,13) m[2],m[3]
  db $C5, $7E, $6F, $A4, $24, $20, $02, $00, $00 // vmovdqu ymm12, [rsp+544]
  db $C5, $F5, $FE, $4C, $24, $40            // vpaddd ymm1, ymm1, [rsp+64]
  db $C5, $F5, $FE, $CD                      // vpaddd ymm1, ymm1, ymm5
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C4, $C1, $55, $EF, $E9                 // vpxor ymm5, ymm5, ymm9
  db $C5, $95, $72, $D5, $0C                 // vpsrld ymm13, ymm5, 12
  db $C5, $D5, $72, $F5, $14                 // vpslld ymm5, ymm5, 20
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  db $C5, $F5, $FE, $4C, $24, $60            // vpaddd ymm1, ymm1, [rsp+96]
  db $C5, $F5, $FE, $CD                      // vpaddd ymm1, ymm1, ymm5
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C5, $7E, $7F, $A4, $24, $20, $02, $00, $00 // vmovdqu [rsp+544], ymm12
  db $C4, $C1, $55, $EF, $E9                 // vpxor ymm5, ymm5, ymm9
  db $C5, $95, $72, $D5, $07                 // vpsrld ymm13, ymm5, 7
  db $C5, $D5, $72, $F5, $19                 // vpslld ymm5, ymm5, 25
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  // G col (2,6,10,14) m[4],m[5]
  db $C5, $7E, $6F, $A4, $24, $40, $02, $00, $00 // vmovdqu ymm12, [rsp+576]
  db $C5, $ED, $FE, $94, $24, $80, $00, $00, $00 // vpaddd ymm2, ymm2, [rsp+128]
  db $C5, $ED, $FE, $D6                      // vpaddd ymm2, ymm2, ymm6
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C4, $C1, $4D, $EF, $F2                 // vpxor ymm6, ymm6, ymm10
  db $C5, $95, $72, $D6, $0C                 // vpsrld ymm13, ymm6, 12
  db $C5, $CD, $72, $F6, $14                 // vpslld ymm6, ymm6, 20
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  db $C5, $ED, $FE, $94, $24, $A0, $00, $00, $00 // vpaddd ymm2, ymm2, [rsp+160]
  db $C5, $ED, $FE, $D6                      // vpaddd ymm2, ymm2, ymm6
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C5, $7E, $7F, $A4, $24, $40, $02, $00, $00 // vmovdqu [rsp+576], ymm12
  db $C4, $C1, $4D, $EF, $F2                 // vpxor ymm6, ymm6, ymm10
  db $C5, $95, $72, $D6, $07                 // vpsrld ymm13, ymm6, 7
  db $C5, $CD, $72, $F6, $19                 // vpslld ymm6, ymm6, 25
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  // G col (3,7,11,15) m[6],m[7]
  db $C5, $7E, $6F, $A4, $24, $60, $02, $00, $00 // vmovdqu ymm12, [rsp+608]
  db $C5, $E5, $FE, $9C, $24, $C0, $00, $00, $00 // vpaddd ymm3, ymm3, [rsp+192]
  db $C5, $E5, $FE, $DF                      // vpaddd ymm3, ymm3, ymm7
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C4, $C1, $45, $EF, $FB                 // vpxor ymm7, ymm7, ymm11
  db $C5, $95, $72, $D7, $0C                 // vpsrld ymm13, ymm7, 12
  db $C5, $C5, $72, $F7, $14                 // vpslld ymm7, ymm7, 20
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  db $C5, $E5, $FE, $9C, $24, $E0, $00, $00, $00 // vpaddd ymm3, ymm3, [rsp+224]
  db $C5, $E5, $FE, $DF                      // vpaddd ymm3, ymm3, ymm7
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C5, $7E, $7F, $A4, $24, $60, $02, $00, $00 // vmovdqu [rsp+608], ymm12
  db $C4, $C1, $45, $EF, $FB                 // vpxor ymm7, ymm7, ymm11
  db $C5, $95, $72, $D7, $07                 // vpsrld ymm13, ymm7, 7
  db $C5, $C5, $72, $F7, $19                 // vpslld ymm7, ymm7, 25
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  // G diag (0,5,10,15) m[8],m[9]
  db $C5, $7E, $6F, $A4, $24, $60, $02, $00, $00 // vmovdqu ymm12, [rsp+608]
  db $C5, $FD, $FE, $84, $24, $00, $01, $00, $00 // vpaddd ymm0, ymm0, [rsp+256]
  db $C5, $FD, $FE, $C5                      // vpaddd ymm0, ymm0, ymm5
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C4, $C1, $55, $EF, $EA                 // vpxor ymm5, ymm5, ymm10
  db $C5, $95, $72, $D5, $0C                 // vpsrld ymm13, ymm5, 12
  db $C5, $D5, $72, $F5, $14                 // vpslld ymm5, ymm5, 20
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  db $C5, $FD, $FE, $84, $24, $20, $01, $00, $00 // vpaddd ymm0, ymm0, [rsp+288]
  db $C5, $FD, $FE, $C5                      // vpaddd ymm0, ymm0, ymm5
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C5, $7E, $7F, $A4, $24, $60, $02, $00, $00 // vmovdqu [rsp+608], ymm12
  db $C4, $C1, $55, $EF, $EA                 // vpxor ymm5, ymm5, ymm10
  db $C5, $95, $72, $D5, $07                 // vpsrld ymm13, ymm5, 7
  db $C5, $D5, $72, $F5, $19                 // vpslld ymm5, ymm5, 25
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  // G diag (1,6,11,12) m[10],m[11]
  db $C5, $7E, $6F, $A4, $24, $00, $02, $00, $00 // vmovdqu ymm12, [rsp+512]
  db $C5, $F5, $FE, $8C, $24, $40, $01, $00, $00 // vpaddd ymm1, ymm1, [rsp+320]
  db $C5, $F5, $FE, $CE                      // vpaddd ymm1, ymm1, ymm6
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C4, $C1, $4D, $EF, $F3                 // vpxor ymm6, ymm6, ymm11
  db $C5, $95, $72, $D6, $0C                 // vpsrld ymm13, ymm6, 12
  db $C5, $CD, $72, $F6, $14                 // vpslld ymm6, ymm6, 20
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  db $C5, $F5, $FE, $8C, $24, $60, $01, $00, $00 // vpaddd ymm1, ymm1, [rsp+352]
  db $C5, $F5, $FE, $CE                      // vpaddd ymm1, ymm1, ymm6
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00 // vmovdqu [rsp+512], ymm12
  db $C4, $C1, $4D, $EF, $F3                 // vpxor ymm6, ymm6, ymm11
  db $C5, $95, $72, $D6, $07                 // vpsrld ymm13, ymm6, 7
  db $C5, $CD, $72, $F6, $19                 // vpslld ymm6, ymm6, 25
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  // G diag (2,7,8,13) m[12],m[13]
  db $C5, $7E, $6F, $A4, $24, $20, $02, $00, $00 // vmovdqu ymm12, [rsp+544]
  db $C5, $ED, $FE, $94, $24, $80, $01, $00, $00 // vpaddd ymm2, ymm2, [rsp+384]
  db $C5, $ED, $FE, $D7                      // vpaddd ymm2, ymm2, ymm7
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C4, $C1, $45, $EF, $F8                 // vpxor ymm7, ymm7, ymm8
  db $C5, $95, $72, $D7, $0C                 // vpsrld ymm13, ymm7, 12
  db $C5, $C5, $72, $F7, $14                 // vpslld ymm7, ymm7, 20
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  db $C5, $ED, $FE, $94, $24, $A0, $01, $00, $00 // vpaddd ymm2, ymm2, [rsp+416]
  db $C5, $ED, $FE, $D7                      // vpaddd ymm2, ymm2, ymm7
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C5, $7E, $7F, $A4, $24, $20, $02, $00, $00 // vmovdqu [rsp+544], ymm12
  db $C4, $C1, $45, $EF, $F8                 // vpxor ymm7, ymm7, ymm8
  db $C5, $95, $72, $D7, $07                 // vpsrld ymm13, ymm7, 7
  db $C5, $C5, $72, $F7, $19                 // vpslld ymm7, ymm7, 25
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  // G diag (3,4,9,14) m[14],m[15]
  db $C5, $7E, $6F, $A4, $24, $40, $02, $00, $00 // vmovdqu ymm12, [rsp+576]
  db $C5, $E5, $FE, $9C, $24, $C0, $01, $00, $00 // vpaddd ymm3, ymm3, [rsp+448]
  db $C5, $E5, $FE, $DC                      // vpaddd ymm3, ymm3, ymm4
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C4, $C1, $5D, $EF, $E1                 // vpxor ymm4, ymm4, ymm9
  db $C5, $95, $72, $D4, $0C                 // vpsrld ymm13, ymm4, 12
  db $C5, $DD, $72, $F4, $14                 // vpslld ymm4, ymm4, 20
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  db $C5, $E5, $FE, $9C, $24, $E0, $01, $00, $00 // vpaddd ymm3, ymm3, [rsp+480]
  db $C5, $E5, $FE, $DC                      // vpaddd ymm3, ymm3, ymm4
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C5, $7E, $7F, $A4, $24, $40, $02, $00, $00 // vmovdqu [rsp+576], ymm12
  db $C4, $C1, $5D, $EF, $E1                 // vpxor ymm4, ymm4, ymm9
  db $C5, $95, $72, $D4, $07                 // vpsrld ymm13, ymm4, 7
  db $C5, $DD, $72, $F4, $19                 // vpslld ymm4, ymm4, 25
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13

  // === Round 1 ===
  // G col (0,4,8,12) m[2],m[6]
  db $C5, $7E, $6F, $A4, $24, $00, $02, $00, $00 // vmovdqu ymm12, [rsp+512]
  db $C5, $FD, $FE, $44, $24, $40            // vpaddd ymm0, ymm0, [rsp+64]
  db $C5, $FD, $FE, $C4                      // vpaddd ymm0, ymm0, ymm4
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C4, $C1, $5D, $EF, $E0                 // vpxor ymm4, ymm4, ymm8
  db $C5, $95, $72, $D4, $0C                 // vpsrld ymm13, ymm4, 12
  db $C5, $DD, $72, $F4, $14                 // vpslld ymm4, ymm4, 20
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  db $C5, $FD, $FE, $84, $24, $C0, $00, $00, $00 // vpaddd ymm0, ymm0, [rsp+192]
  db $C5, $FD, $FE, $C4                      // vpaddd ymm0, ymm0, ymm4
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00 // vmovdqu [rsp+512], ymm12
  db $C4, $C1, $5D, $EF, $E0                 // vpxor ymm4, ymm4, ymm8
  db $C5, $95, $72, $D4, $07                 // vpsrld ymm13, ymm4, 7
  db $C5, $DD, $72, $F4, $19                 // vpslld ymm4, ymm4, 25
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  // G col (1,5,9,13) m[3],m[10]
  db $C5, $7E, $6F, $A4, $24, $20, $02, $00, $00 // vmovdqu ymm12, [rsp+544]
  db $C5, $F5, $FE, $4C, $24, $60            // vpaddd ymm1, ymm1, [rsp+96]
  db $C5, $F5, $FE, $CD                      // vpaddd ymm1, ymm1, ymm5
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C4, $C1, $55, $EF, $E9                 // vpxor ymm5, ymm5, ymm9
  db $C5, $95, $72, $D5, $0C                 // vpsrld ymm13, ymm5, 12
  db $C5, $D5, $72, $F5, $14                 // vpslld ymm5, ymm5, 20
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  db $C5, $F5, $FE, $8C, $24, $40, $01, $00, $00 // vpaddd ymm1, ymm1, [rsp+320]
  db $C5, $F5, $FE, $CD                      // vpaddd ymm1, ymm1, ymm5
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C5, $7E, $7F, $A4, $24, $20, $02, $00, $00 // vmovdqu [rsp+544], ymm12
  db $C4, $C1, $55, $EF, $E9                 // vpxor ymm5, ymm5, ymm9
  db $C5, $95, $72, $D5, $07                 // vpsrld ymm13, ymm5, 7
  db $C5, $D5, $72, $F5, $19                 // vpslld ymm5, ymm5, 25
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  // G col (2,6,10,14) m[7],m[0]
  db $C5, $7E, $6F, $A4, $24, $40, $02, $00, $00 // vmovdqu ymm12, [rsp+576]
  db $C5, $ED, $FE, $94, $24, $E0, $00, $00, $00 // vpaddd ymm2, ymm2, [rsp+224]
  db $C5, $ED, $FE, $D6                      // vpaddd ymm2, ymm2, ymm6
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C4, $C1, $4D, $EF, $F2                 // vpxor ymm6, ymm6, ymm10
  db $C5, $95, $72, $D6, $0C                 // vpsrld ymm13, ymm6, 12
  db $C5, $CD, $72, $F6, $14                 // vpslld ymm6, ymm6, 20
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  db $C5, $ED, $FE, $14, $24                 // vpaddd ymm2, ymm2, [rsp+0]
  db $C5, $ED, $FE, $D6                      // vpaddd ymm2, ymm2, ymm6
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C5, $7E, $7F, $A4, $24, $40, $02, $00, $00 // vmovdqu [rsp+576], ymm12
  db $C4, $C1, $4D, $EF, $F2                 // vpxor ymm6, ymm6, ymm10
  db $C5, $95, $72, $D6, $07                 // vpsrld ymm13, ymm6, 7
  db $C5, $CD, $72, $F6, $19                 // vpslld ymm6, ymm6, 25
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  // G col (3,7,11,15) m[4],m[13]
  db $C5, $7E, $6F, $A4, $24, $60, $02, $00, $00 // vmovdqu ymm12, [rsp+608]
  db $C5, $E5, $FE, $9C, $24, $80, $00, $00, $00 // vpaddd ymm3, ymm3, [rsp+128]
  db $C5, $E5, $FE, $DF                      // vpaddd ymm3, ymm3, ymm7
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C4, $C1, $45, $EF, $FB                 // vpxor ymm7, ymm7, ymm11
  db $C5, $95, $72, $D7, $0C                 // vpsrld ymm13, ymm7, 12
  db $C5, $C5, $72, $F7, $14                 // vpslld ymm7, ymm7, 20
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  db $C5, $E5, $FE, $9C, $24, $A0, $01, $00, $00 // vpaddd ymm3, ymm3, [rsp+416]
  db $C5, $E5, $FE, $DF                      // vpaddd ymm3, ymm3, ymm7
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C5, $7E, $7F, $A4, $24, $60, $02, $00, $00 // vmovdqu [rsp+608], ymm12
  db $C4, $C1, $45, $EF, $FB                 // vpxor ymm7, ymm7, ymm11
  db $C5, $95, $72, $D7, $07                 // vpsrld ymm13, ymm7, 7
  db $C5, $C5, $72, $F7, $19                 // vpslld ymm7, ymm7, 25
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  // G diag (0,5,10,15) m[1],m[11]
  db $C5, $7E, $6F, $A4, $24, $60, $02, $00, $00 // vmovdqu ymm12, [rsp+608]
  db $C5, $FD, $FE, $44, $24, $20            // vpaddd ymm0, ymm0, [rsp+32]
  db $C5, $FD, $FE, $C5                      // vpaddd ymm0, ymm0, ymm5
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C4, $C1, $55, $EF, $EA                 // vpxor ymm5, ymm5, ymm10
  db $C5, $95, $72, $D5, $0C                 // vpsrld ymm13, ymm5, 12
  db $C5, $D5, $72, $F5, $14                 // vpslld ymm5, ymm5, 20
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  db $C5, $FD, $FE, $84, $24, $60, $01, $00, $00 // vpaddd ymm0, ymm0, [rsp+352]
  db $C5, $FD, $FE, $C5                      // vpaddd ymm0, ymm0, ymm5
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C5, $7E, $7F, $A4, $24, $60, $02, $00, $00 // vmovdqu [rsp+608], ymm12
  db $C4, $C1, $55, $EF, $EA                 // vpxor ymm5, ymm5, ymm10
  db $C5, $95, $72, $D5, $07                 // vpsrld ymm13, ymm5, 7
  db $C5, $D5, $72, $F5, $19                 // vpslld ymm5, ymm5, 25
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  // G diag (1,6,11,12) m[12],m[5]
  db $C5, $7E, $6F, $A4, $24, $00, $02, $00, $00 // vmovdqu ymm12, [rsp+512]
  db $C5, $F5, $FE, $8C, $24, $80, $01, $00, $00 // vpaddd ymm1, ymm1, [rsp+384]
  db $C5, $F5, $FE, $CE                      // vpaddd ymm1, ymm1, ymm6
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C4, $C1, $4D, $EF, $F3                 // vpxor ymm6, ymm6, ymm11
  db $C5, $95, $72, $D6, $0C                 // vpsrld ymm13, ymm6, 12
  db $C5, $CD, $72, $F6, $14                 // vpslld ymm6, ymm6, 20
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  db $C5, $F5, $FE, $8C, $24, $A0, $00, $00, $00 // vpaddd ymm1, ymm1, [rsp+160]
  db $C5, $F5, $FE, $CE                      // vpaddd ymm1, ymm1, ymm6
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00 // vmovdqu [rsp+512], ymm12
  db $C4, $C1, $4D, $EF, $F3                 // vpxor ymm6, ymm6, ymm11
  db $C5, $95, $72, $D6, $07                 // vpsrld ymm13, ymm6, 7
  db $C5, $CD, $72, $F6, $19                 // vpslld ymm6, ymm6, 25
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  // G diag (2,7,8,13) m[9],m[14]
  db $C5, $7E, $6F, $A4, $24, $20, $02, $00, $00 // vmovdqu ymm12, [rsp+544]
  db $C5, $ED, $FE, $94, $24, $20, $01, $00, $00 // vpaddd ymm2, ymm2, [rsp+288]
  db $C5, $ED, $FE, $D7                      // vpaddd ymm2, ymm2, ymm7
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C4, $C1, $45, $EF, $F8                 // vpxor ymm7, ymm7, ymm8
  db $C5, $95, $72, $D7, $0C                 // vpsrld ymm13, ymm7, 12
  db $C5, $C5, $72, $F7, $14                 // vpslld ymm7, ymm7, 20
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  db $C5, $ED, $FE, $94, $24, $C0, $01, $00, $00 // vpaddd ymm2, ymm2, [rsp+448]
  db $C5, $ED, $FE, $D7                      // vpaddd ymm2, ymm2, ymm7
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C5, $7E, $7F, $A4, $24, $20, $02, $00, $00 // vmovdqu [rsp+544], ymm12
  db $C4, $C1, $45, $EF, $F8                 // vpxor ymm7, ymm7, ymm8
  db $C5, $95, $72, $D7, $07                 // vpsrld ymm13, ymm7, 7
  db $C5, $C5, $72, $F7, $19                 // vpslld ymm7, ymm7, 25
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  // G diag (3,4,9,14) m[15],m[8]
  db $C5, $7E, $6F, $A4, $24, $40, $02, $00, $00 // vmovdqu ymm12, [rsp+576]
  db $C5, $E5, $FE, $9C, $24, $E0, $01, $00, $00 // vpaddd ymm3, ymm3, [rsp+480]
  db $C5, $E5, $FE, $DC                      // vpaddd ymm3, ymm3, ymm4
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C4, $C1, $5D, $EF, $E1                 // vpxor ymm4, ymm4, ymm9
  db $C5, $95, $72, $D4, $0C                 // vpsrld ymm13, ymm4, 12
  db $C5, $DD, $72, $F4, $14                 // vpslld ymm4, ymm4, 20
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  db $C5, $E5, $FE, $9C, $24, $00, $01, $00, $00 // vpaddd ymm3, ymm3, [rsp+256]
  db $C5, $E5, $FE, $DC                      // vpaddd ymm3, ymm3, ymm4
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C5, $7E, $7F, $A4, $24, $40, $02, $00, $00 // vmovdqu [rsp+576], ymm12
  db $C4, $C1, $5D, $EF, $E1                 // vpxor ymm4, ymm4, ymm9
  db $C5, $95, $72, $D4, $07                 // vpsrld ymm13, ymm4, 7
  db $C5, $DD, $72, $F4, $19                 // vpslld ymm4, ymm4, 25
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13

  // === Round 2 ===
  // G col (0,4,8,12) m[3],m[4]
  db $C5, $7E, $6F, $A4, $24, $00, $02, $00, $00 // vmovdqu ymm12, [rsp+512]
  db $C5, $FD, $FE, $44, $24, $60            // vpaddd ymm0, ymm0, [rsp+96]
  db $C5, $FD, $FE, $C4                      // vpaddd ymm0, ymm0, ymm4
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C4, $C1, $5D, $EF, $E0                 // vpxor ymm4, ymm4, ymm8
  db $C5, $95, $72, $D4, $0C                 // vpsrld ymm13, ymm4, 12
  db $C5, $DD, $72, $F4, $14                 // vpslld ymm4, ymm4, 20
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  db $C5, $FD, $FE, $84, $24, $80, $00, $00, $00 // vpaddd ymm0, ymm0, [rsp+128]
  db $C5, $FD, $FE, $C4                      // vpaddd ymm0, ymm0, ymm4
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00 // vmovdqu [rsp+512], ymm12
  db $C4, $C1, $5D, $EF, $E0                 // vpxor ymm4, ymm4, ymm8
  db $C5, $95, $72, $D4, $07                 // vpsrld ymm13, ymm4, 7
  db $C5, $DD, $72, $F4, $19                 // vpslld ymm4, ymm4, 25
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  // G col (1,5,9,13) m[10],m[12]
  db $C5, $7E, $6F, $A4, $24, $20, $02, $00, $00 // vmovdqu ymm12, [rsp+544]
  db $C5, $F5, $FE, $8C, $24, $40, $01, $00, $00 // vpaddd ymm1, ymm1, [rsp+320]
  db $C5, $F5, $FE, $CD                      // vpaddd ymm1, ymm1, ymm5
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C4, $C1, $55, $EF, $E9                 // vpxor ymm5, ymm5, ymm9
  db $C5, $95, $72, $D5, $0C                 // vpsrld ymm13, ymm5, 12
  db $C5, $D5, $72, $F5, $14                 // vpslld ymm5, ymm5, 20
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  db $C5, $F5, $FE, $8C, $24, $80, $01, $00, $00 // vpaddd ymm1, ymm1, [rsp+384]
  db $C5, $F5, $FE, $CD                      // vpaddd ymm1, ymm1, ymm5
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C5, $7E, $7F, $A4, $24, $20, $02, $00, $00 // vmovdqu [rsp+544], ymm12
  db $C4, $C1, $55, $EF, $E9                 // vpxor ymm5, ymm5, ymm9
  db $C5, $95, $72, $D5, $07                 // vpsrld ymm13, ymm5, 7
  db $C5, $D5, $72, $F5, $19                 // vpslld ymm5, ymm5, 25
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  // G col (2,6,10,14) m[13],m[2]
  db $C5, $7E, $6F, $A4, $24, $40, $02, $00, $00 // vmovdqu ymm12, [rsp+576]
  db $C5, $ED, $FE, $94, $24, $A0, $01, $00, $00 // vpaddd ymm2, ymm2, [rsp+416]
  db $C5, $ED, $FE, $D6                      // vpaddd ymm2, ymm2, ymm6
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C4, $C1, $4D, $EF, $F2                 // vpxor ymm6, ymm6, ymm10
  db $C5, $95, $72, $D6, $0C                 // vpsrld ymm13, ymm6, 12
  db $C5, $CD, $72, $F6, $14                 // vpslld ymm6, ymm6, 20
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  db $C5, $ED, $FE, $54, $24, $40            // vpaddd ymm2, ymm2, [rsp+64]
  db $C5, $ED, $FE, $D6                      // vpaddd ymm2, ymm2, ymm6
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C5, $7E, $7F, $A4, $24, $40, $02, $00, $00 // vmovdqu [rsp+576], ymm12
  db $C4, $C1, $4D, $EF, $F2                 // vpxor ymm6, ymm6, ymm10
  db $C5, $95, $72, $D6, $07                 // vpsrld ymm13, ymm6, 7
  db $C5, $CD, $72, $F6, $19                 // vpslld ymm6, ymm6, 25
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  // G col (3,7,11,15) m[7],m[14]
  db $C5, $7E, $6F, $A4, $24, $60, $02, $00, $00 // vmovdqu ymm12, [rsp+608]
  db $C5, $E5, $FE, $9C, $24, $E0, $00, $00, $00 // vpaddd ymm3, ymm3, [rsp+224]
  db $C5, $E5, $FE, $DF                      // vpaddd ymm3, ymm3, ymm7
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C4, $C1, $45, $EF, $FB                 // vpxor ymm7, ymm7, ymm11
  db $C5, $95, $72, $D7, $0C                 // vpsrld ymm13, ymm7, 12
  db $C5, $C5, $72, $F7, $14                 // vpslld ymm7, ymm7, 20
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  db $C5, $E5, $FE, $9C, $24, $C0, $01, $00, $00 // vpaddd ymm3, ymm3, [rsp+448]
  db $C5, $E5, $FE, $DF                      // vpaddd ymm3, ymm3, ymm7
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C5, $7E, $7F, $A4, $24, $60, $02, $00, $00 // vmovdqu [rsp+608], ymm12
  db $C4, $C1, $45, $EF, $FB                 // vpxor ymm7, ymm7, ymm11
  db $C5, $95, $72, $D7, $07                 // vpsrld ymm13, ymm7, 7
  db $C5, $C5, $72, $F7, $19                 // vpslld ymm7, ymm7, 25
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  // G diag (0,5,10,15) m[6],m[5]
  db $C5, $7E, $6F, $A4, $24, $60, $02, $00, $00 // vmovdqu ymm12, [rsp+608]
  db $C5, $FD, $FE, $84, $24, $C0, $00, $00, $00 // vpaddd ymm0, ymm0, [rsp+192]
  db $C5, $FD, $FE, $C5                      // vpaddd ymm0, ymm0, ymm5
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C4, $C1, $55, $EF, $EA                 // vpxor ymm5, ymm5, ymm10
  db $C5, $95, $72, $D5, $0C                 // vpsrld ymm13, ymm5, 12
  db $C5, $D5, $72, $F5, $14                 // vpslld ymm5, ymm5, 20
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  db $C5, $FD, $FE, $84, $24, $A0, $00, $00, $00 // vpaddd ymm0, ymm0, [rsp+160]
  db $C5, $FD, $FE, $C5                      // vpaddd ymm0, ymm0, ymm5
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C5, $7E, $7F, $A4, $24, $60, $02, $00, $00 // vmovdqu [rsp+608], ymm12
  db $C4, $C1, $55, $EF, $EA                 // vpxor ymm5, ymm5, ymm10
  db $C5, $95, $72, $D5, $07                 // vpsrld ymm13, ymm5, 7
  db $C5, $D5, $72, $F5, $19                 // vpslld ymm5, ymm5, 25
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  // G diag (1,6,11,12) m[9],m[0]
  db $C5, $7E, $6F, $A4, $24, $00, $02, $00, $00 // vmovdqu ymm12, [rsp+512]
  db $C5, $F5, $FE, $8C, $24, $20, $01, $00, $00 // vpaddd ymm1, ymm1, [rsp+288]
  db $C5, $F5, $FE, $CE                      // vpaddd ymm1, ymm1, ymm6
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C4, $C1, $4D, $EF, $F3                 // vpxor ymm6, ymm6, ymm11
  db $C5, $95, $72, $D6, $0C                 // vpsrld ymm13, ymm6, 12
  db $C5, $CD, $72, $F6, $14                 // vpslld ymm6, ymm6, 20
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  db $C5, $F5, $FE, $0C, $24                 // vpaddd ymm1, ymm1, [rsp+0]
  db $C5, $F5, $FE, $CE                      // vpaddd ymm1, ymm1, ymm6
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00 // vmovdqu [rsp+512], ymm12
  db $C4, $C1, $4D, $EF, $F3                 // vpxor ymm6, ymm6, ymm11
  db $C5, $95, $72, $D6, $07                 // vpsrld ymm13, ymm6, 7
  db $C5, $CD, $72, $F6, $19                 // vpslld ymm6, ymm6, 25
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  // G diag (2,7,8,13) m[11],m[15]
  db $C5, $7E, $6F, $A4, $24, $20, $02, $00, $00 // vmovdqu ymm12, [rsp+544]
  db $C5, $ED, $FE, $94, $24, $60, $01, $00, $00 // vpaddd ymm2, ymm2, [rsp+352]
  db $C5, $ED, $FE, $D7                      // vpaddd ymm2, ymm2, ymm7
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C4, $C1, $45, $EF, $F8                 // vpxor ymm7, ymm7, ymm8
  db $C5, $95, $72, $D7, $0C                 // vpsrld ymm13, ymm7, 12
  db $C5, $C5, $72, $F7, $14                 // vpslld ymm7, ymm7, 20
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  db $C5, $ED, $FE, $94, $24, $E0, $01, $00, $00 // vpaddd ymm2, ymm2, [rsp+480]
  db $C5, $ED, $FE, $D7                      // vpaddd ymm2, ymm2, ymm7
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C5, $7E, $7F, $A4, $24, $20, $02, $00, $00 // vmovdqu [rsp+544], ymm12
  db $C4, $C1, $45, $EF, $F8                 // vpxor ymm7, ymm7, ymm8
  db $C5, $95, $72, $D7, $07                 // vpsrld ymm13, ymm7, 7
  db $C5, $C5, $72, $F7, $19                 // vpslld ymm7, ymm7, 25
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  // G diag (3,4,9,14) m[8],m[1]
  db $C5, $7E, $6F, $A4, $24, $40, $02, $00, $00 // vmovdqu ymm12, [rsp+576]
  db $C5, $E5, $FE, $9C, $24, $00, $01, $00, $00 // vpaddd ymm3, ymm3, [rsp+256]
  db $C5, $E5, $FE, $DC                      // vpaddd ymm3, ymm3, ymm4
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C4, $C1, $5D, $EF, $E1                 // vpxor ymm4, ymm4, ymm9
  db $C5, $95, $72, $D4, $0C                 // vpsrld ymm13, ymm4, 12
  db $C5, $DD, $72, $F4, $14                 // vpslld ymm4, ymm4, 20
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  db $C5, $E5, $FE, $5C, $24, $20            // vpaddd ymm3, ymm3, [rsp+32]
  db $C5, $E5, $FE, $DC                      // vpaddd ymm3, ymm3, ymm4
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C5, $7E, $7F, $A4, $24, $40, $02, $00, $00 // vmovdqu [rsp+576], ymm12
  db $C4, $C1, $5D, $EF, $E1                 // vpxor ymm4, ymm4, ymm9
  db $C5, $95, $72, $D4, $07                 // vpsrld ymm13, ymm4, 7
  db $C5, $DD, $72, $F4, $19                 // vpslld ymm4, ymm4, 25
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13

  // === Round 3 ===
  // G col (0,4,8,12) m[10],m[7]
  db $C5, $7E, $6F, $A4, $24, $00, $02, $00, $00 // vmovdqu ymm12, [rsp+512]
  db $C5, $FD, $FE, $84, $24, $40, $01, $00, $00 // vpaddd ymm0, ymm0, [rsp+320]
  db $C5, $FD, $FE, $C4                      // vpaddd ymm0, ymm0, ymm4
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C4, $C1, $5D, $EF, $E0                 // vpxor ymm4, ymm4, ymm8
  db $C5, $95, $72, $D4, $0C                 // vpsrld ymm13, ymm4, 12
  db $C5, $DD, $72, $F4, $14                 // vpslld ymm4, ymm4, 20
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  db $C5, $FD, $FE, $84, $24, $E0, $00, $00, $00 // vpaddd ymm0, ymm0, [rsp+224]
  db $C5, $FD, $FE, $C4                      // vpaddd ymm0, ymm0, ymm4
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00 // vmovdqu [rsp+512], ymm12
  db $C4, $C1, $5D, $EF, $E0                 // vpxor ymm4, ymm4, ymm8
  db $C5, $95, $72, $D4, $07                 // vpsrld ymm13, ymm4, 7
  db $C5, $DD, $72, $F4, $19                 // vpslld ymm4, ymm4, 25
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  // G col (1,5,9,13) m[12],m[9]
  db $C5, $7E, $6F, $A4, $24, $20, $02, $00, $00 // vmovdqu ymm12, [rsp+544]
  db $C5, $F5, $FE, $8C, $24, $80, $01, $00, $00 // vpaddd ymm1, ymm1, [rsp+384]
  db $C5, $F5, $FE, $CD                      // vpaddd ymm1, ymm1, ymm5
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C4, $C1, $55, $EF, $E9                 // vpxor ymm5, ymm5, ymm9
  db $C5, $95, $72, $D5, $0C                 // vpsrld ymm13, ymm5, 12
  db $C5, $D5, $72, $F5, $14                 // vpslld ymm5, ymm5, 20
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  db $C5, $F5, $FE, $8C, $24, $20, $01, $00, $00 // vpaddd ymm1, ymm1, [rsp+288]
  db $C5, $F5, $FE, $CD                      // vpaddd ymm1, ymm1, ymm5
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C5, $7E, $7F, $A4, $24, $20, $02, $00, $00 // vmovdqu [rsp+544], ymm12
  db $C4, $C1, $55, $EF, $E9                 // vpxor ymm5, ymm5, ymm9
  db $C5, $95, $72, $D5, $07                 // vpsrld ymm13, ymm5, 7
  db $C5, $D5, $72, $F5, $19                 // vpslld ymm5, ymm5, 25
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  // G col (2,6,10,14) m[14],m[3]
  db $C5, $7E, $6F, $A4, $24, $40, $02, $00, $00 // vmovdqu ymm12, [rsp+576]
  db $C5, $ED, $FE, $94, $24, $C0, $01, $00, $00 // vpaddd ymm2, ymm2, [rsp+448]
  db $C5, $ED, $FE, $D6                      // vpaddd ymm2, ymm2, ymm6
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C4, $C1, $4D, $EF, $F2                 // vpxor ymm6, ymm6, ymm10
  db $C5, $95, $72, $D6, $0C                 // vpsrld ymm13, ymm6, 12
  db $C5, $CD, $72, $F6, $14                 // vpslld ymm6, ymm6, 20
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  db $C5, $ED, $FE, $54, $24, $60            // vpaddd ymm2, ymm2, [rsp+96]
  db $C5, $ED, $FE, $D6                      // vpaddd ymm2, ymm2, ymm6
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C5, $7E, $7F, $A4, $24, $40, $02, $00, $00 // vmovdqu [rsp+576], ymm12
  db $C4, $C1, $4D, $EF, $F2                 // vpxor ymm6, ymm6, ymm10
  db $C5, $95, $72, $D6, $07                 // vpsrld ymm13, ymm6, 7
  db $C5, $CD, $72, $F6, $19                 // vpslld ymm6, ymm6, 25
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  // G col (3,7,11,15) m[13],m[15]
  db $C5, $7E, $6F, $A4, $24, $60, $02, $00, $00 // vmovdqu ymm12, [rsp+608]
  db $C5, $E5, $FE, $9C, $24, $A0, $01, $00, $00 // vpaddd ymm3, ymm3, [rsp+416]
  db $C5, $E5, $FE, $DF                      // vpaddd ymm3, ymm3, ymm7
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C4, $C1, $45, $EF, $FB                 // vpxor ymm7, ymm7, ymm11
  db $C5, $95, $72, $D7, $0C                 // vpsrld ymm13, ymm7, 12
  db $C5, $C5, $72, $F7, $14                 // vpslld ymm7, ymm7, 20
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  db $C5, $E5, $FE, $9C, $24, $E0, $01, $00, $00 // vpaddd ymm3, ymm3, [rsp+480]
  db $C5, $E5, $FE, $DF                      // vpaddd ymm3, ymm3, ymm7
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C5, $7E, $7F, $A4, $24, $60, $02, $00, $00 // vmovdqu [rsp+608], ymm12
  db $C4, $C1, $45, $EF, $FB                 // vpxor ymm7, ymm7, ymm11
  db $C5, $95, $72, $D7, $07                 // vpsrld ymm13, ymm7, 7
  db $C5, $C5, $72, $F7, $19                 // vpslld ymm7, ymm7, 25
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  // G diag (0,5,10,15) m[4],m[0]
  db $C5, $7E, $6F, $A4, $24, $60, $02, $00, $00 // vmovdqu ymm12, [rsp+608]
  db $C5, $FD, $FE, $84, $24, $80, $00, $00, $00 // vpaddd ymm0, ymm0, [rsp+128]
  db $C5, $FD, $FE, $C5                      // vpaddd ymm0, ymm0, ymm5
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C4, $C1, $55, $EF, $EA                 // vpxor ymm5, ymm5, ymm10
  db $C5, $95, $72, $D5, $0C                 // vpsrld ymm13, ymm5, 12
  db $C5, $D5, $72, $F5, $14                 // vpslld ymm5, ymm5, 20
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  db $C5, $FD, $FE, $04, $24                 // vpaddd ymm0, ymm0, [rsp+0]
  db $C5, $FD, $FE, $C5                      // vpaddd ymm0, ymm0, ymm5
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C5, $7E, $7F, $A4, $24, $60, $02, $00, $00 // vmovdqu [rsp+608], ymm12
  db $C4, $C1, $55, $EF, $EA                 // vpxor ymm5, ymm5, ymm10
  db $C5, $95, $72, $D5, $07                 // vpsrld ymm13, ymm5, 7
  db $C5, $D5, $72, $F5, $19                 // vpslld ymm5, ymm5, 25
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  // G diag (1,6,11,12) m[11],m[2]
  db $C5, $7E, $6F, $A4, $24, $00, $02, $00, $00 // vmovdqu ymm12, [rsp+512]
  db $C5, $F5, $FE, $8C, $24, $60, $01, $00, $00 // vpaddd ymm1, ymm1, [rsp+352]
  db $C5, $F5, $FE, $CE                      // vpaddd ymm1, ymm1, ymm6
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C4, $C1, $4D, $EF, $F3                 // vpxor ymm6, ymm6, ymm11
  db $C5, $95, $72, $D6, $0C                 // vpsrld ymm13, ymm6, 12
  db $C5, $CD, $72, $F6, $14                 // vpslld ymm6, ymm6, 20
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  db $C5, $F5, $FE, $4C, $24, $40            // vpaddd ymm1, ymm1, [rsp+64]
  db $C5, $F5, $FE, $CE                      // vpaddd ymm1, ymm1, ymm6
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00 // vmovdqu [rsp+512], ymm12
  db $C4, $C1, $4D, $EF, $F3                 // vpxor ymm6, ymm6, ymm11
  db $C5, $95, $72, $D6, $07                 // vpsrld ymm13, ymm6, 7
  db $C5, $CD, $72, $F6, $19                 // vpslld ymm6, ymm6, 25
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  // G diag (2,7,8,13) m[5],m[8]
  db $C5, $7E, $6F, $A4, $24, $20, $02, $00, $00 // vmovdqu ymm12, [rsp+544]
  db $C5, $ED, $FE, $94, $24, $A0, $00, $00, $00 // vpaddd ymm2, ymm2, [rsp+160]
  db $C5, $ED, $FE, $D7                      // vpaddd ymm2, ymm2, ymm7
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C4, $C1, $45, $EF, $F8                 // vpxor ymm7, ymm7, ymm8
  db $C5, $95, $72, $D7, $0C                 // vpsrld ymm13, ymm7, 12
  db $C5, $C5, $72, $F7, $14                 // vpslld ymm7, ymm7, 20
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  db $C5, $ED, $FE, $94, $24, $00, $01, $00, $00 // vpaddd ymm2, ymm2, [rsp+256]
  db $C5, $ED, $FE, $D7                      // vpaddd ymm2, ymm2, ymm7
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C5, $7E, $7F, $A4, $24, $20, $02, $00, $00 // vmovdqu [rsp+544], ymm12
  db $C4, $C1, $45, $EF, $F8                 // vpxor ymm7, ymm7, ymm8
  db $C5, $95, $72, $D7, $07                 // vpsrld ymm13, ymm7, 7
  db $C5, $C5, $72, $F7, $19                 // vpslld ymm7, ymm7, 25
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  // G diag (3,4,9,14) m[1],m[6]
  db $C5, $7E, $6F, $A4, $24, $40, $02, $00, $00 // vmovdqu ymm12, [rsp+576]
  db $C5, $E5, $FE, $5C, $24, $20            // vpaddd ymm3, ymm3, [rsp+32]
  db $C5, $E5, $FE, $DC                      // vpaddd ymm3, ymm3, ymm4
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C4, $C1, $5D, $EF, $E1                 // vpxor ymm4, ymm4, ymm9
  db $C5, $95, $72, $D4, $0C                 // vpsrld ymm13, ymm4, 12
  db $C5, $DD, $72, $F4, $14                 // vpslld ymm4, ymm4, 20
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  db $C5, $E5, $FE, $9C, $24, $C0, $00, $00, $00 // vpaddd ymm3, ymm3, [rsp+192]
  db $C5, $E5, $FE, $DC                      // vpaddd ymm3, ymm3, ymm4
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C5, $7E, $7F, $A4, $24, $40, $02, $00, $00 // vmovdqu [rsp+576], ymm12
  db $C4, $C1, $5D, $EF, $E1                 // vpxor ymm4, ymm4, ymm9
  db $C5, $95, $72, $D4, $07                 // vpsrld ymm13, ymm4, 7
  db $C5, $DD, $72, $F4, $19                 // vpslld ymm4, ymm4, 25
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13

  // === Round 4 ===
  // G col (0,4,8,12) m[12],m[13]
  db $C5, $7E, $6F, $A4, $24, $00, $02, $00, $00 // vmovdqu ymm12, [rsp+512]
  db $C5, $FD, $FE, $84, $24, $80, $01, $00, $00 // vpaddd ymm0, ymm0, [rsp+384]
  db $C5, $FD, $FE, $C4                      // vpaddd ymm0, ymm0, ymm4
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C4, $C1, $5D, $EF, $E0                 // vpxor ymm4, ymm4, ymm8
  db $C5, $95, $72, $D4, $0C                 // vpsrld ymm13, ymm4, 12
  db $C5, $DD, $72, $F4, $14                 // vpslld ymm4, ymm4, 20
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  db $C5, $FD, $FE, $84, $24, $A0, $01, $00, $00 // vpaddd ymm0, ymm0, [rsp+416]
  db $C5, $FD, $FE, $C4                      // vpaddd ymm0, ymm0, ymm4
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00 // vmovdqu [rsp+512], ymm12
  db $C4, $C1, $5D, $EF, $E0                 // vpxor ymm4, ymm4, ymm8
  db $C5, $95, $72, $D4, $07                 // vpsrld ymm13, ymm4, 7
  db $C5, $DD, $72, $F4, $19                 // vpslld ymm4, ymm4, 25
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  // G col (1,5,9,13) m[9],m[11]
  db $C5, $7E, $6F, $A4, $24, $20, $02, $00, $00 // vmovdqu ymm12, [rsp+544]
  db $C5, $F5, $FE, $8C, $24, $20, $01, $00, $00 // vpaddd ymm1, ymm1, [rsp+288]
  db $C5, $F5, $FE, $CD                      // vpaddd ymm1, ymm1, ymm5
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C4, $C1, $55, $EF, $E9                 // vpxor ymm5, ymm5, ymm9
  db $C5, $95, $72, $D5, $0C                 // vpsrld ymm13, ymm5, 12
  db $C5, $D5, $72, $F5, $14                 // vpslld ymm5, ymm5, 20
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  db $C5, $F5, $FE, $8C, $24, $60, $01, $00, $00 // vpaddd ymm1, ymm1, [rsp+352]
  db $C5, $F5, $FE, $CD                      // vpaddd ymm1, ymm1, ymm5
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C5, $7E, $7F, $A4, $24, $20, $02, $00, $00 // vmovdqu [rsp+544], ymm12
  db $C4, $C1, $55, $EF, $E9                 // vpxor ymm5, ymm5, ymm9
  db $C5, $95, $72, $D5, $07                 // vpsrld ymm13, ymm5, 7
  db $C5, $D5, $72, $F5, $19                 // vpslld ymm5, ymm5, 25
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  // G col (2,6,10,14) m[15],m[10]
  db $C5, $7E, $6F, $A4, $24, $40, $02, $00, $00 // vmovdqu ymm12, [rsp+576]
  db $C5, $ED, $FE, $94, $24, $E0, $01, $00, $00 // vpaddd ymm2, ymm2, [rsp+480]
  db $C5, $ED, $FE, $D6                      // vpaddd ymm2, ymm2, ymm6
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C4, $C1, $4D, $EF, $F2                 // vpxor ymm6, ymm6, ymm10
  db $C5, $95, $72, $D6, $0C                 // vpsrld ymm13, ymm6, 12
  db $C5, $CD, $72, $F6, $14                 // vpslld ymm6, ymm6, 20
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  db $C5, $ED, $FE, $94, $24, $40, $01, $00, $00 // vpaddd ymm2, ymm2, [rsp+320]
  db $C5, $ED, $FE, $D6                      // vpaddd ymm2, ymm2, ymm6
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C5, $7E, $7F, $A4, $24, $40, $02, $00, $00 // vmovdqu [rsp+576], ymm12
  db $C4, $C1, $4D, $EF, $F2                 // vpxor ymm6, ymm6, ymm10
  db $C5, $95, $72, $D6, $07                 // vpsrld ymm13, ymm6, 7
  db $C5, $CD, $72, $F6, $19                 // vpslld ymm6, ymm6, 25
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  // G col (3,7,11,15) m[14],m[8]
  db $C5, $7E, $6F, $A4, $24, $60, $02, $00, $00 // vmovdqu ymm12, [rsp+608]
  db $C5, $E5, $FE, $9C, $24, $C0, $01, $00, $00 // vpaddd ymm3, ymm3, [rsp+448]
  db $C5, $E5, $FE, $DF                      // vpaddd ymm3, ymm3, ymm7
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C4, $C1, $45, $EF, $FB                 // vpxor ymm7, ymm7, ymm11
  db $C5, $95, $72, $D7, $0C                 // vpsrld ymm13, ymm7, 12
  db $C5, $C5, $72, $F7, $14                 // vpslld ymm7, ymm7, 20
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  db $C5, $E5, $FE, $9C, $24, $00, $01, $00, $00 // vpaddd ymm3, ymm3, [rsp+256]
  db $C5, $E5, $FE, $DF                      // vpaddd ymm3, ymm3, ymm7
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C5, $7E, $7F, $A4, $24, $60, $02, $00, $00 // vmovdqu [rsp+608], ymm12
  db $C4, $C1, $45, $EF, $FB                 // vpxor ymm7, ymm7, ymm11
  db $C5, $95, $72, $D7, $07                 // vpsrld ymm13, ymm7, 7
  db $C5, $C5, $72, $F7, $19                 // vpslld ymm7, ymm7, 25
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  // G diag (0,5,10,15) m[7],m[2]
  db $C5, $7E, $6F, $A4, $24, $60, $02, $00, $00 // vmovdqu ymm12, [rsp+608]
  db $C5, $FD, $FE, $84, $24, $E0, $00, $00, $00 // vpaddd ymm0, ymm0, [rsp+224]
  db $C5, $FD, $FE, $C5                      // vpaddd ymm0, ymm0, ymm5
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C4, $C1, $55, $EF, $EA                 // vpxor ymm5, ymm5, ymm10
  db $C5, $95, $72, $D5, $0C                 // vpsrld ymm13, ymm5, 12
  db $C5, $D5, $72, $F5, $14                 // vpslld ymm5, ymm5, 20
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  db $C5, $FD, $FE, $44, $24, $40            // vpaddd ymm0, ymm0, [rsp+64]
  db $C5, $FD, $FE, $C5                      // vpaddd ymm0, ymm0, ymm5
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C5, $7E, $7F, $A4, $24, $60, $02, $00, $00 // vmovdqu [rsp+608], ymm12
  db $C4, $C1, $55, $EF, $EA                 // vpxor ymm5, ymm5, ymm10
  db $C5, $95, $72, $D5, $07                 // vpsrld ymm13, ymm5, 7
  db $C5, $D5, $72, $F5, $19                 // vpslld ymm5, ymm5, 25
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  // G diag (1,6,11,12) m[5],m[3]
  db $C5, $7E, $6F, $A4, $24, $00, $02, $00, $00 // vmovdqu ymm12, [rsp+512]
  db $C5, $F5, $FE, $8C, $24, $A0, $00, $00, $00 // vpaddd ymm1, ymm1, [rsp+160]
  db $C5, $F5, $FE, $CE                      // vpaddd ymm1, ymm1, ymm6
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C4, $C1, $4D, $EF, $F3                 // vpxor ymm6, ymm6, ymm11
  db $C5, $95, $72, $D6, $0C                 // vpsrld ymm13, ymm6, 12
  db $C5, $CD, $72, $F6, $14                 // vpslld ymm6, ymm6, 20
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  db $C5, $F5, $FE, $4C, $24, $60            // vpaddd ymm1, ymm1, [rsp+96]
  db $C5, $F5, $FE, $CE                      // vpaddd ymm1, ymm1, ymm6
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00 // vmovdqu [rsp+512], ymm12
  db $C4, $C1, $4D, $EF, $F3                 // vpxor ymm6, ymm6, ymm11
  db $C5, $95, $72, $D6, $07                 // vpsrld ymm13, ymm6, 7
  db $C5, $CD, $72, $F6, $19                 // vpslld ymm6, ymm6, 25
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  // G diag (2,7,8,13) m[0],m[1]
  db $C5, $7E, $6F, $A4, $24, $20, $02, $00, $00 // vmovdqu ymm12, [rsp+544]
  db $C5, $ED, $FE, $14, $24                 // vpaddd ymm2, ymm2, [rsp+0]
  db $C5, $ED, $FE, $D7                      // vpaddd ymm2, ymm2, ymm7
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C4, $C1, $45, $EF, $F8                 // vpxor ymm7, ymm7, ymm8
  db $C5, $95, $72, $D7, $0C                 // vpsrld ymm13, ymm7, 12
  db $C5, $C5, $72, $F7, $14                 // vpslld ymm7, ymm7, 20
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  db $C5, $ED, $FE, $54, $24, $20            // vpaddd ymm2, ymm2, [rsp+32]
  db $C5, $ED, $FE, $D7                      // vpaddd ymm2, ymm2, ymm7
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C5, $7E, $7F, $A4, $24, $20, $02, $00, $00 // vmovdqu [rsp+544], ymm12
  db $C4, $C1, $45, $EF, $F8                 // vpxor ymm7, ymm7, ymm8
  db $C5, $95, $72, $D7, $07                 // vpsrld ymm13, ymm7, 7
  db $C5, $C5, $72, $F7, $19                 // vpslld ymm7, ymm7, 25
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  // G diag (3,4,9,14) m[6],m[4]
  db $C5, $7E, $6F, $A4, $24, $40, $02, $00, $00 // vmovdqu ymm12, [rsp+576]
  db $C5, $E5, $FE, $9C, $24, $C0, $00, $00, $00 // vpaddd ymm3, ymm3, [rsp+192]
  db $C5, $E5, $FE, $DC                      // vpaddd ymm3, ymm3, ymm4
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C4, $C1, $5D, $EF, $E1                 // vpxor ymm4, ymm4, ymm9
  db $C5, $95, $72, $D4, $0C                 // vpsrld ymm13, ymm4, 12
  db $C5, $DD, $72, $F4, $14                 // vpslld ymm4, ymm4, 20
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  db $C5, $E5, $FE, $9C, $24, $80, $00, $00, $00 // vpaddd ymm3, ymm3, [rsp+128]
  db $C5, $E5, $FE, $DC                      // vpaddd ymm3, ymm3, ymm4
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C5, $7E, $7F, $A4, $24, $40, $02, $00, $00 // vmovdqu [rsp+576], ymm12
  db $C4, $C1, $5D, $EF, $E1                 // vpxor ymm4, ymm4, ymm9
  db $C5, $95, $72, $D4, $07                 // vpsrld ymm13, ymm4, 7
  db $C5, $DD, $72, $F4, $19                 // vpslld ymm4, ymm4, 25
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13

  // === Round 5 ===
  // G col (0,4,8,12) m[9],m[14]
  db $C5, $7E, $6F, $A4, $24, $00, $02, $00, $00 // vmovdqu ymm12, [rsp+512]
  db $C5, $FD, $FE, $84, $24, $20, $01, $00, $00 // vpaddd ymm0, ymm0, [rsp+288]
  db $C5, $FD, $FE, $C4                      // vpaddd ymm0, ymm0, ymm4
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C4, $C1, $5D, $EF, $E0                 // vpxor ymm4, ymm4, ymm8
  db $C5, $95, $72, $D4, $0C                 // vpsrld ymm13, ymm4, 12
  db $C5, $DD, $72, $F4, $14                 // vpslld ymm4, ymm4, 20
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  db $C5, $FD, $FE, $84, $24, $C0, $01, $00, $00 // vpaddd ymm0, ymm0, [rsp+448]
  db $C5, $FD, $FE, $C4                      // vpaddd ymm0, ymm0, ymm4
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00 // vmovdqu [rsp+512], ymm12
  db $C4, $C1, $5D, $EF, $E0                 // vpxor ymm4, ymm4, ymm8
  db $C5, $95, $72, $D4, $07                 // vpsrld ymm13, ymm4, 7
  db $C5, $DD, $72, $F4, $19                 // vpslld ymm4, ymm4, 25
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  // G col (1,5,9,13) m[11],m[5]
  db $C5, $7E, $6F, $A4, $24, $20, $02, $00, $00 // vmovdqu ymm12, [rsp+544]
  db $C5, $F5, $FE, $8C, $24, $60, $01, $00, $00 // vpaddd ymm1, ymm1, [rsp+352]
  db $C5, $F5, $FE, $CD                      // vpaddd ymm1, ymm1, ymm5
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C4, $C1, $55, $EF, $E9                 // vpxor ymm5, ymm5, ymm9
  db $C5, $95, $72, $D5, $0C                 // vpsrld ymm13, ymm5, 12
  db $C5, $D5, $72, $F5, $14                 // vpslld ymm5, ymm5, 20
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  db $C5, $F5, $FE, $8C, $24, $A0, $00, $00, $00 // vpaddd ymm1, ymm1, [rsp+160]
  db $C5, $F5, $FE, $CD                      // vpaddd ymm1, ymm1, ymm5
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C5, $7E, $7F, $A4, $24, $20, $02, $00, $00 // vmovdqu [rsp+544], ymm12
  db $C4, $C1, $55, $EF, $E9                 // vpxor ymm5, ymm5, ymm9
  db $C5, $95, $72, $D5, $07                 // vpsrld ymm13, ymm5, 7
  db $C5, $D5, $72, $F5, $19                 // vpslld ymm5, ymm5, 25
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  // G col (2,6,10,14) m[8],m[12]
  db $C5, $7E, $6F, $A4, $24, $40, $02, $00, $00 // vmovdqu ymm12, [rsp+576]
  db $C5, $ED, $FE, $94, $24, $00, $01, $00, $00 // vpaddd ymm2, ymm2, [rsp+256]
  db $C5, $ED, $FE, $D6                      // vpaddd ymm2, ymm2, ymm6
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C4, $C1, $4D, $EF, $F2                 // vpxor ymm6, ymm6, ymm10
  db $C5, $95, $72, $D6, $0C                 // vpsrld ymm13, ymm6, 12
  db $C5, $CD, $72, $F6, $14                 // vpslld ymm6, ymm6, 20
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  db $C5, $ED, $FE, $94, $24, $80, $01, $00, $00 // vpaddd ymm2, ymm2, [rsp+384]
  db $C5, $ED, $FE, $D6                      // vpaddd ymm2, ymm2, ymm6
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C5, $7E, $7F, $A4, $24, $40, $02, $00, $00 // vmovdqu [rsp+576], ymm12
  db $C4, $C1, $4D, $EF, $F2                 // vpxor ymm6, ymm6, ymm10
  db $C5, $95, $72, $D6, $07                 // vpsrld ymm13, ymm6, 7
  db $C5, $CD, $72, $F6, $19                 // vpslld ymm6, ymm6, 25
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  // G col (3,7,11,15) m[15],m[1]
  db $C5, $7E, $6F, $A4, $24, $60, $02, $00, $00 // vmovdqu ymm12, [rsp+608]
  db $C5, $E5, $FE, $9C, $24, $E0, $01, $00, $00 // vpaddd ymm3, ymm3, [rsp+480]
  db $C5, $E5, $FE, $DF                      // vpaddd ymm3, ymm3, ymm7
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C4, $C1, $45, $EF, $FB                 // vpxor ymm7, ymm7, ymm11
  db $C5, $95, $72, $D7, $0C                 // vpsrld ymm13, ymm7, 12
  db $C5, $C5, $72, $F7, $14                 // vpslld ymm7, ymm7, 20
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  db $C5, $E5, $FE, $5C, $24, $20            // vpaddd ymm3, ymm3, [rsp+32]
  db $C5, $E5, $FE, $DF                      // vpaddd ymm3, ymm3, ymm7
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C5, $7E, $7F, $A4, $24, $60, $02, $00, $00 // vmovdqu [rsp+608], ymm12
  db $C4, $C1, $45, $EF, $FB                 // vpxor ymm7, ymm7, ymm11
  db $C5, $95, $72, $D7, $07                 // vpsrld ymm13, ymm7, 7
  db $C5, $C5, $72, $F7, $19                 // vpslld ymm7, ymm7, 25
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  // G diag (0,5,10,15) m[13],m[3]
  db $C5, $7E, $6F, $A4, $24, $60, $02, $00, $00 // vmovdqu ymm12, [rsp+608]
  db $C5, $FD, $FE, $84, $24, $A0, $01, $00, $00 // vpaddd ymm0, ymm0, [rsp+416]
  db $C5, $FD, $FE, $C5                      // vpaddd ymm0, ymm0, ymm5
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C4, $C1, $55, $EF, $EA                 // vpxor ymm5, ymm5, ymm10
  db $C5, $95, $72, $D5, $0C                 // vpsrld ymm13, ymm5, 12
  db $C5, $D5, $72, $F5, $14                 // vpslld ymm5, ymm5, 20
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  db $C5, $FD, $FE, $44, $24, $60            // vpaddd ymm0, ymm0, [rsp+96]
  db $C5, $FD, $FE, $C5                      // vpaddd ymm0, ymm0, ymm5
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C5, $7E, $7F, $A4, $24, $60, $02, $00, $00 // vmovdqu [rsp+608], ymm12
  db $C4, $C1, $55, $EF, $EA                 // vpxor ymm5, ymm5, ymm10
  db $C5, $95, $72, $D5, $07                 // vpsrld ymm13, ymm5, 7
  db $C5, $D5, $72, $F5, $19                 // vpslld ymm5, ymm5, 25
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  // G diag (1,6,11,12) m[0],m[10]
  db $C5, $7E, $6F, $A4, $24, $00, $02, $00, $00 // vmovdqu ymm12, [rsp+512]
  db $C5, $F5, $FE, $0C, $24                 // vpaddd ymm1, ymm1, [rsp+0]
  db $C5, $F5, $FE, $CE                      // vpaddd ymm1, ymm1, ymm6
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C4, $C1, $4D, $EF, $F3                 // vpxor ymm6, ymm6, ymm11
  db $C5, $95, $72, $D6, $0C                 // vpsrld ymm13, ymm6, 12
  db $C5, $CD, $72, $F6, $14                 // vpslld ymm6, ymm6, 20
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  db $C5, $F5, $FE, $8C, $24, $40, $01, $00, $00 // vpaddd ymm1, ymm1, [rsp+320]
  db $C5, $F5, $FE, $CE                      // vpaddd ymm1, ymm1, ymm6
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00 // vmovdqu [rsp+512], ymm12
  db $C4, $C1, $4D, $EF, $F3                 // vpxor ymm6, ymm6, ymm11
  db $C5, $95, $72, $D6, $07                 // vpsrld ymm13, ymm6, 7
  db $C5, $CD, $72, $F6, $19                 // vpslld ymm6, ymm6, 25
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  // G diag (2,7,8,13) m[2],m[6]
  db $C5, $7E, $6F, $A4, $24, $20, $02, $00, $00 // vmovdqu ymm12, [rsp+544]
  db $C5, $ED, $FE, $54, $24, $40            // vpaddd ymm2, ymm2, [rsp+64]
  db $C5, $ED, $FE, $D7                      // vpaddd ymm2, ymm2, ymm7
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C4, $C1, $45, $EF, $F8                 // vpxor ymm7, ymm7, ymm8
  db $C5, $95, $72, $D7, $0C                 // vpsrld ymm13, ymm7, 12
  db $C5, $C5, $72, $F7, $14                 // vpslld ymm7, ymm7, 20
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  db $C5, $ED, $FE, $94, $24, $C0, $00, $00, $00 // vpaddd ymm2, ymm2, [rsp+192]
  db $C5, $ED, $FE, $D7                      // vpaddd ymm2, ymm2, ymm7
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C5, $7E, $7F, $A4, $24, $20, $02, $00, $00 // vmovdqu [rsp+544], ymm12
  db $C4, $C1, $45, $EF, $F8                 // vpxor ymm7, ymm7, ymm8
  db $C5, $95, $72, $D7, $07                 // vpsrld ymm13, ymm7, 7
  db $C5, $C5, $72, $F7, $19                 // vpslld ymm7, ymm7, 25
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  // G diag (3,4,9,14) m[4],m[7]
  db $C5, $7E, $6F, $A4, $24, $40, $02, $00, $00 // vmovdqu ymm12, [rsp+576]
  db $C5, $E5, $FE, $9C, $24, $80, $00, $00, $00 // vpaddd ymm3, ymm3, [rsp+128]
  db $C5, $E5, $FE, $DC                      // vpaddd ymm3, ymm3, ymm4
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C4, $C1, $5D, $EF, $E1                 // vpxor ymm4, ymm4, ymm9
  db $C5, $95, $72, $D4, $0C                 // vpsrld ymm13, ymm4, 12
  db $C5, $DD, $72, $F4, $14                 // vpslld ymm4, ymm4, 20
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  db $C5, $E5, $FE, $9C, $24, $E0, $00, $00, $00 // vpaddd ymm3, ymm3, [rsp+224]
  db $C5, $E5, $FE, $DC                      // vpaddd ymm3, ymm3, ymm4
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C5, $7E, $7F, $A4, $24, $40, $02, $00, $00 // vmovdqu [rsp+576], ymm12
  db $C4, $C1, $5D, $EF, $E1                 // vpxor ymm4, ymm4, ymm9
  db $C5, $95, $72, $D4, $07                 // vpsrld ymm13, ymm4, 7
  db $C5, $DD, $72, $F4, $19                 // vpslld ymm4, ymm4, 25
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13

  // === Round 6 ===
  // G col (0,4,8,12) m[11],m[15]
  db $C5, $7E, $6F, $A4, $24, $00, $02, $00, $00 // vmovdqu ymm12, [rsp+512]
  db $C5, $FD, $FE, $84, $24, $60, $01, $00, $00 // vpaddd ymm0, ymm0, [rsp+352]
  db $C5, $FD, $FE, $C4                      // vpaddd ymm0, ymm0, ymm4
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C4, $C1, $5D, $EF, $E0                 // vpxor ymm4, ymm4, ymm8
  db $C5, $95, $72, $D4, $0C                 // vpsrld ymm13, ymm4, 12
  db $C5, $DD, $72, $F4, $14                 // vpslld ymm4, ymm4, 20
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  db $C5, $FD, $FE, $84, $24, $E0, $01, $00, $00 // vpaddd ymm0, ymm0, [rsp+480]
  db $C5, $FD, $FE, $C4                      // vpaddd ymm0, ymm0, ymm4
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00 // vmovdqu [rsp+512], ymm12
  db $C4, $C1, $5D, $EF, $E0                 // vpxor ymm4, ymm4, ymm8
  db $C5, $95, $72, $D4, $07                 // vpsrld ymm13, ymm4, 7
  db $C5, $DD, $72, $F4, $19                 // vpslld ymm4, ymm4, 25
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  // G col (1,5,9,13) m[5],m[0]
  db $C5, $7E, $6F, $A4, $24, $20, $02, $00, $00 // vmovdqu ymm12, [rsp+544]
  db $C5, $F5, $FE, $8C, $24, $A0, $00, $00, $00 // vpaddd ymm1, ymm1, [rsp+160]
  db $C5, $F5, $FE, $CD                      // vpaddd ymm1, ymm1, ymm5
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C4, $C1, $55, $EF, $E9                 // vpxor ymm5, ymm5, ymm9
  db $C5, $95, $72, $D5, $0C                 // vpsrld ymm13, ymm5, 12
  db $C5, $D5, $72, $F5, $14                 // vpslld ymm5, ymm5, 20
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  db $C5, $F5, $FE, $0C, $24                 // vpaddd ymm1, ymm1, [rsp+0]
  db $C5, $F5, $FE, $CD                      // vpaddd ymm1, ymm1, ymm5
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C5, $7E, $7F, $A4, $24, $20, $02, $00, $00 // vmovdqu [rsp+544], ymm12
  db $C4, $C1, $55, $EF, $E9                 // vpxor ymm5, ymm5, ymm9
  db $C5, $95, $72, $D5, $07                 // vpsrld ymm13, ymm5, 7
  db $C5, $D5, $72, $F5, $19                 // vpslld ymm5, ymm5, 25
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  // G col (2,6,10,14) m[1],m[9]
  db $C5, $7E, $6F, $A4, $24, $40, $02, $00, $00 // vmovdqu ymm12, [rsp+576]
  db $C5, $ED, $FE, $54, $24, $20            // vpaddd ymm2, ymm2, [rsp+32]
  db $C5, $ED, $FE, $D6                      // vpaddd ymm2, ymm2, ymm6
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C4, $C1, $4D, $EF, $F2                 // vpxor ymm6, ymm6, ymm10
  db $C5, $95, $72, $D6, $0C                 // vpsrld ymm13, ymm6, 12
  db $C5, $CD, $72, $F6, $14                 // vpslld ymm6, ymm6, 20
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  db $C5, $ED, $FE, $94, $24, $20, $01, $00, $00 // vpaddd ymm2, ymm2, [rsp+288]
  db $C5, $ED, $FE, $D6                      // vpaddd ymm2, ymm2, ymm6
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C5, $7E, $7F, $A4, $24, $40, $02, $00, $00 // vmovdqu [rsp+576], ymm12
  db $C4, $C1, $4D, $EF, $F2                 // vpxor ymm6, ymm6, ymm10
  db $C5, $95, $72, $D6, $07                 // vpsrld ymm13, ymm6, 7
  db $C5, $CD, $72, $F6, $19                 // vpslld ymm6, ymm6, 25
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  // G col (3,7,11,15) m[8],m[6]
  db $C5, $7E, $6F, $A4, $24, $60, $02, $00, $00 // vmovdqu ymm12, [rsp+608]
  db $C5, $E5, $FE, $9C, $24, $00, $01, $00, $00 // vpaddd ymm3, ymm3, [rsp+256]
  db $C5, $E5, $FE, $DF                      // vpaddd ymm3, ymm3, ymm7
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C4, $C1, $45, $EF, $FB                 // vpxor ymm7, ymm7, ymm11
  db $C5, $95, $72, $D7, $0C                 // vpsrld ymm13, ymm7, 12
  db $C5, $C5, $72, $F7, $14                 // vpslld ymm7, ymm7, 20
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  db $C5, $E5, $FE, $9C, $24, $C0, $00, $00, $00 // vpaddd ymm3, ymm3, [rsp+192]
  db $C5, $E5, $FE, $DF                      // vpaddd ymm3, ymm3, ymm7
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C5, $7E, $7F, $A4, $24, $60, $02, $00, $00 // vmovdqu [rsp+608], ymm12
  db $C4, $C1, $45, $EF, $FB                 // vpxor ymm7, ymm7, ymm11
  db $C5, $95, $72, $D7, $07                 // vpsrld ymm13, ymm7, 7
  db $C5, $C5, $72, $F7, $19                 // vpslld ymm7, ymm7, 25
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  // G diag (0,5,10,15) m[14],m[10]
  db $C5, $7E, $6F, $A4, $24, $60, $02, $00, $00 // vmovdqu ymm12, [rsp+608]
  db $C5, $FD, $FE, $84, $24, $C0, $01, $00, $00 // vpaddd ymm0, ymm0, [rsp+448]
  db $C5, $FD, $FE, $C5                      // vpaddd ymm0, ymm0, ymm5
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C4, $C1, $55, $EF, $EA                 // vpxor ymm5, ymm5, ymm10
  db $C5, $95, $72, $D5, $0C                 // vpsrld ymm13, ymm5, 12
  db $C5, $D5, $72, $F5, $14                 // vpslld ymm5, ymm5, 20
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  db $C5, $FD, $FE, $84, $24, $40, $01, $00, $00 // vpaddd ymm0, ymm0, [rsp+320]
  db $C5, $FD, $FE, $C5                      // vpaddd ymm0, ymm0, ymm5
  db $C5, $1D, $EF, $E0                      // vpxor ymm12, ymm12, ymm0
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $2D, $FE, $D4                 // vpaddd ymm10, ymm10, ymm12
  db $C5, $7E, $7F, $A4, $24, $60, $02, $00, $00 // vmovdqu [rsp+608], ymm12
  db $C4, $C1, $55, $EF, $EA                 // vpxor ymm5, ymm5, ymm10
  db $C5, $95, $72, $D5, $07                 // vpsrld ymm13, ymm5, 7
  db $C5, $D5, $72, $F5, $19                 // vpslld ymm5, ymm5, 25
  db $C4, $C1, $55, $EB, $ED                 // vpor ymm5, ymm5, ymm13
  // G diag (1,6,11,12) m[2],m[12]
  db $C5, $7E, $6F, $A4, $24, $00, $02, $00, $00 // vmovdqu ymm12, [rsp+512]
  db $C5, $F5, $FE, $4C, $24, $40            // vpaddd ymm1, ymm1, [rsp+64]
  db $C5, $F5, $FE, $CE                      // vpaddd ymm1, ymm1, ymm6
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C4, $C1, $4D, $EF, $F3                 // vpxor ymm6, ymm6, ymm11
  db $C5, $95, $72, $D6, $0C                 // vpsrld ymm13, ymm6, 12
  db $C5, $CD, $72, $F6, $14                 // vpslld ymm6, ymm6, 20
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  db $C5, $F5, $FE, $8C, $24, $80, $01, $00, $00 // vpaddd ymm1, ymm1, [rsp+384]
  db $C5, $F5, $FE, $CE                      // vpaddd ymm1, ymm1, ymm6
  db $C5, $1D, $EF, $E1                      // vpxor ymm12, ymm12, ymm1
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $25, $FE, $DC                 // vpaddd ymm11, ymm11, ymm12
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00 // vmovdqu [rsp+512], ymm12
  db $C4, $C1, $4D, $EF, $F3                 // vpxor ymm6, ymm6, ymm11
  db $C5, $95, $72, $D6, $07                 // vpsrld ymm13, ymm6, 7
  db $C5, $CD, $72, $F6, $19                 // vpslld ymm6, ymm6, 25
  db $C4, $C1, $4D, $EB, $F5                 // vpor ymm6, ymm6, ymm13
  // G diag (2,7,8,13) m[3],m[4]
  db $C5, $7E, $6F, $A4, $24, $20, $02, $00, $00 // vmovdqu ymm12, [rsp+544]
  db $C5, $ED, $FE, $54, $24, $60            // vpaddd ymm2, ymm2, [rsp+96]
  db $C5, $ED, $FE, $D7                      // vpaddd ymm2, ymm2, ymm7
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C4, $C1, $45, $EF, $F8                 // vpxor ymm7, ymm7, ymm8
  db $C5, $95, $72, $D7, $0C                 // vpsrld ymm13, ymm7, 12
  db $C5, $C5, $72, $F7, $14                 // vpslld ymm7, ymm7, 20
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  db $C5, $ED, $FE, $94, $24, $80, $00, $00, $00 // vpaddd ymm2, ymm2, [rsp+128]
  db $C5, $ED, $FE, $D7                      // vpaddd ymm2, ymm2, ymm7
  db $C5, $1D, $EF, $E2                      // vpxor ymm12, ymm12, ymm2
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $3D, $FE, $C4                 // vpaddd ymm8, ymm8, ymm12
  db $C5, $7E, $7F, $A4, $24, $20, $02, $00, $00 // vmovdqu [rsp+544], ymm12
  db $C4, $C1, $45, $EF, $F8                 // vpxor ymm7, ymm7, ymm8
  db $C5, $95, $72, $D7, $07                 // vpsrld ymm13, ymm7, 7
  db $C5, $C5, $72, $F7, $19                 // vpslld ymm7, ymm7, 25
  db $C4, $C1, $45, $EB, $FD                 // vpor ymm7, ymm7, ymm13
  // G diag (3,4,9,14) m[7],m[13]
  db $C5, $7E, $6F, $A4, $24, $40, $02, $00, $00 // vmovdqu ymm12, [rsp+576]
  db $C5, $E5, $FE, $9C, $24, $E0, $00, $00, $00 // vpaddd ymm3, ymm3, [rsp+224]
  db $C5, $E5, $FE, $DC                      // vpaddd ymm3, ymm3, ymm4
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $41, $7F, $70, $E4, $B1            // vpshuflw ymm12, ymm12, $B1
  db $C4, $41, $7E, $70, $E4, $B1            // vpshufhw ymm12, ymm12, $B1
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C4, $C1, $5D, $EF, $E1                 // vpxor ymm4, ymm4, ymm9
  db $C5, $95, $72, $D4, $0C                 // vpsrld ymm13, ymm4, 12
  db $C5, $DD, $72, $F4, $14                 // vpslld ymm4, ymm4, 20
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13
  db $C5, $E5, $FE, $9C, $24, $A0, $01, $00, $00 // vpaddd ymm3, ymm3, [rsp+416]
  db $C5, $E5, $FE, $DC                      // vpaddd ymm3, ymm3, ymm4
  db $C5, $1D, $EF, $E3                      // vpxor ymm12, ymm12, ymm3
  db $C4, $C1, $15, $72, $D4, $08            // vpsrld ymm13, ymm12, 8
  db $C4, $C1, $1D, $72, $F4, $18            // vpslld ymm12, ymm12, 24
  db $C4, $41, $1D, $EB, $E5                 // vpor ymm12, ymm12, ymm13
  db $C4, $41, $35, $FE, $CC                 // vpaddd ymm9, ymm9, ymm12
  db $C5, $7E, $7F, $A4, $24, $40, $02, $00, $00 // vmovdqu [rsp+576], ymm12
  db $C4, $C1, $5D, $EF, $E1                 // vpxor ymm4, ymm4, ymm9
  db $C5, $95, $72, $D4, $07                 // vpsrld ymm13, ymm4, 7
  db $C5, $DD, $72, $F4, $19                 // vpslld ymm4, ymm4, 25
  db $C4, $C1, $5D, $EB, $E5                 // vpor ymm4, ymm4, ymm13

  // Finalize: new_cv[i] = v[i] XOR v[i+8]
  db $C4, $C1, $7D, $EF, $C0                 // vpxor ymm0, ymm0, ymm8
  db $C4, $C1, $75, $EF, $C9                 // vpxor ymm1, ymm1, ymm9
  db $C4, $C1, $6D, $EF, $D2                 // vpxor ymm2, ymm2, ymm10
  db $C4, $C1, $65, $EF, $DB                 // vpxor ymm3, ymm3, ymm11
  db $C5, $7E, $6F, $A4, $24, $00, $02, $00, $00 // vmovdqu ymm12, [rsp+512]
  db $C4, $C1, $5D, $EF, $E4                 // vpxor ymm4, ymm4, ymm12
  db $C5, $7E, $6F, $A4, $24, $20, $02, $00, $00 // vmovdqu ymm12, [rsp+544]
  db $C4, $C1, $55, $EF, $EC                 // vpxor ymm5, ymm5, ymm12
  db $C5, $7E, $6F, $A4, $24, $40, $02, $00, $00 // vmovdqu ymm12, [rsp+576]
  db $C4, $C1, $4D, $EF, $F4                 // vpxor ymm6, ymm6, ymm12
  db $C5, $7E, $6F, $A4, $24, $60, $02, $00, $00 // vmovdqu ymm12, [rsp+608]
  db $C4, $C1, $45, $EF, $FC                 // vpxor ymm7, ymm7, ymm12

  // Store new CV
  db $C5, $FE, $7F, $84, $24, $80, $02, $00, $00 // vmovdqu [rsp+640], ymm0
  db $C5, $FE, $7F, $8C, $24, $A0, $02, $00, $00 // vmovdqu [rsp+672], ymm1
  db $C5, $FE, $7F, $94, $24, $C0, $02, $00, $00 // vmovdqu [rsp+704], ymm2
  db $C5, $FE, $7F, $9C, $24, $E0, $02, $00, $00 // vmovdqu [rsp+736], ymm3
  db $C5, $FE, $7F, $A4, $24, $00, $03, $00, $00 // vmovdqu [rsp+768], ymm4
  db $C5, $FE, $7F, $AC, $24, $20, $03, $00, $00 // vmovdqu [rsp+800], ymm5
  db $C5, $FE, $7F, $B4, $24, $40, $03, $00, $00 // vmovdqu [rsp+832], ymm6
  db $C5, $FE, $7F, $BC, $24, $60, $03, $00, $00 // vmovdqu [rsp+864], ymm7

  add ebp, 64
  inc ebx
  cmp ebx, 16
  jb @block_loop

  // Output: 8x8 transpose CV back to per-chunk layout
  mov rax, qword ptr [rsp + 1120]

  db $C5, $FE, $6F, $84, $24, $80, $02, $00, $00 // vmovdqu ymm0, [rsp+640]
  db $C5, $FE, $6F, $8C, $24, $A0, $02, $00, $00 // vmovdqu ymm1, [rsp+672]
  db $C5, $FE, $6F, $94, $24, $C0, $02, $00, $00 // vmovdqu ymm2, [rsp+704]
  db $C5, $FE, $6F, $9C, $24, $E0, $02, $00, $00 // vmovdqu ymm3, [rsp+736]
  db $C5, $FE, $6F, $A4, $24, $00, $03, $00, $00 // vmovdqu ymm4, [rsp+768]
  db $C5, $FE, $6F, $AC, $24, $20, $03, $00, $00 // vmovdqu ymm5, [rsp+800]
  db $C5, $FE, $6F, $B4, $24, $40, $03, $00, $00 // vmovdqu ymm6, [rsp+832]
  db $C5, $FE, $6F, $BC, $24, $60, $03, $00, $00 // vmovdqu ymm7, [rsp+864]
  db $C5, $7D, $62, $C1                      // vpunpckldq ymm8, ymm0, ymm1
  db $C5, $7D, $6A, $C9                      // vpunpckhdq ymm9, ymm0, ymm1
  db $C5, $6D, $62, $D3                      // vpunpckldq ymm10, ymm2, ymm3
  db $C5, $6D, $6A, $DB                      // vpunpckhdq ymm11, ymm2, ymm3
  db $C5, $5D, $62, $E5                      // vpunpckldq ymm12, ymm4, ymm5
  db $C5, $5D, $6A, $ED                      // vpunpckhdq ymm13, ymm4, ymm5
  db $C5, $CD, $62, $C7                      // vpunpckldq ymm0, ymm6, ymm7
  db $C5, $CD, $6A, $CF                      // vpunpckhdq ymm1, ymm6, ymm7
  db $C4, $C1, $3D, $6C, $D2                 // vpunpcklqdq ymm2, ymm8, ymm10
  db $C4, $C1, $3D, $6D, $DA                 // vpunpckhqdq ymm3, ymm8, ymm10
  db $C4, $C1, $35, $6C, $E3                 // vpunpcklqdq ymm4, ymm9, ymm11
  db $C4, $C1, $35, $6D, $EB                 // vpunpckhqdq ymm5, ymm9, ymm11
  db $C5, $9D, $6C, $F0                      // vpunpcklqdq ymm6, ymm12, ymm0
  db $C5, $9D, $6D, $F8                      // vpunpckhqdq ymm7, ymm12, ymm0
  db $C5, $15, $6C, $C1                      // vpunpcklqdq ymm8, ymm13, ymm1
  db $C5, $15, $6D, $C9                      // vpunpckhqdq ymm9, ymm13, ymm1
  db $C4, $E3, $6D, $46, $C6, $20            // vperm2i128 ymm0, ymm2, ymm6, $20
  db $C4, $63, $6D, $46, $D6, $31            // vperm2i128 ymm10, ymm2, ymm6, $31
  db $C4, $E3, $65, $46, $CF, $20            // vperm2i128 ymm1, ymm3, ymm7, $20
  db $C4, $63, $65, $46, $DF, $31            // vperm2i128 ymm11, ymm3, ymm7, $31
  db $C4, $C3, $5D, $46, $D0, $20            // vperm2i128 ymm2, ymm4, ymm8, $20
  db $C4, $43, $5D, $46, $E0, $31            // vperm2i128 ymm12, ymm4, ymm8, $31
  db $C4, $C3, $55, $46, $D9, $20            // vperm2i128 ymm3, ymm5, ymm9, $20
  db $C4, $43, $55, $46, $E9, $31            // vperm2i128 ymm13, ymm5, ymm9, $31
  db $C5, $FE, $7F, $00                      // vmovdqu [rax+0], ymm0
  db $C5, $FE, $7F, $48, $20                 // vmovdqu [rax+32], ymm1
  db $C5, $FE, $7F, $50, $40                 // vmovdqu [rax+64], ymm2
  db $C5, $FE, $7F, $58, $60                 // vmovdqu [rax+96], ymm3
  db $C5, $7E, $7F, $90, $80, $00, $00, $00  // vmovdqu [rax+128], ymm10
  db $C5, $7E, $7F, $98, $A0, $00, $00, $00  // vmovdqu [rax+160], ymm11
  db $C5, $7E, $7F, $A0, $C0, $00, $00, $00  // vmovdqu [rax+192], ymm12
  db $C5, $7E, $7F, $A8, $E0, $00, $00, $00  // vmovdqu [rax+224], ymm13

{$IFDEF MSWINDOWS}
  db $C5, $FA, $6F, $B4, $24, $80, $04, $00, $00 // vmovdqu xmm6, [rsp+1152]
  db $C5, $FA, $6F, $BC, $24, $90, $04, $00, $00 // vmovdqu xmm7, [rsp+1168]
  db $C5, $7A, $6F, $84, $24, $A0, $04, $00, $00 // vmovdqu xmm8, [rsp+1184]
  db $C5, $7A, $6F, $8C, $24, $B0, $04, $00, $00 // vmovdqu xmm9, [rsp+1200]
  db $C5, $7A, $6F, $94, $24, $C0, $04, $00, $00 // vmovdqu xmm10, [rsp+1216]
  db $C5, $7A, $6F, $9C, $24, $D0, $04, $00, $00 // vmovdqu xmm11, [rsp+1232]
  db $C5, $7A, $6F, $A4, $24, $E0, $04, $00, $00 // vmovdqu xmm12, [rsp+1248]
  db $C5, $7A, $6F, $AC, $24, $F0, $04, $00, $00 // vmovdqu xmm13, [rsp+1264]
{$ENDIF}

  db $C5, $F8, $77                           // vzeroupper

  mov rsp, qword ptr [rsp + 1136]
  pop r12
  pop rbp
  pop rbx
