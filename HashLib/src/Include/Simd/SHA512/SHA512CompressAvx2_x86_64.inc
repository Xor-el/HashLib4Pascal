// SHA-512 AVX2 two-block implementation (VEX-256), ported from OpenSSL's
// sha512-x86_64.pl (CRYPTOGAMS). Two message blocks are scheduled together in
// 256-bit lanes; the compression rounds stay serial (as SHA-512 requires), so
// scheduling two blocks at once is what makes this faster than the single-block
// AVX path. AVX2 and BMI2 (rorx/andn) instructions are db-encoded for broad
// assembler compatibility (every AVX2 CPU also provides BMI2).
// Expects MS x64 ABI (after SimdProc4Begin): rcx = state ptr, rdx = data ptr,
//   r8d = numblocks, r9 = doubled-K512 ptr (each 128-bit K512 pair stored twice
//   so one table feeds both 256-bit lanes, with the BSWAP64 mask appended; see
//   K512_Doubled). The mask is read unaligned, so the Pascal const needs no
//   special alignment.
//
// MS x64 non-volatile saves: xmm6-xmm15 via the shared SimdNonVolatileSave/Restore
// include (no-op on SysV); rbx, rbp, rdi, rsi, r12-r15 in the local frame.

  {$I ..\Include\Simd\Common\SimdNonVolatileSave_x86_64.inc}

  mov    rax, rsp
  push   r9
  push   rbx
  push   rbp
  push   rsi
  push   rdi
  push   r12
  push   r13
  push   r14
  push   r15
  mov    rdi, rcx
  mov    rsi, rdx
  mov    edx, r8d
  sub    rsp, $580
  shl    rdx, $4
  and    rsp, $FFFFFFFFFFFFF800
  lea    rdx, [rsi + rdx*8]
  add    rsp, $480
  mov    qword [rsp + $80], rdi
  mov    qword [rsp + $88], rsi
  mov    qword [rsp + $90], rdx
  mov    qword [rsp + $98], rax

@prologue:
  db $C5, $F8, $77                                        // vzeroupper
  sub    rsi, $FFFFFFFFFFFFFF80
  mov    rax, qword [rdi]
  mov    r12, rsi
  mov    rbx, qword [rdi + $8]
  cmp    rsi, rdx
  mov    rcx, qword [rdi + $10]
  cmove  r12, rsp
  mov    rdx, qword [rdi + $18]
  mov    r8, qword [rdi + $20]
  mov    r9, qword [rdi + $28]
  mov    r10, qword [rdi + $30]
  mov    r11, qword [rdi + $38]
  jmp @block_loop

@block_loop:
  db $C5, $FA, $6F, $46, $80                              // vmovdqu xmm0, oword [rsi - $80]
  db $C5, $FA, $6F, $4E, $90                              // vmovdqu xmm1, oword [rsi - $70]
  db $C5, $FA, $6F, $56, $A0                              // vmovdqu xmm2, oword [rsi - $60]
  mov    rbp, qword [rsp + $98]
  mov    rbp, qword [rbp - $8]
  add    rbp, $80
  db $C5, $FA, $6F, $5E, $B0                              // vmovdqu xmm3, oword [rsi - $50]
  db $C5, $FA, $6F, $66, $C0                              // vmovdqu xmm4, oword [rsi - $40]
  db $C5, $FA, $6F, $6E, $D0                              // vmovdqu xmm5, oword [rsi - $30]
  db $C5, $FA, $6F, $76, $E0                              // vmovdqu xmm6, oword [rsi - $20]
  db $C5, $FA, $6F, $7E, $F0                              // vmovdqu xmm7, oword [rsi - $10]
  db $C5, $7E, $6F, $95, $80, $04, $00, $00               // vmovdqu ymm10, yword [rbp + $480]
  db $C4, $C3, $7D, $38, $04, $24, $01                    // vinserti128 ymm0, ymm0, oword [r12], $1
  db $C4, $C3, $75, $38, $4C, $24, $10, $01               // vinserti128 ymm1, ymm1, oword [r12 + $10], $1
  db $C4, $C2, $7D, $00, $C2                              // vpshufb ymm0, ymm0, ymm10
  db $C4, $C3, $6D, $38, $54, $24, $20, $01               // vinserti128 ymm2, ymm2, oword [r12 + $20], $1
  db $C4, $C2, $75, $00, $CA                              // vpshufb ymm1, ymm1, ymm10
  db $C4, $C3, $65, $38, $5C, $24, $30, $01               // vinserti128 ymm3, ymm3, oword [r12 + $30], $1
  db $C4, $C2, $6D, $00, $D2                              // vpshufb ymm2, ymm2, ymm10
  db $C4, $C3, $5D, $38, $64, $24, $40, $01               // vinserti128 ymm4, ymm4, oword [r12 + $40], $1
  db $C4, $C2, $65, $00, $DA                              // vpshufb ymm3, ymm3, ymm10
  db $C4, $C3, $55, $38, $6C, $24, $50, $01               // vinserti128 ymm5, ymm5, oword [r12 + $50], $1
  db $C4, $C2, $5D, $00, $E2                              // vpshufb ymm4, ymm4, ymm10
  db $C4, $C3, $4D, $38, $74, $24, $60, $01               // vinserti128 ymm6, ymm6, oword [r12 + $60], $1
  db $C4, $C2, $55, $00, $EA                              // vpshufb ymm5, ymm5, ymm10
  db $C4, $C3, $45, $38, $7C, $24, $70, $01               // vinserti128 ymm7, ymm7, oword [r12 + $70], $1
  db $C5, $7D, $D4, $45, $80                              // vpaddq ymm8, ymm0, yword [rbp - $80]
  db $C4, $C2, $4D, $00, $F2                              // vpshufb ymm6, ymm6, ymm10
  db $C5, $75, $D4, $4D, $A0                              // vpaddq ymm9, ymm1, yword [rbp - $60]
  db $C4, $C2, $45, $00, $FA                              // vpshufb ymm7, ymm7, ymm10
  db $C5, $6D, $D4, $55, $C0                              // vpaddq ymm10, ymm2, yword [rbp - $40]
  db $C5, $65, $D4, $5D, $E0                              // vpaddq ymm11, ymm3, yword [rbp - $20]
  db $C5, $7D, $7F, $04, $24                              // vmovdqa yword [rsp], ymm8
  db $C5, $5D, $D4, $45, $00                              // vpaddq ymm8, ymm4, yword [rbp + $0]
  db $C5, $7D, $7F, $4C, $24, $20                         // vmovdqa yword [rsp + $20], ymm9
  db $C5, $55, $D4, $4D, $20                              // vpaddq ymm9, ymm5, yword [rbp + $20]
  db $C5, $7D, $7F, $54, $24, $40                         // vmovdqa yword [rsp + $40], ymm10
  db $C5, $4D, $D4, $55, $40                              // vpaddq ymm10, ymm6, yword [rbp + $40]
  db $C5, $7D, $7F, $5C, $24, $60                         // vmovdqa yword [rsp + $60], ymm11
  lea    rsp, [rsp - $80]
  db $C5, $45, $D4, $5D, $60                              // vpaddq ymm11, ymm7, yword [rbp + $60]
  db $C5, $7D, $7F, $04, $24                              // vmovdqa yword [rsp], ymm8
  xor    r14, r14
  db $C5, $7D, $7F, $4C, $24, $20                         // vmovdqa yword [rsp + $20], ymm9
  mov    rdi, rbx
  db $C5, $7D, $7F, $54, $24, $40                         // vmovdqa yword [rsp + $40], ymm10
  xor    rdi, rcx
  db $C5, $7D, $7F, $5C, $24, $60                         // vmovdqa yword [rsp + $60], ymm11
  mov    r12, r9
  add    rbp, $100
  jmp @sched_loop

@sched_loop:
  lea    rsp, [rsp - $80]
  db $C4, $63, $75, $0F, $C0, $08                         // vpalignr ymm8, ymm1, ymm0, $8
  add    r11, qword [rsp + $100]
  and    r12, r8
  db $C4, $43, $FB, $F0, $E8, $29                         // rorx   r13, r8, $29
  db $C4, $63, $55, $0F, $DC, $08                         // vpalignr ymm11, ymm5, ymm4, $8
  db $C4, $43, $FB, $F0, $F8, $12                         // rorx   r15, r8, $12
  lea    rax, [rax + r14*1]
  lea    r11, [r11 + r12*1]
  db $C4, $C1, $2D, $73, $D0, $01                         // vpsrlq ymm10, ymm8, $1
  db $C4, $42, $B8, $F2, $E2                              // andn   r12, r8, r10
  xor    r13, r15
  db $C4, $43, $FB, $F0, $F0, $0E                         // rorx   r14, r8, $E
  db $C4, $C1, $7D, $D4, $C3                              // vpaddq ymm0, ymm0, ymm11
  db $C4, $C1, $25, $73, $D0, $07                         // vpsrlq ymm11, ymm8, $7
  lea    r11, [r11 + r12*1]
  xor    r13, r14
  mov    r15, rax
  db $C4, $C1, $35, $73, $F0, $38                         // vpsllq ymm9, ymm8, $38
  db $C4, $41, $25, $EF, $C2                              // vpxor  ymm8, ymm11, ymm10
  db $C4, $63, $FB, $F0, $E0, $27                         // rorx   r12, rax, $27
  lea    r11, [r11 + r13*1]
  xor    r15, rbx
  db $C4, $C1, $2D, $73, $D2, $07                         // vpsrlq ymm10, ymm10, $7
  db $C4, $41, $3D, $EF, $C1                              // vpxor  ymm8, ymm8, ymm9
  db $C4, $63, $FB, $F0, $F0, $22                         // rorx   r14, rax, $22
  db $C4, $63, $FB, $F0, $E8, $1C                         // rorx   r13, rax, $1C
  lea    rdx, [rdx + r11*1]
  db $C4, $C1, $35, $73, $F1, $07                         // vpsllq ymm9, ymm9, $7
  db $C4, $41, $3D, $EF, $C2                              // vpxor  ymm8, ymm8, ymm10
  and    rdi, r15
  xor    r14, r12
  xor    rdi, rbx
  db $C5, $A5, $73, $D7, $06                              // vpsrlq ymm11, ymm7, $6
  db $C4, $41, $3D, $EF, $C1                              // vpxor  ymm8, ymm8, ymm9
  xor    r14, r13
  lea    r11, [r11 + rdi*1]
  mov    r12, r8
  db $C5, $AD, $73, $F7, $03                              // vpsllq ymm10, ymm7, $3
  db $C4, $C1, $7D, $D4, $C0                              // vpaddq ymm0, ymm0, ymm8
  add    r10, qword [rsp + $108]
  and    r12, rdx
  db $C4, $63, $FB, $F0, $EA, $29                         // rorx   r13, rdx, $29
  db $C5, $B5, $73, $D7, $13                              // vpsrlq ymm9, ymm7, $13
  db $C4, $41, $25, $EF, $DA                              // vpxor  ymm11, ymm11, ymm10
  db $C4, $E3, $FB, $F0, $FA, $12                         // rorx   rdi, rdx, $12
  lea    r11, [r11 + r14*1]
  lea    r10, [r10 + r12*1]
  db $C4, $C1, $2D, $73, $F2, $2A                         // vpsllq ymm10, ymm10, $2A
  db $C4, $41, $25, $EF, $D9                              // vpxor  ymm11, ymm11, ymm9
  db $C4, $42, $E8, $F2, $E1                              // andn   r12, rdx, r9
  xor    r13, rdi
  db $C4, $63, $FB, $F0, $F2, $0E                         // rorx   r14, rdx, $E
  db $C4, $C1, $35, $73, $D1, $2A                         // vpsrlq ymm9, ymm9, $2A
  db $C4, $41, $25, $EF, $DA                              // vpxor  ymm11, ymm11, ymm10
  lea    r10, [r10 + r12*1]
  xor    r13, r14
  mov    rdi, r11
  db $C4, $41, $25, $EF, $D9                              // vpxor  ymm11, ymm11, ymm9
  db $C4, $43, $FB, $F0, $E3, $27                         // rorx   r12, r11, $27
  lea    r10, [r10 + r13*1]
  xor    rdi, rax
  db $C4, $C1, $7D, $D4, $C3                              // vpaddq ymm0, ymm0, ymm11
  db $C4, $43, $FB, $F0, $F3, $22                         // rorx   r14, r11, $22
  db $C4, $43, $FB, $F0, $EB, $1C                         // rorx   r13, r11, $1C
  lea    rcx, [rcx + r10*1]
  db $C5, $7D, $D4, $55, $80                              // vpaddq ymm10, ymm0, yword [rbp - $80]
  and    r15, rdi
  xor    r14, r12
  xor    r15, rax
  xor    r14, r13
  lea    r10, [r10 + r15*1]
  mov    r12, rdx
  db $C5, $7D, $7F, $14, $24                              // vmovdqa yword [rsp], ymm10
  db $C4, $63, $6D, $0F, $C1, $08                         // vpalignr ymm8, ymm2, ymm1, $8
  add    r9, qword [rsp + $120]
  and    r12, rcx
  db $C4, $63, $FB, $F0, $E9, $29                         // rorx   r13, rcx, $29
  db $C4, $63, $4D, $0F, $DD, $08                         // vpalignr ymm11, ymm6, ymm5, $8
  db $C4, $63, $FB, $F0, $F9, $12                         // rorx   r15, rcx, $12
  lea    r10, [r10 + r14*1]
  lea    r9, [r9 + r12*1]
  db $C4, $C1, $2D, $73, $D0, $01                         // vpsrlq ymm10, ymm8, $1
  db $C4, $42, $F0, $F2, $E0                              // andn   r12, rcx, r8
  xor    r13, r15
  db $C4, $63, $FB, $F0, $F1, $0E                         // rorx   r14, rcx, $E
  db $C4, $C1, $75, $D4, $CB                              // vpaddq ymm1, ymm1, ymm11
  db $C4, $C1, $25, $73, $D0, $07                         // vpsrlq ymm11, ymm8, $7
  lea    r9, [r9 + r12*1]
  xor    r13, r14
  mov    r15, r10
  db $C4, $C1, $35, $73, $F0, $38                         // vpsllq ymm9, ymm8, $38
  db $C4, $41, $25, $EF, $C2                              // vpxor  ymm8, ymm11, ymm10
  db $C4, $43, $FB, $F0, $E2, $27                         // rorx   r12, r10, $27
  lea    r9, [r9 + r13*1]
  xor    r15, r11
  db $C4, $C1, $2D, $73, $D2, $07                         // vpsrlq ymm10, ymm10, $7
  db $C4, $41, $3D, $EF, $C1                              // vpxor  ymm8, ymm8, ymm9
  db $C4, $43, $FB, $F0, $F2, $22                         // rorx   r14, r10, $22
  db $C4, $43, $FB, $F0, $EA, $1C                         // rorx   r13, r10, $1C
  lea    rbx, [rbx + r9*1]
  db $C4, $C1, $35, $73, $F1, $07                         // vpsllq ymm9, ymm9, $7
  db $C4, $41, $3D, $EF, $C2                              // vpxor  ymm8, ymm8, ymm10
  and    rdi, r15
  xor    r14, r12
  xor    rdi, r11
  db $C5, $A5, $73, $D0, $06                              // vpsrlq ymm11, ymm0, $6
  db $C4, $41, $3D, $EF, $C1                              // vpxor  ymm8, ymm8, ymm9
  xor    r14, r13
  lea    r9, [r9 + rdi*1]
  mov    r12, rcx
  db $C5, $AD, $73, $F0, $03                              // vpsllq ymm10, ymm0, $3
  db $C4, $C1, $75, $D4, $C8                              // vpaddq ymm1, ymm1, ymm8
  add    r8, qword [rsp + $128]
  and    r12, rbx
  db $C4, $63, $FB, $F0, $EB, $29                         // rorx   r13, rbx, $29
  db $C5, $B5, $73, $D0, $13                              // vpsrlq ymm9, ymm0, $13
  db $C4, $41, $25, $EF, $DA                              // vpxor  ymm11, ymm11, ymm10
  db $C4, $E3, $FB, $F0, $FB, $12                         // rorx   rdi, rbx, $12
  lea    r9, [r9 + r14*1]
  lea    r8, [r8 + r12*1]
  db $C4, $C1, $2D, $73, $F2, $2A                         // vpsllq ymm10, ymm10, $2A
  db $C4, $41, $25, $EF, $D9                              // vpxor  ymm11, ymm11, ymm9
  db $C4, $62, $E0, $F2, $E2                              // andn   r12, rbx, rdx
  xor    r13, rdi
  db $C4, $63, $FB, $F0, $F3, $0E                         // rorx   r14, rbx, $E
  db $C4, $C1, $35, $73, $D1, $2A                         // vpsrlq ymm9, ymm9, $2A
  db $C4, $41, $25, $EF, $DA                              // vpxor  ymm11, ymm11, ymm10
  lea    r8, [r8 + r12*1]
  xor    r13, r14
  mov    rdi, r9
  db $C4, $41, $25, $EF, $D9                              // vpxor  ymm11, ymm11, ymm9
  db $C4, $43, $FB, $F0, $E1, $27                         // rorx   r12, r9, $27
  lea    r8, [r8 + r13*1]
  xor    rdi, r10
  db $C4, $C1, $75, $D4, $CB                              // vpaddq ymm1, ymm1, ymm11
  db $C4, $43, $FB, $F0, $F1, $22                         // rorx   r14, r9, $22
  db $C4, $43, $FB, $F0, $E9, $1C                         // rorx   r13, r9, $1C
  lea    rax, [rax + r8*1]
  db $C5, $75, $D4, $55, $A0                              // vpaddq ymm10, ymm1, yword [rbp - $60]
  and    r15, rdi
  xor    r14, r12
  xor    r15, r10
  xor    r14, r13
  lea    r8, [r8 + r15*1]
  mov    r12, rbx
  db $C5, $7D, $7F, $54, $24, $20                         // vmovdqa yword [rsp + $20], ymm10
  db $C4, $63, $65, $0F, $C2, $08                         // vpalignr ymm8, ymm3, ymm2, $8
  add    rdx, qword [rsp + $140]
  and    r12, rax
  db $C4, $63, $FB, $F0, $E8, $29                         // rorx   r13, rax, $29
  db $C4, $63, $45, $0F, $DE, $08                         // vpalignr ymm11, ymm7, ymm6, $8
  db $C4, $63, $FB, $F0, $F8, $12                         // rorx   r15, rax, $12
  lea    r8, [r8 + r14*1]
  lea    rdx, [rdx + r12*1]
  db $C4, $C1, $2D, $73, $D0, $01                         // vpsrlq ymm10, ymm8, $1
  db $C4, $62, $F8, $F2, $E1                              // andn   r12, rax, rcx
  xor    r13, r15
  db $C4, $63, $FB, $F0, $F0, $0E                         // rorx   r14, rax, $E
  db $C4, $C1, $6D, $D4, $D3                              // vpaddq ymm2, ymm2, ymm11
  db $C4, $C1, $25, $73, $D0, $07                         // vpsrlq ymm11, ymm8, $7
  lea    rdx, [rdx + r12*1]
  xor    r13, r14
  mov    r15, r8
  db $C4, $C1, $35, $73, $F0, $38                         // vpsllq ymm9, ymm8, $38
  db $C4, $41, $25, $EF, $C2                              // vpxor  ymm8, ymm11, ymm10
  db $C4, $43, $FB, $F0, $E0, $27                         // rorx   r12, r8, $27
  lea    rdx, [rdx + r13*1]
  xor    r15, r9
  db $C4, $C1, $2D, $73, $D2, $07                         // vpsrlq ymm10, ymm10, $7
  db $C4, $41, $3D, $EF, $C1                              // vpxor  ymm8, ymm8, ymm9
  db $C4, $43, $FB, $F0, $F0, $22                         // rorx   r14, r8, $22
  db $C4, $43, $FB, $F0, $E8, $1C                         // rorx   r13, r8, $1C
  lea    r11, [r11 + rdx*1]
  db $C4, $C1, $35, $73, $F1, $07                         // vpsllq ymm9, ymm9, $7
  db $C4, $41, $3D, $EF, $C2                              // vpxor  ymm8, ymm8, ymm10
  and    rdi, r15
  xor    r14, r12
  xor    rdi, r9
  db $C5, $A5, $73, $D1, $06                              // vpsrlq ymm11, ymm1, $6
  db $C4, $41, $3D, $EF, $C1                              // vpxor  ymm8, ymm8, ymm9
  xor    r14, r13
  lea    rdx, [rdx + rdi*1]
  mov    r12, rax
  db $C5, $AD, $73, $F1, $03                              // vpsllq ymm10, ymm1, $3
  db $C4, $C1, $6D, $D4, $D0                              // vpaddq ymm2, ymm2, ymm8
  add    rcx, qword [rsp + $148]
  and    r12, r11
  db $C4, $43, $FB, $F0, $EB, $29                         // rorx   r13, r11, $29
  db $C5, $B5, $73, $D1, $13                              // vpsrlq ymm9, ymm1, $13
  db $C4, $41, $25, $EF, $DA                              // vpxor  ymm11, ymm11, ymm10
  db $C4, $C3, $FB, $F0, $FB, $12                         // rorx   rdi, r11, $12
  lea    rdx, [rdx + r14*1]
  lea    rcx, [rcx + r12*1]
  db $C4, $C1, $2D, $73, $F2, $2A                         // vpsllq ymm10, ymm10, $2A
  db $C4, $41, $25, $EF, $D9                              // vpxor  ymm11, ymm11, ymm9
  db $C4, $62, $A0, $F2, $E3                              // andn   r12, r11, rbx
  xor    r13, rdi
  db $C4, $43, $FB, $F0, $F3, $0E                         // rorx   r14, r11, $E
  db $C4, $C1, $35, $73, $D1, $2A                         // vpsrlq ymm9, ymm9, $2A
  db $C4, $41, $25, $EF, $DA                              // vpxor  ymm11, ymm11, ymm10
  lea    rcx, [rcx + r12*1]
  xor    r13, r14
  mov    rdi, rdx
  db $C4, $41, $25, $EF, $D9                              // vpxor  ymm11, ymm11, ymm9
  db $C4, $63, $FB, $F0, $E2, $27                         // rorx   r12, rdx, $27
  lea    rcx, [rcx + r13*1]
  xor    rdi, r8
  db $C4, $C1, $6D, $D4, $D3                              // vpaddq ymm2, ymm2, ymm11
  db $C4, $63, $FB, $F0, $F2, $22                         // rorx   r14, rdx, $22
  db $C4, $63, $FB, $F0, $EA, $1C                         // rorx   r13, rdx, $1C
  lea    r10, [r10 + rcx*1]
  db $C5, $6D, $D4, $55, $C0                              // vpaddq ymm10, ymm2, yword [rbp - $40]
  and    r15, rdi
  xor    r14, r12
  xor    r15, r8
  xor    r14, r13
  lea    rcx, [rcx + r15*1]
  mov    r12, r11
  db $C5, $7D, $7F, $54, $24, $40                         // vmovdqa yword [rsp + $40], ymm10
  db $C4, $63, $5D, $0F, $C3, $08                         // vpalignr ymm8, ymm4, ymm3, $8
  add    rbx, qword [rsp + $160]
  and    r12, r10
  db $C4, $43, $FB, $F0, $EA, $29                         // rorx   r13, r10, $29
  db $C4, $63, $7D, $0F, $DF, $08                         // vpalignr ymm11, ymm0, ymm7, $8
  db $C4, $43, $FB, $F0, $FA, $12                         // rorx   r15, r10, $12
  lea    rcx, [rcx + r14*1]
  lea    rbx, [rbx + r12*1]
  db $C4, $C1, $2D, $73, $D0, $01                         // vpsrlq ymm10, ymm8, $1
  db $C4, $62, $A8, $F2, $E0                              // andn   r12, r10, rax
  xor    r13, r15
  db $C4, $43, $FB, $F0, $F2, $0E                         // rorx   r14, r10, $E
  db $C4, $C1, $65, $D4, $DB                              // vpaddq ymm3, ymm3, ymm11
  db $C4, $C1, $25, $73, $D0, $07                         // vpsrlq ymm11, ymm8, $7
  lea    rbx, [rbx + r12*1]
  xor    r13, r14
  mov    r15, rcx
  db $C4, $C1, $35, $73, $F0, $38                         // vpsllq ymm9, ymm8, $38
  db $C4, $41, $25, $EF, $C2                              // vpxor  ymm8, ymm11, ymm10
  db $C4, $63, $FB, $F0, $E1, $27                         // rorx   r12, rcx, $27
  lea    rbx, [rbx + r13*1]
  xor    r15, rdx
  db $C4, $C1, $2D, $73, $D2, $07                         // vpsrlq ymm10, ymm10, $7
  db $C4, $41, $3D, $EF, $C1                              // vpxor  ymm8, ymm8, ymm9
  db $C4, $63, $FB, $F0, $F1, $22                         // rorx   r14, rcx, $22
  db $C4, $63, $FB, $F0, $E9, $1C                         // rorx   r13, rcx, $1C
  lea    r9, [r9 + rbx*1]
  db $C4, $C1, $35, $73, $F1, $07                         // vpsllq ymm9, ymm9, $7
  db $C4, $41, $3D, $EF, $C2                              // vpxor  ymm8, ymm8, ymm10
  and    rdi, r15
  xor    r14, r12
  xor    rdi, rdx
  db $C5, $A5, $73, $D2, $06                              // vpsrlq ymm11, ymm2, $6
  db $C4, $41, $3D, $EF, $C1                              // vpxor  ymm8, ymm8, ymm9
  xor    r14, r13
  lea    rbx, [rbx + rdi*1]
  mov    r12, r10
  db $C5, $AD, $73, $F2, $03                              // vpsllq ymm10, ymm2, $3
  db $C4, $C1, $65, $D4, $D8                              // vpaddq ymm3, ymm3, ymm8
  add    rax, qword [rsp + $168]
  and    r12, r9
  db $C4, $43, $FB, $F0, $E9, $29                         // rorx   r13, r9, $29
  db $C5, $B5, $73, $D2, $13                              // vpsrlq ymm9, ymm2, $13
  db $C4, $41, $25, $EF, $DA                              // vpxor  ymm11, ymm11, ymm10
  db $C4, $C3, $FB, $F0, $F9, $12                         // rorx   rdi, r9, $12
  lea    rbx, [rbx + r14*1]
  lea    rax, [rax + r12*1]
  db $C4, $C1, $2D, $73, $F2, $2A                         // vpsllq ymm10, ymm10, $2A
  db $C4, $41, $25, $EF, $D9                              // vpxor  ymm11, ymm11, ymm9
  db $C4, $42, $B0, $F2, $E3                              // andn   r12, r9, r11
  xor    r13, rdi
  db $C4, $43, $FB, $F0, $F1, $0E                         // rorx   r14, r9, $E
  db $C4, $C1, $35, $73, $D1, $2A                         // vpsrlq ymm9, ymm9, $2A
  db $C4, $41, $25, $EF, $DA                              // vpxor  ymm11, ymm11, ymm10
  lea    rax, [rax + r12*1]
  xor    r13, r14
  mov    rdi, rbx
  db $C4, $41, $25, $EF, $D9                              // vpxor  ymm11, ymm11, ymm9
  db $C4, $63, $FB, $F0, $E3, $27                         // rorx   r12, rbx, $27
  lea    rax, [rax + r13*1]
  xor    rdi, rcx
  db $C4, $C1, $65, $D4, $DB                              // vpaddq ymm3, ymm3, ymm11
  db $C4, $63, $FB, $F0, $F3, $22                         // rorx   r14, rbx, $22
  db $C4, $63, $FB, $F0, $EB, $1C                         // rorx   r13, rbx, $1C
  lea    r8, [r8 + rax*1]
  db $C5, $65, $D4, $55, $E0                              // vpaddq ymm10, ymm3, yword [rbp - $20]
  and    r15, rdi
  xor    r14, r12
  xor    r15, rcx
  xor    r14, r13
  lea    rax, [rax + r15*1]
  mov    r12, r9
  db $C5, $7D, $7F, $54, $24, $60                         // vmovdqa yword [rsp + $60], ymm10
  lea    rsp, [rsp - $80]
  db $C4, $63, $55, $0F, $C4, $08                         // vpalignr ymm8, ymm5, ymm4, $8
  add    r11, qword [rsp + $100]
  and    r12, r8
  db $C4, $43, $FB, $F0, $E8, $29                         // rorx   r13, r8, $29
  db $C4, $63, $75, $0F, $D8, $08                         // vpalignr ymm11, ymm1, ymm0, $8
  db $C4, $43, $FB, $F0, $F8, $12                         // rorx   r15, r8, $12
  lea    rax, [rax + r14*1]
  lea    r11, [r11 + r12*1]
  db $C4, $C1, $2D, $73, $D0, $01                         // vpsrlq ymm10, ymm8, $1
  db $C4, $42, $B8, $F2, $E2                              // andn   r12, r8, r10
  xor    r13, r15
  db $C4, $43, $FB, $F0, $F0, $0E                         // rorx   r14, r8, $E
  db $C4, $C1, $5D, $D4, $E3                              // vpaddq ymm4, ymm4, ymm11
  db $C4, $C1, $25, $73, $D0, $07                         // vpsrlq ymm11, ymm8, $7
  lea    r11, [r11 + r12*1]
  xor    r13, r14
  mov    r15, rax
  db $C4, $C1, $35, $73, $F0, $38                         // vpsllq ymm9, ymm8, $38
  db $C4, $41, $25, $EF, $C2                              // vpxor  ymm8, ymm11, ymm10
  db $C4, $63, $FB, $F0, $E0, $27                         // rorx   r12, rax, $27
  lea    r11, [r11 + r13*1]
  xor    r15, rbx
  db $C4, $C1, $2D, $73, $D2, $07                         // vpsrlq ymm10, ymm10, $7
  db $C4, $41, $3D, $EF, $C1                              // vpxor  ymm8, ymm8, ymm9
  db $C4, $63, $FB, $F0, $F0, $22                         // rorx   r14, rax, $22
  db $C4, $63, $FB, $F0, $E8, $1C                         // rorx   r13, rax, $1C
  lea    rdx, [rdx + r11*1]
  db $C4, $C1, $35, $73, $F1, $07                         // vpsllq ymm9, ymm9, $7
  db $C4, $41, $3D, $EF, $C2                              // vpxor  ymm8, ymm8, ymm10
  and    rdi, r15
  xor    r14, r12
  xor    rdi, rbx
  db $C5, $A5, $73, $D3, $06                              // vpsrlq ymm11, ymm3, $6
  db $C4, $41, $3D, $EF, $C1                              // vpxor  ymm8, ymm8, ymm9
  xor    r14, r13
  lea    r11, [r11 + rdi*1]
  mov    r12, r8
  db $C5, $AD, $73, $F3, $03                              // vpsllq ymm10, ymm3, $3
  db $C4, $C1, $5D, $D4, $E0                              // vpaddq ymm4, ymm4, ymm8
  add    r10, qword [rsp + $108]
  and    r12, rdx
  db $C4, $63, $FB, $F0, $EA, $29                         // rorx   r13, rdx, $29
  db $C5, $B5, $73, $D3, $13                              // vpsrlq ymm9, ymm3, $13
  db $C4, $41, $25, $EF, $DA                              // vpxor  ymm11, ymm11, ymm10
  db $C4, $E3, $FB, $F0, $FA, $12                         // rorx   rdi, rdx, $12
  lea    r11, [r11 + r14*1]
  lea    r10, [r10 + r12*1]
  db $C4, $C1, $2D, $73, $F2, $2A                         // vpsllq ymm10, ymm10, $2A
  db $C4, $41, $25, $EF, $D9                              // vpxor  ymm11, ymm11, ymm9
  db $C4, $42, $E8, $F2, $E1                              // andn   r12, rdx, r9
  xor    r13, rdi
  db $C4, $63, $FB, $F0, $F2, $0E                         // rorx   r14, rdx, $E
  db $C4, $C1, $35, $73, $D1, $2A                         // vpsrlq ymm9, ymm9, $2A
  db $C4, $41, $25, $EF, $DA                              // vpxor  ymm11, ymm11, ymm10
  lea    r10, [r10 + r12*1]
  xor    r13, r14
  mov    rdi, r11
  db $C4, $41, $25, $EF, $D9                              // vpxor  ymm11, ymm11, ymm9
  db $C4, $43, $FB, $F0, $E3, $27                         // rorx   r12, r11, $27
  lea    r10, [r10 + r13*1]
  xor    rdi, rax
  db $C4, $C1, $5D, $D4, $E3                              // vpaddq ymm4, ymm4, ymm11
  db $C4, $43, $FB, $F0, $F3, $22                         // rorx   r14, r11, $22
  db $C4, $43, $FB, $F0, $EB, $1C                         // rorx   r13, r11, $1C
  lea    rcx, [rcx + r10*1]
  db $C5, $5D, $D4, $55, $00                              // vpaddq ymm10, ymm4, yword [rbp + $0]
  and    r15, rdi
  xor    r14, r12
  xor    r15, rax
  xor    r14, r13
  lea    r10, [r10 + r15*1]
  mov    r12, rdx
  db $C5, $7D, $7F, $14, $24                              // vmovdqa yword [rsp], ymm10
  db $C4, $63, $4D, $0F, $C5, $08                         // vpalignr ymm8, ymm6, ymm5, $8
  add    r9, qword [rsp + $120]
  and    r12, rcx
  db $C4, $63, $FB, $F0, $E9, $29                         // rorx   r13, rcx, $29
  db $C4, $63, $6D, $0F, $D9, $08                         // vpalignr ymm11, ymm2, ymm1, $8
  db $C4, $63, $FB, $F0, $F9, $12                         // rorx   r15, rcx, $12
  lea    r10, [r10 + r14*1]
  lea    r9, [r9 + r12*1]
  db $C4, $C1, $2D, $73, $D0, $01                         // vpsrlq ymm10, ymm8, $1
  db $C4, $42, $F0, $F2, $E0                              // andn   r12, rcx, r8
  xor    r13, r15
  db $C4, $63, $FB, $F0, $F1, $0E                         // rorx   r14, rcx, $E
  db $C4, $C1, $55, $D4, $EB                              // vpaddq ymm5, ymm5, ymm11
  db $C4, $C1, $25, $73, $D0, $07                         // vpsrlq ymm11, ymm8, $7
  lea    r9, [r9 + r12*1]
  xor    r13, r14
  mov    r15, r10
  db $C4, $C1, $35, $73, $F0, $38                         // vpsllq ymm9, ymm8, $38
  db $C4, $41, $25, $EF, $C2                              // vpxor  ymm8, ymm11, ymm10
  db $C4, $43, $FB, $F0, $E2, $27                         // rorx   r12, r10, $27
  lea    r9, [r9 + r13*1]
  xor    r15, r11
  db $C4, $C1, $2D, $73, $D2, $07                         // vpsrlq ymm10, ymm10, $7
  db $C4, $41, $3D, $EF, $C1                              // vpxor  ymm8, ymm8, ymm9
  db $C4, $43, $FB, $F0, $F2, $22                         // rorx   r14, r10, $22
  db $C4, $43, $FB, $F0, $EA, $1C                         // rorx   r13, r10, $1C
  lea    rbx, [rbx + r9*1]
  db $C4, $C1, $35, $73, $F1, $07                         // vpsllq ymm9, ymm9, $7
  db $C4, $41, $3D, $EF, $C2                              // vpxor  ymm8, ymm8, ymm10
  and    rdi, r15
  xor    r14, r12
  xor    rdi, r11
  db $C5, $A5, $73, $D4, $06                              // vpsrlq ymm11, ymm4, $6
  db $C4, $41, $3D, $EF, $C1                              // vpxor  ymm8, ymm8, ymm9
  xor    r14, r13
  lea    r9, [r9 + rdi*1]
  mov    r12, rcx
  db $C5, $AD, $73, $F4, $03                              // vpsllq ymm10, ymm4, $3
  db $C4, $C1, $55, $D4, $E8                              // vpaddq ymm5, ymm5, ymm8
  add    r8, qword [rsp + $128]
  and    r12, rbx
  db $C4, $63, $FB, $F0, $EB, $29                         // rorx   r13, rbx, $29
  db $C5, $B5, $73, $D4, $13                              // vpsrlq ymm9, ymm4, $13
  db $C4, $41, $25, $EF, $DA                              // vpxor  ymm11, ymm11, ymm10
  db $C4, $E3, $FB, $F0, $FB, $12                         // rorx   rdi, rbx, $12
  lea    r9, [r9 + r14*1]
  lea    r8, [r8 + r12*1]
  db $C4, $C1, $2D, $73, $F2, $2A                         // vpsllq ymm10, ymm10, $2A
  db $C4, $41, $25, $EF, $D9                              // vpxor  ymm11, ymm11, ymm9
  db $C4, $62, $E0, $F2, $E2                              // andn   r12, rbx, rdx
  xor    r13, rdi
  db $C4, $63, $FB, $F0, $F3, $0E                         // rorx   r14, rbx, $E
  db $C4, $C1, $35, $73, $D1, $2A                         // vpsrlq ymm9, ymm9, $2A
  db $C4, $41, $25, $EF, $DA                              // vpxor  ymm11, ymm11, ymm10
  lea    r8, [r8 + r12*1]
  xor    r13, r14
  mov    rdi, r9
  db $C4, $41, $25, $EF, $D9                              // vpxor  ymm11, ymm11, ymm9
  db $C4, $43, $FB, $F0, $E1, $27                         // rorx   r12, r9, $27
  lea    r8, [r8 + r13*1]
  xor    rdi, r10
  db $C4, $C1, $55, $D4, $EB                              // vpaddq ymm5, ymm5, ymm11
  db $C4, $43, $FB, $F0, $F1, $22                         // rorx   r14, r9, $22
  db $C4, $43, $FB, $F0, $E9, $1C                         // rorx   r13, r9, $1C
  lea    rax, [rax + r8*1]
  db $C5, $55, $D4, $55, $20                              // vpaddq ymm10, ymm5, yword [rbp + $20]
  and    r15, rdi
  xor    r14, r12
  xor    r15, r10
  xor    r14, r13
  lea    r8, [r8 + r15*1]
  mov    r12, rbx
  db $C5, $7D, $7F, $54, $24, $20                         // vmovdqa yword [rsp + $20], ymm10
  db $C4, $63, $45, $0F, $C6, $08                         // vpalignr ymm8, ymm7, ymm6, $8
  add    rdx, qword [rsp + $140]
  and    r12, rax
  db $C4, $63, $FB, $F0, $E8, $29                         // rorx   r13, rax, $29
  db $C4, $63, $65, $0F, $DA, $08                         // vpalignr ymm11, ymm3, ymm2, $8
  db $C4, $63, $FB, $F0, $F8, $12                         // rorx   r15, rax, $12
  lea    r8, [r8 + r14*1]
  lea    rdx, [rdx + r12*1]
  db $C4, $C1, $2D, $73, $D0, $01                         // vpsrlq ymm10, ymm8, $1
  db $C4, $62, $F8, $F2, $E1                              // andn   r12, rax, rcx
  xor    r13, r15
  db $C4, $63, $FB, $F0, $F0, $0E                         // rorx   r14, rax, $E
  db $C4, $C1, $4D, $D4, $F3                              // vpaddq ymm6, ymm6, ymm11
  db $C4, $C1, $25, $73, $D0, $07                         // vpsrlq ymm11, ymm8, $7
  lea    rdx, [rdx + r12*1]
  xor    r13, r14
  mov    r15, r8
  db $C4, $C1, $35, $73, $F0, $38                         // vpsllq ymm9, ymm8, $38
  db $C4, $41, $25, $EF, $C2                              // vpxor  ymm8, ymm11, ymm10
  db $C4, $43, $FB, $F0, $E0, $27                         // rorx   r12, r8, $27
  lea    rdx, [rdx + r13*1]
  xor    r15, r9
  db $C4, $C1, $2D, $73, $D2, $07                         // vpsrlq ymm10, ymm10, $7
  db $C4, $41, $3D, $EF, $C1                              // vpxor  ymm8, ymm8, ymm9
  db $C4, $43, $FB, $F0, $F0, $22                         // rorx   r14, r8, $22
  db $C4, $43, $FB, $F0, $E8, $1C                         // rorx   r13, r8, $1C
  lea    r11, [r11 + rdx*1]
  db $C4, $C1, $35, $73, $F1, $07                         // vpsllq ymm9, ymm9, $7
  db $C4, $41, $3D, $EF, $C2                              // vpxor  ymm8, ymm8, ymm10
  and    rdi, r15
  xor    r14, r12
  xor    rdi, r9
  db $C5, $A5, $73, $D5, $06                              // vpsrlq ymm11, ymm5, $6
  db $C4, $41, $3D, $EF, $C1                              // vpxor  ymm8, ymm8, ymm9
  xor    r14, r13
  lea    rdx, [rdx + rdi*1]
  mov    r12, rax
  db $C5, $AD, $73, $F5, $03                              // vpsllq ymm10, ymm5, $3
  db $C4, $C1, $4D, $D4, $F0                              // vpaddq ymm6, ymm6, ymm8
  add    rcx, qword [rsp + $148]
  and    r12, r11
  db $C4, $43, $FB, $F0, $EB, $29                         // rorx   r13, r11, $29
  db $C5, $B5, $73, $D5, $13                              // vpsrlq ymm9, ymm5, $13
  db $C4, $41, $25, $EF, $DA                              // vpxor  ymm11, ymm11, ymm10
  db $C4, $C3, $FB, $F0, $FB, $12                         // rorx   rdi, r11, $12
  lea    rdx, [rdx + r14*1]
  lea    rcx, [rcx + r12*1]
  db $C4, $C1, $2D, $73, $F2, $2A                         // vpsllq ymm10, ymm10, $2A
  db $C4, $41, $25, $EF, $D9                              // vpxor  ymm11, ymm11, ymm9
  db $C4, $62, $A0, $F2, $E3                              // andn   r12, r11, rbx
  xor    r13, rdi
  db $C4, $43, $FB, $F0, $F3, $0E                         // rorx   r14, r11, $E
  db $C4, $C1, $35, $73, $D1, $2A                         // vpsrlq ymm9, ymm9, $2A
  db $C4, $41, $25, $EF, $DA                              // vpxor  ymm11, ymm11, ymm10
  lea    rcx, [rcx + r12*1]
  xor    r13, r14
  mov    rdi, rdx
  db $C4, $41, $25, $EF, $D9                              // vpxor  ymm11, ymm11, ymm9
  db $C4, $63, $FB, $F0, $E2, $27                         // rorx   r12, rdx, $27
  lea    rcx, [rcx + r13*1]
  xor    rdi, r8
  db $C4, $C1, $4D, $D4, $F3                              // vpaddq ymm6, ymm6, ymm11
  db $C4, $63, $FB, $F0, $F2, $22                         // rorx   r14, rdx, $22
  db $C4, $63, $FB, $F0, $EA, $1C                         // rorx   r13, rdx, $1C
  lea    r10, [r10 + rcx*1]
  db $C5, $4D, $D4, $55, $40                              // vpaddq ymm10, ymm6, yword [rbp + $40]
  and    r15, rdi
  xor    r14, r12
  xor    r15, r8
  xor    r14, r13
  lea    rcx, [rcx + r15*1]
  mov    r12, r11
  db $C5, $7D, $7F, $54, $24, $40                         // vmovdqa yword [rsp + $40], ymm10
  db $C4, $63, $7D, $0F, $C7, $08                         // vpalignr ymm8, ymm0, ymm7, $8
  add    rbx, qword [rsp + $160]
  and    r12, r10
  db $C4, $43, $FB, $F0, $EA, $29                         // rorx   r13, r10, $29
  db $C4, $63, $5D, $0F, $DB, $08                         // vpalignr ymm11, ymm4, ymm3, $8
  db $C4, $43, $FB, $F0, $FA, $12                         // rorx   r15, r10, $12
  lea    rcx, [rcx + r14*1]
  lea    rbx, [rbx + r12*1]
  db $C4, $C1, $2D, $73, $D0, $01                         // vpsrlq ymm10, ymm8, $1
  db $C4, $62, $A8, $F2, $E0                              // andn   r12, r10, rax
  xor    r13, r15
  db $C4, $43, $FB, $F0, $F2, $0E                         // rorx   r14, r10, $E
  db $C4, $C1, $45, $D4, $FB                              // vpaddq ymm7, ymm7, ymm11
  db $C4, $C1, $25, $73, $D0, $07                         // vpsrlq ymm11, ymm8, $7
  lea    rbx, [rbx + r12*1]
  xor    r13, r14
  mov    r15, rcx
  db $C4, $C1, $35, $73, $F0, $38                         // vpsllq ymm9, ymm8, $38
  db $C4, $41, $25, $EF, $C2                              // vpxor  ymm8, ymm11, ymm10
  db $C4, $63, $FB, $F0, $E1, $27                         // rorx   r12, rcx, $27
  lea    rbx, [rbx + r13*1]
  xor    r15, rdx
  db $C4, $C1, $2D, $73, $D2, $07                         // vpsrlq ymm10, ymm10, $7
  db $C4, $41, $3D, $EF, $C1                              // vpxor  ymm8, ymm8, ymm9
  db $C4, $63, $FB, $F0, $F1, $22                         // rorx   r14, rcx, $22
  db $C4, $63, $FB, $F0, $E9, $1C                         // rorx   r13, rcx, $1C
  lea    r9, [r9 + rbx*1]
  db $C4, $C1, $35, $73, $F1, $07                         // vpsllq ymm9, ymm9, $7
  db $C4, $41, $3D, $EF, $C2                              // vpxor  ymm8, ymm8, ymm10
  and    rdi, r15
  xor    r14, r12
  xor    rdi, rdx
  db $C5, $A5, $73, $D6, $06                              // vpsrlq ymm11, ymm6, $6
  db $C4, $41, $3D, $EF, $C1                              // vpxor  ymm8, ymm8, ymm9
  xor    r14, r13
  lea    rbx, [rbx + rdi*1]
  mov    r12, r10
  db $C5, $AD, $73, $F6, $03                              // vpsllq ymm10, ymm6, $3
  db $C4, $C1, $45, $D4, $F8                              // vpaddq ymm7, ymm7, ymm8
  add    rax, qword [rsp + $168]
  and    r12, r9
  db $C4, $43, $FB, $F0, $E9, $29                         // rorx   r13, r9, $29
  db $C5, $B5, $73, $D6, $13                              // vpsrlq ymm9, ymm6, $13
  db $C4, $41, $25, $EF, $DA                              // vpxor  ymm11, ymm11, ymm10
  db $C4, $C3, $FB, $F0, $F9, $12                         // rorx   rdi, r9, $12
  lea    rbx, [rbx + r14*1]
  lea    rax, [rax + r12*1]
  db $C4, $C1, $2D, $73, $F2, $2A                         // vpsllq ymm10, ymm10, $2A
  db $C4, $41, $25, $EF, $D9                              // vpxor  ymm11, ymm11, ymm9
  db $C4, $42, $B0, $F2, $E3                              // andn   r12, r9, r11
  xor    r13, rdi
  db $C4, $43, $FB, $F0, $F1, $0E                         // rorx   r14, r9, $E
  db $C4, $C1, $35, $73, $D1, $2A                         // vpsrlq ymm9, ymm9, $2A
  db $C4, $41, $25, $EF, $DA                              // vpxor  ymm11, ymm11, ymm10
  lea    rax, [rax + r12*1]
  xor    r13, r14
  mov    rdi, rbx
  db $C4, $41, $25, $EF, $D9                              // vpxor  ymm11, ymm11, ymm9
  db $C4, $63, $FB, $F0, $E3, $27                         // rorx   r12, rbx, $27
  lea    rax, [rax + r13*1]
  xor    rdi, rcx
  db $C4, $C1, $45, $D4, $FB                              // vpaddq ymm7, ymm7, ymm11
  db $C4, $63, $FB, $F0, $F3, $22                         // rorx   r14, rbx, $22
  db $C4, $63, $FB, $F0, $EB, $1C                         // rorx   r13, rbx, $1C
  lea    r8, [r8 + rax*1]
  db $C5, $45, $D4, $55, $60                              // vpaddq ymm10, ymm7, yword [rbp + $60]
  and    r15, rdi
  xor    r14, r12
  xor    r15, rcx
  xor    r14, r13
  lea    rax, [rax + r15*1]
  mov    r12, r9
  db $C5, $7D, $7F, $54, $24, $60                         // vmovdqa yword [rsp + $60], ymm10
  lea    rbp, [rbp + $100]
  cmp    byte [rbp - $79], $0
  jne @sched_loop
  add    r11, qword [rsp + $80]
  and    r12, r8
  db $C4, $43, $FB, $F0, $E8, $29                         // rorx   r13, r8, $29
  db $C4, $43, $FB, $F0, $F8, $12                         // rorx   r15, r8, $12
  lea    rax, [rax + r14*1]
  lea    r11, [r11 + r12*1]
  db $C4, $42, $B8, $F2, $E2                              // andn   r12, r8, r10
  xor    r13, r15
  db $C4, $43, $FB, $F0, $F0, $0E                         // rorx   r14, r8, $E
  lea    r11, [r11 + r12*1]
  xor    r13, r14
  mov    r15, rax
  db $C4, $63, $FB, $F0, $E0, $27                         // rorx   r12, rax, $27
  lea    r11, [r11 + r13*1]
  xor    r15, rbx
  db $C4, $63, $FB, $F0, $F0, $22                         // rorx   r14, rax, $22
  db $C4, $63, $FB, $F0, $E8, $1C                         // rorx   r13, rax, $1C
  lea    rdx, [rdx + r11*1]
  and    rdi, r15
  xor    r14, r12
  xor    rdi, rbx
  xor    r14, r13
  lea    r11, [r11 + rdi*1]
  mov    r12, r8
  add    r10, qword [rsp + $88]
  and    r12, rdx
  db $C4, $63, $FB, $F0, $EA, $29                         // rorx   r13, rdx, $29
  db $C4, $E3, $FB, $F0, $FA, $12                         // rorx   rdi, rdx, $12
  lea    r11, [r11 + r14*1]
  lea    r10, [r10 + r12*1]
  db $C4, $42, $E8, $F2, $E1                              // andn   r12, rdx, r9
  xor    r13, rdi
  db $C4, $63, $FB, $F0, $F2, $0E                         // rorx   r14, rdx, $E
  lea    r10, [r10 + r12*1]
  xor    r13, r14
  mov    rdi, r11
  db $C4, $43, $FB, $F0, $E3, $27                         // rorx   r12, r11, $27
  lea    r10, [r10 + r13*1]
  xor    rdi, rax
  db $C4, $43, $FB, $F0, $F3, $22                         // rorx   r14, r11, $22
  db $C4, $43, $FB, $F0, $EB, $1C                         // rorx   r13, r11, $1C
  lea    rcx, [rcx + r10*1]
  and    r15, rdi
  xor    r14, r12
  xor    r15, rax
  xor    r14, r13
  lea    r10, [r10 + r15*1]
  mov    r12, rdx
  add    r9, qword [rsp + $A0]
  and    r12, rcx
  db $C4, $63, $FB, $F0, $E9, $29                         // rorx   r13, rcx, $29
  db $C4, $63, $FB, $F0, $F9, $12                         // rorx   r15, rcx, $12
  lea    r10, [r10 + r14*1]
  lea    r9, [r9 + r12*1]
  db $C4, $42, $F0, $F2, $E0                              // andn   r12, rcx, r8
  xor    r13, r15
  db $C4, $63, $FB, $F0, $F1, $0E                         // rorx   r14, rcx, $E
  lea    r9, [r9 + r12*1]
  xor    r13, r14
  mov    r15, r10
  db $C4, $43, $FB, $F0, $E2, $27                         // rorx   r12, r10, $27
  lea    r9, [r9 + r13*1]
  xor    r15, r11
  db $C4, $43, $FB, $F0, $F2, $22                         // rorx   r14, r10, $22
  db $C4, $43, $FB, $F0, $EA, $1C                         // rorx   r13, r10, $1C
  lea    rbx, [rbx + r9*1]
  and    rdi, r15
  xor    r14, r12
  xor    rdi, r11
  xor    r14, r13
  lea    r9, [r9 + rdi*1]
  mov    r12, rcx
  add    r8, qword [rsp + $A8]
  and    r12, rbx
  db $C4, $63, $FB, $F0, $EB, $29                         // rorx   r13, rbx, $29
  db $C4, $E3, $FB, $F0, $FB, $12                         // rorx   rdi, rbx, $12
  lea    r9, [r9 + r14*1]
  lea    r8, [r8 + r12*1]
  db $C4, $62, $E0, $F2, $E2                              // andn   r12, rbx, rdx
  xor    r13, rdi
  db $C4, $63, $FB, $F0, $F3, $0E                         // rorx   r14, rbx, $E
  lea    r8, [r8 + r12*1]
  xor    r13, r14
  mov    rdi, r9
  db $C4, $43, $FB, $F0, $E1, $27                         // rorx   r12, r9, $27
  lea    r8, [r8 + r13*1]
  xor    rdi, r10
  db $C4, $43, $FB, $F0, $F1, $22                         // rorx   r14, r9, $22
  db $C4, $43, $FB, $F0, $E9, $1C                         // rorx   r13, r9, $1C
  lea    rax, [rax + r8*1]
  and    r15, rdi
  xor    r14, r12
  xor    r15, r10
  xor    r14, r13
  lea    r8, [r8 + r15*1]
  mov    r12, rbx
  add    rdx, qword [rsp + $C0]
  and    r12, rax
  db $C4, $63, $FB, $F0, $E8, $29                         // rorx   r13, rax, $29
  db $C4, $63, $FB, $F0, $F8, $12                         // rorx   r15, rax, $12
  lea    r8, [r8 + r14*1]
  lea    rdx, [rdx + r12*1]
  db $C4, $62, $F8, $F2, $E1                              // andn   r12, rax, rcx
  xor    r13, r15
  db $C4, $63, $FB, $F0, $F0, $0E                         // rorx   r14, rax, $E
  lea    rdx, [rdx + r12*1]
  xor    r13, r14
  mov    r15, r8
  db $C4, $43, $FB, $F0, $E0, $27                         // rorx   r12, r8, $27
  lea    rdx, [rdx + r13*1]
  xor    r15, r9
  db $C4, $43, $FB, $F0, $F0, $22                         // rorx   r14, r8, $22
  db $C4, $43, $FB, $F0, $E8, $1C                         // rorx   r13, r8, $1C
  lea    r11, [r11 + rdx*1]
  and    rdi, r15
  xor    r14, r12
  xor    rdi, r9
  xor    r14, r13
  lea    rdx, [rdx + rdi*1]
  mov    r12, rax
  add    rcx, qword [rsp + $C8]
  and    r12, r11
  db $C4, $43, $FB, $F0, $EB, $29                         // rorx   r13, r11, $29
  db $C4, $C3, $FB, $F0, $FB, $12                         // rorx   rdi, r11, $12
  lea    rdx, [rdx + r14*1]
  lea    rcx, [rcx + r12*1]
  db $C4, $62, $A0, $F2, $E3                              // andn   r12, r11, rbx
  xor    r13, rdi
  db $C4, $43, $FB, $F0, $F3, $0E                         // rorx   r14, r11, $E
  lea    rcx, [rcx + r12*1]
  xor    r13, r14
  mov    rdi, rdx
  db $C4, $63, $FB, $F0, $E2, $27                         // rorx   r12, rdx, $27
  lea    rcx, [rcx + r13*1]
  xor    rdi, r8
  db $C4, $63, $FB, $F0, $F2, $22                         // rorx   r14, rdx, $22
  db $C4, $63, $FB, $F0, $EA, $1C                         // rorx   r13, rdx, $1C
  lea    r10, [r10 + rcx*1]
  and    r15, rdi
  xor    r14, r12
  xor    r15, r8
  xor    r14, r13
  lea    rcx, [rcx + r15*1]
  mov    r12, r11
  add    rbx, qword [rsp + $E0]
  and    r12, r10
  db $C4, $43, $FB, $F0, $EA, $29                         // rorx   r13, r10, $29
  db $C4, $43, $FB, $F0, $FA, $12                         // rorx   r15, r10, $12
  lea    rcx, [rcx + r14*1]
  lea    rbx, [rbx + r12*1]
  db $C4, $62, $A8, $F2, $E0                              // andn   r12, r10, rax
  xor    r13, r15
  db $C4, $43, $FB, $F0, $F2, $0E                         // rorx   r14, r10, $E
  lea    rbx, [rbx + r12*1]
  xor    r13, r14
  mov    r15, rcx
  db $C4, $63, $FB, $F0, $E1, $27                         // rorx   r12, rcx, $27
  lea    rbx, [rbx + r13*1]
  xor    r15, rdx
  db $C4, $63, $FB, $F0, $F1, $22                         // rorx   r14, rcx, $22
  db $C4, $63, $FB, $F0, $E9, $1C                         // rorx   r13, rcx, $1C
  lea    r9, [r9 + rbx*1]
  and    rdi, r15
  xor    r14, r12
  xor    rdi, rdx
  xor    r14, r13
  lea    rbx, [rbx + rdi*1]
  mov    r12, r10
  add    rax, qword [rsp + $E8]
  and    r12, r9
  db $C4, $43, $FB, $F0, $E9, $29                         // rorx   r13, r9, $29
  db $C4, $C3, $FB, $F0, $F9, $12                         // rorx   rdi, r9, $12
  lea    rbx, [rbx + r14*1]
  lea    rax, [rax + r12*1]
  db $C4, $42, $B0, $F2, $E3                              // andn   r12, r9, r11
  xor    r13, rdi
  db $C4, $43, $FB, $F0, $F1, $0E                         // rorx   r14, r9, $E
  lea    rax, [rax + r12*1]
  xor    r13, r14
  mov    rdi, rbx
  db $C4, $63, $FB, $F0, $E3, $27                         // rorx   r12, rbx, $27
  lea    rax, [rax + r13*1]
  xor    rdi, rcx
  db $C4, $63, $FB, $F0, $F3, $22                         // rorx   r14, rbx, $22
  db $C4, $63, $FB, $F0, $EB, $1C                         // rorx   r13, rbx, $1C
  lea    r8, [r8 + rax*1]
  and    r15, rdi
  xor    r14, r12
  xor    r15, rcx
  xor    r14, r13
  lea    rax, [rax + r15*1]
  mov    r12, r9
  add    r11, qword [rsp]
  and    r12, r8
  db $C4, $43, $FB, $F0, $E8, $29                         // rorx   r13, r8, $29
  db $C4, $43, $FB, $F0, $F8, $12                         // rorx   r15, r8, $12
  lea    rax, [rax + r14*1]
  lea    r11, [r11 + r12*1]
  db $C4, $42, $B8, $F2, $E2                              // andn   r12, r8, r10
  xor    r13, r15
  db $C4, $43, $FB, $F0, $F0, $0E                         // rorx   r14, r8, $E
  lea    r11, [r11 + r12*1]
  xor    r13, r14
  mov    r15, rax
  db $C4, $63, $FB, $F0, $E0, $27                         // rorx   r12, rax, $27
  lea    r11, [r11 + r13*1]
  xor    r15, rbx
  db $C4, $63, $FB, $F0, $F0, $22                         // rorx   r14, rax, $22
  db $C4, $63, $FB, $F0, $E8, $1C                         // rorx   r13, rax, $1C
  lea    rdx, [rdx + r11*1]
  and    rdi, r15
  xor    r14, r12
  xor    rdi, rbx
  xor    r14, r13
  lea    r11, [r11 + rdi*1]
  mov    r12, r8
  add    r10, qword [rsp + $8]
  and    r12, rdx
  db $C4, $63, $FB, $F0, $EA, $29                         // rorx   r13, rdx, $29
  db $C4, $E3, $FB, $F0, $FA, $12                         // rorx   rdi, rdx, $12
  lea    r11, [r11 + r14*1]
  lea    r10, [r10 + r12*1]
  db $C4, $42, $E8, $F2, $E1                              // andn   r12, rdx, r9
  xor    r13, rdi
  db $C4, $63, $FB, $F0, $F2, $0E                         // rorx   r14, rdx, $E
  lea    r10, [r10 + r12*1]
  xor    r13, r14
  mov    rdi, r11
  db $C4, $43, $FB, $F0, $E3, $27                         // rorx   r12, r11, $27
  lea    r10, [r10 + r13*1]
  xor    rdi, rax
  db $C4, $43, $FB, $F0, $F3, $22                         // rorx   r14, r11, $22
  db $C4, $43, $FB, $F0, $EB, $1C                         // rorx   r13, r11, $1C
  lea    rcx, [rcx + r10*1]
  and    r15, rdi
  xor    r14, r12
  xor    r15, rax
  xor    r14, r13
  lea    r10, [r10 + r15*1]
  mov    r12, rdx
  add    r9, qword [rsp + $20]
  and    r12, rcx
  db $C4, $63, $FB, $F0, $E9, $29                         // rorx   r13, rcx, $29
  db $C4, $63, $FB, $F0, $F9, $12                         // rorx   r15, rcx, $12
  lea    r10, [r10 + r14*1]
  lea    r9, [r9 + r12*1]
  db $C4, $42, $F0, $F2, $E0                              // andn   r12, rcx, r8
  xor    r13, r15
  db $C4, $63, $FB, $F0, $F1, $0E                         // rorx   r14, rcx, $E
  lea    r9, [r9 + r12*1]
  xor    r13, r14
  mov    r15, r10
  db $C4, $43, $FB, $F0, $E2, $27                         // rorx   r12, r10, $27
  lea    r9, [r9 + r13*1]
  xor    r15, r11
  db $C4, $43, $FB, $F0, $F2, $22                         // rorx   r14, r10, $22
  db $C4, $43, $FB, $F0, $EA, $1C                         // rorx   r13, r10, $1C
  lea    rbx, [rbx + r9*1]
  and    rdi, r15
  xor    r14, r12
  xor    rdi, r11
  xor    r14, r13
  lea    r9, [r9 + rdi*1]
  mov    r12, rcx
  add    r8, qword [rsp + $28]
  and    r12, rbx
  db $C4, $63, $FB, $F0, $EB, $29                         // rorx   r13, rbx, $29
  db $C4, $E3, $FB, $F0, $FB, $12                         // rorx   rdi, rbx, $12
  lea    r9, [r9 + r14*1]
  lea    r8, [r8 + r12*1]
  db $C4, $62, $E0, $F2, $E2                              // andn   r12, rbx, rdx
  xor    r13, rdi
  db $C4, $63, $FB, $F0, $F3, $0E                         // rorx   r14, rbx, $E
  lea    r8, [r8 + r12*1]
  xor    r13, r14
  mov    rdi, r9
  db $C4, $43, $FB, $F0, $E1, $27                         // rorx   r12, r9, $27
  lea    r8, [r8 + r13*1]
  xor    rdi, r10
  db $C4, $43, $FB, $F0, $F1, $22                         // rorx   r14, r9, $22
  db $C4, $43, $FB, $F0, $E9, $1C                         // rorx   r13, r9, $1C
  lea    rax, [rax + r8*1]
  and    r15, rdi
  xor    r14, r12
  xor    r15, r10
  xor    r14, r13
  lea    r8, [r8 + r15*1]
  mov    r12, rbx
  add    rdx, qword [rsp + $40]
  and    r12, rax
  db $C4, $63, $FB, $F0, $E8, $29                         // rorx   r13, rax, $29
  db $C4, $63, $FB, $F0, $F8, $12                         // rorx   r15, rax, $12
  lea    r8, [r8 + r14*1]
  lea    rdx, [rdx + r12*1]
  db $C4, $62, $F8, $F2, $E1                              // andn   r12, rax, rcx
  xor    r13, r15
  db $C4, $63, $FB, $F0, $F0, $0E                         // rorx   r14, rax, $E
  lea    rdx, [rdx + r12*1]
  xor    r13, r14
  mov    r15, r8
  db $C4, $43, $FB, $F0, $E0, $27                         // rorx   r12, r8, $27
  lea    rdx, [rdx + r13*1]
  xor    r15, r9
  db $C4, $43, $FB, $F0, $F0, $22                         // rorx   r14, r8, $22
  db $C4, $43, $FB, $F0, $E8, $1C                         // rorx   r13, r8, $1C
  lea    r11, [r11 + rdx*1]
  and    rdi, r15
  xor    r14, r12
  xor    rdi, r9
  xor    r14, r13
  lea    rdx, [rdx + rdi*1]
  mov    r12, rax
  add    rcx, qword [rsp + $48]
  and    r12, r11
  db $C4, $43, $FB, $F0, $EB, $29                         // rorx   r13, r11, $29
  db $C4, $C3, $FB, $F0, $FB, $12                         // rorx   rdi, r11, $12
  lea    rdx, [rdx + r14*1]
  lea    rcx, [rcx + r12*1]
  db $C4, $62, $A0, $F2, $E3                              // andn   r12, r11, rbx
  xor    r13, rdi
  db $C4, $43, $FB, $F0, $F3, $0E                         // rorx   r14, r11, $E
  lea    rcx, [rcx + r12*1]
  xor    r13, r14
  mov    rdi, rdx
  db $C4, $63, $FB, $F0, $E2, $27                         // rorx   r12, rdx, $27
  lea    rcx, [rcx + r13*1]
  xor    rdi, r8
  db $C4, $63, $FB, $F0, $F2, $22                         // rorx   r14, rdx, $22
  db $C4, $63, $FB, $F0, $EA, $1C                         // rorx   r13, rdx, $1C
  lea    r10, [r10 + rcx*1]
  and    r15, rdi
  xor    r14, r12
  xor    r15, r8
  xor    r14, r13
  lea    rcx, [rcx + r15*1]
  mov    r12, r11
  add    rbx, qword [rsp + $60]
  and    r12, r10
  db $C4, $43, $FB, $F0, $EA, $29                         // rorx   r13, r10, $29
  db $C4, $43, $FB, $F0, $FA, $12                         // rorx   r15, r10, $12
  lea    rcx, [rcx + r14*1]
  lea    rbx, [rbx + r12*1]
  db $C4, $62, $A8, $F2, $E0                              // andn   r12, r10, rax
  xor    r13, r15
  db $C4, $43, $FB, $F0, $F2, $0E                         // rorx   r14, r10, $E
  lea    rbx, [rbx + r12*1]
  xor    r13, r14
  mov    r15, rcx
  db $C4, $63, $FB, $F0, $E1, $27                         // rorx   r12, rcx, $27
  lea    rbx, [rbx + r13*1]
  xor    r15, rdx
  db $C4, $63, $FB, $F0, $F1, $22                         // rorx   r14, rcx, $22
  db $C4, $63, $FB, $F0, $E9, $1C                         // rorx   r13, rcx, $1C
  lea    r9, [r9 + rbx*1]
  and    rdi, r15
  xor    r14, r12
  xor    rdi, rdx
  xor    r14, r13
  lea    rbx, [rbx + rdi*1]
  mov    r12, r10
  add    rax, qword [rsp + $68]
  and    r12, r9
  db $C4, $43, $FB, $F0, $E9, $29                         // rorx   r13, r9, $29
  db $C4, $C3, $FB, $F0, $F9, $12                         // rorx   rdi, r9, $12
  lea    rbx, [rbx + r14*1]
  lea    rax, [rax + r12*1]
  db $C4, $42, $B0, $F2, $E3                              // andn   r12, r9, r11
  xor    r13, rdi
  db $C4, $43, $FB, $F0, $F1, $0E                         // rorx   r14, r9, $E
  lea    rax, [rax + r12*1]
  xor    r13, r14
  mov    rdi, rbx
  db $C4, $63, $FB, $F0, $E3, $27                         // rorx   r12, rbx, $27
  lea    rax, [rax + r13*1]
  xor    rdi, rcx
  db $C4, $63, $FB, $F0, $F3, $22                         // rorx   r14, rbx, $22
  db $C4, $63, $FB, $F0, $EB, $1C                         // rorx   r13, rbx, $1C
  lea    r8, [r8 + rax*1]
  and    r15, rdi
  xor    r14, r12
  xor    r15, rcx
  xor    r14, r13
  lea    rax, [rax + r15*1]
  mov    r12, r9
  mov    rdi, qword [rsp + $500]
  add    rax, r14
  lea    rbp, [rsp + $480]
  add    rax, qword [rdi]
  add    rbx, qword [rdi + $8]
  add    rcx, qword [rdi + $10]
  add    rdx, qword [rdi + $18]
  add    r8, qword [rdi + $20]
  add    r9, qword [rdi + $28]
  add    r10, qword [rdi + $30]
  add    r11, qword [rdi + $38]
  mov    qword [rdi], rax
  mov    qword [rdi + $8], rbx
  mov    qword [rdi + $10], rcx
  mov    qword [rdi + $18], rdx
  mov    qword [rdi + $20], r8
  mov    qword [rdi + $28], r9
  mov    qword [rdi + $30], r10
  mov    qword [rdi + $38], r11
  cmp    rsi, qword [rbp + $90]
  je @done
  xor    r14, r14
  mov    rdi, rbx
  xor    rdi, rcx
  mov    r12, r9
  jmp @tail_loop

@tail_loop:
  add    r11, qword [rbp + $10]
  and    r12, r8
  db $C4, $43, $FB, $F0, $E8, $29                         // rorx   r13, r8, $29
  db $C4, $43, $FB, $F0, $F8, $12                         // rorx   r15, r8, $12
  lea    rax, [rax + r14*1]
  lea    r11, [r11 + r12*1]
  db $C4, $42, $B8, $F2, $E2                              // andn   r12, r8, r10
  xor    r13, r15
  db $C4, $43, $FB, $F0, $F0, $0E                         // rorx   r14, r8, $E
  lea    r11, [r11 + r12*1]
  xor    r13, r14
  mov    r15, rax
  db $C4, $63, $FB, $F0, $E0, $27                         // rorx   r12, rax, $27
  lea    r11, [r11 + r13*1]
  xor    r15, rbx
  db $C4, $63, $FB, $F0, $F0, $22                         // rorx   r14, rax, $22
  db $C4, $63, $FB, $F0, $E8, $1C                         // rorx   r13, rax, $1C
  lea    rdx, [rdx + r11*1]
  and    rdi, r15
  xor    r14, r12
  xor    rdi, rbx
  xor    r14, r13
  lea    r11, [r11 + rdi*1]
  mov    r12, r8
  add    r10, qword [rbp + $18]
  and    r12, rdx
  db $C4, $63, $FB, $F0, $EA, $29                         // rorx   r13, rdx, $29
  db $C4, $E3, $FB, $F0, $FA, $12                         // rorx   rdi, rdx, $12
  lea    r11, [r11 + r14*1]
  lea    r10, [r10 + r12*1]
  db $C4, $42, $E8, $F2, $E1                              // andn   r12, rdx, r9
  xor    r13, rdi
  db $C4, $63, $FB, $F0, $F2, $0E                         // rorx   r14, rdx, $E
  lea    r10, [r10 + r12*1]
  xor    r13, r14
  mov    rdi, r11
  db $C4, $43, $FB, $F0, $E3, $27                         // rorx   r12, r11, $27
  lea    r10, [r10 + r13*1]
  xor    rdi, rax
  db $C4, $43, $FB, $F0, $F3, $22                         // rorx   r14, r11, $22
  db $C4, $43, $FB, $F0, $EB, $1C                         // rorx   r13, r11, $1C
  lea    rcx, [rcx + r10*1]
  and    r15, rdi
  xor    r14, r12
  xor    r15, rax
  xor    r14, r13
  lea    r10, [r10 + r15*1]
  mov    r12, rdx
  add    r9, qword [rbp + $30]
  and    r12, rcx
  db $C4, $63, $FB, $F0, $E9, $29                         // rorx   r13, rcx, $29
  db $C4, $63, $FB, $F0, $F9, $12                         // rorx   r15, rcx, $12
  lea    r10, [r10 + r14*1]
  lea    r9, [r9 + r12*1]
  db $C4, $42, $F0, $F2, $E0                              // andn   r12, rcx, r8
  xor    r13, r15
  db $C4, $63, $FB, $F0, $F1, $0E                         // rorx   r14, rcx, $E
  lea    r9, [r9 + r12*1]
  xor    r13, r14
  mov    r15, r10
  db $C4, $43, $FB, $F0, $E2, $27                         // rorx   r12, r10, $27
  lea    r9, [r9 + r13*1]
  xor    r15, r11
  db $C4, $43, $FB, $F0, $F2, $22                         // rorx   r14, r10, $22
  db $C4, $43, $FB, $F0, $EA, $1C                         // rorx   r13, r10, $1C
  lea    rbx, [rbx + r9*1]
  and    rdi, r15
  xor    r14, r12
  xor    rdi, r11
  xor    r14, r13
  lea    r9, [r9 + rdi*1]
  mov    r12, rcx
  add    r8, qword [rbp + $38]
  and    r12, rbx
  db $C4, $63, $FB, $F0, $EB, $29                         // rorx   r13, rbx, $29
  db $C4, $E3, $FB, $F0, $FB, $12                         // rorx   rdi, rbx, $12
  lea    r9, [r9 + r14*1]
  lea    r8, [r8 + r12*1]
  db $C4, $62, $E0, $F2, $E2                              // andn   r12, rbx, rdx
  xor    r13, rdi
  db $C4, $63, $FB, $F0, $F3, $0E                         // rorx   r14, rbx, $E
  lea    r8, [r8 + r12*1]
  xor    r13, r14
  mov    rdi, r9
  db $C4, $43, $FB, $F0, $E1, $27                         // rorx   r12, r9, $27
  lea    r8, [r8 + r13*1]
  xor    rdi, r10
  db $C4, $43, $FB, $F0, $F1, $22                         // rorx   r14, r9, $22
  db $C4, $43, $FB, $F0, $E9, $1C                         // rorx   r13, r9, $1C
  lea    rax, [rax + r8*1]
  and    r15, rdi
  xor    r14, r12
  xor    r15, r10
  xor    r14, r13
  lea    r8, [r8 + r15*1]
  mov    r12, rbx
  add    rdx, qword [rbp + $50]
  and    r12, rax
  db $C4, $63, $FB, $F0, $E8, $29                         // rorx   r13, rax, $29
  db $C4, $63, $FB, $F0, $F8, $12                         // rorx   r15, rax, $12
  lea    r8, [r8 + r14*1]
  lea    rdx, [rdx + r12*1]
  db $C4, $62, $F8, $F2, $E1                              // andn   r12, rax, rcx
  xor    r13, r15
  db $C4, $63, $FB, $F0, $F0, $0E                         // rorx   r14, rax, $E
  lea    rdx, [rdx + r12*1]
  xor    r13, r14
  mov    r15, r8
  db $C4, $43, $FB, $F0, $E0, $27                         // rorx   r12, r8, $27
  lea    rdx, [rdx + r13*1]
  xor    r15, r9
  db $C4, $43, $FB, $F0, $F0, $22                         // rorx   r14, r8, $22
  db $C4, $43, $FB, $F0, $E8, $1C                         // rorx   r13, r8, $1C
  lea    r11, [r11 + rdx*1]
  and    rdi, r15
  xor    r14, r12
  xor    rdi, r9
  xor    r14, r13
  lea    rdx, [rdx + rdi*1]
  mov    r12, rax
  add    rcx, qword [rbp + $58]
  and    r12, r11
  db $C4, $43, $FB, $F0, $EB, $29                         // rorx   r13, r11, $29
  db $C4, $C3, $FB, $F0, $FB, $12                         // rorx   rdi, r11, $12
  lea    rdx, [rdx + r14*1]
  lea    rcx, [rcx + r12*1]
  db $C4, $62, $A0, $F2, $E3                              // andn   r12, r11, rbx
  xor    r13, rdi
  db $C4, $43, $FB, $F0, $F3, $0E                         // rorx   r14, r11, $E
  lea    rcx, [rcx + r12*1]
  xor    r13, r14
  mov    rdi, rdx
  db $C4, $63, $FB, $F0, $E2, $27                         // rorx   r12, rdx, $27
  lea    rcx, [rcx + r13*1]
  xor    rdi, r8
  db $C4, $63, $FB, $F0, $F2, $22                         // rorx   r14, rdx, $22
  db $C4, $63, $FB, $F0, $EA, $1C                         // rorx   r13, rdx, $1C
  lea    r10, [r10 + rcx*1]
  and    r15, rdi
  xor    r14, r12
  xor    r15, r8
  xor    r14, r13
  lea    rcx, [rcx + r15*1]
  mov    r12, r11
  add    rbx, qword [rbp + $70]
  and    r12, r10
  db $C4, $43, $FB, $F0, $EA, $29                         // rorx   r13, r10, $29
  db $C4, $43, $FB, $F0, $FA, $12                         // rorx   r15, r10, $12
  lea    rcx, [rcx + r14*1]
  lea    rbx, [rbx + r12*1]
  db $C4, $62, $A8, $F2, $E0                              // andn   r12, r10, rax
  xor    r13, r15
  db $C4, $43, $FB, $F0, $F2, $0E                         // rorx   r14, r10, $E
  lea    rbx, [rbx + r12*1]
  xor    r13, r14
  mov    r15, rcx
  db $C4, $63, $FB, $F0, $E1, $27                         // rorx   r12, rcx, $27
  lea    rbx, [rbx + r13*1]
  xor    r15, rdx
  db $C4, $63, $FB, $F0, $F1, $22                         // rorx   r14, rcx, $22
  db $C4, $63, $FB, $F0, $E9, $1C                         // rorx   r13, rcx, $1C
  lea    r9, [r9 + rbx*1]
  and    rdi, r15
  xor    r14, r12
  xor    rdi, rdx
  xor    r14, r13
  lea    rbx, [rbx + rdi*1]
  mov    r12, r10
  add    rax, qword [rbp + $78]
  and    r12, r9
  db $C4, $43, $FB, $F0, $E9, $29                         // rorx   r13, r9, $29
  db $C4, $C3, $FB, $F0, $F9, $12                         // rorx   rdi, r9, $12
  lea    rbx, [rbx + r14*1]
  lea    rax, [rax + r12*1]
  db $C4, $42, $B0, $F2, $E3                              // andn   r12, r9, r11
  xor    r13, rdi
  db $C4, $43, $FB, $F0, $F1, $0E                         // rorx   r14, r9, $E
  lea    rax, [rax + r12*1]
  xor    r13, r14
  mov    rdi, rbx
  db $C4, $63, $FB, $F0, $E3, $27                         // rorx   r12, rbx, $27
  lea    rax, [rax + r13*1]
  xor    rdi, rcx
  db $C4, $63, $FB, $F0, $F3, $22                         // rorx   r14, rbx, $22
  db $C4, $63, $FB, $F0, $EB, $1C                         // rorx   r13, rbx, $1C
  lea    r8, [r8 + rax*1]
  and    r15, rdi
  xor    r14, r12
  xor    r15, rcx
  xor    r14, r13
  lea    rax, [rax + r15*1]
  mov    r12, r9
  lea    rbp, [rbp - $80]
  cmp    rbp, rsp
  jae @tail_loop
  mov    rdi, qword [rsp + $500]
  add    rax, r14
  lea    rsp, [rsp + $480]
  add    rax, qword [rdi]
  add    rbx, qword [rdi + $8]
  add    rcx, qword [rdi + $10]
  add    rdx, qword [rdi + $18]
  add    r8, qword [rdi + $20]
  add    r9, qword [rdi + $28]
  lea    rsi, [rsi + $100]
  add    r10, qword [rdi + $30]
  mov    r12, rsi
  add    r11, qword [rdi + $38]
  cmp    rsi, qword [rsp + $90]
  mov    qword [rdi], rax
  cmove  r12, rsp
  mov    qword [rdi + $8], rbx
  mov    qword [rdi + $10], rcx
  mov    qword [rdi + $18], rdx
  mov    qword [rdi + $20], r8
  mov    qword [rdi + $28], r9
  mov    qword [rdi + $30], r10
  mov    qword [rdi + $38], r11
  jbe @block_loop
  lea    rbp, [rsp]

@done:
  mov    rsi, qword [rbp + $98]
  db $C5, $F8, $77                                        // vzeroupper
  mov    r15, qword [rsi - $48]
  mov    r14, qword [rsi - $40]
  mov    r13, qword [rsi - $38]
  mov    r12, qword [rsi - $30]
  mov    rdi, qword [rsi - $28]
  mov    rbp, qword [rsi - $18]
  mov    rbx, qword [rsi - $10]
  mov    rax, qword [rsi - $20]
  lea    rsp, [rsi]
  mov    rsi, rax

  {$I ..\Include\Simd\Common\SimdNonVolatileRestore_x86_64.inc}
