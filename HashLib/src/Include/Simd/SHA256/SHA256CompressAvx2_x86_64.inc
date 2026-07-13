// AVX2 implementation of SHA-256 compress (VEX-256, two-block). Two message
// blocks are scheduled together in 256-bit lanes; the compression rounds
// stay serial (as SHA-256 requires), so scheduling two blocks at once is
// what makes this faster than the single-block AVX path.
// ABI (after HlpSimdProc4Begin_x86_64.inc): rcx = state ptr, rdx = data ptr,
//   r8d = numblocks, r9 = doubled-K256 ptr (each 128-bit K256 quadruple
//   stored twice so one table feeds both 256-bit lanes, with the byte-swap
//   and two message-schedule masks appended; see K256_Doubled; the masks
//   are read unaligned, so the Pascal const needs no special alignment).
// Saves: xmm6-xmm15 via the shared HlpSimdNonVolatileSave/Restore include
//   (no-op on SysV); rbx, rbp, rdi, rsi, r12-r15 in the local frame.
// AVX2 and BMI2 (rorx/andn) instructions are db-encoded for broad assembler
// compatibility (every AVX2 CPU also provides BMI2).
// Reference: OpenSSL CRYPTOGAMS sha512-x86_64.pl (AVX2 kernel; that
// generator emits both the SHA-256 and the SHA-512 kernels).

  {$I ..\..\Include\Simd\Common\HlpSimdNonVolatileSave_x86_64.inc}

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
  sub    rsp, $260
  shl    rdx, $4
  and    rsp, $FFFFFFFFFFFFFC00
  lea    rdx, [rsi + rdx*4]
  add    rsp, $1C0
  mov    qword [rsp + $40], rdi
  mov    qword [rsp + $48], rsi
  mov    qword [rsp + $50], rdx
  mov    qword [rsp + $58], rax

@prologue:
  mov    rbp, qword [rsp + $58]
  mov    rbp, qword [rbp - $8]
  db $C5, $F8, $77                                        // vzeroupper
  sub    rsi, $FFFFFFFFFFFFFFC0
  mov    eax, dword [rdi]
  mov    r12, rsi
  mov    ebx, dword [rdi + $4]
  cmp    rsi, rdx
  mov    ecx, dword [rdi + $8]
  cmove  r12, rsp
  mov    edx, dword [rdi + $C]
  mov    r8d, dword [rdi + $10]
  mov    r9d, dword [rdi + $14]
  mov    r10d, dword [rdi + $18]
  mov    r11d, dword [rdi + $1C]
  db $C5, $7E, $6F, $85, $20, $02, $00, $00               // vmovdqu ymm8, yword [rbp + $220]
  db $C5, $7E, $6F, $8D, $40, $02, $00, $00               // vmovdqu ymm9, yword [rbp + $240]
  jmp @block_loop

@block_loop:
  mov    rbp, qword [rsp + $58]
  mov    rbp, qword [rbp - $8]
  db $C5, $FE, $6F, $BD, $00, $02, $00, $00               // vmovdqu ymm7, yword [rbp + $200]
  db $C5, $FA, $6F, $46, $C0                              // vmovdqu xmm0, oword [rsi - $40]
  db $C5, $FA, $6F, $4E, $D0                              // vmovdqu xmm1, oword [rsi - $30]
  db $C5, $FA, $6F, $56, $E0                              // vmovdqu xmm2, oword [rsi - $20]
  db $C5, $FA, $6F, $5E, $F0                              // vmovdqu xmm3, oword [rsi - $10]
  db $C4, $C3, $7D, $38, $04, $24, $01                    // vinserti128 ymm0, ymm0, oword [r12], $1
  db $C4, $C3, $75, $38, $4C, $24, $10, $01               // vinserti128 ymm1, ymm1, oword [r12 + $10], $1
  db $C4, $E2, $7D, $00, $C7                              // vpshufb ymm0, ymm0, ymm7
  db $C4, $C3, $6D, $38, $54, $24, $20, $01               // vinserti128 ymm2, ymm2, oword [r12 + $20], $1
  db $C4, $E2, $75, $00, $CF                              // vpshufb ymm1, ymm1, ymm7
  db $C4, $C3, $65, $38, $5C, $24, $30, $01               // vinserti128 ymm3, ymm3, oword [r12 + $30], $1
  db $C4, $E2, $6D, $00, $D7                              // vpshufb ymm2, ymm2, ymm7
  db $C5, $FD, $FE, $65, $00                              // vpaddd ymm4, ymm0, yword [rbp + $0]
  db $C4, $E2, $65, $00, $DF                              // vpshufb ymm3, ymm3, ymm7
  db $C5, $F5, $FE, $6D, $20                              // vpaddd ymm5, ymm1, yword [rbp + $20]
  db $C5, $ED, $FE, $75, $40                              // vpaddd ymm6, ymm2, yword [rbp + $40]
  db $C5, $E5, $FE, $7D, $60                              // vpaddd ymm7, ymm3, yword [rbp + $60]
  db $C5, $FD, $7F, $24, $24                              // vmovdqa yword [rsp], ymm4
  xor    r14d, r14d
  db $C5, $FD, $7F, $6C, $24, $20                         // vmovdqa yword [rsp + $20], ymm5
  lea    rsp, [rsp - $40]
  mov    edi, ebx
  db $C5, $FD, $7F, $34, $24                              // vmovdqa yword [rsp], ymm6
  xor    edi, ecx
  db $C5, $FD, $7F, $7C, $24, $20                         // vmovdqa yword [rsp + $20], ymm7
  mov    r12d, r9d
  sub    rbp, $FFFFFFFFFFFFFF80
  jmp @sched_loop

@sched_loop:
  lea    rsp, [rsp - $40]
  db $C4, $E3, $75, $0F, $E0, $04                         // vpalignr ymm4, ymm1, ymm0, $4
  add    r11d, dword [rsp + $80]
  and    r12d, r8d
  db $C4, $43, $7B, $F0, $E8, $19                         // rorx   r13d, r8d, $19
  db $C4, $E3, $65, $0F, $FA, $04                         // vpalignr ymm7, ymm3, ymm2, $4
  db $C4, $43, $7B, $F0, $F8, $0B                         // rorx   r15d, r8d, $B
  lea    eax, [rax + r14*1]
  lea    r11d, [r11 + r12*1]
  db $C5, $CD, $72, $D4, $07                              // vpsrld ymm6, ymm4, $7
  db $C4, $42, $38, $F2, $E2                              // andn   r12d, r8d, r10d
  xor    r13d, r15d
  db $C4, $43, $7B, $F0, $F0, $06                         // rorx   r14d, r8d, $6
  db $C5, $FD, $FE, $C7                                   // vpaddd ymm0, ymm0, ymm7
  lea    r11d, [r11 + r12*1]
  xor    r13d, r14d
  mov    r15d, eax
  db $C5, $C5, $72, $D4, $03                              // vpsrld ymm7, ymm4, $3
  db $C4, $63, $7B, $F0, $E0, $16                         // rorx   r12d, eax, $16
  lea    r11d, [r11 + r13*1]
  xor    r15d, ebx
  db $C5, $D5, $72, $F4, $0E                              // vpslld ymm5, ymm4, $E
  db $C4, $63, $7B, $F0, $F0, $0D                         // rorx   r14d, eax, $D
  db $C4, $63, $7B, $F0, $E8, $02                         // rorx   r13d, eax, $2
  lea    edx, [rdx + r11*1]
  db $C5, $C5, $EF, $E6                                   // vpxor  ymm4, ymm7, ymm6
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, ebx
  db $C5, $FD, $70, $FB, $FA                              // vpshufd ymm7, ymm3, $FA
  xor    r14d, r13d
  lea    r11d, [r11 + rdi*1]
  mov    r12d, r8d
  db $C5, $CD, $72, $D6, $0B                              // vpsrld ymm6, ymm6, $B
  add    r10d, dword [rsp + $84]
  and    r12d, edx
  db $C4, $63, $7B, $F0, $EA, $19                         // rorx   r13d, edx, $19
  db $C5, $DD, $EF, $E5                                   // vpxor  ymm4, ymm4, ymm5
  db $C4, $E3, $7B, $F0, $FA, $0B                         // rorx   edi, edx, $B
  lea    r11d, [r11 + r14*1]
  lea    r10d, [r10 + r12*1]
  db $C5, $D5, $72, $F5, $0B                              // vpslld ymm5, ymm5, $B
  db $C4, $42, $68, $F2, $E1                              // andn   r12d, edx, r9d
  xor    r13d, edi
  db $C4, $63, $7B, $F0, $F2, $06                         // rorx   r14d, edx, $6
  db $C5, $DD, $EF, $E6                                   // vpxor  ymm4, ymm4, ymm6
  lea    r10d, [r10 + r12*1]
  xor    r13d, r14d
  mov    edi, r11d
  db $C5, $CD, $72, $D7, $0A                              // vpsrld ymm6, ymm7, $A
  db $C4, $43, $7B, $F0, $E3, $16                         // rorx   r12d, r11d, $16
  lea    r10d, [r10 + r13*1]
  xor    edi, eax
  db $C5, $DD, $EF, $E5                                   // vpxor  ymm4, ymm4, ymm5
  db $C4, $43, $7B, $F0, $F3, $0D                         // rorx   r14d, r11d, $D
  db $C4, $43, $7B, $F0, $EB, $02                         // rorx   r13d, r11d, $2
  lea    ecx, [rcx + r10*1]
  db $C5, $C5, $73, $D7, $11                              // vpsrlq ymm7, ymm7, $11
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, eax
  db $C5, $FD, $FE, $C4                                   // vpaddd ymm0, ymm0, ymm4
  xor    r14d, r13d
  lea    r10d, [r10 + r15*1]
  mov    r12d, edx
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  add    r9d, dword [rsp + $88]
  and    r12d, ecx
  db $C4, $63, $7B, $F0, $E9, $19                         // rorx   r13d, ecx, $19
  db $C5, $C5, $73, $D7, $02                              // vpsrlq ymm7, ymm7, $2
  db $C4, $63, $7B, $F0, $F9, $0B                         // rorx   r15d, ecx, $B
  lea    r10d, [r10 + r14*1]
  lea    r9d, [r9 + r12*1]
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  db $C4, $42, $70, $F2, $E0                              // andn   r12d, ecx, r8d
  xor    r13d, r15d
  db $C4, $63, $7B, $F0, $F1, $06                         // rorx   r14d, ecx, $6
  db $C4, $C2, $4D, $00, $F0                              // vpshufb ymm6, ymm6, ymm8
  lea    r9d, [r9 + r12*1]
  xor    r13d, r14d
  mov    r15d, r10d
  db $C5, $FD, $FE, $C6                                   // vpaddd ymm0, ymm0, ymm6
  db $C4, $43, $7B, $F0, $E2, $16                         // rorx   r12d, r10d, $16
  lea    r9d, [r9 + r13*1]
  xor    r15d, r11d
  db $C5, $FD, $70, $F8, $50                              // vpshufd ymm7, ymm0, $50
  db $C4, $43, $7B, $F0, $F2, $0D                         // rorx   r14d, r10d, $D
  db $C4, $43, $7B, $F0, $EA, $02                         // rorx   r13d, r10d, $2
  lea    ebx, [rbx + r9*1]
  db $C5, $CD, $72, $D7, $0A                              // vpsrld ymm6, ymm7, $A
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, r11d
  db $C5, $C5, $73, $D7, $11                              // vpsrlq ymm7, ymm7, $11
  xor    r14d, r13d
  lea    r9d, [r9 + rdi*1]
  mov    r12d, ecx
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  add    r8d, dword [rsp + $8C]
  and    r12d, ebx
  db $C4, $63, $7B, $F0, $EB, $19                         // rorx   r13d, ebx, $19
  db $C5, $C5, $73, $D7, $02                              // vpsrlq ymm7, ymm7, $2
  db $C4, $E3, $7B, $F0, $FB, $0B                         // rorx   edi, ebx, $B
  lea    r9d, [r9 + r14*1]
  lea    r8d, [r8 + r12*1]
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  db $C4, $62, $60, $F2, $E2                              // andn   r12d, ebx, edx
  xor    r13d, edi
  db $C4, $63, $7B, $F0, $F3, $06                         // rorx   r14d, ebx, $6
  db $C4, $C2, $4D, $00, $F1                              // vpshufb ymm6, ymm6, ymm9
  lea    r8d, [r8 + r12*1]
  xor    r13d, r14d
  mov    edi, r9d
  db $C5, $FD, $FE, $C6                                   // vpaddd ymm0, ymm0, ymm6
  db $C4, $43, $7B, $F0, $E1, $16                         // rorx   r12d, r9d, $16
  lea    r8d, [r8 + r13*1]
  xor    edi, r10d
  db $C5, $FD, $FE, $75, $00                              // vpaddd ymm6, ymm0, yword [rbp + $0]
  db $C4, $43, $7B, $F0, $F1, $0D                         // rorx   r14d, r9d, $D
  db $C4, $43, $7B, $F0, $E9, $02                         // rorx   r13d, r9d, $2
  lea    eax, [rax + r8*1]
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, r10d
  xor    r14d, r13d
  lea    r8d, [r8 + r15*1]
  mov    r12d, ebx
  db $C5, $FD, $7F, $34, $24                              // vmovdqa yword [rsp], ymm6
  db $C4, $E3, $6D, $0F, $E1, $04                         // vpalignr ymm4, ymm2, ymm1, $4
  add    edx, dword [rsp + $A0]
  and    r12d, eax
  db $C4, $63, $7B, $F0, $E8, $19                         // rorx   r13d, eax, $19
  db $C4, $E3, $7D, $0F, $FB, $04                         // vpalignr ymm7, ymm0, ymm3, $4
  db $C4, $63, $7B, $F0, $F8, $0B                         // rorx   r15d, eax, $B
  lea    r8d, [r8 + r14*1]
  lea    edx, [rdx + r12*1]
  db $C5, $CD, $72, $D4, $07                              // vpsrld ymm6, ymm4, $7
  db $C4, $62, $78, $F2, $E1                              // andn   r12d, eax, ecx
  xor    r13d, r15d
  db $C4, $63, $7B, $F0, $F0, $06                         // rorx   r14d, eax, $6
  db $C5, $F5, $FE, $CF                                   // vpaddd ymm1, ymm1, ymm7
  lea    edx, [rdx + r12*1]
  xor    r13d, r14d
  mov    r15d, r8d
  db $C5, $C5, $72, $D4, $03                              // vpsrld ymm7, ymm4, $3
  db $C4, $43, $7B, $F0, $E0, $16                         // rorx   r12d, r8d, $16
  lea    edx, [rdx + r13*1]
  xor    r15d, r9d
  db $C5, $D5, $72, $F4, $0E                              // vpslld ymm5, ymm4, $E
  db $C4, $43, $7B, $F0, $F0, $0D                         // rorx   r14d, r8d, $D
  db $C4, $43, $7B, $F0, $E8, $02                         // rorx   r13d, r8d, $2
  lea    r11d, [r11 + rdx*1]
  db $C5, $C5, $EF, $E6                                   // vpxor  ymm4, ymm7, ymm6
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, r9d
  db $C5, $FD, $70, $F8, $FA                              // vpshufd ymm7, ymm0, $FA
  xor    r14d, r13d
  lea    edx, [rdx + rdi*1]
  mov    r12d, eax
  db $C5, $CD, $72, $D6, $0B                              // vpsrld ymm6, ymm6, $B
  add    ecx, dword [rsp + $A4]
  and    r12d, r11d
  db $C4, $43, $7B, $F0, $EB, $19                         // rorx   r13d, r11d, $19
  db $C5, $DD, $EF, $E5                                   // vpxor  ymm4, ymm4, ymm5
  db $C4, $C3, $7B, $F0, $FB, $0B                         // rorx   edi, r11d, $B
  lea    edx, [rdx + r14*1]
  lea    ecx, [rcx + r12*1]
  db $C5, $D5, $72, $F5, $0B                              // vpslld ymm5, ymm5, $B
  db $C4, $62, $20, $F2, $E3                              // andn   r12d, r11d, ebx
  xor    r13d, edi
  db $C4, $43, $7B, $F0, $F3, $06                         // rorx   r14d, r11d, $6
  db $C5, $DD, $EF, $E6                                   // vpxor  ymm4, ymm4, ymm6
  lea    ecx, [rcx + r12*1]
  xor    r13d, r14d
  mov    edi, edx
  db $C5, $CD, $72, $D7, $0A                              // vpsrld ymm6, ymm7, $A
  db $C4, $63, $7B, $F0, $E2, $16                         // rorx   r12d, edx, $16
  lea    ecx, [rcx + r13*1]
  xor    edi, r8d
  db $C5, $DD, $EF, $E5                                   // vpxor  ymm4, ymm4, ymm5
  db $C4, $63, $7B, $F0, $F2, $0D                         // rorx   r14d, edx, $D
  db $C4, $63, $7B, $F0, $EA, $02                         // rorx   r13d, edx, $2
  lea    r10d, [r10 + rcx*1]
  db $C5, $C5, $73, $D7, $11                              // vpsrlq ymm7, ymm7, $11
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, r8d
  db $C5, $F5, $FE, $CC                                   // vpaddd ymm1, ymm1, ymm4
  xor    r14d, r13d
  lea    ecx, [rcx + r15*1]
  mov    r12d, r11d
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  add    ebx, dword [rsp + $A8]
  and    r12d, r10d
  db $C4, $43, $7B, $F0, $EA, $19                         // rorx   r13d, r10d, $19
  db $C5, $C5, $73, $D7, $02                              // vpsrlq ymm7, ymm7, $2
  db $C4, $43, $7B, $F0, $FA, $0B                         // rorx   r15d, r10d, $B
  lea    ecx, [rcx + r14*1]
  lea    ebx, [rbx + r12*1]
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  db $C4, $62, $28, $F2, $E0                              // andn   r12d, r10d, eax
  xor    r13d, r15d
  db $C4, $43, $7B, $F0, $F2, $06                         // rorx   r14d, r10d, $6
  db $C4, $C2, $4D, $00, $F0                              // vpshufb ymm6, ymm6, ymm8
  lea    ebx, [rbx + r12*1]
  xor    r13d, r14d
  mov    r15d, ecx
  db $C5, $F5, $FE, $CE                                   // vpaddd ymm1, ymm1, ymm6
  db $C4, $63, $7B, $F0, $E1, $16                         // rorx   r12d, ecx, $16
  lea    ebx, [rbx + r13*1]
  xor    r15d, edx
  db $C5, $FD, $70, $F9, $50                              // vpshufd ymm7, ymm1, $50
  db $C4, $63, $7B, $F0, $F1, $0D                         // rorx   r14d, ecx, $D
  db $C4, $63, $7B, $F0, $E9, $02                         // rorx   r13d, ecx, $2
  lea    r9d, [r9 + rbx*1]
  db $C5, $CD, $72, $D7, $0A                              // vpsrld ymm6, ymm7, $A
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, edx
  db $C5, $C5, $73, $D7, $11                              // vpsrlq ymm7, ymm7, $11
  xor    r14d, r13d
  lea    ebx, [rbx + rdi*1]
  mov    r12d, r10d
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  add    eax, dword [rsp + $AC]
  and    r12d, r9d
  db $C4, $43, $7B, $F0, $E9, $19                         // rorx   r13d, r9d, $19
  db $C5, $C5, $73, $D7, $02                              // vpsrlq ymm7, ymm7, $2
  db $C4, $C3, $7B, $F0, $F9, $0B                         // rorx   edi, r9d, $B
  lea    ebx, [rbx + r14*1]
  lea    eax, [rax + r12*1]
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  db $C4, $42, $30, $F2, $E3                              // andn   r12d, r9d, r11d
  xor    r13d, edi
  db $C4, $43, $7B, $F0, $F1, $06                         // rorx   r14d, r9d, $6
  db $C4, $C2, $4D, $00, $F1                              // vpshufb ymm6, ymm6, ymm9
  lea    eax, [rax + r12*1]
  xor    r13d, r14d
  mov    edi, ebx
  db $C5, $F5, $FE, $CE                                   // vpaddd ymm1, ymm1, ymm6
  db $C4, $63, $7B, $F0, $E3, $16                         // rorx   r12d, ebx, $16
  lea    eax, [rax + r13*1]
  xor    edi, ecx
  db $C5, $F5, $FE, $75, $20                              // vpaddd ymm6, ymm1, yword [rbp + $20]
  db $C4, $63, $7B, $F0, $F3, $0D                         // rorx   r14d, ebx, $D
  db $C4, $63, $7B, $F0, $EB, $02                         // rorx   r13d, ebx, $2
  lea    r8d, [r8 + rax*1]
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, ecx
  xor    r14d, r13d
  lea    eax, [rax + r15*1]
  mov    r12d, r9d
  db $C5, $FD, $7F, $74, $24, $20                         // vmovdqa yword [rsp + $20], ymm6
  lea    rsp, [rsp - $40]
  db $C4, $E3, $65, $0F, $E2, $04                         // vpalignr ymm4, ymm3, ymm2, $4
  add    r11d, dword [rsp + $80]
  and    r12d, r8d
  db $C4, $43, $7B, $F0, $E8, $19                         // rorx   r13d, r8d, $19
  db $C4, $E3, $75, $0F, $F8, $04                         // vpalignr ymm7, ymm1, ymm0, $4
  db $C4, $43, $7B, $F0, $F8, $0B                         // rorx   r15d, r8d, $B
  lea    eax, [rax + r14*1]
  lea    r11d, [r11 + r12*1]
  db $C5, $CD, $72, $D4, $07                              // vpsrld ymm6, ymm4, $7
  db $C4, $42, $38, $F2, $E2                              // andn   r12d, r8d, r10d
  xor    r13d, r15d
  db $C4, $43, $7B, $F0, $F0, $06                         // rorx   r14d, r8d, $6
  db $C5, $ED, $FE, $D7                                   // vpaddd ymm2, ymm2, ymm7
  lea    r11d, [r11 + r12*1]
  xor    r13d, r14d
  mov    r15d, eax
  db $C5, $C5, $72, $D4, $03                              // vpsrld ymm7, ymm4, $3
  db $C4, $63, $7B, $F0, $E0, $16                         // rorx   r12d, eax, $16
  lea    r11d, [r11 + r13*1]
  xor    r15d, ebx
  db $C5, $D5, $72, $F4, $0E                              // vpslld ymm5, ymm4, $E
  db $C4, $63, $7B, $F0, $F0, $0D                         // rorx   r14d, eax, $D
  db $C4, $63, $7B, $F0, $E8, $02                         // rorx   r13d, eax, $2
  lea    edx, [rdx + r11*1]
  db $C5, $C5, $EF, $E6                                   // vpxor  ymm4, ymm7, ymm6
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, ebx
  db $C5, $FD, $70, $F9, $FA                              // vpshufd ymm7, ymm1, $FA
  xor    r14d, r13d
  lea    r11d, [r11 + rdi*1]
  mov    r12d, r8d
  db $C5, $CD, $72, $D6, $0B                              // vpsrld ymm6, ymm6, $B
  add    r10d, dword [rsp + $84]
  and    r12d, edx
  db $C4, $63, $7B, $F0, $EA, $19                         // rorx   r13d, edx, $19
  db $C5, $DD, $EF, $E5                                   // vpxor  ymm4, ymm4, ymm5
  db $C4, $E3, $7B, $F0, $FA, $0B                         // rorx   edi, edx, $B
  lea    r11d, [r11 + r14*1]
  lea    r10d, [r10 + r12*1]
  db $C5, $D5, $72, $F5, $0B                              // vpslld ymm5, ymm5, $B
  db $C4, $42, $68, $F2, $E1                              // andn   r12d, edx, r9d
  xor    r13d, edi
  db $C4, $63, $7B, $F0, $F2, $06                         // rorx   r14d, edx, $6
  db $C5, $DD, $EF, $E6                                   // vpxor  ymm4, ymm4, ymm6
  lea    r10d, [r10 + r12*1]
  xor    r13d, r14d
  mov    edi, r11d
  db $C5, $CD, $72, $D7, $0A                              // vpsrld ymm6, ymm7, $A
  db $C4, $43, $7B, $F0, $E3, $16                         // rorx   r12d, r11d, $16
  lea    r10d, [r10 + r13*1]
  xor    edi, eax
  db $C5, $DD, $EF, $E5                                   // vpxor  ymm4, ymm4, ymm5
  db $C4, $43, $7B, $F0, $F3, $0D                         // rorx   r14d, r11d, $D
  db $C4, $43, $7B, $F0, $EB, $02                         // rorx   r13d, r11d, $2
  lea    ecx, [rcx + r10*1]
  db $C5, $C5, $73, $D7, $11                              // vpsrlq ymm7, ymm7, $11
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, eax
  db $C5, $ED, $FE, $D4                                   // vpaddd ymm2, ymm2, ymm4
  xor    r14d, r13d
  lea    r10d, [r10 + r15*1]
  mov    r12d, edx
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  add    r9d, dword [rsp + $88]
  and    r12d, ecx
  db $C4, $63, $7B, $F0, $E9, $19                         // rorx   r13d, ecx, $19
  db $C5, $C5, $73, $D7, $02                              // vpsrlq ymm7, ymm7, $2
  db $C4, $63, $7B, $F0, $F9, $0B                         // rorx   r15d, ecx, $B
  lea    r10d, [r10 + r14*1]
  lea    r9d, [r9 + r12*1]
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  db $C4, $42, $70, $F2, $E0                              // andn   r12d, ecx, r8d
  xor    r13d, r15d
  db $C4, $63, $7B, $F0, $F1, $06                         // rorx   r14d, ecx, $6
  db $C4, $C2, $4D, $00, $F0                              // vpshufb ymm6, ymm6, ymm8
  lea    r9d, [r9 + r12*1]
  xor    r13d, r14d
  mov    r15d, r10d
  db $C5, $ED, $FE, $D6                                   // vpaddd ymm2, ymm2, ymm6
  db $C4, $43, $7B, $F0, $E2, $16                         // rorx   r12d, r10d, $16
  lea    r9d, [r9 + r13*1]
  xor    r15d, r11d
  db $C5, $FD, $70, $FA, $50                              // vpshufd ymm7, ymm2, $50
  db $C4, $43, $7B, $F0, $F2, $0D                         // rorx   r14d, r10d, $D
  db $C4, $43, $7B, $F0, $EA, $02                         // rorx   r13d, r10d, $2
  lea    ebx, [rbx + r9*1]
  db $C5, $CD, $72, $D7, $0A                              // vpsrld ymm6, ymm7, $A
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, r11d
  db $C5, $C5, $73, $D7, $11                              // vpsrlq ymm7, ymm7, $11
  xor    r14d, r13d
  lea    r9d, [r9 + rdi*1]
  mov    r12d, ecx
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  add    r8d, dword [rsp + $8C]
  and    r12d, ebx
  db $C4, $63, $7B, $F0, $EB, $19                         // rorx   r13d, ebx, $19
  db $C5, $C5, $73, $D7, $02                              // vpsrlq ymm7, ymm7, $2
  db $C4, $E3, $7B, $F0, $FB, $0B                         // rorx   edi, ebx, $B
  lea    r9d, [r9 + r14*1]
  lea    r8d, [r8 + r12*1]
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  db $C4, $62, $60, $F2, $E2                              // andn   r12d, ebx, edx
  xor    r13d, edi
  db $C4, $63, $7B, $F0, $F3, $06                         // rorx   r14d, ebx, $6
  db $C4, $C2, $4D, $00, $F1                              // vpshufb ymm6, ymm6, ymm9
  lea    r8d, [r8 + r12*1]
  xor    r13d, r14d
  mov    edi, r9d
  db $C5, $ED, $FE, $D6                                   // vpaddd ymm2, ymm2, ymm6
  db $C4, $43, $7B, $F0, $E1, $16                         // rorx   r12d, r9d, $16
  lea    r8d, [r8 + r13*1]
  xor    edi, r10d
  db $C5, $ED, $FE, $75, $40                              // vpaddd ymm6, ymm2, yword [rbp + $40]
  db $C4, $43, $7B, $F0, $F1, $0D                         // rorx   r14d, r9d, $D
  db $C4, $43, $7B, $F0, $E9, $02                         // rorx   r13d, r9d, $2
  lea    eax, [rax + r8*1]
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, r10d
  xor    r14d, r13d
  lea    r8d, [r8 + r15*1]
  mov    r12d, ebx
  db $C5, $FD, $7F, $34, $24                              // vmovdqa yword [rsp], ymm6
  db $C4, $E3, $7D, $0F, $E3, $04                         // vpalignr ymm4, ymm0, ymm3, $4
  add    edx, dword [rsp + $A0]
  and    r12d, eax
  db $C4, $63, $7B, $F0, $E8, $19                         // rorx   r13d, eax, $19
  db $C4, $E3, $6D, $0F, $F9, $04                         // vpalignr ymm7, ymm2, ymm1, $4
  db $C4, $63, $7B, $F0, $F8, $0B                         // rorx   r15d, eax, $B
  lea    r8d, [r8 + r14*1]
  lea    edx, [rdx + r12*1]
  db $C5, $CD, $72, $D4, $07                              // vpsrld ymm6, ymm4, $7
  db $C4, $62, $78, $F2, $E1                              // andn   r12d, eax, ecx
  xor    r13d, r15d
  db $C4, $63, $7B, $F0, $F0, $06                         // rorx   r14d, eax, $6
  db $C5, $E5, $FE, $DF                                   // vpaddd ymm3, ymm3, ymm7
  lea    edx, [rdx + r12*1]
  xor    r13d, r14d
  mov    r15d, r8d
  db $C5, $C5, $72, $D4, $03                              // vpsrld ymm7, ymm4, $3
  db $C4, $43, $7B, $F0, $E0, $16                         // rorx   r12d, r8d, $16
  lea    edx, [rdx + r13*1]
  xor    r15d, r9d
  db $C5, $D5, $72, $F4, $0E                              // vpslld ymm5, ymm4, $E
  db $C4, $43, $7B, $F0, $F0, $0D                         // rorx   r14d, r8d, $D
  db $C4, $43, $7B, $F0, $E8, $02                         // rorx   r13d, r8d, $2
  lea    r11d, [r11 + rdx*1]
  db $C5, $C5, $EF, $E6                                   // vpxor  ymm4, ymm7, ymm6
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, r9d
  db $C5, $FD, $70, $FA, $FA                              // vpshufd ymm7, ymm2, $FA
  xor    r14d, r13d
  lea    edx, [rdx + rdi*1]
  mov    r12d, eax
  db $C5, $CD, $72, $D6, $0B                              // vpsrld ymm6, ymm6, $B
  add    ecx, dword [rsp + $A4]
  and    r12d, r11d
  db $C4, $43, $7B, $F0, $EB, $19                         // rorx   r13d, r11d, $19
  db $C5, $DD, $EF, $E5                                   // vpxor  ymm4, ymm4, ymm5
  db $C4, $C3, $7B, $F0, $FB, $0B                         // rorx   edi, r11d, $B
  lea    edx, [rdx + r14*1]
  lea    ecx, [rcx + r12*1]
  db $C5, $D5, $72, $F5, $0B                              // vpslld ymm5, ymm5, $B
  db $C4, $62, $20, $F2, $E3                              // andn   r12d, r11d, ebx
  xor    r13d, edi
  db $C4, $43, $7B, $F0, $F3, $06                         // rorx   r14d, r11d, $6
  db $C5, $DD, $EF, $E6                                   // vpxor  ymm4, ymm4, ymm6
  lea    ecx, [rcx + r12*1]
  xor    r13d, r14d
  mov    edi, edx
  db $C5, $CD, $72, $D7, $0A                              // vpsrld ymm6, ymm7, $A
  db $C4, $63, $7B, $F0, $E2, $16                         // rorx   r12d, edx, $16
  lea    ecx, [rcx + r13*1]
  xor    edi, r8d
  db $C5, $DD, $EF, $E5                                   // vpxor  ymm4, ymm4, ymm5
  db $C4, $63, $7B, $F0, $F2, $0D                         // rorx   r14d, edx, $D
  db $C4, $63, $7B, $F0, $EA, $02                         // rorx   r13d, edx, $2
  lea    r10d, [r10 + rcx*1]
  db $C5, $C5, $73, $D7, $11                              // vpsrlq ymm7, ymm7, $11
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, r8d
  db $C5, $E5, $FE, $DC                                   // vpaddd ymm3, ymm3, ymm4
  xor    r14d, r13d
  lea    ecx, [rcx + r15*1]
  mov    r12d, r11d
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  add    ebx, dword [rsp + $A8]
  and    r12d, r10d
  db $C4, $43, $7B, $F0, $EA, $19                         // rorx   r13d, r10d, $19
  db $C5, $C5, $73, $D7, $02                              // vpsrlq ymm7, ymm7, $2
  db $C4, $43, $7B, $F0, $FA, $0B                         // rorx   r15d, r10d, $B
  lea    ecx, [rcx + r14*1]
  lea    ebx, [rbx + r12*1]
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  db $C4, $62, $28, $F2, $E0                              // andn   r12d, r10d, eax
  xor    r13d, r15d
  db $C4, $43, $7B, $F0, $F2, $06                         // rorx   r14d, r10d, $6
  db $C4, $C2, $4D, $00, $F0                              // vpshufb ymm6, ymm6, ymm8
  lea    ebx, [rbx + r12*1]
  xor    r13d, r14d
  mov    r15d, ecx
  db $C5, $E5, $FE, $DE                                   // vpaddd ymm3, ymm3, ymm6
  db $C4, $63, $7B, $F0, $E1, $16                         // rorx   r12d, ecx, $16
  lea    ebx, [rbx + r13*1]
  xor    r15d, edx
  db $C5, $FD, $70, $FB, $50                              // vpshufd ymm7, ymm3, $50
  db $C4, $63, $7B, $F0, $F1, $0D                         // rorx   r14d, ecx, $D
  db $C4, $63, $7B, $F0, $E9, $02                         // rorx   r13d, ecx, $2
  lea    r9d, [r9 + rbx*1]
  db $C5, $CD, $72, $D7, $0A                              // vpsrld ymm6, ymm7, $A
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, edx
  db $C5, $C5, $73, $D7, $11                              // vpsrlq ymm7, ymm7, $11
  xor    r14d, r13d
  lea    ebx, [rbx + rdi*1]
  mov    r12d, r10d
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  add    eax, dword [rsp + $AC]
  and    r12d, r9d
  db $C4, $43, $7B, $F0, $E9, $19                         // rorx   r13d, r9d, $19
  db $C5, $C5, $73, $D7, $02                              // vpsrlq ymm7, ymm7, $2
  db $C4, $C3, $7B, $F0, $F9, $0B                         // rorx   edi, r9d, $B
  lea    ebx, [rbx + r14*1]
  lea    eax, [rax + r12*1]
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  db $C4, $42, $30, $F2, $E3                              // andn   r12d, r9d, r11d
  xor    r13d, edi
  db $C4, $43, $7B, $F0, $F1, $06                         // rorx   r14d, r9d, $6
  db $C4, $C2, $4D, $00, $F1                              // vpshufb ymm6, ymm6, ymm9
  lea    eax, [rax + r12*1]
  xor    r13d, r14d
  mov    edi, ebx
  db $C5, $E5, $FE, $DE                                   // vpaddd ymm3, ymm3, ymm6
  db $C4, $63, $7B, $F0, $E3, $16                         // rorx   r12d, ebx, $16
  lea    eax, [rax + r13*1]
  xor    edi, ecx
  db $C5, $E5, $FE, $75, $60                              // vpaddd ymm6, ymm3, yword [rbp + $60]
  db $C4, $63, $7B, $F0, $F3, $0D                         // rorx   r14d, ebx, $D
  db $C4, $63, $7B, $F0, $EB, $02                         // rorx   r13d, ebx, $2
  lea    r8d, [r8 + rax*1]
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, ecx
  xor    r14d, r13d
  lea    eax, [rax + r15*1]
  mov    r12d, r9d
  db $C5, $FD, $7F, $74, $24, $20                         // vmovdqa yword [rsp + $20], ymm6
  lea    rbp, [rbp + $80]
  cmp    byte [rbp + $3], $0
  jne @sched_loop
  add    r11d, dword [rsp + $40]
  and    r12d, r8d
  db $C4, $43, $7B, $F0, $E8, $19                         // rorx   r13d, r8d, $19
  db $C4, $43, $7B, $F0, $F8, $0B                         // rorx   r15d, r8d, $B
  lea    eax, [rax + r14*1]
  lea    r11d, [r11 + r12*1]
  db $C4, $42, $38, $F2, $E2                              // andn   r12d, r8d, r10d
  xor    r13d, r15d
  db $C4, $43, $7B, $F0, $F0, $06                         // rorx   r14d, r8d, $6
  lea    r11d, [r11 + r12*1]
  xor    r13d, r14d
  mov    r15d, eax
  db $C4, $63, $7B, $F0, $E0, $16                         // rorx   r12d, eax, $16
  lea    r11d, [r11 + r13*1]
  xor    r15d, ebx
  db $C4, $63, $7B, $F0, $F0, $0D                         // rorx   r14d, eax, $D
  db $C4, $63, $7B, $F0, $E8, $02                         // rorx   r13d, eax, $2
  lea    edx, [rdx + r11*1]
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, ebx
  xor    r14d, r13d
  lea    r11d, [r11 + rdi*1]
  mov    r12d, r8d
  add    r10d, dword [rsp + $44]
  and    r12d, edx
  db $C4, $63, $7B, $F0, $EA, $19                         // rorx   r13d, edx, $19
  db $C4, $E3, $7B, $F0, $FA, $0B                         // rorx   edi, edx, $B
  lea    r11d, [r11 + r14*1]
  lea    r10d, [r10 + r12*1]
  db $C4, $42, $68, $F2, $E1                              // andn   r12d, edx, r9d
  xor    r13d, edi
  db $C4, $63, $7B, $F0, $F2, $06                         // rorx   r14d, edx, $6
  lea    r10d, [r10 + r12*1]
  xor    r13d, r14d
  mov    edi, r11d
  db $C4, $43, $7B, $F0, $E3, $16                         // rorx   r12d, r11d, $16
  lea    r10d, [r10 + r13*1]
  xor    edi, eax
  db $C4, $43, $7B, $F0, $F3, $0D                         // rorx   r14d, r11d, $D
  db $C4, $43, $7B, $F0, $EB, $02                         // rorx   r13d, r11d, $2
  lea    ecx, [rcx + r10*1]
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, eax
  xor    r14d, r13d
  lea    r10d, [r10 + r15*1]
  mov    r12d, edx
  add    r9d, dword [rsp + $48]
  and    r12d, ecx
  db $C4, $63, $7B, $F0, $E9, $19                         // rorx   r13d, ecx, $19
  db $C4, $63, $7B, $F0, $F9, $0B                         // rorx   r15d, ecx, $B
  lea    r10d, [r10 + r14*1]
  lea    r9d, [r9 + r12*1]
  db $C4, $42, $70, $F2, $E0                              // andn   r12d, ecx, r8d
  xor    r13d, r15d
  db $C4, $63, $7B, $F0, $F1, $06                         // rorx   r14d, ecx, $6
  lea    r9d, [r9 + r12*1]
  xor    r13d, r14d
  mov    r15d, r10d
  db $C4, $43, $7B, $F0, $E2, $16                         // rorx   r12d, r10d, $16
  lea    r9d, [r9 + r13*1]
  xor    r15d, r11d
  db $C4, $43, $7B, $F0, $F2, $0D                         // rorx   r14d, r10d, $D
  db $C4, $43, $7B, $F0, $EA, $02                         // rorx   r13d, r10d, $2
  lea    ebx, [rbx + r9*1]
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, r11d
  xor    r14d, r13d
  lea    r9d, [r9 + rdi*1]
  mov    r12d, ecx
  add    r8d, dword [rsp + $4C]
  and    r12d, ebx
  db $C4, $63, $7B, $F0, $EB, $19                         // rorx   r13d, ebx, $19
  db $C4, $E3, $7B, $F0, $FB, $0B                         // rorx   edi, ebx, $B
  lea    r9d, [r9 + r14*1]
  lea    r8d, [r8 + r12*1]
  db $C4, $62, $60, $F2, $E2                              // andn   r12d, ebx, edx
  xor    r13d, edi
  db $C4, $63, $7B, $F0, $F3, $06                         // rorx   r14d, ebx, $6
  lea    r8d, [r8 + r12*1]
  xor    r13d, r14d
  mov    edi, r9d
  db $C4, $43, $7B, $F0, $E1, $16                         // rorx   r12d, r9d, $16
  lea    r8d, [r8 + r13*1]
  xor    edi, r10d
  db $C4, $43, $7B, $F0, $F1, $0D                         // rorx   r14d, r9d, $D
  db $C4, $43, $7B, $F0, $E9, $02                         // rorx   r13d, r9d, $2
  lea    eax, [rax + r8*1]
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, r10d
  xor    r14d, r13d
  lea    r8d, [r8 + r15*1]
  mov    r12d, ebx
  add    edx, dword [rsp + $60]
  and    r12d, eax
  db $C4, $63, $7B, $F0, $E8, $19                         // rorx   r13d, eax, $19
  db $C4, $63, $7B, $F0, $F8, $0B                         // rorx   r15d, eax, $B
  lea    r8d, [r8 + r14*1]
  lea    edx, [rdx + r12*1]
  db $C4, $62, $78, $F2, $E1                              // andn   r12d, eax, ecx
  xor    r13d, r15d
  db $C4, $63, $7B, $F0, $F0, $06                         // rorx   r14d, eax, $6
  lea    edx, [rdx + r12*1]
  xor    r13d, r14d
  mov    r15d, r8d
  db $C4, $43, $7B, $F0, $E0, $16                         // rorx   r12d, r8d, $16
  lea    edx, [rdx + r13*1]
  xor    r15d, r9d
  db $C4, $43, $7B, $F0, $F0, $0D                         // rorx   r14d, r8d, $D
  db $C4, $43, $7B, $F0, $E8, $02                         // rorx   r13d, r8d, $2
  lea    r11d, [r11 + rdx*1]
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, r9d
  xor    r14d, r13d
  lea    edx, [rdx + rdi*1]
  mov    r12d, eax
  add    ecx, dword [rsp + $64]
  and    r12d, r11d
  db $C4, $43, $7B, $F0, $EB, $19                         // rorx   r13d, r11d, $19
  db $C4, $C3, $7B, $F0, $FB, $0B                         // rorx   edi, r11d, $B
  lea    edx, [rdx + r14*1]
  lea    ecx, [rcx + r12*1]
  db $C4, $62, $20, $F2, $E3                              // andn   r12d, r11d, ebx
  xor    r13d, edi
  db $C4, $43, $7B, $F0, $F3, $06                         // rorx   r14d, r11d, $6
  lea    ecx, [rcx + r12*1]
  xor    r13d, r14d
  mov    edi, edx
  db $C4, $63, $7B, $F0, $E2, $16                         // rorx   r12d, edx, $16
  lea    ecx, [rcx + r13*1]
  xor    edi, r8d
  db $C4, $63, $7B, $F0, $F2, $0D                         // rorx   r14d, edx, $D
  db $C4, $63, $7B, $F0, $EA, $02                         // rorx   r13d, edx, $2
  lea    r10d, [r10 + rcx*1]
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, r8d
  xor    r14d, r13d
  lea    ecx, [rcx + r15*1]
  mov    r12d, r11d
  add    ebx, dword [rsp + $68]
  and    r12d, r10d
  db $C4, $43, $7B, $F0, $EA, $19                         // rorx   r13d, r10d, $19
  db $C4, $43, $7B, $F0, $FA, $0B                         // rorx   r15d, r10d, $B
  lea    ecx, [rcx + r14*1]
  lea    ebx, [rbx + r12*1]
  db $C4, $62, $28, $F2, $E0                              // andn   r12d, r10d, eax
  xor    r13d, r15d
  db $C4, $43, $7B, $F0, $F2, $06                         // rorx   r14d, r10d, $6
  lea    ebx, [rbx + r12*1]
  xor    r13d, r14d
  mov    r15d, ecx
  db $C4, $63, $7B, $F0, $E1, $16                         // rorx   r12d, ecx, $16
  lea    ebx, [rbx + r13*1]
  xor    r15d, edx
  db $C4, $63, $7B, $F0, $F1, $0D                         // rorx   r14d, ecx, $D
  db $C4, $63, $7B, $F0, $E9, $02                         // rorx   r13d, ecx, $2
  lea    r9d, [r9 + rbx*1]
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, edx
  xor    r14d, r13d
  lea    ebx, [rbx + rdi*1]
  mov    r12d, r10d
  add    eax, dword [rsp + $6C]
  and    r12d, r9d
  db $C4, $43, $7B, $F0, $E9, $19                         // rorx   r13d, r9d, $19
  db $C4, $C3, $7B, $F0, $F9, $0B                         // rorx   edi, r9d, $B
  lea    ebx, [rbx + r14*1]
  lea    eax, [rax + r12*1]
  db $C4, $42, $30, $F2, $E3                              // andn   r12d, r9d, r11d
  xor    r13d, edi
  db $C4, $43, $7B, $F0, $F1, $06                         // rorx   r14d, r9d, $6
  lea    eax, [rax + r12*1]
  xor    r13d, r14d
  mov    edi, ebx
  db $C4, $63, $7B, $F0, $E3, $16                         // rorx   r12d, ebx, $16
  lea    eax, [rax + r13*1]
  xor    edi, ecx
  db $C4, $63, $7B, $F0, $F3, $0D                         // rorx   r14d, ebx, $D
  db $C4, $63, $7B, $F0, $EB, $02                         // rorx   r13d, ebx, $2
  lea    r8d, [r8 + rax*1]
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, ecx
  xor    r14d, r13d
  lea    eax, [rax + r15*1]
  mov    r12d, r9d
  add    r11d, dword [rsp]
  and    r12d, r8d
  db $C4, $43, $7B, $F0, $E8, $19                         // rorx   r13d, r8d, $19
  db $C4, $43, $7B, $F0, $F8, $0B                         // rorx   r15d, r8d, $B
  lea    eax, [rax + r14*1]
  lea    r11d, [r11 + r12*1]
  db $C4, $42, $38, $F2, $E2                              // andn   r12d, r8d, r10d
  xor    r13d, r15d
  db $C4, $43, $7B, $F0, $F0, $06                         // rorx   r14d, r8d, $6
  lea    r11d, [r11 + r12*1]
  xor    r13d, r14d
  mov    r15d, eax
  db $C4, $63, $7B, $F0, $E0, $16                         // rorx   r12d, eax, $16
  lea    r11d, [r11 + r13*1]
  xor    r15d, ebx
  db $C4, $63, $7B, $F0, $F0, $0D                         // rorx   r14d, eax, $D
  db $C4, $63, $7B, $F0, $E8, $02                         // rorx   r13d, eax, $2
  lea    edx, [rdx + r11*1]
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, ebx
  xor    r14d, r13d
  lea    r11d, [r11 + rdi*1]
  mov    r12d, r8d
  add    r10d, dword [rsp + $4]
  and    r12d, edx
  db $C4, $63, $7B, $F0, $EA, $19                         // rorx   r13d, edx, $19
  db $C4, $E3, $7B, $F0, $FA, $0B                         // rorx   edi, edx, $B
  lea    r11d, [r11 + r14*1]
  lea    r10d, [r10 + r12*1]
  db $C4, $42, $68, $F2, $E1                              // andn   r12d, edx, r9d
  xor    r13d, edi
  db $C4, $63, $7B, $F0, $F2, $06                         // rorx   r14d, edx, $6
  lea    r10d, [r10 + r12*1]
  xor    r13d, r14d
  mov    edi, r11d
  db $C4, $43, $7B, $F0, $E3, $16                         // rorx   r12d, r11d, $16
  lea    r10d, [r10 + r13*1]
  xor    edi, eax
  db $C4, $43, $7B, $F0, $F3, $0D                         // rorx   r14d, r11d, $D
  db $C4, $43, $7B, $F0, $EB, $02                         // rorx   r13d, r11d, $2
  lea    ecx, [rcx + r10*1]
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, eax
  xor    r14d, r13d
  lea    r10d, [r10 + r15*1]
  mov    r12d, edx
  add    r9d, dword [rsp + $8]
  and    r12d, ecx
  db $C4, $63, $7B, $F0, $E9, $19                         // rorx   r13d, ecx, $19
  db $C4, $63, $7B, $F0, $F9, $0B                         // rorx   r15d, ecx, $B
  lea    r10d, [r10 + r14*1]
  lea    r9d, [r9 + r12*1]
  db $C4, $42, $70, $F2, $E0                              // andn   r12d, ecx, r8d
  xor    r13d, r15d
  db $C4, $63, $7B, $F0, $F1, $06                         // rorx   r14d, ecx, $6
  lea    r9d, [r9 + r12*1]
  xor    r13d, r14d
  mov    r15d, r10d
  db $C4, $43, $7B, $F0, $E2, $16                         // rorx   r12d, r10d, $16
  lea    r9d, [r9 + r13*1]
  xor    r15d, r11d
  db $C4, $43, $7B, $F0, $F2, $0D                         // rorx   r14d, r10d, $D
  db $C4, $43, $7B, $F0, $EA, $02                         // rorx   r13d, r10d, $2
  lea    ebx, [rbx + r9*1]
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, r11d
  xor    r14d, r13d
  lea    r9d, [r9 + rdi*1]
  mov    r12d, ecx
  add    r8d, dword [rsp + $C]
  and    r12d, ebx
  db $C4, $63, $7B, $F0, $EB, $19                         // rorx   r13d, ebx, $19
  db $C4, $E3, $7B, $F0, $FB, $0B                         // rorx   edi, ebx, $B
  lea    r9d, [r9 + r14*1]
  lea    r8d, [r8 + r12*1]
  db $C4, $62, $60, $F2, $E2                              // andn   r12d, ebx, edx
  xor    r13d, edi
  db $C4, $63, $7B, $F0, $F3, $06                         // rorx   r14d, ebx, $6
  lea    r8d, [r8 + r12*1]
  xor    r13d, r14d
  mov    edi, r9d
  db $C4, $43, $7B, $F0, $E1, $16                         // rorx   r12d, r9d, $16
  lea    r8d, [r8 + r13*1]
  xor    edi, r10d
  db $C4, $43, $7B, $F0, $F1, $0D                         // rorx   r14d, r9d, $D
  db $C4, $43, $7B, $F0, $E9, $02                         // rorx   r13d, r9d, $2
  lea    eax, [rax + r8*1]
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, r10d
  xor    r14d, r13d
  lea    r8d, [r8 + r15*1]
  mov    r12d, ebx
  add    edx, dword [rsp + $20]
  and    r12d, eax
  db $C4, $63, $7B, $F0, $E8, $19                         // rorx   r13d, eax, $19
  db $C4, $63, $7B, $F0, $F8, $0B                         // rorx   r15d, eax, $B
  lea    r8d, [r8 + r14*1]
  lea    edx, [rdx + r12*1]
  db $C4, $62, $78, $F2, $E1                              // andn   r12d, eax, ecx
  xor    r13d, r15d
  db $C4, $63, $7B, $F0, $F0, $06                         // rorx   r14d, eax, $6
  lea    edx, [rdx + r12*1]
  xor    r13d, r14d
  mov    r15d, r8d
  db $C4, $43, $7B, $F0, $E0, $16                         // rorx   r12d, r8d, $16
  lea    edx, [rdx + r13*1]
  xor    r15d, r9d
  db $C4, $43, $7B, $F0, $F0, $0D                         // rorx   r14d, r8d, $D
  db $C4, $43, $7B, $F0, $E8, $02                         // rorx   r13d, r8d, $2
  lea    r11d, [r11 + rdx*1]
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, r9d
  xor    r14d, r13d
  lea    edx, [rdx + rdi*1]
  mov    r12d, eax
  add    ecx, dword [rsp + $24]
  and    r12d, r11d
  db $C4, $43, $7B, $F0, $EB, $19                         // rorx   r13d, r11d, $19
  db $C4, $C3, $7B, $F0, $FB, $0B                         // rorx   edi, r11d, $B
  lea    edx, [rdx + r14*1]
  lea    ecx, [rcx + r12*1]
  db $C4, $62, $20, $F2, $E3                              // andn   r12d, r11d, ebx
  xor    r13d, edi
  db $C4, $43, $7B, $F0, $F3, $06                         // rorx   r14d, r11d, $6
  lea    ecx, [rcx + r12*1]
  xor    r13d, r14d
  mov    edi, edx
  db $C4, $63, $7B, $F0, $E2, $16                         // rorx   r12d, edx, $16
  lea    ecx, [rcx + r13*1]
  xor    edi, r8d
  db $C4, $63, $7B, $F0, $F2, $0D                         // rorx   r14d, edx, $D
  db $C4, $63, $7B, $F0, $EA, $02                         // rorx   r13d, edx, $2
  lea    r10d, [r10 + rcx*1]
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, r8d
  xor    r14d, r13d
  lea    ecx, [rcx + r15*1]
  mov    r12d, r11d
  add    ebx, dword [rsp + $28]
  and    r12d, r10d
  db $C4, $43, $7B, $F0, $EA, $19                         // rorx   r13d, r10d, $19
  db $C4, $43, $7B, $F0, $FA, $0B                         // rorx   r15d, r10d, $B
  lea    ecx, [rcx + r14*1]
  lea    ebx, [rbx + r12*1]
  db $C4, $62, $28, $F2, $E0                              // andn   r12d, r10d, eax
  xor    r13d, r15d
  db $C4, $43, $7B, $F0, $F2, $06                         // rorx   r14d, r10d, $6
  lea    ebx, [rbx + r12*1]
  xor    r13d, r14d
  mov    r15d, ecx
  db $C4, $63, $7B, $F0, $E1, $16                         // rorx   r12d, ecx, $16
  lea    ebx, [rbx + r13*1]
  xor    r15d, edx
  db $C4, $63, $7B, $F0, $F1, $0D                         // rorx   r14d, ecx, $D
  db $C4, $63, $7B, $F0, $E9, $02                         // rorx   r13d, ecx, $2
  lea    r9d, [r9 + rbx*1]
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, edx
  xor    r14d, r13d
  lea    ebx, [rbx + rdi*1]
  mov    r12d, r10d
  add    eax, dword [rsp + $2C]
  and    r12d, r9d
  db $C4, $43, $7B, $F0, $E9, $19                         // rorx   r13d, r9d, $19
  db $C4, $C3, $7B, $F0, $F9, $0B                         // rorx   edi, r9d, $B
  lea    ebx, [rbx + r14*1]
  lea    eax, [rax + r12*1]
  db $C4, $42, $30, $F2, $E3                              // andn   r12d, r9d, r11d
  xor    r13d, edi
  db $C4, $43, $7B, $F0, $F1, $06                         // rorx   r14d, r9d, $6
  lea    eax, [rax + r12*1]
  xor    r13d, r14d
  mov    edi, ebx
  db $C4, $63, $7B, $F0, $E3, $16                         // rorx   r12d, ebx, $16
  lea    eax, [rax + r13*1]
  xor    edi, ecx
  db $C4, $63, $7B, $F0, $F3, $0D                         // rorx   r14d, ebx, $D
  db $C4, $63, $7B, $F0, $EB, $02                         // rorx   r13d, ebx, $2
  lea    r8d, [r8 + rax*1]
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, ecx
  xor    r14d, r13d
  lea    eax, [rax + r15*1]
  mov    r12d, r9d
  mov    rdi, qword [rsp + $200]
  add    eax, r14d
  lea    rbp, [rsp + $1C0]
  add    eax, dword [rdi]
  add    ebx, dword [rdi + $4]
  add    ecx, dword [rdi + $8]
  add    edx, dword [rdi + $C]
  add    r8d, dword [rdi + $10]
  add    r9d, dword [rdi + $14]
  add    r10d, dword [rdi + $18]
  add    r11d, dword [rdi + $1C]
  mov    dword [rdi], eax
  mov    dword [rdi + $4], ebx
  mov    dword [rdi + $8], ecx
  mov    dword [rdi + $C], edx
  mov    dword [rdi + $10], r8d
  mov    dword [rdi + $14], r9d
  mov    dword [rdi + $18], r10d
  mov    dword [rdi + $1C], r11d
  cmp    rsi, qword [rbp + $50]
  je @done
  xor    r14d, r14d
  mov    edi, ebx
  xor    edi, ecx
  mov    r12d, r9d
  jmp @tail_loop

@tail_loop:
  add    r11d, dword [rbp + $10]
  and    r12d, r8d
  db $C4, $43, $7B, $F0, $E8, $19                         // rorx   r13d, r8d, $19
  db $C4, $43, $7B, $F0, $F8, $0B                         // rorx   r15d, r8d, $B
  lea    eax, [rax + r14*1]
  lea    r11d, [r11 + r12*1]
  db $C4, $42, $38, $F2, $E2                              // andn   r12d, r8d, r10d
  xor    r13d, r15d
  db $C4, $43, $7B, $F0, $F0, $06                         // rorx   r14d, r8d, $6
  lea    r11d, [r11 + r12*1]
  xor    r13d, r14d
  mov    r15d, eax
  db $C4, $63, $7B, $F0, $E0, $16                         // rorx   r12d, eax, $16
  lea    r11d, [r11 + r13*1]
  xor    r15d, ebx
  db $C4, $63, $7B, $F0, $F0, $0D                         // rorx   r14d, eax, $D
  db $C4, $63, $7B, $F0, $E8, $02                         // rorx   r13d, eax, $2
  lea    edx, [rdx + r11*1]
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, ebx
  xor    r14d, r13d
  lea    r11d, [r11 + rdi*1]
  mov    r12d, r8d
  add    r10d, dword [rbp + $14]
  and    r12d, edx
  db $C4, $63, $7B, $F0, $EA, $19                         // rorx   r13d, edx, $19
  db $C4, $E3, $7B, $F0, $FA, $0B                         // rorx   edi, edx, $B
  lea    r11d, [r11 + r14*1]
  lea    r10d, [r10 + r12*1]
  db $C4, $42, $68, $F2, $E1                              // andn   r12d, edx, r9d
  xor    r13d, edi
  db $C4, $63, $7B, $F0, $F2, $06                         // rorx   r14d, edx, $6
  lea    r10d, [r10 + r12*1]
  xor    r13d, r14d
  mov    edi, r11d
  db $C4, $43, $7B, $F0, $E3, $16                         // rorx   r12d, r11d, $16
  lea    r10d, [r10 + r13*1]
  xor    edi, eax
  db $C4, $43, $7B, $F0, $F3, $0D                         // rorx   r14d, r11d, $D
  db $C4, $43, $7B, $F0, $EB, $02                         // rorx   r13d, r11d, $2
  lea    ecx, [rcx + r10*1]
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, eax
  xor    r14d, r13d
  lea    r10d, [r10 + r15*1]
  mov    r12d, edx
  add    r9d, dword [rbp + $18]
  and    r12d, ecx
  db $C4, $63, $7B, $F0, $E9, $19                         // rorx   r13d, ecx, $19
  db $C4, $63, $7B, $F0, $F9, $0B                         // rorx   r15d, ecx, $B
  lea    r10d, [r10 + r14*1]
  lea    r9d, [r9 + r12*1]
  db $C4, $42, $70, $F2, $E0                              // andn   r12d, ecx, r8d
  xor    r13d, r15d
  db $C4, $63, $7B, $F0, $F1, $06                         // rorx   r14d, ecx, $6
  lea    r9d, [r9 + r12*1]
  xor    r13d, r14d
  mov    r15d, r10d
  db $C4, $43, $7B, $F0, $E2, $16                         // rorx   r12d, r10d, $16
  lea    r9d, [r9 + r13*1]
  xor    r15d, r11d
  db $C4, $43, $7B, $F0, $F2, $0D                         // rorx   r14d, r10d, $D
  db $C4, $43, $7B, $F0, $EA, $02                         // rorx   r13d, r10d, $2
  lea    ebx, [rbx + r9*1]
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, r11d
  xor    r14d, r13d
  lea    r9d, [r9 + rdi*1]
  mov    r12d, ecx
  add    r8d, dword [rbp + $1C]
  and    r12d, ebx
  db $C4, $63, $7B, $F0, $EB, $19                         // rorx   r13d, ebx, $19
  db $C4, $E3, $7B, $F0, $FB, $0B                         // rorx   edi, ebx, $B
  lea    r9d, [r9 + r14*1]
  lea    r8d, [r8 + r12*1]
  db $C4, $62, $60, $F2, $E2                              // andn   r12d, ebx, edx
  xor    r13d, edi
  db $C4, $63, $7B, $F0, $F3, $06                         // rorx   r14d, ebx, $6
  lea    r8d, [r8 + r12*1]
  xor    r13d, r14d
  mov    edi, r9d
  db $C4, $43, $7B, $F0, $E1, $16                         // rorx   r12d, r9d, $16
  lea    r8d, [r8 + r13*1]
  xor    edi, r10d
  db $C4, $43, $7B, $F0, $F1, $0D                         // rorx   r14d, r9d, $D
  db $C4, $43, $7B, $F0, $E9, $02                         // rorx   r13d, r9d, $2
  lea    eax, [rax + r8*1]
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, r10d
  xor    r14d, r13d
  lea    r8d, [r8 + r15*1]
  mov    r12d, ebx
  add    edx, dword [rbp + $30]
  and    r12d, eax
  db $C4, $63, $7B, $F0, $E8, $19                         // rorx   r13d, eax, $19
  db $C4, $63, $7B, $F0, $F8, $0B                         // rorx   r15d, eax, $B
  lea    r8d, [r8 + r14*1]
  lea    edx, [rdx + r12*1]
  db $C4, $62, $78, $F2, $E1                              // andn   r12d, eax, ecx
  xor    r13d, r15d
  db $C4, $63, $7B, $F0, $F0, $06                         // rorx   r14d, eax, $6
  lea    edx, [rdx + r12*1]
  xor    r13d, r14d
  mov    r15d, r8d
  db $C4, $43, $7B, $F0, $E0, $16                         // rorx   r12d, r8d, $16
  lea    edx, [rdx + r13*1]
  xor    r15d, r9d
  db $C4, $43, $7B, $F0, $F0, $0D                         // rorx   r14d, r8d, $D
  db $C4, $43, $7B, $F0, $E8, $02                         // rorx   r13d, r8d, $2
  lea    r11d, [r11 + rdx*1]
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, r9d
  xor    r14d, r13d
  lea    edx, [rdx + rdi*1]
  mov    r12d, eax
  add    ecx, dword [rbp + $34]
  and    r12d, r11d
  db $C4, $43, $7B, $F0, $EB, $19                         // rorx   r13d, r11d, $19
  db $C4, $C3, $7B, $F0, $FB, $0B                         // rorx   edi, r11d, $B
  lea    edx, [rdx + r14*1]
  lea    ecx, [rcx + r12*1]
  db $C4, $62, $20, $F2, $E3                              // andn   r12d, r11d, ebx
  xor    r13d, edi
  db $C4, $43, $7B, $F0, $F3, $06                         // rorx   r14d, r11d, $6
  lea    ecx, [rcx + r12*1]
  xor    r13d, r14d
  mov    edi, edx
  db $C4, $63, $7B, $F0, $E2, $16                         // rorx   r12d, edx, $16
  lea    ecx, [rcx + r13*1]
  xor    edi, r8d
  db $C4, $63, $7B, $F0, $F2, $0D                         // rorx   r14d, edx, $D
  db $C4, $63, $7B, $F0, $EA, $02                         // rorx   r13d, edx, $2
  lea    r10d, [r10 + rcx*1]
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, r8d
  xor    r14d, r13d
  lea    ecx, [rcx + r15*1]
  mov    r12d, r11d
  add    ebx, dword [rbp + $38]
  and    r12d, r10d
  db $C4, $43, $7B, $F0, $EA, $19                         // rorx   r13d, r10d, $19
  db $C4, $43, $7B, $F0, $FA, $0B                         // rorx   r15d, r10d, $B
  lea    ecx, [rcx + r14*1]
  lea    ebx, [rbx + r12*1]
  db $C4, $62, $28, $F2, $E0                              // andn   r12d, r10d, eax
  xor    r13d, r15d
  db $C4, $43, $7B, $F0, $F2, $06                         // rorx   r14d, r10d, $6
  lea    ebx, [rbx + r12*1]
  xor    r13d, r14d
  mov    r15d, ecx
  db $C4, $63, $7B, $F0, $E1, $16                         // rorx   r12d, ecx, $16
  lea    ebx, [rbx + r13*1]
  xor    r15d, edx
  db $C4, $63, $7B, $F0, $F1, $0D                         // rorx   r14d, ecx, $D
  db $C4, $63, $7B, $F0, $E9, $02                         // rorx   r13d, ecx, $2
  lea    r9d, [r9 + rbx*1]
  and    edi, r15d
  xor    r14d, r12d
  xor    edi, edx
  xor    r14d, r13d
  lea    ebx, [rbx + rdi*1]
  mov    r12d, r10d
  add    eax, dword [rbp + $3C]
  and    r12d, r9d
  db $C4, $43, $7B, $F0, $E9, $19                         // rorx   r13d, r9d, $19
  db $C4, $C3, $7B, $F0, $F9, $0B                         // rorx   edi, r9d, $B
  lea    ebx, [rbx + r14*1]
  lea    eax, [rax + r12*1]
  db $C4, $42, $30, $F2, $E3                              // andn   r12d, r9d, r11d
  xor    r13d, edi
  db $C4, $43, $7B, $F0, $F1, $06                         // rorx   r14d, r9d, $6
  lea    eax, [rax + r12*1]
  xor    r13d, r14d
  mov    edi, ebx
  db $C4, $63, $7B, $F0, $E3, $16                         // rorx   r12d, ebx, $16
  lea    eax, [rax + r13*1]
  xor    edi, ecx
  db $C4, $63, $7B, $F0, $F3, $0D                         // rorx   r14d, ebx, $D
  db $C4, $63, $7B, $F0, $EB, $02                         // rorx   r13d, ebx, $2
  lea    r8d, [r8 + rax*1]
  and    r15d, edi
  xor    r14d, r12d
  xor    r15d, ecx
  xor    r14d, r13d
  lea    eax, [rax + r15*1]
  mov    r12d, r9d
  lea    rbp, [rbp - $40]
  cmp    rbp, rsp
  jae @tail_loop
  mov    rdi, qword [rsp + $200]
  add    eax, r14d
  lea    rsp, [rsp + $1C0]
  add    eax, dword [rdi]
  add    ebx, dword [rdi + $4]
  add    ecx, dword [rdi + $8]
  add    edx, dword [rdi + $C]
  add    r8d, dword [rdi + $10]
  add    r9d, dword [rdi + $14]
  lea    rsi, [rsi + $80]
  add    r10d, dword [rdi + $18]
  mov    r12, rsi
  add    r11d, dword [rdi + $1C]
  cmp    rsi, qword [rsp + $50]
  mov    dword [rdi], eax
  cmove  r12, rsp
  mov    dword [rdi + $4], ebx
  mov    dword [rdi + $8], ecx
  mov    dword [rdi + $C], edx
  mov    dword [rdi + $10], r8d
  mov    dword [rdi + $14], r9d
  mov    dword [rdi + $18], r10d
  mov    dword [rdi + $1C], r11d
  jbe @block_loop
  lea    rbp, [rsp]

@done:
  mov    rsi, qword [rbp + $58]
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

  {$I ..\..\Include\Simd\Common\HlpSimdNonVolatileRestore_x86_64.inc}
