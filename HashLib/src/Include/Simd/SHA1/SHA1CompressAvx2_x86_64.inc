// SHA-1 AVX2 two-block implementation (VEX-256), ported from OpenSSL's
// sha1-x86_64.pl (CRYPTOGAMS). Two message blocks are scheduled together in
// 256-bit lanes and the 80 rounds are interleaved with the SIMD schedule, so the
// vector and integer units run in parallel. AVX2 and BMI (rorx/andn/shlx)
// instructions are db-encoded for broad assembler compatibility (every AVX2 CPU
// also provides BMI).
// Expects MS x64 ABI (after HlpSimdProc4Begin): rcx = state ptr, rdx = data ptr,
//   r8d = numblocks, r9 = K_SHA1_Doubled ptr (the four SHA-1 round constants each
//   replicated across 256 bits, then the byte-swap mask and a reverse mask; see
//   K_SHA1_Doubled). The masks are read unaligned, so the const needs no alignment.
//
// MS x64 non-volatile saves: xmm6-xmm15 via the shared HlpSimdNonVolatileSave/Restore
// include (no-op on SysV); rbx, rbp, rdi, rsi, r12-r14 in the local frame; r11
// holds the caller rsp across the kernel for the unwind.

  {$I ..\Include\Simd\Common\HlpSimdNonVolatileSave_x86_64.inc}

  mov    r11, rsp
  push   r9
  push   rbx
  push   rbp
  push   r12
  push   r13
  push   r14
  push   rdi
  push   rsi
  mov    rdi, rcx
  mov    rsi, rdx
  mov    rdx, r8
  db $C5, $F8, $77                                        // vzeroupper
  mov    r8, rdi
  mov    r9, rsi
  mov    r10, rdx
  lea    rsp, [rsp - $280]
  shl    r10, $6
  lea    r13, [r9 + $40]
  and    rsp, $FFFFFFFFFFFFFF80
  add    r10, r9
  mov    r14, qword [r11 - $8]
  add    r14, $40
  mov    eax, dword [r8]
  cmp    r13, r10
  cmovae r13, r9
  mov    ebp, dword [r8 + $4]
  mov    ecx, dword [r8 + $8]
  mov    edx, dword [r8 + $C]
  mov    esi, dword [r8 + $10]
  db $C4, $C1, $7E, $6F, $76, $40                         // vmovdqu ymm6, yword [r14 + $40]
  db $C4, $C1, $7A, $6F, $01                              // vmovdqu xmm0, oword [r9]
  db $C4, $C1, $7A, $6F, $49, $10                         // vmovdqu xmm1, oword [r9 + $10]
  db $C4, $C1, $7A, $6F, $51, $20                         // vmovdqu xmm2, oword [r9 + $20]
  db $C4, $C1, $7A, $6F, $59, $30                         // vmovdqu xmm3, oword [r9 + $30]
  lea    r9, [r9 + $40]
  db $C4, $C3, $7D, $38, $45, $00, $01                    // vinserti128 ymm0, ymm0, oword [r13 + $0], $1
  db $C4, $C3, $75, $38, $4D, $10, $01                    // vinserti128 ymm1, ymm1, oword [r13 + $10], $1
  db $C4, $E2, $7D, $00, $C6                              // vpshufb ymm0, ymm0, ymm6
  db $C4, $C3, $6D, $38, $55, $20, $01                    // vinserti128 ymm2, ymm2, oword [r13 + $20], $1
  db $C4, $E2, $75, $00, $CE                              // vpshufb ymm1, ymm1, ymm6
  db $C4, $C3, $65, $38, $5D, $30, $01                    // vinserti128 ymm3, ymm3, oword [r13 + $30], $1
  db $C4, $E2, $6D, $00, $D6                              // vpshufb ymm2, ymm2, ymm6
  db $C4, $41, $7E, $6F, $5E, $C0                         // vmovdqu ymm11, yword [r14 - $40]
  db $C4, $E2, $65, $00, $DE                              // vpshufb ymm3, ymm3, ymm6
  db $C4, $C1, $7D, $FE, $E3                              // vpaddd ymm4, ymm0, ymm11
  db $C4, $C1, $75, $FE, $EB                              // vpaddd ymm5, ymm1, ymm11
  db $C5, $FE, $7F, $24, $24                              // vmovdqu yword [rsp], ymm4
  db $C4, $C1, $6D, $FE, $F3                              // vpaddd ymm6, ymm2, ymm11
  db $C5, $FE, $7F, $6C, $24, $20                         // vmovdqu yword [rsp + $20], ymm5
  db $C4, $C1, $65, $FE, $FB                              // vpaddd ymm7, ymm3, ymm11
  db $C5, $FE, $7F, $74, $24, $40                         // vmovdqu yword [rsp + $40], ymm6
  db $C5, $FE, $7F, $7C, $24, $60                         // vmovdqu yword [rsp + $60], ymm7
  db $C4, $E3, $75, $0F, $E0, $08                         // vpalignr ymm4, ymm1, ymm0, $8
  db $C5, $BD, $73, $DB, $04                              // vpsrldq ymm8, ymm3, $4
  db $C5, $DD, $EF, $E0                                   // vpxor  ymm4, ymm4, ymm0
  db $C5, $3D, $EF, $C2                                   // vpxor  ymm8, ymm8, ymm2
  db $C4, $C1, $5D, $EF, $E0                              // vpxor  ymm4, ymm4, ymm8
  db $C5, $BD, $72, $D4, $1F                              // vpsrld ymm8, ymm4, $1F
  db $C5, $AD, $73, $FC, $0C                              // vpslldq ymm10, ymm4, $C
  db $C5, $DD, $FE, $E4                                   // vpaddd ymm4, ymm4, ymm4
  db $C4, $C1, $35, $72, $D2, $1E                         // vpsrld ymm9, ymm10, $1E
  db $C4, $C1, $5D, $EB, $E0                              // vpor   ymm4, ymm4, ymm8
  db $C4, $C1, $2D, $72, $F2, $02                         // vpslld ymm10, ymm10, $2
  db $C4, $C1, $5D, $EF, $E1                              // vpxor  ymm4, ymm4, ymm9
  db $C4, $C1, $5D, $EF, $E2                              // vpxor  ymm4, ymm4, ymm10
  db $C4, $41, $5D, $FE, $CB                              // vpaddd ymm9, ymm4, ymm11
  db $C5, $7E, $7F, $8C, $24, $80, $00, $00, $00          // vmovdqu yword [rsp + $80], ymm9
  db $C4, $E3, $6D, $0F, $E9, $08                         // vpalignr ymm5, ymm2, ymm1, $8
  db $C5, $BD, $73, $DC, $04                              // vpsrldq ymm8, ymm4, $4
  db $C5, $D5, $EF, $E9                                   // vpxor  ymm5, ymm5, ymm1
  db $C5, $3D, $EF, $C3                                   // vpxor  ymm8, ymm8, ymm3
  db $C4, $C1, $55, $EF, $E8                              // vpxor  ymm5, ymm5, ymm8
  db $C5, $BD, $72, $D5, $1F                              // vpsrld ymm8, ymm5, $1F
  db $C4, $41, $7E, $6F, $5E, $E0                         // vmovdqu ymm11, yword [r14 - $20]
  db $C5, $AD, $73, $FD, $0C                              // vpslldq ymm10, ymm5, $C
  db $C5, $D5, $FE, $ED                                   // vpaddd ymm5, ymm5, ymm5
  db $C4, $C1, $35, $72, $D2, $1E                         // vpsrld ymm9, ymm10, $1E
  db $C4, $C1, $55, $EB, $E8                              // vpor   ymm5, ymm5, ymm8
  db $C4, $C1, $2D, $72, $F2, $02                         // vpslld ymm10, ymm10, $2
  db $C4, $C1, $55, $EF, $E9                              // vpxor  ymm5, ymm5, ymm9
  db $C4, $C1, $55, $EF, $EA                              // vpxor  ymm5, ymm5, ymm10
  db $C4, $41, $55, $FE, $CB                              // vpaddd ymm9, ymm5, ymm11
  db $C5, $7E, $7F, $8C, $24, $A0, $00, $00, $00          // vmovdqu yword [rsp + $A0], ymm9
  db $C4, $E3, $65, $0F, $F2, $08                         // vpalignr ymm6, ymm3, ymm2, $8
  db $C5, $BD, $73, $DD, $04                              // vpsrldq ymm8, ymm5, $4
  db $C5, $CD, $EF, $F2                                   // vpxor  ymm6, ymm6, ymm2
  db $C5, $3D, $EF, $C4                                   // vpxor  ymm8, ymm8, ymm4
  db $C4, $C1, $4D, $EF, $F0                              // vpxor  ymm6, ymm6, ymm8
  db $C5, $BD, $72, $D6, $1F                              // vpsrld ymm8, ymm6, $1F
  db $C5, $AD, $73, $FE, $0C                              // vpslldq ymm10, ymm6, $C
  db $C5, $CD, $FE, $F6                                   // vpaddd ymm6, ymm6, ymm6
  db $C4, $C1, $35, $72, $D2, $1E                         // vpsrld ymm9, ymm10, $1E
  db $C4, $C1, $4D, $EB, $F0                              // vpor   ymm6, ymm6, ymm8
  db $C4, $C1, $2D, $72, $F2, $02                         // vpslld ymm10, ymm10, $2
  db $C4, $C1, $4D, $EF, $F1                              // vpxor  ymm6, ymm6, ymm9
  db $C4, $C1, $4D, $EF, $F2                              // vpxor  ymm6, ymm6, ymm10
  db $C4, $41, $4D, $FE, $CB                              // vpaddd ymm9, ymm6, ymm11
  db $C5, $7E, $7F, $8C, $24, $C0, $00, $00, $00          // vmovdqu yword [rsp + $C0], ymm9
  db $C4, $E3, $5D, $0F, $FB, $08                         // vpalignr ymm7, ymm4, ymm3, $8
  db $C5, $BD, $73, $DE, $04                              // vpsrldq ymm8, ymm6, $4
  db $C5, $C5, $EF, $FB                                   // vpxor  ymm7, ymm7, ymm3
  db $C5, $3D, $EF, $C5                                   // vpxor  ymm8, ymm8, ymm5
  db $C4, $C1, $45, $EF, $F8                              // vpxor  ymm7, ymm7, ymm8
  db $C5, $BD, $72, $D7, $1F                              // vpsrld ymm8, ymm7, $1F
  db $C5, $AD, $73, $FF, $0C                              // vpslldq ymm10, ymm7, $C
  db $C5, $C5, $FE, $FF                                   // vpaddd ymm7, ymm7, ymm7
  db $C4, $C1, $35, $72, $D2, $1E                         // vpsrld ymm9, ymm10, $1E
  db $C4, $C1, $45, $EB, $F8                              // vpor   ymm7, ymm7, ymm8
  db $C4, $C1, $2D, $72, $F2, $02                         // vpslld ymm10, ymm10, $2
  db $C4, $C1, $45, $EF, $F9                              // vpxor  ymm7, ymm7, ymm9
  db $C4, $C1, $45, $EF, $FA                              // vpxor  ymm7, ymm7, ymm10
  db $C4, $41, $45, $FE, $CB                              // vpaddd ymm9, ymm7, ymm11
  db $C5, $7E, $7F, $8C, $24, $E0, $00, $00, $00          // vmovdqu yword [rsp + $E0], ymm9
  lea    r13, [rsp + $80]
  jmp @block_loop

@block_loop:
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  db $C4, $E2, $50, $F2, $FA                              // andn   edi, ebp, edx
  and    ebp, ecx
  xor    ebp, edi
  jmp @align32_1

@align32_1:
  db $C4, $63, $45, $0F, $C6, $08                         // vpalignr ymm8, ymm7, ymm6, $8
  db $C5, $FD, $EF, $C4                                   // vpxor  ymm0, ymm0, ymm4
  add    esi, dword [r13 - $80]
  db $C4, $E2, $78, $F2, $F9                              // andn   edi, eax, ecx
  db $C5, $FD, $EF, $C1                                   // vpxor  ymm0, ymm0, ymm1
  add    esi, ebp
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  db $C4, $C1, $7D, $EF, $C0                              // vpxor  ymm0, ymm0, ymm8
  and    eax, ebx
  add    esi, r12d
  xor    eax, edi
  db $C5, $BD, $72, $D0, $1E                              // vpsrld ymm8, ymm0, $1E
  db $C5, $FD, $72, $F0, $02                              // vpslld ymm0, ymm0, $2
  add    edx, dword [r13 - $7C]
  db $C4, $E2, $48, $F2, $FB                              // andn   edi, esi, ebx
  add    edx, eax
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  and    esi, ebp
  db $C4, $C1, $7D, $EB, $C0                              // vpor   ymm0, ymm0, ymm8
  add    edx, r12d
  xor    esi, edi
  add    ecx, dword [r13 - $78]
  db $C4, $E2, $68, $F2, $FD                              // andn   edi, edx, ebp
  db $C4, $41, $7D, $FE, $CB                              // vpaddd ymm9, ymm0, ymm11
  add    ecx, esi
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  and    edx, eax
  db $C5, $7E, $7F, $8C, $24, $00, $01, $00, $00          // vmovdqu yword [rsp + $100], ymm9
  add    ecx, r12d
  xor    edx, edi
  add    ebx, dword [r13 - $74]
  db $C4, $E2, $70, $F2, $F8                              // andn   edi, ecx, eax
  add    ebx, edx
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  and    ecx, esi
  add    ebx, r12d
  xor    ecx, edi
  add    ebp, dword [r13 - $60]
  db $C4, $E2, $60, $F2, $FE                              // andn   edi, ebx, esi
  add    ebp, ecx
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  and    ebx, edx
  add    ebp, r12d
  xor    ebx, edi
  db $C4, $63, $7D, $0F, $C7, $08                         // vpalignr ymm8, ymm0, ymm7, $8
  db $C5, $F5, $EF, $CD                                   // vpxor  ymm1, ymm1, ymm5
  add    eax, dword [r13 - $5C]
  db $C4, $E2, $50, $F2, $FA                              // andn   edi, ebp, edx
  db $C5, $F5, $EF, $CA                                   // vpxor  ymm1, ymm1, ymm2
  add    eax, ebx
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  db $C4, $C1, $75, $EF, $C8                              // vpxor  ymm1, ymm1, ymm8
  and    ebp, ecx
  add    eax, r12d
  xor    ebp, edi
  db $C5, $BD, $72, $D1, $1E                              // vpsrld ymm8, ymm1, $1E
  db $C5, $F5, $72, $F1, $02                              // vpslld ymm1, ymm1, $2
  add    esi, dword [r13 - $58]
  db $C4, $E2, $78, $F2, $F9                              // andn   edi, eax, ecx
  add    esi, ebp
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  and    eax, ebx
  db $C4, $C1, $75, $EB, $C8                              // vpor   ymm1, ymm1, ymm8
  add    esi, r12d
  xor    eax, edi
  add    edx, dword [r13 - $54]
  db $C4, $E2, $48, $F2, $FB                              // andn   edi, esi, ebx
  db $C4, $41, $75, $FE, $CB                              // vpaddd ymm9, ymm1, ymm11
  add    edx, eax
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  and    esi, ebp
  db $C5, $7E, $7F, $8C, $24, $20, $01, $00, $00          // vmovdqu yword [rsp + $120], ymm9
  add    edx, r12d
  xor    esi, edi
  add    ecx, dword [r13 - $40]
  db $C4, $E2, $68, $F2, $FD                              // andn   edi, edx, ebp
  add    ecx, esi
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  and    edx, eax
  add    ecx, r12d
  xor    edx, edi
  add    ebx, dword [r13 - $3C]
  db $C4, $E2, $70, $F2, $F8                              // andn   edi, ecx, eax
  add    ebx, edx
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  and    ecx, esi
  add    ebx, r12d
  xor    ecx, edi
  db $C4, $63, $75, $0F, $C0, $08                         // vpalignr ymm8, ymm1, ymm0, $8
  db $C5, $ED, $EF, $D6                                   // vpxor  ymm2, ymm2, ymm6
  add    ebp, dword [r13 - $38]
  db $C4, $E2, $60, $F2, $FE                              // andn   edi, ebx, esi
  db $C5, $ED, $EF, $D3                                   // vpxor  ymm2, ymm2, ymm3
  db $C4, $41, $7E, $6F, $1E                              // vmovdqu ymm11, yword [r14]
  add    ebp, ecx
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  db $C4, $C1, $6D, $EF, $D0                              // vpxor  ymm2, ymm2, ymm8
  and    ebx, edx
  add    ebp, r12d
  xor    ebx, edi
  db $C5, $BD, $72, $D2, $1E                              // vpsrld ymm8, ymm2, $1E
  db $C5, $ED, $72, $F2, $02                              // vpslld ymm2, ymm2, $2
  add    eax, dword [r13 - $34]
  db $C4, $E2, $50, $F2, $FA                              // andn   edi, ebp, edx
  add    eax, ebx
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  and    ebp, ecx
  db $C4, $C1, $6D, $EB, $D0                              // vpor   ymm2, ymm2, ymm8
  add    eax, r12d
  xor    ebp, edi
  add    esi, dword [r13 - $20]
  db $C4, $E2, $78, $F2, $F9                              // andn   edi, eax, ecx
  db $C4, $41, $6D, $FE, $CB                              // vpaddd ymm9, ymm2, ymm11
  add    esi, ebp
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  and    eax, ebx
  db $C5, $7E, $7F, $8C, $24, $40, $01, $00, $00          // vmovdqu yword [rsp + $140], ymm9
  add    esi, r12d
  xor    eax, edi
  add    edx, dword [r13 - $1C]
  db $C4, $E2, $48, $F2, $FB                              // andn   edi, esi, ebx
  add    edx, eax
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  and    esi, ebp
  add    edx, r12d
  xor    esi, edi
  add    ecx, dword [r13 - $18]
  db $C4, $E2, $68, $F2, $FD                              // andn   edi, edx, ebp
  add    ecx, esi
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  and    edx, eax
  add    ecx, r12d
  xor    edx, edi
  db $C4, $63, $6D, $0F, $C1, $08                         // vpalignr ymm8, ymm2, ymm1, $8
  db $C5, $E5, $EF, $DF                                   // vpxor  ymm3, ymm3, ymm7
  add    ebx, dword [r13 - $14]
  db $C4, $E2, $70, $F2, $F8                              // andn   edi, ecx, eax
  db $C5, $E5, $EF, $DC                                   // vpxor  ymm3, ymm3, ymm4
  add    ebx, edx
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  db $C4, $C1, $65, $EF, $D8                              // vpxor  ymm3, ymm3, ymm8
  and    ecx, esi
  add    ebx, r12d
  xor    ecx, edi
  db $C5, $BD, $72, $D3, $1E                              // vpsrld ymm8, ymm3, $1E
  db $C5, $E5, $72, $F3, $02                              // vpslld ymm3, ymm3, $2
  add    ebp, dword [r13 + $0]
  db $C4, $E2, $60, $F2, $FE                              // andn   edi, ebx, esi
  add    ebp, ecx
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  and    ebx, edx
  db $C4, $C1, $65, $EB, $D8                              // vpor   ymm3, ymm3, ymm8
  add    ebp, r12d
  xor    ebx, edi
  add    eax, dword [r13 + $4]
  db $C4, $E2, $50, $F2, $FA                              // andn   edi, ebp, edx
  db $C4, $41, $65, $FE, $CB                              // vpaddd ymm9, ymm3, ymm11
  add    eax, ebx
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  and    ebp, ecx
  db $C5, $7E, $7F, $8C, $24, $60, $01, $00, $00          // vmovdqu yword [rsp + $160], ymm9
  add    eax, r12d
  xor    ebp, edi
  add    esi, dword [r13 + $8]
  db $C4, $E2, $78, $F2, $F9                              // andn   edi, eax, ecx
  add    esi, ebp
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  and    eax, ebx
  add    esi, r12d
  xor    eax, edi
  add    edx, dword [r13 + $C]
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  xor    esi, ebp
  add    edx, r12d
  xor    esi, ebx
  db $C4, $63, $65, $0F, $C2, $08                         // vpalignr ymm8, ymm3, ymm2, $8
  db $C5, $DD, $EF, $E0                                   // vpxor  ymm4, ymm4, ymm0
  add    ecx, dword [r13 + $20]
  lea    ecx, [rcx + rsi*1]
  db $C5, $DD, $EF, $E5                                   // vpxor  ymm4, ymm4, ymm5
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  db $C4, $C1, $5D, $EF, $E0                              // vpxor  ymm4, ymm4, ymm8
  add    ecx, r12d
  xor    edx, ebp
  add    ebx, dword [r13 + $24]
  db $C5, $BD, $72, $D4, $1E                              // vpsrld ymm8, ymm4, $1E
  db $C5, $DD, $72, $F4, $02                              // vpslld ymm4, ymm4, $2
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  add    ebx, r12d
  xor    ecx, eax
  db $C4, $C1, $5D, $EB, $E0                              // vpor   ymm4, ymm4, ymm8
  add    ebp, dword [r13 + $28]
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  db $C4, $41, $5D, $FE, $CB                              // vpaddd ymm9, ymm4, ymm11
  xor    ebx, edx
  add    ebp, r12d
  xor    ebx, esi
  add    eax, dword [r13 + $2C]
  db $C5, $7E, $7F, $8C, $24, $80, $01, $00, $00          // vmovdqu yword [rsp + $180], ymm9
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  xor    ebp, edx
  add    esi, dword [r13 + $40]
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  xor    eax, ecx
  db $C4, $63, $5D, $0F, $C3, $08                         // vpalignr ymm8, ymm4, ymm3, $8
  db $C5, $D5, $EF, $E9                                   // vpxor  ymm5, ymm5, ymm1
  add    edx, dword [r13 + $44]
  lea    edx, [rdx + rax*1]
  db $C5, $D5, $EF, $EE                                   // vpxor  ymm5, ymm5, ymm6
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  xor    esi, ebp
  db $C4, $C1, $55, $EF, $E8                              // vpxor  ymm5, ymm5, ymm8
  add    edx, r12d
  xor    esi, ebx
  add    ecx, dword [r13 + $48]
  db $C5, $BD, $72, $D5, $1E                              // vpsrld ymm8, ymm5, $1E
  db $C5, $D5, $72, $F5, $02                              // vpslld ymm5, ymm5, $2
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  add    ecx, r12d
  xor    edx, ebp
  db $C4, $C1, $55, $EB, $E8                              // vpor   ymm5, ymm5, ymm8
  add    ebx, dword [r13 + $4C]
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  db $C4, $41, $55, $FE, $CB                              // vpaddd ymm9, ymm5, ymm11
  xor    ecx, esi
  add    ebx, r12d
  xor    ecx, eax
  add    ebp, dword [r13 + $60]
  db $C5, $7E, $7F, $8C, $24, $A0, $01, $00, $00          // vmovdqu yword [rsp + $1A0], ymm9
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  add    ebp, r12d
  xor    ebx, esi
  add    eax, dword [r13 + $64]
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  xor    ebp, edx
  db $C4, $63, $55, $0F, $C4, $08                         // vpalignr ymm8, ymm5, ymm4, $8
  db $C5, $CD, $EF, $F2                                   // vpxor  ymm6, ymm6, ymm2
  add    esi, dword [r13 + $68]
  lea    esi, [rsi + rbp*1]
  db $C5, $CD, $EF, $F7                                   // vpxor  ymm6, ymm6, ymm7
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  db $C4, $C1, $4D, $EF, $F0                              // vpxor  ymm6, ymm6, ymm8
  add    esi, r12d
  xor    eax, ecx
  add    edx, dword [r13 + $6C]
  lea    r13, [r13 + $100]
  db $C5, $BD, $72, $D6, $1E                              // vpsrld ymm8, ymm6, $1E
  db $C5, $CD, $72, $F6, $02                              // vpslld ymm6, ymm6, $2
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  xor    esi, ebp
  add    edx, r12d
  xor    esi, ebx
  db $C4, $C1, $4D, $EB, $F0                              // vpor   ymm6, ymm6, ymm8
  add    ecx, dword [r13 - $80]
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  db $C4, $41, $4D, $FE, $CB                              // vpaddd ymm9, ymm6, ymm11
  xor    edx, eax
  add    ecx, r12d
  xor    edx, ebp
  add    ebx, dword [r13 - $7C]
  db $C5, $7E, $7F, $8C, $24, $C0, $01, $00, $00          // vmovdqu yword [rsp + $1C0], ymm9
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  add    ebx, r12d
  xor    ecx, eax
  add    ebp, dword [r13 - $78]
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  add    ebp, r12d
  xor    ebx, esi
  db $C4, $63, $4D, $0F, $C5, $08                         // vpalignr ymm8, ymm6, ymm5, $8
  db $C5, $C5, $EF, $FB                                   // vpxor  ymm7, ymm7, ymm3
  add    eax, dword [r13 - $74]
  lea    eax, [rax + rbx*1]
  db $C5, $C5, $EF, $F8                                   // vpxor  ymm7, ymm7, ymm0
  db $C4, $41, $7E, $6F, $5E, $20                         // vmovdqu ymm11, yword [r14 + $20]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  db $C4, $C1, $45, $EF, $F8                              // vpxor  ymm7, ymm7, ymm8
  add    eax, r12d
  xor    ebp, edx
  add    esi, dword [r13 - $60]
  db $C5, $BD, $72, $D7, $1E                              // vpsrld ymm8, ymm7, $1E
  db $C5, $C5, $72, $F7, $02                              // vpslld ymm7, ymm7, $2
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  xor    eax, ecx
  db $C4, $C1, $45, $EB, $F8                              // vpor   ymm7, ymm7, ymm8
  add    edx, dword [r13 - $5C]
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  db $C4, $41, $45, $FE, $CB                              // vpaddd ymm9, ymm7, ymm11
  xor    esi, ebp
  add    edx, r12d
  xor    esi, ebx
  add    ecx, dword [r13 - $58]
  db $C5, $7E, $7F, $8C, $24, $E0, $01, $00, $00          // vmovdqu yword [rsp + $1E0], ymm9
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  add    ecx, r12d
  xor    edx, ebp
  add    ebx, dword [r13 - $54]
  mov    edi, esi
  xor    edi, eax
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  add    ebx, r12d
  and    ecx, edi
  jmp @align32_2

@align32_2:
  db $C4, $63, $45, $0F, $C6, $08                         // vpalignr ymm8, ymm7, ymm6, $8
  db $C5, $FD, $EF, $C4                                   // vpxor  ymm0, ymm0, ymm4
  add    ebp, dword [r13 - $40]
  xor    ecx, esi
  db $C5, $FD, $EF, $C1                                   // vpxor  ymm0, ymm0, ymm1
  mov    edi, edx
  xor    edi, esi
  lea    ebp, [rcx + rbp*1]
  db $C4, $C1, $7D, $EF, $C0                              // vpxor  ymm0, ymm0, ymm8
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  db $C5, $BD, $72, $D0, $1E                              // vpsrld ymm8, ymm0, $1E
  db $C5, $FD, $72, $F0, $02                              // vpslld ymm0, ymm0, $2
  add    ebp, r12d
  and    ebx, edi
  add    eax, dword [r13 - $3C]
  xor    ebx, edx
  mov    edi, ecx
  xor    edi, edx
  db $C4, $C1, $7D, $EB, $C0                              // vpor   ymm0, ymm0, ymm8
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  db $C4, $41, $7D, $FE, $CB                              // vpaddd ymm9, ymm0, ymm11
  add    eax, r12d
  and    ebp, edi
  add    esi, dword [r13 - $38]
  xor    ebp, ecx
  db $C5, $7E, $7F, $8C, $24, $00, $02, $00, $00          // vmovdqu yword [rsp + $200], ymm9
  mov    edi, ebx
  xor    edi, ecx
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  and    eax, edi
  add    edx, dword [r13 - $34]
  xor    eax, ebx
  mov    edi, ebp
  xor    edi, ebx
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  xor    esi, ebp
  add    edx, r12d
  and    esi, edi
  add    ecx, dword [r13 - $20]
  xor    esi, ebp
  mov    edi, eax
  xor    edi, ebp
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  add    ecx, r12d
  and    edx, edi
  db $C4, $63, $7D, $0F, $C7, $08                         // vpalignr ymm8, ymm0, ymm7, $8
  db $C5, $F5, $EF, $CD                                   // vpxor  ymm1, ymm1, ymm5
  add    ebx, dword [r13 - $1C]
  xor    edx, eax
  db $C5, $F5, $EF, $CA                                   // vpxor  ymm1, ymm1, ymm2
  mov    edi, esi
  xor    edi, eax
  lea    ebx, [rbx + rdx*1]
  db $C4, $C1, $75, $EF, $C8                              // vpxor  ymm1, ymm1, ymm8
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  db $C5, $BD, $72, $D1, $1E                              // vpsrld ymm8, ymm1, $1E
  db $C5, $F5, $72, $F1, $02                              // vpslld ymm1, ymm1, $2
  add    ebx, r12d
  and    ecx, edi
  add    ebp, dword [r13 - $18]
  xor    ecx, esi
  mov    edi, edx
  xor    edi, esi
  db $C4, $C1, $75, $EB, $C8                              // vpor   ymm1, ymm1, ymm8
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  db $C4, $41, $75, $FE, $CB                              // vpaddd ymm9, ymm1, ymm11
  add    ebp, r12d
  and    ebx, edi
  add    eax, dword [r13 - $14]
  xor    ebx, edx
  db $C5, $7E, $7F, $8C, $24, $20, $02, $00, $00          // vmovdqu yword [rsp + $220], ymm9
  mov    edi, ecx
  xor    edi, edx
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  and    ebp, edi
  add    esi, dword [r13 + $0]
  xor    ebp, ecx
  mov    edi, ebx
  xor    edi, ecx
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  and    eax, edi
  add    edx, dword [r13 + $4]
  xor    eax, ebx
  mov    edi, ebp
  xor    edi, ebx
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  xor    esi, ebp
  add    edx, r12d
  and    esi, edi
  db $C4, $63, $75, $0F, $C0, $08                         // vpalignr ymm8, ymm1, ymm0, $8
  db $C5, $ED, $EF, $D6                                   // vpxor  ymm2, ymm2, ymm6
  add    ecx, dword [r13 + $8]
  xor    esi, ebp
  db $C5, $ED, $EF, $D3                                   // vpxor  ymm2, ymm2, ymm3
  mov    edi, eax
  xor    edi, ebp
  lea    ecx, [rcx + rsi*1]
  db $C4, $C1, $6D, $EF, $D0                              // vpxor  ymm2, ymm2, ymm8
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  db $C5, $BD, $72, $D2, $1E                              // vpsrld ymm8, ymm2, $1E
  db $C5, $ED, $72, $F2, $02                              // vpslld ymm2, ymm2, $2
  add    ecx, r12d
  and    edx, edi
  add    ebx, dword [r13 + $C]
  xor    edx, eax
  mov    edi, esi
  xor    edi, eax
  db $C4, $C1, $6D, $EB, $D0                              // vpor   ymm2, ymm2, ymm8
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  db $C4, $41, $6D, $FE, $CB                              // vpaddd ymm9, ymm2, ymm11
  add    ebx, r12d
  and    ecx, edi
  add    ebp, dword [r13 + $20]
  xor    ecx, esi
  db $C5, $7E, $7F, $8C, $24, $40, $02, $00, $00          // vmovdqu yword [rsp + $240], ymm9
  mov    edi, edx
  xor    edi, esi
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  add    ebp, r12d
  and    ebx, edi
  add    eax, dword [r13 + $24]
  xor    ebx, edx
  mov    edi, ecx
  xor    edi, edx
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  and    ebp, edi
  add    esi, dword [r13 + $28]
  xor    ebp, ecx
  mov    edi, ebx
  xor    edi, ecx
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  and    eax, edi
  db $C4, $63, $6D, $0F, $C1, $08                         // vpalignr ymm8, ymm2, ymm1, $8
  db $C5, $E5, $EF, $DF                                   // vpxor  ymm3, ymm3, ymm7
  add    edx, dword [r13 + $2C]
  xor    eax, ebx
  db $C5, $E5, $EF, $DC                                   // vpxor  ymm3, ymm3, ymm4
  mov    edi, ebp
  xor    edi, ebx
  lea    edx, [rdx + rax*1]
  db $C4, $C1, $65, $EF, $D8                              // vpxor  ymm3, ymm3, ymm8
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  xor    esi, ebp
  db $C5, $BD, $72, $D3, $1E                              // vpsrld ymm8, ymm3, $1E
  db $C5, $E5, $72, $F3, $02                              // vpslld ymm3, ymm3, $2
  add    edx, r12d
  and    esi, edi
  add    ecx, dword [r13 + $40]
  xor    esi, ebp
  mov    edi, eax
  xor    edi, ebp
  db $C4, $C1, $65, $EB, $D8                              // vpor   ymm3, ymm3, ymm8
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  db $C4, $41, $65, $FE, $CB                              // vpaddd ymm9, ymm3, ymm11
  add    ecx, r12d
  and    edx, edi
  add    ebx, dword [r13 + $44]
  xor    edx, eax
  db $C5, $7E, $7F, $8C, $24, $60, $02, $00, $00          // vmovdqu yword [rsp + $260], ymm9
  mov    edi, esi
  xor    edi, eax
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  add    ebx, r12d
  and    ecx, edi
  add    ebp, dword [r13 + $48]
  xor    ecx, esi
  mov    edi, edx
  xor    edi, esi
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  add    ebp, r12d
  and    ebx, edi
  add    eax, dword [r13 + $4C]
  xor    ebx, edx
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  xor    ebp, edx
  add    esi, dword [r13 + $60]
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  xor    eax, ecx
  add    edx, dword [r13 + $64]
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  xor    esi, ebp
  add    edx, r12d
  xor    esi, ebx
  add    ecx, dword [r13 + $68]
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  add    ecx, r12d
  xor    edx, ebp
  add    ebx, dword [r13 + $6C]
  lea    r13, [r13 + $100]
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  add    ebx, r12d
  xor    ecx, eax
  add    ebp, dword [r13 - $80]
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  add    ebp, r12d
  xor    ebx, esi
  add    eax, dword [r13 - $7C]
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  xor    ebp, edx
  add    esi, dword [r13 - $78]
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  xor    eax, ecx
  add    edx, dword [r13 - $74]
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  xor    esi, ebp
  add    edx, r12d
  xor    esi, ebx
  add    ecx, dword [r13 - $60]
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  add    ecx, r12d
  xor    edx, ebp
  add    ebx, dword [r13 - $5C]
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  add    ebx, r12d
  xor    ecx, eax
  add    ebp, dword [r13 - $58]
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  add    ebp, r12d
  xor    ebx, esi
  add    eax, dword [r13 - $54]
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  xor    ebp, edx
  add    esi, dword [r13 - $40]
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  xor    eax, ecx
  add    edx, dword [r13 - $3C]
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  xor    esi, ebp
  add    edx, r12d
  xor    esi, ebx
  add    ecx, dword [r13 - $38]
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  add    ecx, r12d
  xor    edx, ebp
  add    ebx, dword [r13 - $34]
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  add    ebx, r12d
  xor    ecx, eax
  add    ebp, dword [r13 - $20]
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  add    ebp, r12d
  xor    ebx, esi
  add    eax, dword [r13 - $1C]
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  xor    ebp, edx
  add    esi, dword [r13 - $18]
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  xor    eax, ecx
  add    edx, dword [r13 - $14]
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  add    edx, r12d
  lea    r13, [r9 + $80]
  lea    rdi, [r9 + $80]
  cmp    r13, r10
  cmovae r13, r9
  add    edx, dword [r8]
  add    esi, dword [r8 + $4]
  add    ebp, dword [r8 + $8]
  mov    dword [r8], edx
  add    ebx, dword [r8 + $C]
  mov    dword [r8 + $4], esi
  mov    eax, edx
  add    ecx, dword [r8 + $10]
  mov    r12d, ebp
  mov    dword [r8 + $8], ebp
  mov    edx, ebx
  mov    dword [r8 + $C], ebx
  mov    ebp, esi
  mov    dword [r8 + $10], ecx
  mov    esi, ecx
  mov    ecx, r12d
  cmp    r9, r10
  je @done
  db $C4, $C1, $7E, $6F, $76, $40                         // vmovdqu ymm6, yword [r14 + $40]
  cmp    rdi, r10
  ja @tail
  db $C5, $FA, $6F, $47, $C0                              // vmovdqu xmm0, oword [rdi - $40]
  db $C5, $FA, $6F, $4F, $D0                              // vmovdqu xmm1, oword [rdi - $30]
  db $C5, $FA, $6F, $57, $E0                              // vmovdqu xmm2, oword [rdi - $20]
  db $C5, $FA, $6F, $5F, $F0                              // vmovdqu xmm3, oword [rdi - $10]
  db $C4, $C3, $7D, $38, $45, $00, $01                    // vinserti128 ymm0, ymm0, oword [r13 + $0], $1
  db $C4, $C3, $75, $38, $4D, $10, $01                    // vinserti128 ymm1, ymm1, oword [r13 + $10], $1
  db $C4, $C3, $6D, $38, $55, $20, $01                    // vinserti128 ymm2, ymm2, oword [r13 + $20], $1
  db $C4, $C3, $65, $38, $5D, $30, $01                    // vinserti128 ymm3, ymm3, oword [r13 + $30], $1
  jmp @tail

@tail:
  lea    r13, [rsp + $90]
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  db $C4, $E2, $50, $F2, $FA                              // andn   edi, ebp, edx
  and    ebp, ecx
  xor    ebp, edi
  sub    r9, $FFFFFFFFFFFFFF80
  add    esi, dword [r13 - $80]
  db $C4, $E2, $78, $F2, $F9                              // andn   edi, eax, ecx
  add    esi, ebp
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  and    eax, ebx
  add    esi, r12d
  xor    eax, edi
  add    edx, dword [r13 - $7C]
  db $C4, $E2, $48, $F2, $FB                              // andn   edi, esi, ebx
  add    edx, eax
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  and    esi, ebp
  add    edx, r12d
  xor    esi, edi
  add    ecx, dword [r13 - $78]
  db $C4, $E2, $68, $F2, $FD                              // andn   edi, edx, ebp
  add    ecx, esi
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  and    edx, eax
  add    ecx, r12d
  xor    edx, edi
  add    ebx, dword [r13 - $74]
  db $C4, $E2, $70, $F2, $F8                              // andn   edi, ecx, eax
  add    ebx, edx
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  and    ecx, esi
  add    ebx, r12d
  xor    ecx, edi
  add    ebp, dword [r13 - $60]
  db $C4, $E2, $60, $F2, $FE                              // andn   edi, ebx, esi
  add    ebp, ecx
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  and    ebx, edx
  add    ebp, r12d
  xor    ebx, edi
  add    eax, dword [r13 - $5C]
  db $C4, $E2, $50, $F2, $FA                              // andn   edi, ebp, edx
  add    eax, ebx
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  and    ebp, ecx
  add    eax, r12d
  xor    ebp, edi
  add    esi, dword [r13 - $58]
  db $C4, $E2, $78, $F2, $F9                              // andn   edi, eax, ecx
  add    esi, ebp
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  and    eax, ebx
  add    esi, r12d
  xor    eax, edi
  add    edx, dword [r13 - $54]
  db $C4, $E2, $48, $F2, $FB                              // andn   edi, esi, ebx
  add    edx, eax
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  and    esi, ebp
  add    edx, r12d
  xor    esi, edi
  add    ecx, dword [r13 - $40]
  db $C4, $E2, $68, $F2, $FD                              // andn   edi, edx, ebp
  add    ecx, esi
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  and    edx, eax
  add    ecx, r12d
  xor    edx, edi
  add    ebx, dword [r13 - $3C]
  db $C4, $E2, $70, $F2, $F8                              // andn   edi, ecx, eax
  add    ebx, edx
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  and    ecx, esi
  add    ebx, r12d
  xor    ecx, edi
  add    ebp, dword [r13 - $38]
  db $C4, $E2, $60, $F2, $FE                              // andn   edi, ebx, esi
  add    ebp, ecx
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  and    ebx, edx
  add    ebp, r12d
  xor    ebx, edi
  add    eax, dword [r13 - $34]
  db $C4, $E2, $50, $F2, $FA                              // andn   edi, ebp, edx
  add    eax, ebx
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  and    ebp, ecx
  add    eax, r12d
  xor    ebp, edi
  add    esi, dword [r13 - $20]
  db $C4, $E2, $78, $F2, $F9                              // andn   edi, eax, ecx
  add    esi, ebp
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  and    eax, ebx
  add    esi, r12d
  xor    eax, edi
  add    edx, dword [r13 - $1C]
  db $C4, $E2, $48, $F2, $FB                              // andn   edi, esi, ebx
  add    edx, eax
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  and    esi, ebp
  add    edx, r12d
  xor    esi, edi
  add    ecx, dword [r13 - $18]
  db $C4, $E2, $68, $F2, $FD                              // andn   edi, edx, ebp
  add    ecx, esi
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  and    edx, eax
  add    ecx, r12d
  xor    edx, edi
  add    ebx, dword [r13 - $14]
  db $C4, $E2, $70, $F2, $F8                              // andn   edi, ecx, eax
  add    ebx, edx
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  and    ecx, esi
  add    ebx, r12d
  xor    ecx, edi
  add    ebp, dword [r13 + $0]
  db $C4, $E2, $60, $F2, $FE                              // andn   edi, ebx, esi
  add    ebp, ecx
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  and    ebx, edx
  add    ebp, r12d
  xor    ebx, edi
  add    eax, dword [r13 + $4]
  db $C4, $E2, $50, $F2, $FA                              // andn   edi, ebp, edx
  add    eax, ebx
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  and    ebp, ecx
  add    eax, r12d
  xor    ebp, edi
  add    esi, dword [r13 + $8]
  db $C4, $E2, $78, $F2, $F9                              // andn   edi, eax, ecx
  add    esi, ebp
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  and    eax, ebx
  add    esi, r12d
  xor    eax, edi
  add    edx, dword [r13 + $C]
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  xor    esi, ebp
  add    edx, r12d
  xor    esi, ebx
  add    ecx, dword [r13 + $20]
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  add    ecx, r12d
  xor    edx, ebp
  add    ebx, dword [r13 + $24]
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  add    ebx, r12d
  xor    ecx, eax
  add    ebp, dword [r13 + $28]
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  add    ebp, r12d
  xor    ebx, esi
  add    eax, dword [r13 + $2C]
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  xor    ebp, edx
  add    esi, dword [r13 + $40]
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  xor    eax, ecx
  db $C4, $41, $7E, $6F, $5E, $C0                         // vmovdqu ymm11, yword [r14 - $40]
  db $C4, $E2, $7D, $00, $C6                              // vpshufb ymm0, ymm0, ymm6
  add    edx, dword [r13 + $44]
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  xor    esi, ebp
  add    edx, r12d
  xor    esi, ebx
  add    ecx, dword [r13 + $48]
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  add    ecx, r12d
  xor    edx, ebp
  add    ebx, dword [r13 + $4C]
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  add    ebx, r12d
  xor    ecx, eax
  add    ebp, dword [r13 + $60]
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  add    ebp, r12d
  xor    ebx, esi
  add    eax, dword [r13 + $64]
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  xor    ebp, edx
  db $C4, $E2, $75, $00, $CE                              // vpshufb ymm1, ymm1, ymm6
  db $C4, $41, $7D, $FE, $C3                              // vpaddd ymm8, ymm0, ymm11
  add    esi, dword [r13 + $68]
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  xor    eax, ecx
  add    edx, dword [r13 + $6C]
  lea    r13, [r13 + $100]
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  xor    esi, ebp
  add    edx, r12d
  xor    esi, ebx
  add    ecx, dword [r13 - $80]
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  add    ecx, r12d
  xor    edx, ebp
  add    ebx, dword [r13 - $7C]
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  add    ebx, r12d
  xor    ecx, eax
  add    ebp, dword [r13 - $78]
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  add    ebp, r12d
  xor    ebx, esi
  db $C5, $7E, $7F, $04, $24                              // vmovdqu yword [rsp], ymm8
  db $C4, $E2, $6D, $00, $D6                              // vpshufb ymm2, ymm2, ymm6
  db $C4, $41, $75, $FE, $CB                              // vpaddd ymm9, ymm1, ymm11
  add    eax, dword [r13 - $74]
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  xor    ebp, edx
  add    esi, dword [r13 - $60]
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  xor    eax, ecx
  add    edx, dword [r13 - $5C]
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  xor    esi, ebp
  add    edx, r12d
  xor    esi, ebx
  add    ecx, dword [r13 - $58]
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  add    ecx, r12d
  xor    edx, ebp
  add    ebx, dword [r13 - $54]
  mov    edi, esi
  xor    edi, eax
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  add    ebx, r12d
  and    ecx, edi
  db $C5, $7E, $7F, $4C, $24, $20                         // vmovdqu yword [rsp + $20], ymm9
  db $C4, $E2, $65, $00, $DE                              // vpshufb ymm3, ymm3, ymm6
  db $C4, $C1, $6D, $FE, $F3                              // vpaddd ymm6, ymm2, ymm11
  add    ebp, dword [r13 - $40]
  xor    ecx, esi
  mov    edi, edx
  xor    edi, esi
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  add    ebp, r12d
  and    ebx, edi
  add    eax, dword [r13 - $3C]
  xor    ebx, edx
  mov    edi, ecx
  xor    edi, edx
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  and    ebp, edi
  add    esi, dword [r13 - $38]
  xor    ebp, ecx
  mov    edi, ebx
  xor    edi, ecx
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  and    eax, edi
  add    edx, dword [r13 - $34]
  xor    eax, ebx
  mov    edi, ebp
  xor    edi, ebx
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  xor    esi, ebp
  add    edx, r12d
  and    esi, edi
  add    ecx, dword [r13 - $20]
  xor    esi, ebp
  mov    edi, eax
  xor    edi, ebp
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  add    ecx, r12d
  and    edx, edi
  jmp @align32_3

@align32_3:
  db $C5, $FE, $7F, $74, $24, $40                         // vmovdqu yword [rsp + $40], ymm6
  db $C4, $C1, $65, $FE, $FB                              // vpaddd ymm7, ymm3, ymm11
  add    ebx, dword [r13 - $1C]
  xor    edx, eax
  mov    edi, esi
  xor    edi, eax
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  add    ebx, r12d
  and    ecx, edi
  add    ebp, dword [r13 - $18]
  xor    ecx, esi
  mov    edi, edx
  xor    edi, esi
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  add    ebp, r12d
  and    ebx, edi
  add    eax, dword [r13 - $14]
  xor    ebx, edx
  mov    edi, ecx
  xor    edi, edx
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  and    ebp, edi
  add    esi, dword [r13 + $0]
  xor    ebp, ecx
  mov    edi, ebx
  xor    edi, ecx
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  and    eax, edi
  add    edx, dword [r13 + $4]
  xor    eax, ebx
  mov    edi, ebp
  xor    edi, ebx
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  xor    esi, ebp
  add    edx, r12d
  and    esi, edi
  db $C5, $FE, $7F, $7C, $24, $60                         // vmovdqu yword [rsp + $60], ymm7
  add    ecx, dword [r13 + $8]
  xor    esi, ebp
  mov    edi, eax
  xor    edi, ebp
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  add    ecx, r12d
  and    edx, edi
  add    ebx, dword [r13 + $C]
  xor    edx, eax
  mov    edi, esi
  xor    edi, eax
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  add    ebx, r12d
  and    ecx, edi
  add    ebp, dword [r13 + $20]
  xor    ecx, esi
  mov    edi, edx
  xor    edi, esi
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  add    ebp, r12d
  and    ebx, edi
  add    eax, dword [r13 + $24]
  xor    ebx, edx
  mov    edi, ecx
  xor    edi, edx
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  and    ebp, edi
  add    esi, dword [r13 + $28]
  xor    ebp, ecx
  mov    edi, ebx
  xor    edi, ecx
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  and    eax, edi
  db $C4, $E3, $75, $0F, $E0, $08                         // vpalignr ymm4, ymm1, ymm0, $8
  add    edx, dword [r13 + $2C]
  xor    eax, ebx
  mov    edi, ebp
  xor    edi, ebx
  db $C5, $BD, $73, $DB, $04                              // vpsrldq ymm8, ymm3, $4
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  db $C5, $DD, $EF, $E0                                   // vpxor  ymm4, ymm4, ymm0
  db $C5, $3D, $EF, $C2                                   // vpxor  ymm8, ymm8, ymm2
  xor    esi, ebp
  add    edx, r12d
  db $C4, $C1, $5D, $EF, $E0                              // vpxor  ymm4, ymm4, ymm8
  and    esi, edi
  add    ecx, dword [r13 + $40]
  xor    esi, ebp
  mov    edi, eax
  db $C5, $BD, $72, $D4, $1F                              // vpsrld ymm8, ymm4, $1F
  xor    edi, ebp
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C5, $AD, $73, $FC, $0C                              // vpslldq ymm10, ymm4, $C
  db $C5, $DD, $FE, $E4                                   // vpaddd ymm4, ymm4, ymm4
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  db $C4, $C1, $35, $72, $D2, $1E                         // vpsrld ymm9, ymm10, $1E
  db $C4, $C1, $5D, $EB, $E0                              // vpor   ymm4, ymm4, ymm8
  add    ecx, r12d
  and    edx, edi
  db $C4, $C1, $2D, $72, $F2, $02                         // vpslld ymm10, ymm10, $2
  db $C4, $C1, $5D, $EF, $E1                              // vpxor  ymm4, ymm4, ymm9
  add    ebx, dword [r13 + $44]
  xor    edx, eax
  db $C4, $C1, $5D, $EF, $E2                              // vpxor  ymm4, ymm4, ymm10
  mov    edi, esi
  xor    edi, eax
  lea    ebx, [rbx + rdx*1]
  db $C4, $41, $5D, $FE, $CB                              // vpaddd ymm9, ymm4, ymm11
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  db $C5, $7E, $7F, $8C, $24, $80, $00, $00, $00          // vmovdqu yword [rsp + $80], ymm9
  add    ebx, r12d
  and    ecx, edi
  add    ebp, dword [r13 + $48]
  xor    ecx, esi
  mov    edi, edx
  xor    edi, esi
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  add    ebp, r12d
  and    ebx, edi
  add    eax, dword [r13 + $4C]
  xor    ebx, edx
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  xor    ebp, edx
  db $C4, $E3, $6D, $0F, $E9, $08                         // vpalignr ymm5, ymm2, ymm1, $8
  add    esi, dword [r13 + $60]
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  db $C5, $BD, $73, $DC, $04                              // vpsrldq ymm8, ymm4, $4
  xor    eax, ebx
  add    esi, r12d
  xor    eax, ecx
  db $C5, $D5, $EF, $E9                                   // vpxor  ymm5, ymm5, ymm1
  db $C5, $3D, $EF, $C3                                   // vpxor  ymm8, ymm8, ymm3
  add    edx, dword [r13 + $64]
  lea    edx, [rdx + rax*1]
  db $C4, $C1, $55, $EF, $E8                              // vpxor  ymm5, ymm5, ymm8
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  xor    esi, ebp
  add    edx, r12d
  db $C5, $BD, $72, $D5, $1F                              // vpsrld ymm8, ymm5, $1F
  db $C4, $41, $7E, $6F, $5E, $E0                         // vmovdqu ymm11, yword [r14 - $20]
  xor    esi, ebx
  add    ecx, dword [r13 + $68]
  lea    ecx, [rcx + rsi*1]
  db $C5, $AD, $73, $FD, $0C                              // vpslldq ymm10, ymm5, $C
  db $C5, $D5, $FE, $ED                                   // vpaddd ymm5, ymm5, ymm5
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  db $C4, $C1, $35, $72, $D2, $1E                         // vpsrld ymm9, ymm10, $1E
  db $C4, $C1, $55, $EB, $E8                              // vpor   ymm5, ymm5, ymm8
  xor    edx, eax
  add    ecx, r12d
  db $C4, $C1, $2D, $72, $F2, $02                         // vpslld ymm10, ymm10, $2
  db $C4, $C1, $55, $EF, $E9                              // vpxor  ymm5, ymm5, ymm9
  xor    edx, ebp
  add    ebx, dword [r13 + $6C]
  lea    r13, [r13 + $100]
  db $C4, $C1, $55, $EF, $EA                              // vpxor  ymm5, ymm5, ymm10
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  db $C4, $41, $55, $FE, $CB                              // vpaddd ymm9, ymm5, ymm11
  xor    ecx, esi
  add    ebx, r12d
  xor    ecx, eax
  db $C5, $7E, $7F, $8C, $24, $A0, $00, $00, $00          // vmovdqu yword [rsp + $A0], ymm9
  add    ebp, dword [r13 - $80]
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  add    ebp, r12d
  xor    ebx, esi
  db $C4, $E3, $65, $0F, $F2, $08                         // vpalignr ymm6, ymm3, ymm2, $8
  add    eax, dword [r13 - $7C]
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  db $C5, $BD, $73, $DD, $04                              // vpsrldq ymm8, ymm5, $4
  xor    ebp, ecx
  add    eax, r12d
  xor    ebp, edx
  db $C5, $CD, $EF, $F2                                   // vpxor  ymm6, ymm6, ymm2
  db $C5, $3D, $EF, $C4                                   // vpxor  ymm8, ymm8, ymm4
  add    esi, dword [r13 - $78]
  lea    esi, [rsi + rbp*1]
  db $C4, $C1, $4D, $EF, $F0                              // vpxor  ymm6, ymm6, ymm8
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  db $C5, $BD, $72, $D6, $1F                              // vpsrld ymm8, ymm6, $1F
  xor    eax, ecx
  add    edx, dword [r13 - $74]
  lea    edx, [rdx + rax*1]
  db $C5, $AD, $73, $FE, $0C                              // vpslldq ymm10, ymm6, $C
  db $C5, $CD, $FE, $F6                                   // vpaddd ymm6, ymm6, ymm6
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  db $C4, $C1, $35, $72, $D2, $1E                         // vpsrld ymm9, ymm10, $1E
  db $C4, $C1, $4D, $EB, $F0                              // vpor   ymm6, ymm6, ymm8
  xor    esi, ebp
  add    edx, r12d
  db $C4, $C1, $2D, $72, $F2, $02                         // vpslld ymm10, ymm10, $2
  db $C4, $C1, $4D, $EF, $F1                              // vpxor  ymm6, ymm6, ymm9
  xor    esi, ebx
  add    ecx, dword [r13 - $60]
  db $C4, $C1, $4D, $EF, $F2                              // vpxor  ymm6, ymm6, ymm10
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  db $C4, $41, $4D, $FE, $CB                              // vpaddd ymm9, ymm6, ymm11
  xor    edx, eax
  add    ecx, r12d
  xor    edx, ebp
  db $C5, $7E, $7F, $8C, $24, $C0, $00, $00, $00          // vmovdqu yword [rsp + $C0], ymm9
  add    ebx, dword [r13 - $5C]
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  add    ebx, r12d
  xor    ecx, eax
  db $C4, $E3, $5D, $0F, $FB, $08                         // vpalignr ymm7, ymm4, ymm3, $8
  add    ebp, dword [r13 - $58]
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  db $C5, $BD, $73, $DE, $04                              // vpsrldq ymm8, ymm6, $4
  xor    ebx, edx
  add    ebp, r12d
  xor    ebx, esi
  db $C5, $C5, $EF, $FB                                   // vpxor  ymm7, ymm7, ymm3
  db $C5, $3D, $EF, $C5                                   // vpxor  ymm8, ymm8, ymm5
  add    eax, dword [r13 - $54]
  lea    eax, [rax + rbx*1]
  db $C4, $C1, $45, $EF, $F8                              // vpxor  ymm7, ymm7, ymm8
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  db $C5, $BD, $72, $D7, $1F                              // vpsrld ymm8, ymm7, $1F
  xor    ebp, edx
  add    esi, dword [r13 - $40]
  lea    esi, [rsi + rbp*1]
  db $C5, $AD, $73, $FF, $0C                              // vpslldq ymm10, ymm7, $C
  db $C5, $C5, $FE, $FF                                   // vpaddd ymm7, ymm7, ymm7
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  db $C4, $C1, $35, $72, $D2, $1E                         // vpsrld ymm9, ymm10, $1E
  db $C4, $C1, $45, $EB, $F8                              // vpor   ymm7, ymm7, ymm8
  xor    eax, ebx
  add    esi, r12d
  db $C4, $C1, $2D, $72, $F2, $02                         // vpslld ymm10, ymm10, $2
  db $C4, $C1, $45, $EF, $F9                              // vpxor  ymm7, ymm7, ymm9
  xor    eax, ecx
  add    edx, dword [r13 - $3C]
  db $C4, $C1, $45, $EF, $FA                              // vpxor  ymm7, ymm7, ymm10
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  db $C4, $E3, $7B, $F0, $C6, $02                         // rorx   eax, esi, $2
  db $C4, $41, $45, $FE, $CB                              // vpaddd ymm9, ymm7, ymm11
  xor    esi, ebp
  add    edx, r12d
  xor    esi, ebx
  db $C5, $7E, $7F, $8C, $24, $E0, $00, $00, $00          // vmovdqu yword [rsp + $E0], ymm9
  add    ecx, dword [r13 - $38]
  lea    ecx, [rcx + rsi*1]
  db $C4, $63, $7B, $F0, $E2, $1B                         // rorx   r12d, edx, $1B
  db $C4, $E3, $7B, $F0, $F2, $02                         // rorx   esi, edx, $2
  xor    edx, eax
  add    ecx, r12d
  xor    edx, ebp
  add    ebx, dword [r13 - $34]
  lea    ebx, [rbx + rdx*1]
  db $C4, $63, $7B, $F0, $E1, $1B                         // rorx   r12d, ecx, $1B
  db $C4, $E3, $7B, $F0, $D1, $02                         // rorx   edx, ecx, $2
  xor    ecx, esi
  add    ebx, r12d
  xor    ecx, eax
  add    ebp, dword [r13 - $20]
  lea    ebp, [rcx + rbp*1]
  db $C4, $63, $7B, $F0, $E3, $1B                         // rorx   r12d, ebx, $1B
  db $C4, $E3, $7B, $F0, $CB, $02                         // rorx   ecx, ebx, $2
  xor    ebx, edx
  add    ebp, r12d
  xor    ebx, esi
  add    eax, dword [r13 - $1C]
  lea    eax, [rax + rbx*1]
  db $C4, $63, $7B, $F0, $E5, $1B                         // rorx   r12d, ebp, $1B
  db $C4, $E3, $7B, $F0, $DD, $02                         // rorx   ebx, ebp, $2
  xor    ebp, ecx
  add    eax, r12d
  xor    ebp, edx
  add    esi, dword [r13 - $18]
  lea    esi, [rsi + rbp*1]
  db $C4, $63, $7B, $F0, $E0, $1B                         // rorx   r12d, eax, $1B
  db $C4, $E3, $7B, $F0, $E8, $02                         // rorx   ebp, eax, $2
  xor    eax, ebx
  add    esi, r12d
  xor    eax, ecx
  add    edx, dword [r13 - $14]
  lea    edx, [rdx + rax*1]
  db $C4, $63, $7B, $F0, $E6, $1B                         // rorx   r12d, esi, $1B
  add    edx, r12d
  lea    r13, [rsp + $80]
  add    edx, dword [r8]
  add    esi, dword [r8 + $4]
  add    ebp, dword [r8 + $8]
  mov    dword [r8], edx
  add    ebx, dword [r8 + $C]
  mov    dword [r8 + $4], esi
  mov    eax, edx
  add    ecx, dword [r8 + $10]
  mov    r12d, ebp
  mov    dword [r8 + $8], ebp
  mov    edx, ebx
  mov    dword [r8 + $C], ebx
  mov    ebp, esi
  mov    dword [r8 + $10], ecx
  mov    esi, ecx
  mov    ecx, r12d
  cmp    r9, r10
  jbe @block_loop

@done:
  db $C5, $F8, $77                                        // vzeroupper
  mov    rsi, qword [r11 - $40]
  mov    rdi, qword [r11 - $38]
  mov    r14, qword [r11 - $30]
  mov    r13, qword [r11 - $28]
  mov    r12, qword [r11 - $20]
  mov    rbp, qword [r11 - $18]
  mov    rbx, qword [r11 - $10]
  lea    rsp, [r11]

  {$I ..\Include\Simd\Common\HlpSimdNonVolatileRestore_x86_64.inc}
