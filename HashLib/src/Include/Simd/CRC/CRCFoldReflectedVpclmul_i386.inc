// AVX2 + VPCLMULQDQ CRC folding + Barrett reduction for reflected (LSB-first)
// CRCs with width 8..64 (IA-32). CRC-64 uses a special Barrett path for the
// 65-bit G. Mirrors CRCFoldReflectedVpclmul_x86_64.inc; ymm0-7/xmm0-7 only,
// so the structure carries over 1:1 (all vector registers are volatile on
// IA-32 - no save/restore needed, just vzeroupper before returning).
// AVX2/VPCLMULQDQ instructions are db-encoded for broad assembler
// compatibility; every register-register byte sequence is identical to the
// verified x86_64 kernel's encoding (regs 0-7 carry no REX/VEX extension
// bits), and the memory forms are machine-assembled for the IA-32 bases.
//
// After HlpSimdProc4Begin_i386: ebx = AData, esi = ALength (>= 16),
//   edi = AState, eax = Ctx (PCRCFoldRuntimeCtx; FoldConstants at +0).
//   AState: pointer to the initial CRC (reflected) as one UInt64.
//   Ctx: [+0] Fold_4x128, [+16] Fold_1x128, [+32] Barrett,
//        [+48] Fold_8x128, [+80] CrcBits.
// Result UInt64 in edx:eax (high qword of xmm0).

  push ebp
  mov ebp, eax
  cmp esi, 128
  jb @xmm_path
  db $C4, $E2, $7D, $5A, $75, $30                 // vbroadcasti128 ymm6, [ebp + 48]
  db $C5, $FE, $6F, $03                           // vmovdqu ymm0, [ebx]
  db $C5, $FE, $6F, $4B, $20                      // vmovdqu ymm1, [ebx + 32]
  db $C5, $FE, $6F, $53, $40                      // vmovdqu ymm2, [ebx + 64]
  db $C5, $FE, $6F, $5B, $60                      // vmovdqu ymm3, [ebx + 96]
  db $C5, $FA, $7E, $27                           // vmovq xmm4, qword ptr [edi]
  db $C5, $FD, $EF, $C4                           // vpxor ymm0, ymm0, ymm4
  add ebx, 128
  sub esi, 128
  cmp esi, 128
  jb @ymm_done

@ymm_loop:
  db $C4, $E3, $7D, $44, $E6, $11                 // vpclmulqdq ymm4, ymm0, ymm6, $11
  db $C4, $E3, $7D, $44, $C6, $00                 // vpclmulqdq ymm0, ymm0, ymm6, $00
  db $C5, $FD, $EF, $C4                           // vpxor ymm0, ymm0, ymm4
  db $C5, $FE, $6F, $2B                           // vmovdqu ymm5, [ebx]
  db $C5, $FD, $EF, $C5                           // vpxor ymm0, ymm0, ymm5
  db $C4, $E3, $75, $44, $E6, $11                 // vpclmulqdq ymm4, ymm1, ymm6, $11
  db $C4, $E3, $75, $44, $CE, $00                 // vpclmulqdq ymm1, ymm1, ymm6, $00
  db $C5, $F5, $EF, $CC                           // vpxor ymm1, ymm1, ymm4
  db $C5, $FE, $6F, $6B, $20                      // vmovdqu ymm5, [ebx + 32]
  db $C5, $F5, $EF, $CD                           // vpxor ymm1, ymm1, ymm5
  db $C4, $E3, $6D, $44, $E6, $11                 // vpclmulqdq ymm4, ymm2, ymm6, $11
  db $C4, $E3, $6D, $44, $D6, $00                 // vpclmulqdq ymm2, ymm2, ymm6, $00
  db $C5, $ED, $EF, $D4                           // vpxor ymm2, ymm2, ymm4
  db $C5, $FE, $6F, $6B, $40                      // vmovdqu ymm5, [ebx + 64]
  db $C5, $ED, $EF, $D5                           // vpxor ymm2, ymm2, ymm5
  db $C4, $E3, $65, $44, $E6, $11                 // vpclmulqdq ymm4, ymm3, ymm6, $11
  db $C4, $E3, $65, $44, $DE, $00                 // vpclmulqdq ymm3, ymm3, ymm6, $00
  db $C5, $E5, $EF, $DC                           // vpxor ymm3, ymm3, ymm4
  db $C5, $FE, $6F, $6B, $60                      // vmovdqu ymm5, [ebx + 96]
  db $C5, $E5, $EF, $DD                           // vpxor ymm3, ymm3, ymm5
  add ebx, 128
  sub esi, 128
  cmp esi, 128
  jae @ymm_loop

@ymm_done:
  db $C4, $E2, $7D, $5A, $75, $00                 // vbroadcasti128 ymm6, [ebp]
  db $C4, $E3, $7D, $44, $E6, $11                 // vpclmulqdq ymm4, ymm0, ymm6, $11
  db $C4, $E3, $7D, $44, $C6, $00                 // vpclmulqdq ymm0, ymm0, ymm6, $00
  db $C5, $FD, $EF, $C4                           // vpxor ymm0, ymm0, ymm4
  db $C5, $FD, $EF, $C2                           // vpxor ymm0, ymm0, ymm2
  db $C4, $E3, $75, $44, $E6, $11                 // vpclmulqdq ymm4, ymm1, ymm6, $11
  db $C4, $E3, $75, $44, $CE, $00                 // vpclmulqdq ymm1, ymm1, ymm6, $00
  db $C5, $F5, $EF, $CC                           // vpxor ymm1, ymm1, ymm4
  db $C5, $F5, $EF, $CB                           // vpxor ymm1, ymm1, ymm3
  db $C5, $F9, $6F, $D1                           // vmovdqa xmm2, xmm1
  db $C4, $E3, $7D, $39, $CB, $01                 // vextracti128 xmm3, ymm1, 1
  db $C4, $E3, $7D, $39, $C1, $01                 // vextracti128 xmm1, ymm0, 1
  db $C5, $F8, $77                                // vzeroupper
  jmp @fold4to1

@xmm_path:
  cmp esi, 64
  jae @xmm_large
  db $C5, $FA, $6F, $03                           // vmovdqu xmm0, [ebx]
  db $C5, $FA, $7E, $27                           // vmovq xmm4, qword ptr [edi]
  db $C5, $F9, $EF, $C4                           // vpxor xmm0, xmm0, xmm4
  add ebx, 16
  sub esi, 16
  db $C5, $FA, $6F, $7D, $10                      // vmovdqu xmm7, [ebp + 16]
  jmp @tail_check

@xmm_large:
  db $C5, $FA, $6F, $03                           // vmovdqu xmm0, [ebx]
  db $C5, $FA, $6F, $4B, $10                      // vmovdqu xmm1, [ebx + 16]
  db $C5, $FA, $6F, $53, $20                      // vmovdqu xmm2, [ebx + 32]
  db $C5, $FA, $6F, $5B, $30                      // vmovdqu xmm3, [ebx + 48]
  db $C5, $FA, $7E, $27                           // vmovq xmm4, qword ptr [edi]
  db $C5, $F9, $EF, $C4                           // vpxor xmm0, xmm0, xmm4
  add ebx, 64
  sub esi, 64

@fold4to1:
  db $C5, $FA, $6F, $7D, $10                      // vmovdqu xmm7, [ebp + 16]
  db $C4, $E3, $79, $44, $E7, $11                 // vpclmulqdq xmm4, xmm0, xmm7, $11
  db $C4, $E3, $79, $44, $C7, $00                 // vpclmulqdq xmm0, xmm0, xmm7, $00
  db $C5, $F9, $EF, $C4                           // vpxor xmm0, xmm0, xmm4
  db $C5, $F9, $EF, $C1                           // vpxor xmm0, xmm0, xmm1
  db $C4, $E3, $79, $44, $E7, $11                 // vpclmulqdq xmm4, xmm0, xmm7, $11
  db $C4, $E3, $79, $44, $C7, $00                 // vpclmulqdq xmm0, xmm0, xmm7, $00
  db $C5, $F9, $EF, $C4                           // vpxor xmm0, xmm0, xmm4
  db $C5, $F9, $EF, $C2                           // vpxor xmm0, xmm0, xmm2
  db $C4, $E3, $79, $44, $E7, $11                 // vpclmulqdq xmm4, xmm0, xmm7, $11
  db $C4, $E3, $79, $44, $C7, $00                 // vpclmulqdq xmm0, xmm0, xmm7, $00
  db $C5, $F9, $EF, $C4                           // vpxor xmm0, xmm0, xmm4
  db $C5, $F9, $EF, $C3                           // vpxor xmm0, xmm0, xmm3

@tail_check:
  cmp esi, 16
  jb @tail_done

@tail_loop:
  db $C4, $E3, $79, $44, $E7, $11                 // vpclmulqdq xmm4, xmm0, xmm7, $11
  db $C4, $E3, $79, $44, $C7, $00                 // vpclmulqdq xmm0, xmm0, xmm7, $00
  db $C5, $F9, $EF, $C4                           // vpxor xmm0, xmm0, xmm4
  db $C5, $FA, $6F, $2B                           // vmovdqu xmm5, [ebx]
  db $C5, $F9, $EF, $C5                           // vpxor xmm0, xmm0, xmm5
  add ebx, 16
  sub esi, 16
  cmp esi, 16
  jae @tail_loop

@tail_done:
  db $C4, $E3, $79, $44, $CF, $10                 // vpclmulqdq xmm1, xmm0, xmm7, $10
  db $C5, $F9, $73, $D8, $08                      // vpsrldq xmm0, xmm0, 8
  db $C5, $F9, $EF, $C1                           // vpxor xmm0, xmm0, xmm1
  db $C5, $FA, $6F, $75, $20                      // vmovdqu xmm6, [ebp + 32]
  db $C4, $E3, $79, $44, $CE, $00                 // vpclmulqdq xmm1, xmm0, xmm6, $00
  cmp dword ptr [ebp + 80], 64
  je @barrett_64
  db $C4, $E3, $71, $44, $CE, $10                 // vpclmulqdq xmm1, xmm1, xmm6, $10
  db $C5, $F9, $EF, $C1                           // vpxor xmm0, xmm0, xmm1
  jmp @extract_crc

@barrett_64:
  db $C5, $F9, $6F, $D1                           // vmovdqa xmm2, xmm1
  db $C4, $E3, $71, $44, $CE, $10                 // vpclmulqdq xmm1, xmm1, xmm6, $10
  db $C5, $E9, $6C, $D2                           // vpunpcklqdq xmm2, xmm2, xmm2
  db $C5, $F9, $EF, $C1                           // vpxor xmm0, xmm0, xmm1
  db $C5, $F9, $EF, $C2                           // vpxor xmm0, xmm0, xmm2

@extract_crc:
  db $C5, $F8, $77                                // vzeroupper
  psrldq xmm0, 8
  movd eax, xmm0
  psrldq xmm0, 4
  movd edx, xmm0
  pop ebp
  pop edi
  pop esi
  pop ebx
