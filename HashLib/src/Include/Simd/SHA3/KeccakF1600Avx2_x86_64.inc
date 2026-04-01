// Keccak-f[1600] AVX2 permutation.
// Ported from Andy Polyakov's keccak1600-avx2.pl (CRYPTOGAMS project),
// as adopted by XKCP (eXtended Keccak Code Package):
//   https://github.com/dot-asm/cryptogams/blob/master/x86_64/keccak1600-avx2.pl
//   https://github.com/XKCP/XKCP/blob/master/lib/low/KeccakP-1600/AVX2/KeccakP-1600-AVX2.s
// Uses "plane-per-register" technique: 25 Keccak lanes packed into 7 YMM registers.
// All VEX instructions are db-encoded for broad assembler compatibility.
// Expects MS x64 ABI: rcx = state ptr (25 x UInt64, standard layout),
//   rdx = constants ptr (rhotates_left[24], rhotates_right[24], iotas[96]).
//
// YMM register mapping (after gather):
//   ymm0 = broadcast(state[0])
//   ymm1 = { state[1],  state[2],  state[3],  state[4]  }
//   ymm2 = { state[10], state[20], state[5],  state[15] }
//   ymm3 = { state[16], state[7],  state[23], state[14] }
//   ymm4 = { state[11], state[22], state[8],  state[19] }
//   ymm5 = { state[21], state[17], state[13], state[9]  }
//   ymm6 = { state[6],  state[12], state[18], state[24] }
//
// Stack layout (sub rsp, 224):
//   [rsp+0..31]   : 32-byte temp buffer for gather/scatter
//   [rsp+32..191] : save xmm6-xmm15 (Windows only)
//   [rsp+192..223]: padding

  sub rsp, 224

{$IFDEF MSWINDOWS}
  db $C5, $FA, $7F, $74, $24, $20  // vmovdqu [rsp+32], xmm6
  db $C5, $FA, $7F, $7C, $24, $30  // vmovdqu [rsp+48], xmm7
  db $C4, $61, $7A, $7F, $44, $24, $40  // vmovdqu [rsp+64], xmm8
  db $C4, $61, $7A, $7F, $4C, $24, $50  // vmovdqu [rsp+80], xmm9
  db $C4, $61, $7A, $7F, $54, $24, $60  // vmovdqu [rsp+96], xmm10
  db $C4, $61, $7A, $7F, $5C, $24, $70  // vmovdqu [rsp+112], xmm11
  db $C4, $61, $7A, $7F, $A4, $24, $80, $00, $00, $00  // vmovdqu [rsp+128], xmm12
  db $C4, $61, $7A, $7F, $AC, $24, $90, $00, $00, $00  // vmovdqu [rsp+144], xmm13
  db $C4, $61, $7A, $7F, $B4, $24, $A0, $00, $00, $00  // vmovdqu [rsp+160], xmm14
  db $C4, $61, $7A, $7F, $BC, $24, $B0, $00, $00, $00  // vmovdqu [rsp+176], xmm15
{$ENDIF}

  // Set up table pointers (biased by +96 for compact displacements)
  lea r8, [rdx + 96]
  lea r9, [rdx + 288]
  lea r10, [rdx + 384]

  // ===== Gather: standard state -> YMM registers =====
  db $C4, $E2, $7D, $59, $01  // vpbroadcastq ymm0, [rcx]
  db $C5, $FE, $6F, $49, $08  // vmovdqu ymm1, [rcx+8]
  mov rax, [rcx + 80]
  mov [rsp + 0], rax
  mov rax, [rcx + 160]
  mov [rsp + 8], rax
  mov rax, [rcx + 40]
  mov [rsp + 16], rax
  mov rax, [rcx + 120]
  mov [rsp + 24], rax
  db $C5, $FE, $6F, $14, $24  // vmovdqu ymm2, [rsp]
  mov rax, [rcx + 128]
  mov [rsp + 0], rax
  mov rax, [rcx + 56]
  mov [rsp + 8], rax
  mov rax, [rcx + 184]
  mov [rsp + 16], rax
  mov rax, [rcx + 112]
  mov [rsp + 24], rax
  db $C5, $FE, $6F, $1C, $24  // vmovdqu ymm3, [rsp]
  mov rax, [rcx + 88]
  mov [rsp + 0], rax
  mov rax, [rcx + 176]
  mov [rsp + 8], rax
  mov rax, [rcx + 64]
  mov [rsp + 16], rax
  mov rax, [rcx + 152]
  mov [rsp + 24], rax
  db $C5, $FE, $6F, $24, $24  // vmovdqu ymm4, [rsp]
  mov rax, [rcx + 168]
  mov [rsp + 0], rax
  mov rax, [rcx + 136]
  mov [rsp + 8], rax
  mov rax, [rcx + 104]
  mov [rsp + 16], rax
  mov rax, [rcx + 72]
  mov [rsp + 24], rax
  db $C5, $FE, $6F, $2C, $24  // vmovdqu ymm5, [rsp]
  mov rax, [rcx + 48]
  mov [rsp + 0], rax
  mov rax, [rcx + 96]
  mov [rsp + 8], rax
  mov rax, [rcx + 144]
  mov [rsp + 16], rax
  mov rax, [rcx + 192]
  mov [rsp + 24], rax
  db $C5, $FE, $6F, $34, $24  // vmovdqu ymm6, [rsp]

  // ===== Permutation loop (24 rounds) =====
  mov eax, 24
@keccak_avx2_loop:
  // Theta
  db $C4, $61, $7D, $70, $EA, $4E  // vpshufd ymm13, ymm2, $4E
  db $C4, $61, $55, $EF, $E3  // vpxor ymm12, ymm5, ymm3
  db $C4, $61, $5D, $EF, $CE  // vpxor ymm9, ymm4, ymm6
  db $C4, $61, $1D, $EF, $E1  // vpxor ymm12, ymm12, ymm1
  db $C4, $41, $1D, $EF, $E1  // vpxor ymm12, ymm12, ymm9

  db $C4, $43, $FD, $00, $DC, $93  // vpermq ymm11, ymm12, $93
  db $C4, $61, $15, $EF, $EA  // vpxor ymm13, ymm13, ymm2
  db $C4, $C3, $FD, $00, $FD, $4E  // vpermq ymm7, ymm13, $4E

  db $C4, $C1, $3D, $73, $D4, $3F  // vpsrlq ymm8, ymm12, $3F
  db $C4, $41, $1D, $D4, $CC  // vpaddq ymm9, ymm12, ymm12
  db $C4, $41, $3D, $EB, $C1  // vpor ymm8, ymm8, ymm9

  db $C4, $43, $FD, $00, $F8, $39  // vpermq ymm15, ymm8, $39
  db $C4, $41, $3D, $EF, $F3  // vpxor ymm14, ymm8, ymm11
  db $C4, $43, $FD, $00, $F6, $00  // vpermq ymm14, ymm14, $00

  db $C4, $61, $15, $EF, $E8  // vpxor ymm13, ymm13, ymm0
  db $C4, $61, $15, $EF, $EF  // vpxor ymm13, ymm13, ymm7

  db $C4, $C1, $45, $73, $D5, $3F  // vpsrlq ymm7, ymm13, $3F
  db $C4, $41, $15, $D4, $C5  // vpaddq ymm8, ymm13, ymm13
  db $C4, $41, $45, $EB, $C0  // vpor ymm8, ymm7, ymm8

  db $C4, $C1, $6D, $EF, $D6  // vpxor ymm2, ymm2, ymm14
  db $C4, $C1, $7D, $EF, $C6  // vpxor ymm0, ymm0, ymm14

  db $C4, $43, $05, $02, $F8, $C0  // vpblendd ymm15, ymm15, ymm8, $C0
  db $C4, $43, $25, $02, $DD, $03  // vpblendd ymm11, ymm11, ymm13, $03
  db $C4, $41, $05, $EF, $FB  // vpxor ymm15, ymm15, ymm11

  // Rho + Pi + pre-Chi shuffle
  db $C4, $42, $ED, $47, $50, $A0  // vpsllvq ymm10, ymm2, [r8-96]
  db $C4, $C2, $ED, $45, $51, $A0  // vpsrlvq ymm2, ymm2, [r9-96]
  db $C5, $AD, $EB, $D2  // vpor ymm2, ymm10, ymm2

  db $C4, $C1, $65, $EF, $DF  // vpxor ymm3, ymm3, ymm15
  db $C4, $42, $E5, $47, $58, $E0  // vpsllvq ymm11, ymm3, [r8-32]
  db $C4, $C2, $E5, $45, $59, $E0  // vpsrlvq ymm3, ymm3, [r9-32]
  db $C5, $A5, $EB, $DB  // vpor ymm3, ymm11, ymm3

  db $C4, $C1, $5D, $EF, $E7  // vpxor ymm4, ymm4, ymm15
  db $C4, $42, $DD, $47, $20  // vpsllvq ymm12, ymm4, [r8]
  db $C4, $C2, $DD, $45, $21  // vpsrlvq ymm4, ymm4, [r9]
  db $C5, $9D, $EB, $E4  // vpor ymm4, ymm12, ymm4

  db $C4, $C1, $55, $EF, $EF  // vpxor ymm5, ymm5, ymm15
  db $C4, $42, $D5, $47, $68, $20  // vpsllvq ymm13, ymm5, [r8+32]
  db $C4, $C2, $D5, $45, $69, $20  // vpsrlvq ymm5, ymm5, [r9+32]
  db $C5, $95, $EB, $ED  // vpor ymm5, ymm13, ymm5

  db $C4, $C1, $4D, $EF, $F7  // vpxor ymm6, ymm6, ymm15
  db $C4, $63, $FD, $00, $D2, $8D  // vpermq ymm10, ymm2, $8D
  db $C4, $63, $FD, $00, $DB, $8D  // vpermq ymm11, ymm3, $8D
  db $C4, $42, $CD, $47, $70, $40  // vpsllvq ymm14, ymm6, [r8+64]
  db $C4, $42, $CD, $45, $41, $40  // vpsrlvq ymm8, ymm6, [r9+64]
  db $C4, $41, $0D, $EB, $C0  // vpor ymm8, ymm14, ymm8

  db $C4, $C1, $75, $EF, $CF  // vpxor ymm1, ymm1, ymm15
  db $C4, $63, $FD, $00, $E4, $1B  // vpermq ymm12, ymm4, $1B
  db $C4, $63, $FD, $00, $ED, $72  // vpermq ymm13, ymm5, $72
  db $C4, $42, $F5, $47, $78, $C0  // vpsllvq ymm15, ymm1, [r8-64]
  db $C4, $42, $F5, $45, $49, $C0  // vpsrlvq ymm9, ymm1, [r9-64]
  db $C4, $41, $05, $EB, $C9  // vpor ymm9, ymm15, ymm9

  // Chi
  db $C4, $C1, $0D, $73, $D8, $08  // vpsrldq ymm14, ymm8, $08
  db $C4, $C1, $3D, $DF, $FE  // vpandn ymm7, ymm8, ymm14

  db $C4, $C3, $35, $02, $DD, $0C  // vpblendd ymm3, ymm9, ymm13, $0C
  db $C4, $43, $25, $02, $F9, $0C  // vpblendd ymm15, ymm11, ymm9, $0C
  db $C4, $C3, $2D, $02, $EB, $0C  // vpblendd ymm5, ymm10, ymm11, $0C
  db $C4, $43, $35, $02, $F2, $0C  // vpblendd ymm14, ymm9, ymm10, $0C
  db $C4, $C3, $65, $02, $DB, $30  // vpblendd ymm3, ymm3, ymm11, $30
  db $C4, $43, $05, $02, $FC, $30  // vpblendd ymm15, ymm15, ymm12, $30
  db $C4, $C3, $55, $02, $E9, $30  // vpblendd ymm5, ymm5, ymm9, $30
  db $C4, $43, $0D, $02, $F5, $30  // vpblendd ymm14, ymm14, ymm13, $30
  db $C4, $C3, $65, $02, $DC, $C0  // vpblendd ymm3, ymm3, ymm12, $C0
  db $C4, $43, $05, $02, $FD, $C0  // vpblendd ymm15, ymm15, ymm13, $C0
  db $C4, $C3, $55, $02, $ED, $C0  // vpblendd ymm5, ymm5, ymm13, $C0
  db $C4, $43, $0D, $02, $F3, $C0  // vpblendd ymm14, ymm14, ymm11, $C0
  db $C4, $C1, $65, $DF, $DF  // vpandn ymm3, ymm3, ymm15
  db $C4, $C1, $55, $DF, $EE  // vpandn ymm5, ymm5, ymm14

  db $C4, $C3, $1D, $02, $F1, $0C  // vpblendd ymm6, ymm12, ymm9, $0C
  db $C4, $43, $2D, $02, $FC, $0C  // vpblendd ymm15, ymm10, ymm12, $0C
  db $C4, $C1, $65, $EF, $DA  // vpxor ymm3, ymm3, ymm10
  db $C4, $C3, $4D, $02, $F2, $30  // vpblendd ymm6, ymm6, ymm10, $30
  db $C4, $43, $05, $02, $FB, $30  // vpblendd ymm15, ymm15, ymm11, $30
  db $C4, $C1, $55, $EF, $EC  // vpxor ymm5, ymm5, ymm12
  db $C4, $C3, $4D, $02, $F3, $C0  // vpblendd ymm6, ymm6, ymm11, $C0
  db $C4, $43, $05, $02, $F9, $C0  // vpblendd ymm15, ymm15, ymm9, $C0
  db $C4, $C1, $4D, $DF, $F7  // vpandn ymm6, ymm6, ymm15
  db $C4, $C1, $4D, $EF, $F5  // vpxor ymm6, ymm6, ymm13

  db $C4, $C3, $FD, $00, $E0, $1E  // vpermq ymm4, ymm8, $1E
  db $C4, $63, $5D, $02, $F8, $30  // vpblendd ymm15, ymm4, ymm0, $30
  db $C4, $C3, $FD, $00, $C8, $39  // vpermq ymm1, ymm8, $39
  db $C4, $E3, $75, $02, $C8, $C0  // vpblendd ymm1, ymm1, ymm0, $C0
  db $C4, $C1, $75, $DF, $CF  // vpandn ymm1, ymm1, ymm15

  db $C4, $C3, $25, $02, $D4, $0C  // vpblendd ymm2, ymm11, ymm12, $0C
  db $C4, $43, $15, $02, $F3, $0C  // vpblendd ymm14, ymm13, ymm11, $0C
  db $C4, $C3, $6D, $02, $D5, $30  // vpblendd ymm2, ymm2, ymm13, $30
  db $C4, $43, $0D, $02, $F2, $30  // vpblendd ymm14, ymm14, ymm10, $30
  db $C4, $C3, $6D, $02, $D2, $C0  // vpblendd ymm2, ymm2, ymm10, $C0
  db $C4, $43, $0D, $02, $F4, $C0  // vpblendd ymm14, ymm14, ymm12, $C0
  db $C4, $C1, $6D, $DF, $D6  // vpandn ymm2, ymm2, ymm14
  db $C4, $C1, $6D, $EF, $D1  // vpxor ymm2, ymm2, ymm9

  db $C4, $E3, $FD, $00, $FF, $00  // vpermq ymm7, ymm7, $00
  db $C4, $E3, $FD, $00, $DB, $1B  // vpermq ymm3, ymm3, $1B
  db $C4, $E3, $FD, $00, $ED, $8D  // vpermq ymm5, ymm5, $8D
  db $C4, $E3, $FD, $00, $F6, $72  // vpermq ymm6, ymm6, $72

  db $C4, $C3, $15, $02, $E2, $0C  // vpblendd ymm4, ymm13, ymm10, $0C
  db $C4, $43, $1D, $02, $F5, $0C  // vpblendd ymm14, ymm12, ymm13, $0C
  db $C4, $C3, $5D, $02, $E4, $30  // vpblendd ymm4, ymm4, ymm12, $30
  db $C4, $43, $0D, $02, $F1, $30  // vpblendd ymm14, ymm14, ymm9, $30
  db $C4, $C3, $5D, $02, $E1, $C0  // vpblendd ymm4, ymm4, ymm9, $C0
  db $C4, $43, $0D, $02, $F2, $C0  // vpblendd ymm14, ymm14, ymm10, $C0
  db $C4, $C1, $5D, $DF, $E6  // vpandn ymm4, ymm4, ymm14

  db $C5, $FD, $EF, $C7  // vpxor ymm0, ymm0, ymm7
  db $C4, $C1, $75, $EF, $C8  // vpxor ymm1, ymm1, ymm8
  db $C4, $C1, $5D, $EF, $E3  // vpxor ymm4, ymm4, ymm11

  // Iota
  db $C4, $C1, $7D, $EF, $02  // vpxor ymm0, ymm0, [r10]
  lea r10, [r10 + 32]

  dec eax
  jnz @keccak_avx2_loop

  // ===== Scatter: YMM registers -> standard state =====
  db $C5, $F9, $D6, $01  // vmovq [rcx], xmm0
  db $C5, $FE, $7F, $49, $08  // vmovdqu [rcx+8], ymm1
  db $C5, $FE, $7F, $14, $24  // vmovdqu [rsp], ymm2
  mov rax, [rsp + 0]
  mov [rcx + 80], rax
  mov rax, [rsp + 8]
  mov [rcx + 160], rax
  mov rax, [rsp + 16]
  mov [rcx + 40], rax
  mov rax, [rsp + 24]
  mov [rcx + 120], rax
  db $C5, $FE, $7F, $1C, $24  // vmovdqu [rsp], ymm3
  mov rax, [rsp + 0]
  mov [rcx + 128], rax
  mov rax, [rsp + 8]
  mov [rcx + 56], rax
  mov rax, [rsp + 16]
  mov [rcx + 184], rax
  mov rax, [rsp + 24]
  mov [rcx + 112], rax
  db $C5, $FE, $7F, $24, $24  // vmovdqu [rsp], ymm4
  mov rax, [rsp + 0]
  mov [rcx + 88], rax
  mov rax, [rsp + 8]
  mov [rcx + 176], rax
  mov rax, [rsp + 16]
  mov [rcx + 64], rax
  mov rax, [rsp + 24]
  mov [rcx + 152], rax
  db $C5, $FE, $7F, $2C, $24  // vmovdqu [rsp], ymm5
  mov rax, [rsp + 0]
  mov [rcx + 168], rax
  mov rax, [rsp + 8]
  mov [rcx + 136], rax
  mov rax, [rsp + 16]
  mov [rcx + 104], rax
  mov rax, [rsp + 24]
  mov [rcx + 72], rax
  db $C5, $FE, $7F, $34, $24  // vmovdqu [rsp], ymm6
  mov rax, [rsp + 0]
  mov [rcx + 48], rax
  mov rax, [rsp + 8]
  mov [rcx + 96], rax
  mov rax, [rsp + 16]
  mov [rcx + 144], rax
  mov rax, [rsp + 24]
  mov [rcx + 192], rax

  db $C5, $F8, $77  // vzeroupper

{$IFDEF MSWINDOWS}
  db $C5, $FA, $6F, $74, $24, $20  // vmovdqu xmm6, [rsp+32]
  db $C5, $FA, $6F, $7C, $24, $30  // vmovdqu xmm7, [rsp+48]
  db $C4, $61, $7A, $6F, $44, $24, $40  // vmovdqu xmm8, [rsp+64]
  db $C4, $61, $7A, $6F, $4C, $24, $50  // vmovdqu xmm9, [rsp+80]
  db $C4, $61, $7A, $6F, $54, $24, $60  // vmovdqu xmm10, [rsp+96]
  db $C4, $61, $7A, $6F, $5C, $24, $70  // vmovdqu xmm11, [rsp+112]
  db $C4, $61, $7A, $6F, $A4, $24, $80, $00, $00, $00  // vmovdqu xmm12, [rsp+128]
  db $C4, $61, $7A, $6F, $AC, $24, $90, $00, $00, $00  // vmovdqu xmm13, [rsp+144]
  db $C4, $61, $7A, $6F, $B4, $24, $A0, $00, $00, $00  // vmovdqu xmm14, [rsp+160]
  db $C4, $61, $7A, $6F, $BC, $24, $B0, $00, $00, $00  // vmovdqu xmm15, [rsp+176]
{$ENDIF}

  add rsp, 224
