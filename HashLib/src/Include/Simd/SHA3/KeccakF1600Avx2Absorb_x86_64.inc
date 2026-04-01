// Keccak-f[1600] AVX2 multi-block absorb.
// Fuses data-XOR + permutation into a single loop with one gather/scatter.
// Ported from Andy Polyakov's keccak1600-avx2.pl (CRYPTOGAMS project),
// as adopted by XKCP (eXtended Keccak Code Package):
//   https://github.com/dot-asm/cryptogams/blob/master/x86_64/keccak1600-avx2.pl
//   https://github.com/XKCP/XKCP/blob/master/lib/low/KeccakP-1600/AVX2/KeccakP-1600-AVX2.s
//
// Uses "plane-per-register" technique: 25 Keccak lanes packed into 7 YMM registers.
// All VEX instructions are db-encoded for broad assembler compatibility.
//
// After SimdProc5Begin_x86_64.inc:
//   rcx = state ptr (25 x UInt64, standard layout)
//   rdx = data ptr (input bytes, little-endian UInt64 words)
//   r8d = block count
//   r9d = block size in bytes
//   r10 = constants ptr (K_KECCAK: rhotates, iotas, A_JAGGED)
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
// Stack layout (sub rsp, 424):
//   [rsp+0..223]   : jagged buffer (7 x 32 bytes)
//   [rsp+224..255]  : scratch
//   [rsp+256..415] : save xmm6-xmm15 (Windows only)
//
// Callee-saved GPRs (pushed): rbx, rbp, r12-r15, rdi, rsi (Win) / rbx, rbp, r12-r15 (Linux)
// Register allocation across absorb loop:
//   r12  = state pointer (for final scatter)
//   r13  = data pointer (advances per block)
//   r14d = block count (decremented per block)
//   r15d = block size in bytes (constant)
//   rbx  = constants pointer (constant)
//   ebp  = block size in qwords (constant)
//   rsi  = A_JAGGED base pointer (constant, Windows callee-saved)

  // ===== Prologue: save callee-saved GPRs =====
  push rbx
  push rbp
  push r12
  push r13
  push r14
  push r15
{$IFDEF MSWINDOWS}
  push rdi
  push rsi
{$ENDIF}

  sub rsp, 424

  // Save XMM6-XMM15 (Windows only)
{$IFDEF MSWINDOWS}
  db $C5, $FA, $7F, $B4, $24, $00, $01, $00, $00  // vmovdqu [rsp+256], xmm6
  db $C5, $FA, $7F, $BC, $24, $10, $01, $00, $00  // vmovdqu [rsp+272], xmm7
  db $C4, $61, $7A, $7F, $84, $24, $20, $01, $00, $00  // vmovdqu [rsp+288], xmm8
  db $C4, $61, $7A, $7F, $8C, $24, $30, $01, $00, $00  // vmovdqu [rsp+304], xmm9
  db $C4, $61, $7A, $7F, $94, $24, $40, $01, $00, $00  // vmovdqu [rsp+320], xmm10
  db $C4, $61, $7A, $7F, $9C, $24, $50, $01, $00, $00  // vmovdqu [rsp+336], xmm11
  db $C4, $61, $7A, $7F, $A4, $24, $60, $01, $00, $00  // vmovdqu [rsp+352], xmm12
  db $C4, $61, $7A, $7F, $AC, $24, $70, $01, $00, $00  // vmovdqu [rsp+368], xmm13
  db $C4, $61, $7A, $7F, $B4, $24, $80, $01, $00, $00  // vmovdqu [rsp+384], xmm14
  db $C4, $61, $7A, $7F, $BC, $24, $90, $01, $00, $00  // vmovdqu [rsp+400], xmm15
{$ENDIF}

  // Save parameters to callee-saved registers
  mov r12, rcx
  mov r13, rdx
  mov r14d, r8d
  mov r15d, r9d
  mov rbx, r10
  mov ebp, r9d
  shr ebp, 3
  lea rsi, [r10 + 1152]

  // ===== Gather: standard state [r12] -> jagged buffer [rsp] =====
  // ymm0 slot: broadcast state[0] to all 4 qwords
  mov rax, [r12]
  mov [rsp + 0], rax
  mov [rsp + 8], rax
  mov [rsp + 16], rax
  mov [rsp + 24], rax

  // ymm1 slot: state[1..4] (contiguous)
  mov rax, [r12 + 8]
  mov [rsp + 32], rax
  mov rax, [r12 + 16]
  mov [rsp + 40], rax
  mov rax, [r12 + 24]
  mov [rsp + 48], rax
  mov rax, [r12 + 32]
  mov [rsp + 56], rax

  // ymm2 slot: state[10,20,5,15]
  mov rax, [r12 + 80]
  mov [rsp + 64], rax
  mov rax, [r12 + 160]
  mov [rsp + 72], rax
  mov rax, [r12 + 40]
  mov [rsp + 80], rax
  mov rax, [r12 + 120]
  mov [rsp + 88], rax

  // ymm3 slot: state[16,7,23,14]
  mov rax, [r12 + 128]
  mov [rsp + 96], rax
  mov rax, [r12 + 56]
  mov [rsp + 104], rax
  mov rax, [r12 + 184]
  mov [rsp + 112], rax
  mov rax, [r12 + 112]
  mov [rsp + 120], rax

  // ymm4 slot: state[11,22,8,19]
  mov rax, [r12 + 88]
  mov [rsp + 128], rax
  mov rax, [r12 + 176]
  mov [rsp + 136], rax
  mov rax, [r12 + 64]
  mov [rsp + 144], rax
  mov rax, [r12 + 152]
  mov [rsp + 152], rax

  // ymm5 slot: state[21,17,13,9]
  mov rax, [r12 + 168]
  mov [rsp + 160], rax
  mov rax, [r12 + 136]
  mov [rsp + 168], rax
  mov rax, [r12 + 104]
  mov [rsp + 176], rax
  mov rax, [r12 + 72]
  mov [rsp + 184], rax

  // ymm6 slot: state[6,12,18,24]
  mov rax, [r12 + 48]
  mov [rsp + 192], rax
  mov rax, [r12 + 96]
  mov [rsp + 200], rax
  mov rax, [r12 + 144]
  mov [rsp + 208], rax
  mov rax, [r12 + 192]
  mov [rsp + 216], rax

  // Check block count
  test r14d, r14d
  jz @keccak_absorb_done

  // ===== Absorb loop =====
@keccak_absorb_loop:

  // XOR data[0..blockSizeWords-1] into jagged buffer via A_JAGGED table
  xor ecx, ecx
@keccak_absorb_xor:
  mov rax, [r13 + rcx*8]
  movsxd rdx, dword [rsi + rcx*4]
  xor [rsp + rdx], rax
  inc ecx
  cmp ecx, ebp
  jb @keccak_absorb_xor

  // Load YMM registers from jagged buffer
  db $C4, $E2, $7D, $59, $04, $24  // vpbroadcastq ymm0, [rsp+0]
  db $C5, $FE, $6F, $4C, $24, $20  // vmovdqu ymm1, [rsp+32]
  db $C5, $FE, $6F, $54, $24, $40  // vmovdqu ymm2, [rsp+64]
  db $C5, $FE, $6F, $5C, $24, $60  // vmovdqu ymm3, [rsp+96]
  db $C5, $FE, $6F, $A4, $24, $80, $00, $00, $00  // vmovdqu ymm4, [rsp+128]
  db $C5, $FE, $6F, $AC, $24, $A0, $00, $00, $00  // vmovdqu ymm5, [rsp+160]
  db $C5, $FE, $6F, $B4, $24, $C0, $00, $00, $00  // vmovdqu ymm6, [rsp+192]

  // Set up permutation constant pointers (biased by +96 for compact displacements)
  lea r8, [rbx + 96]
  lea r9, [rbx + 288]
  lea r10, [rbx + 384]

  // ===== Permutation (24 rounds) =====
  mov eax, 24
@keccak_absorb_round:
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
  jnz @keccak_absorb_round

  // Store YMM registers to jagged buffer
  db $C5, $FE, $7F, $04, $24  // vmovdqu [rsp+0], ymm0
  db $C5, $FE, $7F, $4C, $24, $20  // vmovdqu [rsp+32], ymm1
  db $C5, $FE, $7F, $54, $24, $40  // vmovdqu [rsp+64], ymm2
  db $C5, $FE, $7F, $5C, $24, $60  // vmovdqu [rsp+96], ymm3
  db $C5, $FE, $7F, $A4, $24, $80, $00, $00, $00  // vmovdqu [rsp+128], ymm4
  db $C5, $FE, $7F, $AC, $24, $A0, $00, $00, $00  // vmovdqu [rsp+160], ymm5
  db $C5, $FE, $7F, $B4, $24, $C0, $00, $00, $00  // vmovdqu [rsp+192], ymm6

  // Advance data pointer by block size
  movsxd rax, r15d
  add r13, rax

  // Decrement block count
  dec r14d
  jnz @keccak_absorb_loop

@keccak_absorb_done:
  // ===== Scatter: jagged buffer [rsp] -> standard state [r12] =====
  // state[0] from ymm0 slot qword 0
  mov rax, [rsp + 0]
  mov [r12], rax

  // state[1..4] from ymm1 slot (contiguous)
  mov rax, [rsp + 32]
  mov [r12 + 8], rax
  mov rax, [rsp + 40]
  mov [r12 + 16], rax
  mov rax, [rsp + 48]
  mov [r12 + 24], rax
  mov rax, [rsp + 56]
  mov [r12 + 32], rax

  // state[10,20,5,15] from ymm2 slot
  mov rax, [rsp + 64]
  mov [r12 + 80], rax
  mov rax, [rsp + 72]
  mov [r12 + 160], rax
  mov rax, [rsp + 80]
  mov [r12 + 40], rax
  mov rax, [rsp + 88]
  mov [r12 + 120], rax

  // state[16,7,23,14] from ymm3 slot
  mov rax, [rsp + 96]
  mov [r12 + 128], rax
  mov rax, [rsp + 104]
  mov [r12 + 56], rax
  mov rax, [rsp + 112]
  mov [r12 + 184], rax
  mov rax, [rsp + 120]
  mov [r12 + 112], rax

  // state[11,22,8,19] from ymm4 slot
  mov rax, [rsp + 128]
  mov [r12 + 88], rax
  mov rax, [rsp + 136]
  mov [r12 + 176], rax
  mov rax, [rsp + 144]
  mov [r12 + 64], rax
  mov rax, [rsp + 152]
  mov [r12 + 152], rax

  // state[21,17,13,9] from ymm5 slot
  mov rax, [rsp + 160]
  mov [r12 + 168], rax
  mov rax, [rsp + 168]
  mov [r12 + 136], rax
  mov rax, [rsp + 176]
  mov [r12 + 104], rax
  mov rax, [rsp + 184]
  mov [r12 + 72], rax

  // state[6,12,18,24] from ymm6 slot
  mov rax, [rsp + 192]
  mov [r12 + 48], rax
  mov rax, [rsp + 200]
  mov [r12 + 96], rax
  mov rax, [rsp + 208]
  mov [r12 + 144], rax
  mov rax, [rsp + 216]
  mov [r12 + 192], rax


  // ===== Epilogue =====
  db $C5, $F8, $77  // vzeroupper

  // Restore XMM6-XMM15 (Windows only)
{$IFDEF MSWINDOWS}
  db $C5, $FA, $6F, $B4, $24, $00, $01, $00, $00  // vmovdqu xmm6, [rsp+256]
  db $C5, $FA, $6F, $BC, $24, $10, $01, $00, $00  // vmovdqu xmm7, [rsp+272]
  db $C4, $61, $7A, $6F, $84, $24, $20, $01, $00, $00  // vmovdqu xmm8, [rsp+288]
  db $C4, $61, $7A, $6F, $8C, $24, $30, $01, $00, $00  // vmovdqu xmm9, [rsp+304]
  db $C4, $61, $7A, $6F, $94, $24, $40, $01, $00, $00  // vmovdqu xmm10, [rsp+320]
  db $C4, $61, $7A, $6F, $9C, $24, $50, $01, $00, $00  // vmovdqu xmm11, [rsp+336]
  db $C4, $61, $7A, $6F, $A4, $24, $60, $01, $00, $00  // vmovdqu xmm12, [rsp+352]
  db $C4, $61, $7A, $6F, $AC, $24, $70, $01, $00, $00  // vmovdqu xmm13, [rsp+368]
  db $C4, $61, $7A, $6F, $B4, $24, $80, $01, $00, $00  // vmovdqu xmm14, [rsp+384]
  db $C4, $61, $7A, $6F, $BC, $24, $90, $01, $00, $00  // vmovdqu xmm15, [rsp+400]
{$ENDIF}

  add rsp, 424

{$IFDEF MSWINDOWS}
  pop rsi
  pop rdi
{$ENDIF}
  pop r15
  pop r14
  pop r13
  pop r12
  pop rbp
  pop rbx
