// SHA-1 SHA-NI implementation.
// Expects MS x64 ABI: rcx = state ptr, rdx = data ptr, r8d = numblocks, r9 = K_SHA1 ptr.
// K_SHA1 layout: K_00_19 at 0, K_20_39 at 16, K_40_59 at 32,
//   K_60_79 at 48, BSWAP32 mask (16 bytes) at offset 64.
// Uses xmm0-xmm8. Non-volatile xmm6-xmm8 saved/restored on Windows.
// Reference: Intel SHA Extensions whitepaper.
//
// SHA-NI instruction db encodings (for assembler compatibility):
//   sha1rnds4  dst, src, imm  = $0F $3A $CC <ModRM> <imm8>
//   sha1nexte  dst, src       = $0F $38 $C8 <ModRM>
//   sha1msg1   dst, src       = $0F $38 $C9 <ModRM>
//   sha1msg2   dst, src       = $0F $38 $CA <ModRM>
//
// Register map:
//   xmm0  = ABCD state (SHA-NI format: A at [127:96], D at [31:0])
//   xmm1  = E0 (ping-pong E register, even groups)
//   xmm2  = E1 (ping-pong E register, odd groups)
//   xmm3  = MSG0 (W[0..3] / W[16..19] / ...)
//   xmm4  = MSG1 (W[4..7] / W[20..23] / ...)
//   xmm5  = MSG2 (W[8..11] / W[24..27] / ...)
//   xmm6  = MSG3 (W[12..15] / W[28..31] / ...)
//   xmm7  = BSWAP mask, then E_SAVE
//   xmm8  = ABCD_SAVE

{$IFDEF MSWINDOWS}
  sub rsp, 56
  movdqu oword [rsp], xmm6
  movdqu oword [rsp + $10], xmm7
  movdqu oword [rsp + $20], xmm8
{$ENDIF}

  test r8d, r8d
  jz @sha1ni_done

  // Load state and convert to SHA-NI register format
  movdqu xmm0, oword [rcx]         // xmm0 = [A,B,C,D] memory order
  pshufd xmm0, xmm0, $1B           // xmm0 = [D,C,B,A] -> SHA-NI ABCD format
  movd   xmm1, [rcx + 16]          // xmm1[31:0] = E
  pslldq xmm1, 12                  // xmm1[127:96] = E, rest zero

@sha1ni_block_loop:

  // Save state for final addition
  movdqa xmm8, xmm0                // ABCD_SAVE

  // Load, byte-swap, and reverse dword order for all 4 message blocks.
  // The per-dword BSWAP mask puts W[0] at [31:0], but sha1rnds4 reads
  // W[0] from [127:96]. The pshufd $1B reverses the dword order.
  movdqu xmm7, oword [r9 + $40]    // BSWAP mask at offset 64
  movdqu xmm3, oword [rdx]
  pshufb xmm3, xmm7
  pshufd xmm3, xmm3, $1B
  movdqu xmm4, oword [rdx + $10]
  pshufb xmm4, xmm7
  pshufd xmm4, xmm4, $1B
  movdqu xmm5, oword [rdx + $20]
  pshufb xmm5, xmm7
  pshufd xmm5, xmm5, $1B
  movdqu xmm6, oword [rdx + $30]
  pshufb xmm6, xmm7
  pshufd xmm6, xmm6, $1B

  // Save E for final addition (reuse xmm7)
  movdqa xmm7, xmm1                // E_SAVE

  // ===== Rounds 0-3 (Group 0): imm=0 (Ch), consume MSG0 =====
  paddd  xmm1, xmm3                // E0 = [E+W0, W1, W2, W3]
  movdqa xmm2, xmm0                // Save ABCD into E1
  db $0F, $3A, $CC, $C1, $00       // sha1rnds4 xmm0, xmm1, 0

  // ===== Rounds 4-7 (Group 1): imm=0, consume MSG1 =====
  db $0F, $38, $C8, $D4            // sha1nexte xmm2, xmm4
  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $00       // sha1rnds4 xmm0, xmm2, 0
  db $0F, $38, $C9, $DC            // sha1msg1 xmm3, xmm4

  // ===== Rounds 8-11 (Group 2): imm=0, consume MSG2 =====
  db $0F, $38, $C8, $CD            // sha1nexte xmm1, xmm5
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $00       // sha1rnds4 xmm0, xmm1, 0
  db $0F, $38, $C9, $E5            // sha1msg1 xmm4, xmm5
  pxor   xmm3, xmm5

  // ===== Rounds 12-15 (Group 3): imm=0, consume MSG3 =====
  db $0F, $38, $C8, $D6            // sha1nexte xmm2, xmm6
  movdqa xmm1, xmm0
  db $0F, $38, $CA, $DE            // sha1msg2 xmm3, xmm6
  db $0F, $3A, $CC, $C2, $00       // sha1rnds4 xmm0, xmm2, 0
  db $0F, $38, $C9, $EE            // sha1msg1 xmm5, xmm6
  pxor   xmm4, xmm6

  // ===== Rounds 16-19 (Group 4): imm=0, consume MSG0 =====
  db $0F, $38, $C8, $CB            // sha1nexte xmm1, xmm3
  movdqa xmm2, xmm0
  db $0F, $38, $CA, $E3            // sha1msg2 xmm4, xmm3
  db $0F, $3A, $CC, $C1, $00       // sha1rnds4 xmm0, xmm1, 0
  db $0F, $38, $C9, $F3            // sha1msg1 xmm6, xmm3
  pxor   xmm5, xmm3

  // ===== Rounds 20-23 (Group 5): imm=1 (Parity), consume MSG1 =====
  db $0F, $38, $C8, $D4            // sha1nexte xmm2, xmm4
  movdqa xmm1, xmm0
  db $0F, $38, $CA, $EC            // sha1msg2 xmm5, xmm4
  db $0F, $3A, $CC, $C2, $01       // sha1rnds4 xmm0, xmm2, 1
  db $0F, $38, $C9, $DC            // sha1msg1 xmm3, xmm4
  pxor   xmm6, xmm4

  // ===== Rounds 24-27 (Group 6): imm=1, consume MSG2 =====
  db $0F, $38, $C8, $CD            // sha1nexte xmm1, xmm5
  movdqa xmm2, xmm0
  db $0F, $38, $CA, $F5            // sha1msg2 xmm6, xmm5
  db $0F, $3A, $CC, $C1, $01       // sha1rnds4 xmm0, xmm1, 1
  db $0F, $38, $C9, $E5            // sha1msg1 xmm4, xmm5
  pxor   xmm3, xmm5

  // ===== Rounds 28-31 (Group 7): imm=1, consume MSG3 =====
  db $0F, $38, $C8, $D6            // sha1nexte xmm2, xmm6
  movdqa xmm1, xmm0
  db $0F, $38, $CA, $DE            // sha1msg2 xmm3, xmm6
  db $0F, $3A, $CC, $C2, $01       // sha1rnds4 xmm0, xmm2, 1
  db $0F, $38, $C9, $EE            // sha1msg1 xmm5, xmm6
  pxor   xmm4, xmm6

  // ===== Rounds 32-35 (Group 8): imm=1, consume MSG0 =====
  db $0F, $38, $C8, $CB            // sha1nexte xmm1, xmm3
  movdqa xmm2, xmm0
  db $0F, $38, $CA, $E3            // sha1msg2 xmm4, xmm3
  db $0F, $3A, $CC, $C1, $01       // sha1rnds4 xmm0, xmm1, 1
  db $0F, $38, $C9, $F3            // sha1msg1 xmm6, xmm3
  pxor   xmm5, xmm3

  // ===== Rounds 36-39 (Group 9): imm=1, consume MSG1 =====
  db $0F, $38, $C8, $D4            // sha1nexte xmm2, xmm4
  movdqa xmm1, xmm0
  db $0F, $38, $CA, $EC            // sha1msg2 xmm5, xmm4
  db $0F, $3A, $CC, $C2, $01       // sha1rnds4 xmm0, xmm2, 1
  db $0F, $38, $C9, $DC            // sha1msg1 xmm3, xmm4
  pxor   xmm6, xmm4

  // ===== Rounds 40-43 (Group 10): imm=2 (Maj), consume MSG2 =====
  db $0F, $38, $C8, $CD            // sha1nexte xmm1, xmm5
  movdqa xmm2, xmm0
  db $0F, $38, $CA, $F5            // sha1msg2 xmm6, xmm5
  db $0F, $3A, $CC, $C1, $02       // sha1rnds4 xmm0, xmm1, 2
  db $0F, $38, $C9, $E5            // sha1msg1 xmm4, xmm5
  pxor   xmm3, xmm5

  // ===== Rounds 44-47 (Group 11): imm=2, consume MSG3 =====
  db $0F, $38, $C8, $D6            // sha1nexte xmm2, xmm6
  movdqa xmm1, xmm0
  db $0F, $38, $CA, $DE            // sha1msg2 xmm3, xmm6
  db $0F, $3A, $CC, $C2, $02       // sha1rnds4 xmm0, xmm2, 2
  db $0F, $38, $C9, $EE            // sha1msg1 xmm5, xmm6
  pxor   xmm4, xmm6

  // ===== Rounds 48-51 (Group 12): imm=2, consume MSG0 =====
  db $0F, $38, $C8, $CB            // sha1nexte xmm1, xmm3
  movdqa xmm2, xmm0
  db $0F, $38, $CA, $E3            // sha1msg2 xmm4, xmm3
  db $0F, $3A, $CC, $C1, $02       // sha1rnds4 xmm0, xmm1, 2
  db $0F, $38, $C9, $F3            // sha1msg1 xmm6, xmm3
  pxor   xmm5, xmm3

  // ===== Rounds 52-55 (Group 13): imm=2, consume MSG1 =====
  db $0F, $38, $C8, $D4            // sha1nexte xmm2, xmm4
  movdqa xmm1, xmm0
  db $0F, $38, $CA, $EC            // sha1msg2 xmm5, xmm4
  db $0F, $3A, $CC, $C2, $02       // sha1rnds4 xmm0, xmm2, 2
  db $0F, $38, $C9, $DC            // sha1msg1 xmm3, xmm4
  pxor   xmm6, xmm4

  // ===== Rounds 56-59 (Group 14): imm=2, consume MSG2 =====
  db $0F, $38, $C8, $CD            // sha1nexte xmm1, xmm5
  movdqa xmm2, xmm0
  db $0F, $38, $CA, $F5            // sha1msg2 xmm6, xmm5
  db $0F, $3A, $CC, $C1, $02       // sha1rnds4 xmm0, xmm1, 2
  db $0F, $38, $C9, $E5            // sha1msg1 xmm4, xmm5
  pxor   xmm3, xmm5

  // ===== Rounds 60-63 (Group 15): imm=3 (Parity), consume MSG3 =====
  db $0F, $38, $C8, $D6            // sha1nexte xmm2, xmm6
  movdqa xmm1, xmm0
  db $0F, $38, $CA, $DE            // sha1msg2 xmm3, xmm6
  db $0F, $3A, $CC, $C2, $03       // sha1rnds4 xmm0, xmm2, 3
  db $0F, $38, $C9, $EE            // sha1msg1 xmm5, xmm6
  pxor   xmm4, xmm6

  // ===== Rounds 64-67 (Group 16): imm=3, consume MSG0 =====
  db $0F, $38, $C8, $CB            // sha1nexte xmm1, xmm3
  movdqa xmm2, xmm0
  db $0F, $38, $CA, $E3            // sha1msg2 xmm4, xmm3
  db $0F, $3A, $CC, $C1, $03       // sha1rnds4 xmm0, xmm1, 3
  db $0F, $38, $C9, $F3            // sha1msg1 xmm6, xmm3
  pxor   xmm5, xmm3

  // ===== Rounds 68-71 (Group 17): imm=3, consume MSG1 =====
  db $0F, $38, $C8, $D4            // sha1nexte xmm2, xmm4
  movdqa xmm1, xmm0
  db $0F, $38, $CA, $EC            // sha1msg2 xmm5, xmm4
  db $0F, $3A, $CC, $C2, $03       // sha1rnds4 xmm0, xmm2, 3
  pxor   xmm6, xmm4

  // ===== Rounds 72-75 (Group 18): imm=3, consume MSG2 =====
  db $0F, $38, $C8, $CD            // sha1nexte xmm1, xmm5
  movdqa xmm2, xmm0
  db $0F, $38, $CA, $F5            // sha1msg2 xmm6, xmm5
  db $0F, $3A, $CC, $C1, $03       // sha1rnds4 xmm0, xmm1, 3

  // ===== Rounds 76-79 (Group 19): imm=3, consume MSG3 =====
  db $0F, $38, $C8, $D6            // sha1nexte xmm2, xmm6
  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $03       // sha1rnds4 xmm0, xmm2, 3

  // Finalize E: compute E_new = ROL30(A_before_last_rnds4) + E_SAVE
  db $0F, $38, $C8, $CF            // sha1nexte xmm1, xmm7

  // Add saved state back
  paddd  xmm0, xmm8                // ABCD += ABCD_SAVE

  // Advance data pointer and loop
  add rdx, 64
  dec r8d
  jnz @sha1ni_block_loop

  // Convert state back to memory format
  pshufd xmm0, xmm0, $1B           // Reverse to [A,B,C,D] memory order
  movdqu oword [rcx], xmm0         // Store H0-H3
  psrldq xmm1, 12                  // Move E from [127:96] to [31:0]
  movd   [rcx + 16], xmm1          // Store H4

@sha1ni_done:

{$IFDEF MSWINDOWS}
  movdqu xmm6, oword [rsp]
  movdqu xmm7, oword [rsp + $10]
  movdqu xmm8, oword [rsp + $20]
  add rsp, 56
{$ENDIF}
