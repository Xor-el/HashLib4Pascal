// SHA-256 SHA-NI implementation.
// Expects MS x64 ABI: rcx = state ptr, rdx = data ptr, r8d = numblocks, r9 = K256 ptr.
// K256 layout: 64 UInt32 round constants (256 bytes), then BSWAP mask (16 bytes) at offset 256.
// Uses xmm0-xmm9. Non-volatile xmm6-xmm9 saved/restored on Windows.
// Reference: Jeffrey Walton / Sean Gulley / Intel SHA Extensions whitepaper.
//
// SHA-NI instruction db encodings (for assembler compatibility):
//   sha256rnds2  dst, src  = $0F $38 $CB <ModRM>  (implicit xmm0)
//   sha256msg1   dst, src  = $0F $38 $CC <ModRM>
//   sha256msg2   dst, src  = $0F $38 $CD <ModRM>
//
// Register map:
//   xmm0  = temp MSG+K for sha256rnds2 (implicit operand)
//   xmm1  = STATE0 (ABEF in SHA-NI format)
//   xmm2  = STATE1 (CDGH in SHA-NI format)
//   xmm3  = MSG0
//   xmm4  = MSG1
//   xmm5  = MSG2
//   xmm6  = MSG3
//   xmm7  = TMP (palignr scratch / BSWAP mask during load)
//   xmm8  = ABEF_SAVE
//   xmm9  = CDGH_SAVE

{$IFDEF MSWINDOWS}
  sub rsp, 72
  movdqu oword [rsp], xmm6
  movdqu oword [rsp + $10], xmm7
  movdqu oword [rsp + $20], xmm8
  movdqu oword [rsp + $30], xmm9
{$ENDIF}

  test r8d, r8d
  jz @shani_done

  // Convert state to SHA-NI register format (once, before block loop)
  movdqu xmm0, oword [rcx]              // [A,B,C,D]
  movdqu xmm2, oword [rcx + $10]        // [E,F,G,H]
  pshufd xmm0, xmm0, $B1                // [B,A,D,C]
  pshufd xmm2, xmm2, $1B                // [H,G,F,E]
  movdqa xmm1, xmm0
  palignr xmm1, xmm2, 8                 // STATE0 = ABEF
  pblendw xmm2, xmm0, $F0              // STATE1 = CDGH

@shani_block_loop:

  // Save current state for final addition
  movdqa xmm8, xmm1
  movdqa xmm9, xmm2

  // Load and byte-swap all 4 message blocks
  movdqu xmm7, oword [r9 + $100]        // BSWAP mask at offset 256
  movdqu xmm3, oword [rdx]
  pshufb xmm3, xmm7
  movdqu xmm4, oword [rdx + $10]
  pshufb xmm4, xmm7
  movdqu xmm5, oword [rdx + $20]
  pshufb xmm5, xmm7
  movdqu xmm6, oword [rdx + $30]
  pshufb xmm6, xmm7

  // ===== Rounds 0-3 (MSG0, no msg schedule) =====
  movdqa xmm0, xmm3
  paddd xmm0, oword [r9]
  db $0F, $38, $CB, $D1              // sha256rnds2 xmm2, xmm1
  pshufd xmm0, xmm0, $0E
  db $0F, $38, $CB, $CA              // sha256rnds2 xmm1, xmm2

  // ===== Rounds 4-7 (MSG1 + sha256msg1 MSG0,MSG1) =====
  movdqa xmm0, xmm4
  paddd xmm0, oword [r9 + $10]
  db $0F, $38, $CB, $D1              // sha256rnds2 xmm2, xmm1
  pshufd xmm0, xmm0, $0E
  db $0F, $38, $CB, $CA              // sha256rnds2 xmm1, xmm2
  db $0F, $38, $CC, $DC              // sha256msg1 xmm3, xmm4

  // ===== Rounds 8-11 (MSG2 + sha256msg1 MSG1,MSG2) =====
  movdqa xmm0, xmm5
  paddd xmm0, oword [r9 + $20]
  db $0F, $38, $CB, $D1              // sha256rnds2 xmm2, xmm1
  pshufd xmm0, xmm0, $0E
  db $0F, $38, $CB, $CA              // sha256rnds2 xmm1, xmm2
  db $0F, $38, $CC, $E5              // sha256msg1 xmm4, xmm5

  // ===== Rounds 12-15 (MSG3 + complete MSG0 + sha256msg1 MSG2,MSG3) =====
  movdqa xmm0, xmm6
  paddd xmm0, oword [r9 + $30]
  db $0F, $38, $CB, $D1              // sha256rnds2 xmm2, xmm1
  movdqa xmm7, xmm6
  palignr xmm7, xmm5, 4
  paddd xmm3, xmm7
  db $0F, $38, $CD, $DE              // sha256msg2 xmm3, xmm6
  pshufd xmm0, xmm0, $0E
  db $0F, $38, $CB, $CA              // sha256rnds2 xmm1, xmm2
  db $0F, $38, $CC, $EE              // sha256msg1 xmm5, xmm6

  // ===== Rounds 16-19 (MSG0 + complete MSG1 + sha256msg1 MSG3,MSG0) =====
  movdqa xmm0, xmm3
  paddd xmm0, oword [r9 + $40]
  db $0F, $38, $CB, $D1              // sha256rnds2 xmm2, xmm1
  movdqa xmm7, xmm3
  palignr xmm7, xmm6, 4
  paddd xmm4, xmm7
  db $0F, $38, $CD, $E3              // sha256msg2 xmm4, xmm3
  pshufd xmm0, xmm0, $0E
  db $0F, $38, $CB, $CA              // sha256rnds2 xmm1, xmm2
  db $0F, $38, $CC, $F3              // sha256msg1 xmm6, xmm3

  // ===== Rounds 20-23 (MSG1 + complete MSG2 + sha256msg1 MSG0,MSG1) =====
  movdqa xmm0, xmm4
  paddd xmm0, oword [r9 + $50]
  db $0F, $38, $CB, $D1              // sha256rnds2 xmm2, xmm1
  movdqa xmm7, xmm4
  palignr xmm7, xmm3, 4
  paddd xmm5, xmm7
  db $0F, $38, $CD, $EC              // sha256msg2 xmm5, xmm4
  pshufd xmm0, xmm0, $0E
  db $0F, $38, $CB, $CA              // sha256rnds2 xmm1, xmm2
  db $0F, $38, $CC, $DC              // sha256msg1 xmm3, xmm4

  // ===== Rounds 24-27 (MSG2 + complete MSG3 + sha256msg1 MSG1,MSG2) =====
  movdqa xmm0, xmm5
  paddd xmm0, oword [r9 + $60]
  db $0F, $38, $CB, $D1              // sha256rnds2 xmm2, xmm1
  movdqa xmm7, xmm5
  palignr xmm7, xmm4, 4
  paddd xmm6, xmm7
  db $0F, $38, $CD, $F5              // sha256msg2 xmm6, xmm5
  pshufd xmm0, xmm0, $0E
  db $0F, $38, $CB, $CA              // sha256rnds2 xmm1, xmm2
  db $0F, $38, $CC, $E5              // sha256msg1 xmm4, xmm5

  // ===== Rounds 28-31 (MSG3 + complete MSG0 + sha256msg1 MSG2,MSG3) =====
  movdqa xmm0, xmm6
  paddd xmm0, oword [r9 + $70]
  db $0F, $38, $CB, $D1              // sha256rnds2 xmm2, xmm1
  movdqa xmm7, xmm6
  palignr xmm7, xmm5, 4
  paddd xmm3, xmm7
  db $0F, $38, $CD, $DE              // sha256msg2 xmm3, xmm6
  pshufd xmm0, xmm0, $0E
  db $0F, $38, $CB, $CA              // sha256rnds2 xmm1, xmm2
  db $0F, $38, $CC, $EE              // sha256msg1 xmm5, xmm6

  // ===== Rounds 32-35 (MSG0 + complete MSG1 + sha256msg1 MSG3,MSG0) =====
  movdqa xmm0, xmm3
  paddd xmm0, oword [r9 + $80]
  db $0F, $38, $CB, $D1              // sha256rnds2 xmm2, xmm1
  movdqa xmm7, xmm3
  palignr xmm7, xmm6, 4
  paddd xmm4, xmm7
  db $0F, $38, $CD, $E3              // sha256msg2 xmm4, xmm3
  pshufd xmm0, xmm0, $0E
  db $0F, $38, $CB, $CA              // sha256rnds2 xmm1, xmm2
  db $0F, $38, $CC, $F3              // sha256msg1 xmm6, xmm3

  // ===== Rounds 36-39 (MSG1 + complete MSG2 + sha256msg1 MSG0,MSG1) =====
  movdqa xmm0, xmm4
  paddd xmm0, oword [r9 + $90]
  db $0F, $38, $CB, $D1              // sha256rnds2 xmm2, xmm1
  movdqa xmm7, xmm4
  palignr xmm7, xmm3, 4
  paddd xmm5, xmm7
  db $0F, $38, $CD, $EC              // sha256msg2 xmm5, xmm4
  pshufd xmm0, xmm0, $0E
  db $0F, $38, $CB, $CA              // sha256rnds2 xmm1, xmm2
  db $0F, $38, $CC, $DC              // sha256msg1 xmm3, xmm4

  // ===== Rounds 40-43 (MSG2 + complete MSG3 + sha256msg1 MSG1,MSG2) =====
  movdqa xmm0, xmm5
  paddd xmm0, oword [r9 + $A0]
  db $0F, $38, $CB, $D1              // sha256rnds2 xmm2, xmm1
  movdqa xmm7, xmm5
  palignr xmm7, xmm4, 4
  paddd xmm6, xmm7
  db $0F, $38, $CD, $F5              // sha256msg2 xmm6, xmm5
  pshufd xmm0, xmm0, $0E
  db $0F, $38, $CB, $CA              // sha256rnds2 xmm1, xmm2
  db $0F, $38, $CC, $E5              // sha256msg1 xmm4, xmm5

  // ===== Rounds 44-47 (MSG3 + complete MSG0 + sha256msg1 MSG2,MSG3) =====
  movdqa xmm0, xmm6
  paddd xmm0, oword [r9 + $B0]
  db $0F, $38, $CB, $D1              // sha256rnds2 xmm2, xmm1
  movdqa xmm7, xmm6
  palignr xmm7, xmm5, 4
  paddd xmm3, xmm7
  db $0F, $38, $CD, $DE              // sha256msg2 xmm3, xmm6
  pshufd xmm0, xmm0, $0E
  db $0F, $38, $CB, $CA              // sha256rnds2 xmm1, xmm2
  db $0F, $38, $CC, $EE              // sha256msg1 xmm5, xmm6

  // ===== Rounds 48-51 (MSG0 + complete MSG1 + sha256msg1 MSG3,MSG0) =====
  movdqa xmm0, xmm3
  paddd xmm0, oword [r9 + $C0]
  db $0F, $38, $CB, $D1              // sha256rnds2 xmm2, xmm1
  movdqa xmm7, xmm3
  palignr xmm7, xmm6, 4
  paddd xmm4, xmm7
  db $0F, $38, $CD, $E3              // sha256msg2 xmm4, xmm3
  pshufd xmm0, xmm0, $0E
  db $0F, $38, $CB, $CA              // sha256rnds2 xmm1, xmm2
  db $0F, $38, $CC, $F3              // sha256msg1 xmm6, xmm3

  // ===== Rounds 52-55 (MSG1 + complete MSG2, no msg1) =====
  movdqa xmm0, xmm4
  paddd xmm0, oword [r9 + $D0]
  db $0F, $38, $CB, $D1              // sha256rnds2 xmm2, xmm1
  movdqa xmm7, xmm4
  palignr xmm7, xmm3, 4
  paddd xmm5, xmm7
  db $0F, $38, $CD, $EC              // sha256msg2 xmm5, xmm4
  pshufd xmm0, xmm0, $0E
  db $0F, $38, $CB, $CA              // sha256rnds2 xmm1, xmm2

  // ===== Rounds 56-59 (MSG2 + complete MSG3, no msg1) =====
  movdqa xmm0, xmm5
  paddd xmm0, oword [r9 + $E0]
  db $0F, $38, $CB, $D1              // sha256rnds2 xmm2, xmm1
  movdqa xmm7, xmm5
  palignr xmm7, xmm4, 4
  paddd xmm6, xmm7
  db $0F, $38, $CD, $F5              // sha256msg2 xmm6, xmm5
  pshufd xmm0, xmm0, $0E
  db $0F, $38, $CB, $CA              // sha256rnds2 xmm1, xmm2

  // ===== Rounds 60-63 (MSG3, no msg schedule) =====
  movdqa xmm0, xmm6
  paddd xmm0, oword [r9 + $F0]
  db $0F, $38, $CB, $D1              // sha256rnds2 xmm2, xmm1
  pshufd xmm0, xmm0, $0E
  db $0F, $38, $CB, $CA              // sha256rnds2 xmm1, xmm2

  // Add saved state back
  paddd xmm1, xmm8
  paddd xmm2, xmm9

  // Advance data pointer and loop
  add rdx, 64
  dec r8d
  jnz @shani_block_loop

  // Convert state back from SHA-NI format to standard [A,B,C,D],[E,F,G,H]
  pshufd xmm0, xmm1, $1B            // TMP = shuffle STATE0
  pshufd xmm2, xmm2, $B1            // STATE1 shuffled
  movdqa xmm1, xmm0
  pblendw xmm1, xmm2, $F0           // xmm1 = [A,B,C,D]
  palignr xmm2, xmm0, 8             // xmm2 = [E,F,G,H]

  // Store result
  movdqu oword [rcx], xmm1
  movdqu oword [rcx + $10], xmm2

@shani_done:

{$IFDEF MSWINDOWS}
  movdqu xmm6, oword [rsp]
  movdqu xmm7, oword [rsp + $10]
  movdqu xmm8, oword [rsp + $20]
  movdqu xmm9, oword [rsp + $30]
  add rsp, 72
{$ENDIF}
