// SHA-1 SHA-NI implementation (Intel SHA Extensions), the same design as
// OpenSSL's x86_64 sha1_block_data_order_shaext (CRYPTOGAMS). The 20 sha1rnds4
// groups run with the message schedule (sha1msg1/sha1msg2/sha1nexte) interleaved.
// The input is byte-swapped with a single pshufb against a full-reverse mask
// (byte-swap and dword-reverse folded into one mask, loaded once into xmm3), so
// no per-word pshufd is needed. The next block's message loads are software-
// pipelined into rounds 64-79 and the data pointer is advanced branchlessly
// (cmovnz).
//
// Expects MS x64 ABI (after HlpSimdProc5Begin): rcx = state ptr, rdx = data ptr,
//   r8d = numblocks, r9 = round-constant ptr (unused - sha1rnds4 has the round
//   constants built in), r10 = byte-swap mask ptr (16 bytes; see BSWAP32_MASK,
//   matching OpenSSL K_XX_XX+0xa0).
//
// SHA-NI instructions, db-encoded for assembler compatibility:
//   sha1rnds4  dst, src, imm  = $0F $3A $CC <ModRM> <imm8>
//   sha1nexte  dst, src       = $0F $38 $C8 <ModRM>
//   sha1msg1   dst, src       = $0F $38 $C9 <ModRM>
//   sha1msg2   dst, src       = $0F $38 $CA <ModRM>
//   pshufb     dst, src       = $66 $0F $38 $00 <ModRM>
//
// Register map (identical to OpenSSL):
//   xmm0 = ABCD state
//   xmm1 = E
//   xmm2 = E' (ping-pong E register)
//   xmm3 = byte-swap mask (loaded once)
//   xmm4 = MSG0
//   xmm5 = MSG1
//   xmm6 = MSG2
//   xmm7 = MSG3
//   xmm8 = ABCD_SAVE
//   xmm9 = E_SAVE
//
// MS x64 non-volatile saves: xmm6-xmm15 via the shared HlpSimdNonVolatileSave/Restore
// include (no-op on SysV); the kernel itself uses only volatile GPRs (rcx/rdx/r8-r11).

  {$I ..\Include\Simd\Common\HlpSimdNonVolatileSave_x86_64.inc}

  test r8d, r8d
  jz @sha1ni_done

  // ===== Setup: load state + mask, load & byte-swap first block, offload E =====
  movdqu xmm0, [rcx]
  movd   xmm1, [rcx + $10]
  movdqu xmm3, [r10]           // full-reverse mask (loaded once)

  movdqu xmm4, [rdx]
  pshufd xmm0, xmm0, $1B
  movdqu xmm5, [rdx + $10]
  pshufd xmm1, xmm1, $1B
  movdqu xmm6, [rdx + $20]
  db $66, $0F, $38, $00, $E3      // pshufb xmm4, xmm3
  movdqu xmm7, [rdx + $30]
  db $66, $0F, $38, $00, $EB      // pshufb xmm5, xmm3
  db $66, $0F, $38, $00, $F3      // pshufb xmm6, xmm3
  movdqa xmm9, xmm1
  db $66, $0F, $38, $00, $FB      // pshufb xmm7, xmm3
  jmp    @sha1ni_loop

@sha1ni_loop:
  dec    r8d
  lea    r11, [rdx + $40]
  paddd  xmm1, xmm4
  cmovnz rdx, r11
  movdqa xmm8, xmm0
  db $0F, $38, $C9, $E5           // sha1msg1 xmm4, xmm5
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $00      // sha1rnds4 xmm0, xmm1, 0
  db $0F, $38, $C8, $D5           // sha1nexte xmm2, xmm5
  pxor   xmm4, xmm6
  db $0F, $38, $C9, $EE           // sha1msg1 xmm5, xmm6
  db $0F, $38, $CA, $E7           // sha1msg2 xmm4, xmm7

  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $00      // sha1rnds4 xmm0, xmm2, 0
  db $0F, $38, $C8, $CE           // sha1nexte xmm1, xmm6
  pxor   xmm5, xmm7
  db $0F, $38, $CA, $EC           // sha1msg2 xmm5, xmm4
  db $0F, $38, $C9, $F7           // sha1msg1 xmm6, xmm7
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $00      // sha1rnds4 xmm0, xmm1, 0
  db $0F, $38, $C8, $D7           // sha1nexte xmm2, xmm7
  pxor   xmm6, xmm4
  db $0F, $38, $C9, $FC           // sha1msg1 xmm7, xmm4
  db $0F, $38, $CA, $F5           // sha1msg2 xmm6, xmm5

  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $00      // sha1rnds4 xmm0, xmm2, 0
  db $0F, $38, $C8, $CC           // sha1nexte xmm1, xmm4
  pxor   xmm7, xmm5
  db $0F, $38, $CA, $FE           // sha1msg2 xmm7, xmm6
  db $0F, $38, $C9, $E5           // sha1msg1 xmm4, xmm5
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $00      // sha1rnds4 xmm0, xmm1, 0
  db $0F, $38, $C8, $D5           // sha1nexte xmm2, xmm5
  pxor   xmm4, xmm6
  db $0F, $38, $C9, $EE           // sha1msg1 xmm5, xmm6
  db $0F, $38, $CA, $E7           // sha1msg2 xmm4, xmm7

  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $01      // sha1rnds4 xmm0, xmm2, 1
  db $0F, $38, $C8, $CE           // sha1nexte xmm1, xmm6
  pxor   xmm5, xmm7
  db $0F, $38, $CA, $EC           // sha1msg2 xmm5, xmm4
  db $0F, $38, $C9, $F7           // sha1msg1 xmm6, xmm7
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $01      // sha1rnds4 xmm0, xmm1, 1
  db $0F, $38, $C8, $D7           // sha1nexte xmm2, xmm7
  pxor   xmm6, xmm4
  db $0F, $38, $C9, $FC           // sha1msg1 xmm7, xmm4
  db $0F, $38, $CA, $F5           // sha1msg2 xmm6, xmm5

  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $01      // sha1rnds4 xmm0, xmm2, 1
  db $0F, $38, $C8, $CC           // sha1nexte xmm1, xmm4
  pxor   xmm7, xmm5
  db $0F, $38, $CA, $FE           // sha1msg2 xmm7, xmm6
  db $0F, $38, $C9, $E5           // sha1msg1 xmm4, xmm5
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $01      // sha1rnds4 xmm0, xmm1, 1
  db $0F, $38, $C8, $D5           // sha1nexte xmm2, xmm5
  pxor   xmm4, xmm6
  db $0F, $38, $C9, $EE           // sha1msg1 xmm5, xmm6
  db $0F, $38, $CA, $E7           // sha1msg2 xmm4, xmm7

  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $01      // sha1rnds4 xmm0, xmm2, 1
  db $0F, $38, $C8, $CE           // sha1nexte xmm1, xmm6
  pxor   xmm5, xmm7
  db $0F, $38, $CA, $EC           // sha1msg2 xmm5, xmm4
  db $0F, $38, $C9, $F7           // sha1msg1 xmm6, xmm7
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $02      // sha1rnds4 xmm0, xmm1, 2
  db $0F, $38, $C8, $D7           // sha1nexte xmm2, xmm7
  pxor   xmm6, xmm4
  db $0F, $38, $C9, $FC           // sha1msg1 xmm7, xmm4
  db $0F, $38, $CA, $F5           // sha1msg2 xmm6, xmm5

  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $02      // sha1rnds4 xmm0, xmm2, 2
  db $0F, $38, $C8, $CC           // sha1nexte xmm1, xmm4
  pxor   xmm7, xmm5
  db $0F, $38, $CA, $FE           // sha1msg2 xmm7, xmm6
  db $0F, $38, $C9, $E5           // sha1msg1 xmm4, xmm5
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $02      // sha1rnds4 xmm0, xmm1, 2
  db $0F, $38, $C8, $D5           // sha1nexte xmm2, xmm5
  pxor   xmm4, xmm6
  db $0F, $38, $C9, $EE           // sha1msg1 xmm5, xmm6
  db $0F, $38, $CA, $E7           // sha1msg2 xmm4, xmm7

  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $02      // sha1rnds4 xmm0, xmm2, 2
  db $0F, $38, $C8, $CE           // sha1nexte xmm1, xmm6
  pxor   xmm5, xmm7
  db $0F, $38, $CA, $EC           // sha1msg2 xmm5, xmm4
  db $0F, $38, $C9, $F7           // sha1msg1 xmm6, xmm7
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $02      // sha1rnds4 xmm0, xmm1, 2
  db $0F, $38, $C8, $D7           // sha1nexte xmm2, xmm7
  pxor   xmm6, xmm4
  db $0F, $38, $C9, $FC           // sha1msg1 xmm7, xmm4
  db $0F, $38, $CA, $F5           // sha1msg2 xmm6, xmm5

  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $03      // sha1rnds4 xmm0, xmm2, 3
  db $0F, $38, $C8, $CC           // sha1nexte xmm1, xmm4
  pxor   xmm7, xmm5
  db $0F, $38, $CA, $FE           // sha1msg2 xmm7, xmm6
  movdqu xmm4, [rdx]
  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $03      // sha1rnds4 xmm0, xmm1, 3
  db $0F, $38, $C8, $D5           // sha1nexte xmm2, xmm5
  movdqu xmm5, [rdx + $10]
  db $66, $0F, $38, $00, $E3      // pshufb xmm4, xmm3

  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $03      // sha1rnds4 xmm0, xmm2, 3
  db $0F, $38, $C8, $CE           // sha1nexte xmm1, xmm6
  movdqu xmm6, [rdx + $20]
  db $66, $0F, $38, $00, $EB      // pshufb xmm5, xmm3

  movdqa xmm2, xmm0
  db $0F, $3A, $CC, $C1, $03      // sha1rnds4 xmm0, xmm1, 3
  db $0F, $38, $C8, $D7           // sha1nexte xmm2, xmm7
  movdqu xmm7, [rdx + $30]
  db $66, $0F, $38, $00, $F3      // pshufb xmm6, xmm3

  movdqa xmm1, xmm0
  db $0F, $3A, $CC, $C2, $03      // sha1rnds4 xmm0, xmm2, 3
  db $41, $0F, $38, $C8, $C9      // sha1nexte xmm1, xmm9
  db $66, $0F, $38, $00, $FB      // pshufb xmm7, xmm3

  paddd  xmm0, xmm8
  movdqa xmm9, xmm1

  jnz    @sha1ni_loop

  pshufd xmm0, xmm0, $1B
  pshufd xmm1, xmm1, $1B
  movdqu [rcx], xmm0
  movd   [rcx + $10], xmm1

@sha1ni_done:

  {$I ..\Include\Simd\Common\HlpSimdNonVolatileRestore_x86_64.inc}
