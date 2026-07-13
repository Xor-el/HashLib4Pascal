// SSE2 implementation of the reflected (LSB-first) 64-bit CRC 16-byte slice
// (SSE2 loads + GPR table XOR). GPR slicing core; SSE2 is genuinely
// required for the 128-bit loads and the CRC state shuttle - the Sse2 name
// states the ISA requirement. SSE2 ops: movdqu, movq, pxor, psrldq;
// no PCLMUL.
// ABI (after HlpSimdProc4Begin_x86_64.inc): rcx = AData, edx = ALength,
//   r8 = AState, r9 = Ctx (PCRCFoldRuntimeCtx).
//   TableRow[i] begins at Ctx + SizeOf(TCRCFoldConstants) = Ctx + 96.
//   Returns the final CRC in rax.
// Reference: classic slicing-by-16 table CRC.

  push rbx
  push r12

  mov rbx, qword ptr [r8]          // LTemp

@LsbSse2_main_loop:
  cmp edx, 16
  jb @LsbSse2_done

  movdqu xmm0, dqword ptr [rcx]
  movq xmm2, rbx
  pxor xmm0, xmm2
  movq rax, xmm0
  movdqa xmm2, xmm0
  psrldq xmm2, 8
  movq r12, xmm2                   // LQWord2

  xor rbx, rbx                     // acc = 0; 16 xors into rbx

  // LQWord1: rows 15..8, bytes low to high
  movzx r10d, al
  mov r11, qword ptr [r9 + 96 + 15 * 8]
  xor rbx, qword ptr [r11 + r10 * 8]
  shr rax, 8
  movzx r10d, al
  mov r11, qword ptr [r9 + 96 + 14 * 8]
  xor rbx, qword ptr [r11 + r10 * 8]
  shr rax, 8
  movzx r10d, al
  mov r11, qword ptr [r9 + 96 + 13 * 8]
  xor rbx, qword ptr [r11 + r10 * 8]
  shr rax, 8
  movzx r10d, al
  mov r11, qword ptr [r9 + 96 + 12 * 8]
  xor rbx, qword ptr [r11 + r10 * 8]
  shr rax, 8
  movzx r10d, al
  mov r11, qword ptr [r9 + 96 + 11 * 8]
  xor rbx, qword ptr [r11 + r10 * 8]
  shr rax, 8
  movzx r10d, al
  mov r11, qword ptr [r9 + 96 + 10 * 8]
  xor rbx, qword ptr [r11 + r10 * 8]
  shr rax, 8
  movzx r10d, al
  mov r11, qword ptr [r9 + 96 + 9 * 8]
  xor rbx, qword ptr [r11 + r10 * 8]
  shr rax, 8
  movzx r10d, al
  mov r11, qword ptr [r9 + 96 + 8 * 8]
  xor rbx, qword ptr [r11 + r10 * 8]
  shr rax, 8

  // LQWord2: rows 7..0
  mov rax, r12
  movzx r10d, al
  mov r11, qword ptr [r9 + 96 + 7 * 8]
  xor rbx, qword ptr [r11 + r10 * 8]
  shr rax, 8
  movzx r10d, al
  mov r11, qword ptr [r9 + 96 + 6 * 8]
  xor rbx, qword ptr [r11 + r10 * 8]
  shr rax, 8
  movzx r10d, al
  mov r11, qword ptr [r9 + 96 + 5 * 8]
  xor rbx, qword ptr [r11 + r10 * 8]
  shr rax, 8
  movzx r10d, al
  mov r11, qword ptr [r9 + 96 + 4 * 8]
  xor rbx, qword ptr [r11 + r10 * 8]
  shr rax, 8
  movzx r10d, al
  mov r11, qword ptr [r9 + 96 + 3 * 8]
  xor rbx, qword ptr [r11 + r10 * 8]
  shr rax, 8
  movzx r10d, al
  mov r11, qword ptr [r9 + 96 + 2 * 8]
  xor rbx, qword ptr [r11 + r10 * 8]
  shr rax, 8
  movzx r10d, al
  mov r11, qword ptr [r9 + 96 + 1 * 8]
  xor rbx, qword ptr [r11 + r10 * 8]
  shr rax, 8
  movzx r10d, al
  mov r11, qword ptr [r9 + 96 + 0 * 8]
  xor rbx, qword ptr [r11 + r10 * 8]

  add rcx, 16
  sub edx, 16
  jmp @LsbSse2_main_loop

@LsbSse2_done:
  mov qword ptr [r8], rbx
  mov rax, rbx
  pop r12
  pop rbx
