// Reflected (LSB-first) 64-bit CRC: 16-byte slice using SSE2 loads + GPR table XOR.
// Signature (after SimdProc4Begin.inc):
//   function CRC_Fold_Lsb_Sse2(AData: PByte; ALength: UInt32;
//     AState: Pointer; AConstants: Pointer): UInt64;
// MS x64: rcx=AData, edx=ALength, r8=AState, r9=Ctx (PCRCFoldRuntimeCtx64).
// TableRow[i] begins at Ctx + SizeOf(TCRCFoldConstants) = Ctx + 96.
//
// SSE2: movdqu, movq, pxor, psrldq. No PCLMUL.

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
