// MSB-first 64-bit CRC: 16-byte slice (slicing-by-16) using SSE2 for load only.
// IA-32 counterpart: CRCFoldMsbSse2_i386.inc (Width/CrcMask at +160/+164).
// Signature (after SimdProc4Begin.inc):
//   function CRC_Fold_Msb_Sse2(AData: PByte; ALength: UInt32;
//     AState: Pointer; AConstants: Pointer): UInt64;
// MS x64: rcx=AData, edx=ALength, r8=AState, r9=Ctx.
// Offsets in PCRCFoldRuntimeCtx64 (packed): TableRow at +96, Width at +224,
//   CrcMask at +228 (verify with SizeOf if compiler padding differs).

  push rbx
  push rbp
  push r12
  push r13
  push r14
  push r15

  mov rbx, qword ptr [r8]          // LTemp
  mov r15, rcx                     // data pointer (stable)

@MsbSse2_outer:
  cmp edx, 16
  jb @MsbSse2_done

  mov r14d, dword ptr [r9 + 224]   // Width
  mov r12, qword ptr [r9 + 228]    // CrcMask

  mov eax, r14d
  add eax, 7
  shr eax, 3                        // LCrcBytes
  mov r13d, eax

  xor rbp, rbp                      // LNewTemp
  mov rsi, rbx                      // LTempCopy
  xor edi, edi                      // LBIdx

  mov ecx, r14d
  sub ecx, 8                        // Width - 8, shift count for top byte

@MsbSse2_m1:
  cmp edi, r13d
  jge @MsbSse2_m2

  mov rax, rsi
  shr rax, cl
  movzx r10d, al

  movzx eax, byte ptr [r15 + rdi]
  xor r10d, eax

  mov eax, 15
  sub eax, edi
  mov r11, qword ptr [r9 + 96 + rax * 8]
  xor rbp, qword ptr [r11 + r10 * 8]

  shl rsi, 8
  and rsi, r12

  inc edi
  jmp @MsbSse2_m1

@MsbSse2_m2:
  cmp edi, 16
  jge @MsbSse2_blkend

  movzx r10d, byte ptr [r15 + rdi]
  mov eax, 15
  sub eax, edi
  mov r11, qword ptr [r9 + 96 + rax * 8]
  xor rbp, qword ptr [r11 + r10 * 8]

  inc edi
  jmp @MsbSse2_m2

@MsbSse2_blkend:
  mov rbx, rbp
  add r15, 16
  sub edx, 16
  jmp @MsbSse2_outer

@MsbSse2_done:
  mov qword ptr [r8], rbx
  mov rax, rbx
  pop r15
  pop r14
  pop r13
  pop r12
  pop rbp
  pop rbx
