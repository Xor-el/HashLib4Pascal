// CRC32 reflected (PKZIP-style) 16-byte slice: SSE2 movdqu + dword table XOR.
// Little-endian host only (matches TConverters.le2me_32 = identity on LE).
// Signature (after SimdProc4Begin.inc):
//   function CRC_Fold_Lsb32_Sse2(AData: PByte; ALength: UInt32;
//     AState: Pointer; AConstants: Pointer): UInt64;
// State: low UInt32 of qword at AState is the running CRC.
// Ctx: PCRCFoldRuntimeCtx32; TableRow offset = 96.

  push rbx
  push r12
  push r13
  push r14
  push r15

  mov ebx, dword ptr [r8]

@L32Sse2_outer:
  cmp edx, 16
  jb @L32Sse2_done

  movdqu xmm0, dqword ptr [rcx]
  movd r10d, xmm0
  psrldq xmm0, 4
  movd r11d, xmm0
  psrldq xmm0, 4
  movd r12d, xmm0
  psrldq xmm0, 4
  movd r13d, xmm0

  xor r10d, ebx

  xor ebx, ebx

  mov eax, r13d
  shr eax, 24
  mov r14, qword ptr [r9 + 96 + 0 * 8]
  xor ebx, dword ptr [r14 + rax * 4]

  mov eax, r13d
  shr eax, 16
  and eax, $FF
  mov r14, qword ptr [r9 + 96 + 1 * 8]
  xor ebx, dword ptr [r14 + rax * 4]

  mov eax, r13d
  shr eax, 8
  and eax, $FF
  mov r14, qword ptr [r9 + 96 + 2 * 8]
  xor ebx, dword ptr [r14 + rax * 4]

  mov eax, r13d
  and eax, $FF
  mov r14, qword ptr [r9 + 96 + 3 * 8]
  xor ebx, dword ptr [r14 + rax * 4]

  mov eax, r12d
  shr eax, 24
  mov r14, qword ptr [r9 + 96 + 4 * 8]
  xor ebx, dword ptr [r14 + rax * 4]

  mov eax, r12d
  shr eax, 16
  and eax, $FF
  mov r14, qword ptr [r9 + 96 + 5 * 8]
  xor ebx, dword ptr [r14 + rax * 4]

  mov eax, r12d
  shr eax, 8
  and eax, $FF
  mov r14, qword ptr [r9 + 96 + 6 * 8]
  xor ebx, dword ptr [r14 + rax * 4]

  mov eax, r12d
  and eax, $FF
  mov r14, qword ptr [r9 + 96 + 7 * 8]
  xor ebx, dword ptr [r14 + rax * 4]

  mov eax, r11d
  shr eax, 24
  mov r14, qword ptr [r9 + 96 + 8 * 8]
  xor ebx, dword ptr [r14 + rax * 4]

  mov eax, r11d
  shr eax, 16
  and eax, $FF
  mov r14, qword ptr [r9 + 96 + 9 * 8]
  xor ebx, dword ptr [r14 + rax * 4]

  mov eax, r11d
  shr eax, 8
  and eax, $FF
  mov r14, qword ptr [r9 + 96 + 10 * 8]
  xor ebx, dword ptr [r14 + rax * 4]

  mov eax, r11d
  and eax, $FF
  mov r14, qword ptr [r9 + 96 + 11 * 8]
  xor ebx, dword ptr [r14 + rax * 4]

  mov eax, r10d
  shr eax, 24
  mov r14, qword ptr [r9 + 96 + 12 * 8]
  xor ebx, dword ptr [r14 + rax * 4]

  mov eax, r10d
  shr eax, 16
  and eax, $FF
  mov r14, qword ptr [r9 + 96 + 13 * 8]
  xor ebx, dword ptr [r14 + rax * 4]

  mov eax, r10d
  shr eax, 8
  and eax, $FF
  mov r14, qword ptr [r9 + 96 + 14 * 8]
  xor ebx, dword ptr [r14 + rax * 4]

  mov eax, r10d
  and eax, $FF
  mov r14, qword ptr [r9 + 96 + 15 * 8]
  xor ebx, dword ptr [r14 + rax * 4]

  add rcx, 16
  sub edx, 16
  jmp @L32Sse2_outer

@L32Sse2_done:
  mov dword ptr [r8], ebx
  mov rax, rbx
  and rax, $FFFFFFFF

  pop r15
  pop r14
  pop r13
  pop r12
  pop rbx
