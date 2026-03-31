// Reflected (LSB-first) 64-bit CRC: 16-byte slice (IA-32 SSE2 + GPR table XOR).
// After SimdProc4Begin_i386: ebx = AData, esi = ALength, edi = AState, eax = Ctx.
// TableRow[i] at Ctx + 96; each entry is a 32-bit pointer (PUInt64).
// Result UInt64 in edx:eax (high:low). Preserves Delphi/FPC i386 frame via push/pop ebp.

  push ebp
  mov ebp, eax

  sub esp, 28
  // [esp+0..7]   LQWord1, [esp+8..15] LQWord2
  // [esp+16..19] saved esi (length) during inner
  // [esp+20..23] acc lo, [esp+24..27] acc hi

@LsbSse2_main_loop:
  cmp esi, 16
  jb @LsbSse2_done

  movdqu xmm0, oword ptr [ebx]
  movq xmm2, qword ptr [edi]
  pxor xmm0, xmm2
  movq qword ptr [esp], xmm0
  psrldq xmm0, 8
  movq qword ptr [esp + 8], xmm0

  mov dword ptr [esp + 16], esi
  mov dword ptr [esp + 20], 0
  mov dword ptr [esp + 24], 0

  movzx eax, byte ptr [esp]
  mov esi, dword ptr [ebp + 96 + 15 * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 20], ecx
  xor dword ptr [esp + 24], edx

  movzx eax, byte ptr [esp + 1]
  mov esi, dword ptr [ebp + 96 + 14 * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 20], ecx
  xor dword ptr [esp + 24], edx

  movzx eax, byte ptr [esp + 2]
  mov esi, dword ptr [ebp + 96 + 13 * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 20], ecx
  xor dword ptr [esp + 24], edx

  movzx eax, byte ptr [esp + 3]
  mov esi, dword ptr [ebp + 96 + 12 * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 20], ecx
  xor dword ptr [esp + 24], edx

  movzx eax, byte ptr [esp + 4]
  mov esi, dword ptr [ebp + 96 + 11 * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 20], ecx
  xor dword ptr [esp + 24], edx

  movzx eax, byte ptr [esp + 5]
  mov esi, dword ptr [ebp + 96 + 10 * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 20], ecx
  xor dword ptr [esp + 24], edx

  movzx eax, byte ptr [esp + 6]
  mov esi, dword ptr [ebp + 96 + 9 * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 20], ecx
  xor dword ptr [esp + 24], edx

  movzx eax, byte ptr [esp + 7]
  mov esi, dword ptr [ebp + 96 + 8 * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 20], ecx
  xor dword ptr [esp + 24], edx

  movzx eax, byte ptr [esp + 8]
  mov esi, dword ptr [ebp + 96 + 7 * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 20], ecx
  xor dword ptr [esp + 24], edx

  movzx eax, byte ptr [esp + 9]
  mov esi, dword ptr [ebp + 96 + 6 * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 20], ecx
  xor dword ptr [esp + 24], edx

  movzx eax, byte ptr [esp + 10]
  mov esi, dword ptr [ebp + 96 + 5 * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 20], ecx
  xor dword ptr [esp + 24], edx

  movzx eax, byte ptr [esp + 11]
  mov esi, dword ptr [ebp + 96 + 4 * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 20], ecx
  xor dword ptr [esp + 24], edx

  movzx eax, byte ptr [esp + 12]
  mov esi, dword ptr [ebp + 96 + 3 * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 20], ecx
  xor dword ptr [esp + 24], edx

  movzx eax, byte ptr [esp + 13]
  mov esi, dword ptr [ebp + 96 + 2 * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 20], ecx
  xor dword ptr [esp + 24], edx

  movzx eax, byte ptr [esp + 14]
  mov esi, dword ptr [ebp + 96 + 1 * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 20], ecx
  xor dword ptr [esp + 24], edx

  movzx eax, byte ptr [esp + 15]
  mov esi, dword ptr [ebp + 96 + 0 * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 20], ecx
  xor dword ptr [esp + 24], edx

  mov eax, dword ptr [esp + 20]
  mov edx, dword ptr [esp + 24]
  mov dword ptr [edi], eax
  mov dword ptr [edi + 4], edx

  mov esi, dword ptr [esp + 16]
  add ebx, 16
  sub esi, 16
  jmp @LsbSse2_main_loop

@LsbSse2_done:
  mov eax, dword ptr [edi]
  mov edx, dword ptr [edi + 4]
  add esp, 28
  pop ebp
  pop edi
  pop esi
  pop ebx
