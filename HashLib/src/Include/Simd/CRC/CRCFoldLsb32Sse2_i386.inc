// CRC32 reflected (PKZIP-style) 16-byte slice (IA-32 SSE2 + dword table XOR).
// After SimdProc4Begin_i386: ebx = AData, esi = ALength, edi = AState, eax = Ctx.
// Little-endian host only. PUInt32 rows at Ctx + 96.
// d0 xor CRC saved at [esp+12]; d1 in edx; d2/d3 on stack. Result eax, edx=0.

  push ebp
  mov ebp, eax

  sub esp, 32
  // [esp+12] d0 after xor CRC, [esp+16] saved esi, [esp+20] d2, [esp+24] d3

@L32Sse2_outer:
  cmp esi, 16
  jb @L32Sse2_done

  movdqu xmm0, oword ptr [ebx]

  movd eax, xmm0
  psrldq xmm0, 4
  movd edx, xmm0
  psrldq xmm0, 4
  movd dword ptr [esp + 20], xmm0
  psrldq xmm0, 4
  movd dword ptr [esp + 24], xmm0

  mov dword ptr [esp + 16], esi

  xor eax, dword ptr [edi]
  mov dword ptr [esp + 12], eax

  xor ecx, ecx

  mov esi, dword ptr [esp + 24]
  shr esi, 24
  mov eax, dword ptr [ebp + 96 + 0 * 4]
  xor ecx, dword ptr [eax + esi * 4]

  mov esi, dword ptr [esp + 24]
  shr esi, 16
  and esi, $FF
  mov eax, dword ptr [ebp + 96 + 1 * 4]
  xor ecx, dword ptr [eax + esi * 4]

  mov esi, dword ptr [esp + 24]
  shr esi, 8
  and esi, $FF
  mov eax, dword ptr [ebp + 96 + 2 * 4]
  xor ecx, dword ptr [eax + esi * 4]

  mov esi, dword ptr [esp + 24]
  and esi, $FF
  mov eax, dword ptr [ebp + 96 + 3 * 4]
  xor ecx, dword ptr [eax + esi * 4]

  mov esi, dword ptr [esp + 20]
  shr esi, 24
  mov eax, dword ptr [ebp + 96 + 4 * 4]
  xor ecx, dword ptr [eax + esi * 4]

  mov esi, dword ptr [esp + 20]
  shr esi, 16
  and esi, $FF
  mov eax, dword ptr [ebp + 96 + 5 * 4]
  xor ecx, dword ptr [eax + esi * 4]

  mov esi, dword ptr [esp + 20]
  shr esi, 8
  and esi, $FF
  mov eax, dword ptr [ebp + 96 + 6 * 4]
  xor ecx, dword ptr [eax + esi * 4]

  mov esi, dword ptr [esp + 20]
  and esi, $FF
  mov eax, dword ptr [ebp + 96 + 7 * 4]
  xor ecx, dword ptr [eax + esi * 4]

  mov esi, edx
  shr esi, 24
  mov eax, dword ptr [ebp + 96 + 8 * 4]
  xor ecx, dword ptr [eax + esi * 4]

  mov esi, edx
  shr esi, 16
  and esi, $FF
  mov eax, dword ptr [ebp + 96 + 9 * 4]
  xor ecx, dword ptr [eax + esi * 4]

  mov esi, edx
  shr esi, 8
  and esi, $FF
  mov eax, dword ptr [ebp + 96 + 10 * 4]
  xor ecx, dword ptr [eax + esi * 4]

  mov esi, edx
  and esi, $FF
  mov eax, dword ptr [ebp + 96 + 11 * 4]
  xor ecx, dword ptr [eax + esi * 4]

  mov esi, dword ptr [esp + 12]
  shr esi, 24
  mov eax, dword ptr [ebp + 96 + 12 * 4]
  xor ecx, dword ptr [eax + esi * 4]

  mov esi, dword ptr [esp + 12]
  shr esi, 16
  and esi, $FF
  mov eax, dword ptr [ebp + 96 + 13 * 4]
  xor ecx, dword ptr [eax + esi * 4]

  mov esi, dword ptr [esp + 12]
  shr esi, 8
  and esi, $FF
  mov eax, dword ptr [ebp + 96 + 14 * 4]
  xor ecx, dword ptr [eax + esi * 4]

  mov esi, dword ptr [esp + 12]
  and esi, $FF
  mov eax, dword ptr [ebp + 96 + 15 * 4]
  xor ecx, dword ptr [eax + esi * 4]

  mov dword ptr [edi], ecx
  mov esi, dword ptr [esp + 16]
  add ebx, 16
  sub esi, 16
  jmp @L32Sse2_outer

@L32Sse2_done:
  mov eax, dword ptr [edi]
  xor edx, edx
  add esp, 32
  pop ebp
  pop edi
  pop esi
  pop ebx
