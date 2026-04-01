// SSE2 implementation of XXH3_initCustomSecret (fully unrolled, 12 x 16-byte chunks).
// IA-32: after SimdProc3Begin_i386 — ebx = customSecret, esi = defaultSecret, edi = seed.lo32,
//   dword [esp+16] = seed.hi32 (UInt64 third parameter; high dword on stack).
//   (parallel to MS x64 ABI: rcx, rdx, r8).
// Uses only volatile XMM: xmm0–xmm2.
// Reference: official xxHash C - XXH3_initCustomSecret_sse2 in xxhash.h

  mov eax, edi
  mov edx, dword ptr [esp + 16]

  push eax
  push edx
  movq xmm0, qword ptr [esp]
  add esp, 8

  mov ecx, eax
  mov edi, edx
  not ecx
  not edi
  add ecx, 1
  adc edi, 0
  push ecx
  push edi
  movq xmm1, qword ptr [esp]
  add esp, 8
  punpcklqdq xmm0, xmm1

  movdqu xmm1, oword [esi]
  paddq xmm1, xmm0
  movdqu oword [ebx], xmm1

  movdqu xmm1, oword [esi + $10]
  paddq xmm1, xmm0
  movdqu oword [ebx + $10], xmm1

  movdqu xmm1, oword [esi + $20]
  paddq xmm1, xmm0
  movdqu oword [ebx + $20], xmm1

  movdqu xmm1, oword [esi + $30]
  paddq xmm1, xmm0
  movdqu oword [ebx + $30], xmm1

  movdqu xmm1, oword [esi + $40]
  paddq xmm1, xmm0
  movdqu oword [ebx + $40], xmm1

  movdqu xmm1, oword [esi + $50]
  paddq xmm1, xmm0
  movdqu oword [ebx + $50], xmm1

  movdqu xmm1, oword [esi + $60]
  paddq xmm1, xmm0
  movdqu oword [ebx + $60], xmm1

  movdqu xmm1, oword [esi + $70]
  paddq xmm1, xmm0
  movdqu oword [ebx + $70], xmm1

  movdqu xmm1, oword [esi + $80]
  paddq xmm1, xmm0
  movdqu oword [ebx + $80], xmm1

  movdqu xmm1, oword [esi + $90]
  paddq xmm1, xmm0
  movdqu oword [ebx + $90], xmm1

  movdqu xmm1, oword [esi + $A0]
  paddq xmm1, xmm0
  movdqu oword [ebx + $A0], xmm1

  movdqu xmm1, oword [esi + $B0]
  paddq xmm1, xmm0
  movdqu oword [ebx + $B0], xmm1

  pop edi
  pop esi
  pop ebx
