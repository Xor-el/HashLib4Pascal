// SSE2 implementation of the Keccak-f[1600] permutation (IA-32; 64-bit
// lanes in the low qwords of xmm0-xmm7, upper halves carry garbage that is
// never stored). The original MMX inner function is converted to SSE2:
// mm0-7 -> xmm0-7, packed memory-source ops rewritten through a
// liveness-proven dead scratch register (SSE2 has no m64 forms), emms
// dropped. The round loop XOR-swaps esi/edi to ping-pong between the state
// and the stack scratch plane each round (24 rounds = even, so pointers
// end where they started).
// ABI (after HlpSimdProc2Begin_i386.inc): ebx = AState (25 x UInt64,
//   standard layout), esi = AConstants (iotas: 24 x UInt64).
// Frame: mirrors the OpenSSL wrapper - 240-byte scratch, esp 8-aligned,
//   edi = esp + 140, esi biased by +100. The inner routine keeps the
//   original calling shape (call/ret) so its esp-relative spill slots stay
//   valid.
// Saves: edi/ebp saved here (the shared prologue only saves ebx/esi);
//   clobbers eax, ecx, edx, xmm0-xmm7.
// Reference: OpenSSL CRYPTOGAMS keccak1600-mmx.pl by Andy Polyakov.

  push edi
  push ebp

  mov eax, ebx          // AState
  mov ebx, esi          // iotas -> ebx (inner's table pointer)
  lea esi, [eax + 100]  // biased state pointer (lanes at esi - 100 .. + 96)

  mov ebp, esp
  sub esp, 240
  and esp, $FFFFFFF8
  lea edi, [esp + 140]

  call @keccak_inner

  mov esp, ebp
  pop ebp
  pop edi
  jmp @keccak_done

@keccak_inner:
  movq xmm0, qword ptr [esi + 60]
  movq xmm1, qword ptr [esi + 68]
  movq xmm2, qword ptr [esi + 76]
  movq xmm3, qword ptr [esi + 84]
  movq xmm4, qword ptr [esi + 92]
  mov ecx, 24
  jmp @keccak_round_loop

@keccak_round_loop:
  movq xmm5, qword ptr [esi - 100]
  pxor xmm0, xmm5
  movq xmm5, qword ptr [esi - 92]
  pxor xmm1, xmm5
  movq xmm5, qword ptr [esi - 84]
  pxor xmm2, xmm5
  movq xmm5, qword ptr [esi - 76]
  pxor xmm3, xmm5
  movq xmm5, qword ptr [esi - 68]
  pxor xmm4, xmm5
  movq xmm5, qword ptr [esi - 60]
  pxor xmm0, xmm5
  movq xmm5, qword ptr [esi - 52]
  pxor xmm1, xmm5
  movq xmm5, qword ptr [esi - 44]
  pxor xmm2, xmm5
  movq xmm5, qword ptr [esi - 36]
  pxor xmm3, xmm5
  movq xmm5, qword ptr [esi - 28]
  pxor xmm4, xmm5
  movq xmm5, qword ptr [esi - 20]
  pxor xmm0, xmm5
  movq xmm5, qword ptr [esi - 12]
  pxor xmm1, xmm5
  movq xmm5, qword ptr [esi - 4]
  pxor xmm2, xmm5
  movq xmm5, qword ptr [esi + 4]
  pxor xmm3, xmm5
  movq xmm5, qword ptr [esi + 12]
  pxor xmm4, xmm5
  movq xmm5, qword ptr [esi + 36]
  pxor xmm2, xmm5
  movq xmm5, qword ptr [esi + 20]
  pxor xmm0, xmm5
  movq xmm5, qword ptr [esi + 28]
  pxor xmm1, xmm5
  movq xmm5, qword ptr [esi + 44]
  pxor xmm3, xmm5
  movq xmm5, xmm2
  movq xmm6, qword ptr [esi + 52]
  pxor xmm4, xmm6
  movq xmm7, xmm2
  psrlq xmm5, 63
  movq xmm6, xmm0
  psllq xmm7, 1
  pxor xmm5, xmm0
  psrlq xmm0, 63
  pxor xmm5, xmm7
  psllq xmm6, 1
  movq xmm7, xmm1
  movq qword ptr [esp + 12], xmm5
  pxor xmm6, xmm0
  psrlq xmm7, 63
  pxor xmm6, xmm3
  movq xmm0, xmm1
  movq qword ptr [esp + 36], xmm6
  psllq xmm0, 1
  pxor xmm7, xmm4
  pxor xmm0, xmm7
  movq xmm7, xmm3
  psrlq xmm3, 63
  movq qword ptr [esp + 4], xmm0
  psllq xmm7, 1
  movq xmm5, xmm4
  psrlq xmm4, 63
  pxor xmm1, xmm3
  psllq xmm5, 1
  pxor xmm1, xmm7
  pxor xmm2, xmm4
  movq qword ptr [esp + 20], xmm1
  pxor xmm2, xmm5
  movq xmm3, qword ptr [esi + 44]
  movq qword ptr [esp + 28], xmm2
  pxor xmm3, xmm2
  movq xmm4, qword ptr [esi + 92]
  movq xmm7, xmm3
  psrlq xmm3, 43
  pxor xmm4, xmm6
  psllq xmm7, 21
  movq xmm6, xmm4
  psrlq xmm4, 50
  por xmm3, xmm7
  psllq xmm6, 14
  movq xmm2, qword ptr [esi - 4]
  por xmm4, xmm6
  pxor xmm2, xmm1
  movq xmm1, qword ptr [esi - 52]
  movq xmm6, xmm2
  psrlq xmm2, 21
  movq xmm5, qword ptr [esp + 12]
  pxor xmm1, xmm5
  psllq xmm6, 43
  movq xmm7, xmm1
  psrlq xmm1, 20
  por xmm2, xmm6
  psllq xmm7, 44
  movq xmm5, qword ptr [esi - 100]
  pxor xmm0, xmm5
  por xmm1, xmm7
  movq xmm5, xmm1
  movq xmm6, xmm2
  pandn xmm5, xmm2
  pandn xmm2, xmm3
  pxor xmm5, xmm0
  pxor xmm2, xmm1
  movq xmm7, qword ptr [ebx]
  pxor xmm5, xmm7
  lea ebx, [ebx + 8]
  movq xmm7, xmm3
  movq qword ptr [edi - 100], xmm5
  movq xmm5, xmm4
  pandn xmm3, xmm4
  pandn xmm4, xmm0
  pxor xmm3, xmm6
  movq qword ptr [edi - 92], xmm2
  pxor xmm4, xmm7
  movq xmm7, qword ptr [esi - 76]
  movq qword ptr [edi - 84], xmm3
  pandn xmm0, xmm1
  movq qword ptr [edi - 76], xmm4
  pxor xmm0, xmm5
  movq xmm1, qword ptr [esp + 28]
  pxor xmm7, xmm1
  movq qword ptr [edi - 68], xmm0
  movq xmm0, xmm7
  psrlq xmm7, 36
  movq xmm1, qword ptr [esi - 28]
  psllq xmm0, 28
  movq xmm2, qword ptr [esp + 36]
  pxor xmm1, xmm2
  por xmm0, xmm7
  movq xmm6, xmm1
  psrlq xmm1, 44
  movq xmm2, qword ptr [esi - 20]
  psllq xmm6, 20
  movq xmm3, qword ptr [esp + 4]
  pxor xmm2, xmm3
  por xmm1, xmm6
  movq xmm7, xmm2
  psrlq xmm2, 61
  movq xmm3, qword ptr [esi + 28]
  psllq xmm7, 3
  movq xmm4, qword ptr [esp + 12]
  pxor xmm3, xmm4
  por xmm2, xmm7
  movq xmm5, xmm3
  psrlq xmm3, 19
  movq xmm4, qword ptr [esi + 76]
  psllq xmm5, 45
  movq xmm6, qword ptr [esp + 20]
  pxor xmm4, xmm6
  por xmm3, xmm5
  movq xmm6, xmm4
  psrlq xmm4, 3
  psllq xmm6, 61
  por xmm4, xmm6
  movq xmm5, xmm1
  movq xmm6, xmm2
  pandn xmm5, xmm2
  pandn xmm2, xmm3
  pxor xmm5, xmm0
  pxor xmm2, xmm1
  movq xmm7, xmm3
  movq qword ptr [edi - 60], xmm5
  movq xmm5, xmm4
  pandn xmm3, xmm4
  pandn xmm4, xmm0
  pxor xmm3, xmm6
  movq qword ptr [edi - 52], xmm2
  pxor xmm4, xmm7
  movq xmm7, qword ptr [esi - 92]
  movq qword ptr [edi - 44], xmm3
  pandn xmm0, xmm1
  movq qword ptr [edi - 36], xmm4
  pxor xmm0, xmm5
  movq xmm1, qword ptr [esp + 12]
  pxor xmm7, xmm1
  movq qword ptr [edi - 28], xmm0
  movq xmm0, xmm7
  psrlq xmm7, 63
  movq xmm1, qword ptr [esi - 44]
  psllq xmm0, 1
  movq xmm2, qword ptr [esp + 20]
  pxor xmm1, xmm2
  por xmm0, xmm7
  movq xmm6, xmm1
  psrlq xmm1, 58
  movq xmm2, qword ptr [esi + 4]
  psllq xmm6, 6
  movq xmm3, qword ptr [esp + 28]
  pxor xmm2, xmm3
  por xmm1, xmm6
  movq xmm7, xmm2
  psrlq xmm2, 39
  movq xmm3, qword ptr [esi + 52]
  psllq xmm7, 25
  movq xmm4, qword ptr [esp + 36]
  pxor xmm3, xmm4
  por xmm2, xmm7
  movq xmm5, xmm3
  psrlq xmm3, 56
  movq xmm4, qword ptr [esi + 60]
  psllq xmm5, 8
  movq xmm6, qword ptr [esp + 4]
  pxor xmm4, xmm6
  por xmm3, xmm5
  movq xmm6, xmm4
  psrlq xmm4, 46
  psllq xmm6, 18
  por xmm4, xmm6
  movq xmm5, xmm1
  movq xmm6, xmm2
  pandn xmm5, xmm2
  pandn xmm2, xmm3
  pxor xmm5, xmm0
  pxor xmm2, xmm1
  movq xmm7, xmm3
  movq qword ptr [edi - 20], xmm5
  movq xmm5, xmm4
  pandn xmm3, xmm4
  pandn xmm4, xmm0
  pxor xmm3, xmm6
  movq qword ptr [edi - 12], xmm2
  pxor xmm4, xmm7
  movq xmm7, qword ptr [esi - 68]
  movq qword ptr [edi - 4], xmm3
  pandn xmm0, xmm1
  movq qword ptr [edi + 4], xmm4
  pxor xmm0, xmm5
  movq xmm1, qword ptr [esp + 36]
  pxor xmm7, xmm1
  movq qword ptr [edi + 12], xmm0
  movq xmm0, xmm7
  psrlq xmm7, 37
  movq xmm1, qword ptr [esi - 60]
  psllq xmm0, 27
  movq xmm2, qword ptr [esp + 4]
  pxor xmm1, xmm2
  por xmm0, xmm7
  movq xmm6, xmm1
  psrlq xmm1, 28
  movq xmm2, qword ptr [esi - 12]
  psllq xmm6, 36
  movq xmm3, qword ptr [esp + 12]
  pxor xmm2, xmm3
  por xmm1, xmm6
  movq xmm7, xmm2
  psrlq xmm2, 54
  movq xmm3, qword ptr [esi + 36]
  psllq xmm7, 10
  movq xmm4, qword ptr [esp + 20]
  pxor xmm3, xmm4
  por xmm2, xmm7
  movq xmm5, xmm3
  psrlq xmm3, 49
  movq xmm4, qword ptr [esi + 84]
  psllq xmm5, 15
  movq xmm6, qword ptr [esp + 28]
  pxor xmm4, xmm6
  por xmm3, xmm5
  movq xmm6, xmm4
  psrlq xmm4, 8
  psllq xmm6, 56
  por xmm4, xmm6
  movq xmm5, xmm1
  movq xmm6, xmm2
  pandn xmm5, xmm2
  pandn xmm2, xmm3
  pxor xmm5, xmm0
  pxor xmm2, xmm1
  movq xmm7, xmm3
  movq qword ptr [edi + 20], xmm5
  movq xmm5, xmm4
  pandn xmm3, xmm4
  pandn xmm4, xmm0
  pxor xmm3, xmm6
  movq qword ptr [edi + 28], xmm2
  pxor xmm4, xmm7
  movq xmm7, qword ptr [esi - 84]
  movq qword ptr [edi + 36], xmm3
  pandn xmm0, xmm1
  movq qword ptr [edi + 44], xmm4
  pxor xmm0, xmm5
  movq xmm1, qword ptr [esp + 20]
  pxor xmm7, xmm1
  movq qword ptr [edi + 52], xmm0
  movq xmm0, xmm7
  psrlq xmm7, 2
  movq xmm1, qword ptr [esi - 36]
  psllq xmm0, 62
  movq xmm2, qword ptr [esp + 28]
  pxor xmm1, xmm2
  por xmm0, xmm7
  movq xmm6, xmm1
  psrlq xmm1, 9
  movq xmm2, qword ptr [esi + 12]
  psllq xmm6, 55
  movq xmm3, qword ptr [esp + 36]
  pxor xmm2, xmm3
  por xmm1, xmm6
  movq xmm7, xmm2
  psrlq xmm2, 25
  movq xmm3, qword ptr [esi + 20]
  psllq xmm7, 39
  movq xmm4, qword ptr [esp + 4]
  pxor xmm3, xmm4
  por xmm2, xmm7
  movq xmm5, xmm3
  psrlq xmm3, 23
  movq xmm4, qword ptr [esi + 68]
  psllq xmm5, 41
  movq xmm6, qword ptr [esp + 12]
  pxor xmm4, xmm6
  por xmm3, xmm5
  movq xmm6, xmm4
  psrlq xmm4, 62
  psllq xmm6, 2
  por xmm4, xmm6
  movq xmm5, xmm0
  xor edi, esi
  movq qword ptr [esp + 12], xmm1
  xor esi, edi
  xor edi, esi
  movq xmm6, xmm1
  movq xmm7, xmm2
  pandn xmm6, xmm2
  pandn xmm7, xmm3
  pxor xmm0, xmm6
  pxor xmm1, xmm7
  movq xmm6, xmm3
  movq qword ptr [esi + 60], xmm0
  pandn xmm6, xmm4
  movq qword ptr [esi + 68], xmm1
  pxor xmm2, xmm6
  movq xmm7, xmm4
  movq qword ptr [esi + 76], xmm2
  pandn xmm7, xmm5
  movq xmm6, qword ptr [esp + 12]
  pandn xmm5, xmm6
  pxor xmm3, xmm7
  pxor xmm4, xmm5
  movq qword ptr [esi + 84], xmm3
  sub ecx, 1
  movq qword ptr [esi + 92], xmm4
  jnz @keccak_round_loop
  lea ebx, [ebx - 192]
  ret

@keccak_done:
  pop esi
  pop ebx
