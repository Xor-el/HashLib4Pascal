// SSE2 implementation of XXH3_scrambleAcc (fully unrolled, 4 x 16-byte chunks).
// IA-32: after SimdProc2Begin_i386 — ebx = acc, esi = secret
//   (parallel to MS x64 ABI: rcx, rdx).
// Uses only volatile registers: xmm0–xmm5, eax.
// Algorithm per 128-bit chunk:
//   acc ^= (acc >> 47)
//   acc ^= secret
//   acc *= XXH_PRIME32_1
// Reference: official xxHash C - XXH3_scrambleAcc_sse2 in xxhash.h

  mov eax, $9E3779B1
  movd xmm5, eax
  pshufd xmm5, xmm5, 0

  movdqu xmm0, oword [ebx]
  movdqu xmm1, xmm0
  psrlq xmm1, 47
  pxor xmm0, xmm1
  movdqu xmm1, oword [esi]
  pxor xmm0, xmm1
  pshufd xmm1, xmm0, $31
  pmuludq xmm0, xmm5
  pmuludq xmm1, xmm5
  psllq xmm1, 32
  paddq xmm0, xmm1
  movdqu oword [ebx], xmm0

  movdqu xmm0, oword [ebx + $10]
  movdqu xmm1, xmm0
  psrlq xmm1, 47
  pxor xmm0, xmm1
  movdqu xmm1, oword [esi + $10]
  pxor xmm0, xmm1
  pshufd xmm1, xmm0, $31
  pmuludq xmm0, xmm5
  pmuludq xmm1, xmm5
  psllq xmm1, 32
  paddq xmm0, xmm1
  movdqu oword [ebx + $10], xmm0

  movdqu xmm0, oword [ebx + $20]
  movdqu xmm1, xmm0
  psrlq xmm1, 47
  pxor xmm0, xmm1
  movdqu xmm1, oword [esi + $20]
  pxor xmm0, xmm1
  pshufd xmm1, xmm0, $31
  pmuludq xmm0, xmm5
  pmuludq xmm1, xmm5
  psllq xmm1, 32
  paddq xmm0, xmm1
  movdqu oword [ebx + $20], xmm0

  movdqu xmm0, oword [ebx + $30]
  movdqu xmm1, xmm0
  psrlq xmm1, 47
  pxor xmm0, xmm1
  movdqu xmm1, oword [esi + $30]
  pxor xmm0, xmm1
  pshufd xmm1, xmm0, $31
  pmuludq xmm0, xmm5
  pmuludq xmm1, xmm5
  psllq xmm1, 32
  paddq xmm0, xmm1
  movdqu oword [ebx + $30], xmm0

  pop esi
  pop ebx
