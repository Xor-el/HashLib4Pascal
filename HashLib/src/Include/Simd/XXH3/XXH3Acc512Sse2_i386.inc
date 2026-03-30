// SSE2 implementation of XXH3_accumulate_512 (fully unrolled, 4 x 16-byte chunks).
// IA-32: after SimdProc3Begin_i386 — ebx = acc, esi = input, edi = secret
//   (parallel to MS x64 ABI: rcx, rdx, r8).
// Uses only volatile XMM: xmm0–xmm5.
// Reference: official xxHash C - XXH3_accumulate_512_sse2 in xxhash.h

  movdqu xmm0, oword [ebx]
  movdqu xmm1, oword [esi]
  movdqu xmm2, oword [edi]
  pxor xmm2, xmm1
  pshufd xmm3, xmm2, $31
  pmuludq xmm2, xmm3
  pshufd xmm1, xmm1, $4E
  paddq xmm0, xmm1
  paddq xmm0, xmm2
  movdqu oword [ebx], xmm0

  movdqu xmm0, oword [ebx + $10]
  movdqu xmm1, oword [esi + $10]
  movdqu xmm2, oword [edi + $10]
  pxor xmm2, xmm1
  pshufd xmm3, xmm2, $31
  pmuludq xmm2, xmm3
  pshufd xmm1, xmm1, $4E
  paddq xmm0, xmm1
  paddq xmm0, xmm2
  movdqu oword [ebx + $10], xmm0

  movdqu xmm0, oword [ebx + $20]
  movdqu xmm1, oword [esi + $20]
  movdqu xmm2, oword [edi + $20]
  pxor xmm2, xmm1
  pshufd xmm3, xmm2, $31
  pmuludq xmm2, xmm3
  pshufd xmm1, xmm1, $4E
  paddq xmm0, xmm1
  paddq xmm0, xmm2
  movdqu oword [ebx + $20], xmm0

  movdqu xmm0, oword [ebx + $30]
  movdqu xmm1, oword [esi + $30]
  movdqu xmm2, oword [edi + $30]
  pxor xmm2, xmm1
  pshufd xmm3, xmm2, $31
  pmuludq xmm2, xmm3
  pshufd xmm1, xmm1, $4E
  paddq xmm0, xmm1
  paddq xmm0, xmm2
  movdqu oword [ebx + $30], xmm0

  pop edi
  pop esi
  pop ebx
