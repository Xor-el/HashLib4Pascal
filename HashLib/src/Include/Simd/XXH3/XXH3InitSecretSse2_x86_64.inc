// SSE2 implementation of XXH3_initCustomSecret (fully unrolled, 12 x 16-byte chunks).
// Expects MS x64 ABI: rcx = customSecret ptr, rdx = defaultSecret ptr, r8 = seed (UInt64).
// Uses only volatile registers: xmm0-xmm2.
// Algorithm: for each 16-byte block, lo_qword += seed, hi_qword -= seed.
// Reference: official xxHash C - XXH3_initCustomSecret_sse2 in xxhash.h

  // Build seed vector xmm0 = [seed, -seed]
  movq xmm0, r8
  mov rax, r8
  neg rax
  movq xmm1, rax
  punpcklqdq xmm0, xmm1

  // Block 0
  movdqu xmm1, oword [rdx]
  paddq xmm1, xmm0
  movdqu oword [rcx], xmm1

  // Block 1
  movdqu xmm1, oword [rdx + $10]
  paddq xmm1, xmm0
  movdqu oword [rcx + $10], xmm1

  // Block 2
  movdqu xmm1, oword [rdx + $20]
  paddq xmm1, xmm0
  movdqu oword [rcx + $20], xmm1

  // Block 3
  movdqu xmm1, oword [rdx + $30]
  paddq xmm1, xmm0
  movdqu oword [rcx + $30], xmm1

  // Block 4
  movdqu xmm1, oword [rdx + $40]
  paddq xmm1, xmm0
  movdqu oword [rcx + $40], xmm1

  // Block 5
  movdqu xmm1, oword [rdx + $50]
  paddq xmm1, xmm0
  movdqu oword [rcx + $50], xmm1

  // Block 6
  movdqu xmm1, oword [rdx + $60]
  paddq xmm1, xmm0
  movdqu oword [rcx + $60], xmm1

  // Block 7
  movdqu xmm1, oword [rdx + $70]
  paddq xmm1, xmm0
  movdqu oword [rcx + $70], xmm1

  // Block 8
  movdqu xmm1, oword [rdx + $80]
  paddq xmm1, xmm0
  movdqu oword [rcx + $80], xmm1

  // Block 9
  movdqu xmm1, oword [rdx + $90]
  paddq xmm1, xmm0
  movdqu oword [rcx + $90], xmm1

  // Block 10
  movdqu xmm1, oword [rdx + $A0]
  paddq xmm1, xmm0
  movdqu oword [rcx + $A0], xmm1

  // Block 11
  movdqu xmm1, oword [rdx + $B0]
  paddq xmm1, xmm0
  movdqu oword [rcx + $B0], xmm1
