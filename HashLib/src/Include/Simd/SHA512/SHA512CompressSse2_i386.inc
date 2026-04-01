// SHA-512 SSE2 implementation (IA-32).
// Based on SHA512CompressSse2_x86_64.inc (x86-64); same algorithm.
// IA-32: after SimdProc4Begin_i386 — ebx = state, esi = data, edi = numblocks, eax = K512 ptr
//   (parallel to MS x64 ABI: rcx, rdx, r8d, r9).
// K512: 80 UInt64 round constants (640 bytes).
// Phase 1: SSE2 xmm0/xmm4; ebx = W ring @ [esp+$2F0], ebp = W+K @ [esp+$70].
// Phase 2: rax..r11 in [esp+880]..[esp+936] (8 qwords).
// Scratch: expand [esp+$3B8]..$3E0; shrd [esp+1000]/[esp+1004]; and M,M [esp+1008]..1015.
// After expand, [esp+$3BC] = W+K end ptr (K512 ptr only during expand); x64 r15 equivalent.


  sub esp, 1016

{$IFDEF MSWINDOWS}
  movdqu oword ptr [esp], xmm6
  movdqu oword ptr [esp + $10], xmm7
{$ENDIF}
  mov dword ptr [esp + $20], ebx
  mov dword ptr [esp + $24], esi
  mov dword ptr [esp + $28], edi
  mov dword ptr [esp + $2C], eax
  mov dword ptr [esp + $30], ebp

  cmp dword ptr [esp + $28], 0
  jz @sse2_512_done

@sse2_512_block_loop:
  mov eax, dword ptr [esp + $2C]
  lea ebp, [esp + $70]
  lea ebx, [esp + $2F0]
  mov esi, dword ptr [esp + $24]

  movdqu xmm0, oword ptr [esi+$0]
  pshuflw xmm0, xmm0, $1B
  pshufhw xmm0, xmm0, $1B
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqu oword ptr [ebx+$0], xmm0
  movdqu xmm4, oword ptr [eax+$0]
  paddq  xmm4, xmm0
  movdqu oword ptr [ebp+$0], xmm4

  movdqu xmm0, oword ptr [esi+$10]
  pshuflw xmm0, xmm0, $1B
  pshufhw xmm0, xmm0, $1B
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqu oword ptr [ebx+$10], xmm0
  movdqu xmm4, oword ptr [eax+$10]
  paddq  xmm4, xmm0
  movdqu oword ptr [ebp+$10], xmm4

  movdqu xmm0, oword ptr [esi+$20]
  pshuflw xmm0, xmm0, $1B
  pshufhw xmm0, xmm0, $1B
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqu oword ptr [ebx+$20], xmm0
  movdqu xmm4, oword ptr [eax+$20]
  paddq  xmm4, xmm0
  movdqu oword ptr [ebp+$20], xmm4

  movdqu xmm0, oword ptr [esi+$30]
  pshuflw xmm0, xmm0, $1B
  pshufhw xmm0, xmm0, $1B
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqu oword ptr [ebx+$30], xmm0
  movdqu xmm4, oword ptr [eax+$30]
  paddq  xmm4, xmm0
  movdqu oword ptr [ebp+$30], xmm4

  movdqu xmm0, oword ptr [esi+$40]
  pshuflw xmm0, xmm0, $1B
  pshufhw xmm0, xmm0, $1B
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqu oword ptr [ebx+$40], xmm0
  movdqu xmm4, oword ptr [eax+$40]
  paddq  xmm4, xmm0
  movdqu oword ptr [ebp+$40], xmm4

  movdqu xmm0, oword ptr [esi+$50]
  pshuflw xmm0, xmm0, $1B
  pshufhw xmm0, xmm0, $1B
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqu oword ptr [ebx+$50], xmm0
  movdqu xmm4, oword ptr [eax+$50]
  paddq  xmm4, xmm0
  movdqu oword ptr [ebp+$50], xmm4

  movdqu xmm0, oword ptr [esi+$60]
  pshuflw xmm0, xmm0, $1B
  pshufhw xmm0, xmm0, $1B
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqu oword ptr [ebx+$60], xmm0
  movdqu xmm4, oword ptr [eax+$60]
  paddq  xmm4, xmm0
  movdqu oword ptr [ebp+$60], xmm4

  movdqu xmm0, oword ptr [esi+$70]
  pshuflw xmm0, xmm0, $1B
  pshufhw xmm0, xmm0, $1B
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqu oword ptr [ebx+$70], xmm0
  movdqu xmm4, oword ptr [eax+$70]
  paddq  xmm4, xmm0
  movdqu oword ptr [ebp+$70], xmm4

  mov dword ptr [esp + $3BC], eax

  mov dword ptr [esp + $3B8], 16

@sse2_512_expand_loop:
  mov ecx, dword ptr [esp + $3B8]
  mov edx, ecx
  sub edx, 2
  and edx, 15
  mov esi, dword ptr [ebx+edx*8]
  mov edi, dword ptr [ebx+edx*8+4]

  mov eax, esi
  mov edx, edi
  mov dword ptr [esp + $3E0], ecx
  mov ecx, eax
  shrd eax, edx, 19
  shrd edx, ecx, 19
  mov ecx, dword ptr [esp + $3E0]
  mov dword ptr [esp + $3C0], eax
  mov dword ptr [esp + $3C4], edx

  mov eax, esi
  mov edx, edi
  mov dword ptr [esp + $3E0], ecx
  xchg eax, edx
  mov ecx, eax
  shrd eax, edx, 29
  shrd edx, ecx, 29
  mov ecx, dword ptr [esp + $3E0]
  xor dword ptr [esp + $3C0], eax
  xor dword ptr [esp + $3C4], edx

  mov eax, esi
  mov edx, edi
  shrd eax, edx, 6
  shr edx, 6
  xor dword ptr [esp + $3C0], eax
  xor dword ptr [esp + $3C4], edx

  mov ecx, dword ptr [esp + $3B8]
  mov esi, ecx
  sub esi, 7
  and esi, 15
  mov eax, dword ptr [ebx+esi*8]
  mov edx, dword ptr [ebx+esi*8+4]
  add eax, dword ptr [esp + $3C0]
  adc edx, dword ptr [esp + $3C4]
  mov dword ptr [esp + $3C0], eax
  mov dword ptr [esp + $3C4], edx

  mov ecx, dword ptr [esp + $3B8]
  mov esi, ecx
  sub esi, 15
  and esi, 15
  mov eax, dword ptr [ebx+esi*8]
  mov edx, dword ptr [ebx+esi*8+4]

  mov esi, eax
  mov edi, edx
  mov eax, esi
  mov edx, edi
  mov dword ptr [esp + $3E0], ecx
  mov ecx, eax
  shrd eax, edx, 1
  shrd edx, ecx, 1
  mov ecx, dword ptr [esp + $3E0]
  mov dword ptr [esp + $3C8], eax
  mov dword ptr [esp + $3CC], edx

  mov eax, esi
  mov edx, edi
  mov dword ptr [esp + $3E0], ecx
  mov ecx, eax
  shrd eax, edx, 8
  shrd edx, ecx, 8
  mov ecx, dword ptr [esp + $3E0]
  xor dword ptr [esp + $3C8], eax
  xor dword ptr [esp + $3CC], edx

  mov eax, esi
  mov edx, edi
  shrd eax, edx, 7
  shr edx, 7
  xor dword ptr [esp + $3C8], eax
  xor dword ptr [esp + $3CC], edx

  mov eax, dword ptr [esp + $3C0]
  mov edx, dword ptr [esp + $3C4]
  add eax, dword ptr [esp + $3C8]
  adc edx, dword ptr [esp + $3CC]
  mov dword ptr [esp + $3C0], eax
  mov dword ptr [esp + $3C4], edx

  mov ecx, dword ptr [esp + $3B8]
  mov esi, ecx
  sub esi, 16
  and esi, 15
  add eax, dword ptr [ebx+esi*8]
  adc edx, dword ptr [ebx+esi*8+4]

  mov ecx, dword ptr [esp + $3B8]
  mov esi, ecx
  and esi, 15
  mov dword ptr [ebx+esi*8], eax
  mov dword ptr [ebx+esi*8+4], edx

  mov dword ptr [esp + $3D0], eax
  mov dword ptr [esp + $3D4], edx
  mov ecx, dword ptr [esp + $3B8]
  mov eax, dword ptr [esp + $3BC]
  mov esi, dword ptr [eax+ecx*8]
  mov edi, dword ptr [eax+ecx*8+4]
  add esi, dword ptr [esp + $3D0]
  adc edi, dword ptr [esp + $3D4]
  mov dword ptr [ebp+ecx*8], esi
  mov dword ptr [ebp+ecx*8+4], edi

  inc dword ptr [esp + $3B8]
  mov ecx, dword ptr [esp + $3B8]
  cmp ecx, 80
  jb @sse2_512_expand_loop
  mov esi, dword ptr [esp+$20]
  mov eax, dword ptr [esi+$0]
  mov edx, dword ptr [esi+$0+4]
  mov dword ptr [esp+880], eax
  mov dword ptr [esp+880+4], edx
  mov eax, dword ptr [esi+$8]
  mov edx, dword ptr [esi+$8+4]
  mov dword ptr [esp+888], eax
  mov dword ptr [esp+888+4], edx
  mov eax, dword ptr [esi+$10]
  mov edx, dword ptr [esi+$10+4]
  mov dword ptr [esp+896], eax
  mov dword ptr [esp+896+4], edx
  mov eax, dword ptr [esi+$18]
  mov edx, dword ptr [esi+$18+4]
  mov dword ptr [esp+904], eax
  mov dword ptr [esp+904+4], edx
  mov eax, dword ptr [esi+$20]
  mov edx, dword ptr [esi+$20+4]
  mov dword ptr [esp+912], eax
  mov dword ptr [esp+912+4], edx
  mov eax, dword ptr [esi+$28]
  mov edx, dword ptr [esi+$28+4]
  mov dword ptr [esp+920], eax
  mov dword ptr [esp+920+4], edx
  mov eax, dword ptr [esi+$30]
  mov edx, dword ptr [esi+$30+4]
  mov dword ptr [esp+928], eax
  mov dword ptr [esp+928+4], edx
  mov eax, dword ptr [esi+$38]
  mov edx, dword ptr [esi+$38+4]
  mov dword ptr [esp+936], eax
  mov dword ptr [esp+936+4], edx

  lea eax, [ebp + $280]
  mov dword ptr [esp + $3BC], eax

@sse2_512_round_loop:
  mov esi, dword ptr [esp+912]
  mov edi, dword ptr [esp+912+4]
  mov ebx, dword ptr [esp+912]
  mov ecx, dword ptr [esp+912+4]
  mov dword ptr [esp+1000], esi
  shrd esi, edi, 14
  mov eax, dword ptr [esp+1000]
  shrd edi, eax, 14
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 18
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 18
  xor esi, ebx
  xor edi, ecx
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 23
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 23
  xor esi, ebx
  xor edi, ecx
  mov ebx, dword ptr [esp+920]
  mov ecx, dword ptr [esp+920+4]
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  and ebx, eax
  and ecx, edx
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  add esi, eax
  adc edi, edx
  add esi, ebx
  adc edi, ecx
  add esi, dword ptr [ebp+0]
  adc edi, dword ptr [ebp+0+4]
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  add eax, esi
  adc edx, edi
  mov dword ptr [esp+904], eax
  mov dword ptr [esp+904+4], edx
  mov ebx, dword ptr [esp+880]
  mov ecx, dword ptr [esp+880+4]
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  mov dword ptr [esp+936], eax
  mov dword ptr [esp+936+4], edx
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 28
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 28
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  xchg eax, edx
  mov dword ptr [esp+1000], eax
  shrd eax, edx, 2
  mov dword ptr [esp+1004], eax
  mov eax, dword ptr [esp+1000]
  shrd edx, eax, 2
  mov eax, dword ptr [esp+1004]
  mov dword ptr [esp+936], eax
  mov dword ptr [esp+936+4], edx
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  mov dword ptr [esp+1000], eax
  shrd eax, edx, 5
  mov dword ptr [esp+1004], eax
  mov eax, dword ptr [esp+1000]
  shrd edx, eax, 5
  mov eax, dword ptr [esp+1004]
  mov dword ptr [esp+936], eax
  mov dword ptr [esp+936+4], edx
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  xor ebx, eax
  xor ecx, edx
  add esi, ebx
  adc edi, ecx
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  mov dword ptr [esp+936], eax
  mov dword ptr [esp+936+4], edx
  mov eax, dword ptr [esp+888]
  mov dword ptr [esp+1008], eax
  mov eax, dword ptr [esp+888+4]
  mov dword ptr [esp+1008+4], eax
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  and eax, dword ptr [esp+1008]
  and edx, dword ptr [esp+1008+4]
  mov dword ptr [esp+936], eax
  mov dword ptr [esp+936+4], edx
  mov ebx, dword ptr [esp+880]
  mov ecx, dword ptr [esp+880+4]
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  and ebx, eax
  and ecx, edx
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  xor eax, ebx
  xor edx, ecx
  mov dword ptr [esp+936], eax
  mov dword ptr [esp+936+4], edx
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  add eax, esi
  adc edx, edi
  mov dword ptr [esp+936], eax
  mov dword ptr [esp+936+4], edx
  mov esi, dword ptr [esp+904]
  mov edi, dword ptr [esp+904+4]
  mov ebx, dword ptr [esp+904]
  mov ecx, dword ptr [esp+904+4]
  mov dword ptr [esp+1000], esi
  shrd esi, edi, 14
  mov eax, dword ptr [esp+1000]
  shrd edi, eax, 14
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 18
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 18
  xor esi, ebx
  xor edi, ecx
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 23
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 23
  xor esi, ebx
  xor edi, ecx
  mov ebx, dword ptr [esp+912]
  mov ecx, dword ptr [esp+912+4]
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  and ebx, eax
  and ecx, edx
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  add esi, eax
  adc edi, edx
  add esi, ebx
  adc edi, ecx
  add esi, dword ptr [ebp+8]
  adc edi, dword ptr [ebp+8+4]
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  add eax, esi
  adc edx, edi
  mov dword ptr [esp+896], eax
  mov dword ptr [esp+896+4], edx
  mov ebx, dword ptr [esp+936]
  mov ecx, dword ptr [esp+936+4]
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  mov dword ptr [esp+928], eax
  mov dword ptr [esp+928+4], edx
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 28
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 28
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  xchg eax, edx
  mov dword ptr [esp+1000], eax
  shrd eax, edx, 2
  mov dword ptr [esp+1004], eax
  mov eax, dword ptr [esp+1000]
  shrd edx, eax, 2
  mov eax, dword ptr [esp+1004]
  mov dword ptr [esp+928], eax
  mov dword ptr [esp+928+4], edx
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  mov dword ptr [esp+1000], eax
  shrd eax, edx, 5
  mov dword ptr [esp+1004], eax
  mov eax, dword ptr [esp+1000]
  shrd edx, eax, 5
  mov eax, dword ptr [esp+1004]
  mov dword ptr [esp+928], eax
  mov dword ptr [esp+928+4], edx
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  xor ebx, eax
  xor ecx, edx
  add esi, ebx
  adc edi, ecx
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  mov dword ptr [esp+928], eax
  mov dword ptr [esp+928+4], edx
  mov eax, dword ptr [esp+880]
  mov dword ptr [esp+1008], eax
  mov eax, dword ptr [esp+880+4]
  mov dword ptr [esp+1008+4], eax
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  and eax, dword ptr [esp+1008]
  and edx, dword ptr [esp+1008+4]
  mov dword ptr [esp+928], eax
  mov dword ptr [esp+928+4], edx
  mov ebx, dword ptr [esp+936]
  mov ecx, dword ptr [esp+936+4]
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  and ebx, eax
  and ecx, edx
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  xor eax, ebx
  xor edx, ecx
  mov dword ptr [esp+928], eax
  mov dword ptr [esp+928+4], edx
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  add eax, esi
  adc edx, edi
  mov dword ptr [esp+928], eax
  mov dword ptr [esp+928+4], edx
  mov esi, dword ptr [esp+896]
  mov edi, dword ptr [esp+896+4]
  mov ebx, dword ptr [esp+896]
  mov ecx, dword ptr [esp+896+4]
  mov dword ptr [esp+1000], esi
  shrd esi, edi, 14
  mov eax, dword ptr [esp+1000]
  shrd edi, eax, 14
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 18
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 18
  xor esi, ebx
  xor edi, ecx
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 23
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 23
  xor esi, ebx
  xor edi, ecx
  mov ebx, dword ptr [esp+904]
  mov ecx, dword ptr [esp+904+4]
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  and ebx, eax
  and ecx, edx
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  add esi, eax
  adc edi, edx
  add esi, ebx
  adc edi, ecx
  add esi, dword ptr [ebp+16]
  adc edi, dword ptr [ebp+16+4]
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  add eax, esi
  adc edx, edi
  mov dword ptr [esp+888], eax
  mov dword ptr [esp+888+4], edx
  mov ebx, dword ptr [esp+928]
  mov ecx, dword ptr [esp+928+4]
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  mov dword ptr [esp+920], eax
  mov dword ptr [esp+920+4], edx
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 28
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 28
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  xchg eax, edx
  mov dword ptr [esp+1000], eax
  shrd eax, edx, 2
  mov dword ptr [esp+1004], eax
  mov eax, dword ptr [esp+1000]
  shrd edx, eax, 2
  mov eax, dword ptr [esp+1004]
  mov dword ptr [esp+920], eax
  mov dword ptr [esp+920+4], edx
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  mov dword ptr [esp+1000], eax
  shrd eax, edx, 5
  mov dword ptr [esp+1004], eax
  mov eax, dword ptr [esp+1000]
  shrd edx, eax, 5
  mov eax, dword ptr [esp+1004]
  mov dword ptr [esp+920], eax
  mov dword ptr [esp+920+4], edx
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  xor ebx, eax
  xor ecx, edx
  add esi, ebx
  adc edi, ecx
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  mov dword ptr [esp+920], eax
  mov dword ptr [esp+920+4], edx
  mov eax, dword ptr [esp+936]
  mov dword ptr [esp+1008], eax
  mov eax, dword ptr [esp+936+4]
  mov dword ptr [esp+1008+4], eax
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  and eax, dword ptr [esp+1008]
  and edx, dword ptr [esp+1008+4]
  mov dword ptr [esp+920], eax
  mov dword ptr [esp+920+4], edx
  mov ebx, dword ptr [esp+928]
  mov ecx, dword ptr [esp+928+4]
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  and ebx, eax
  and ecx, edx
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  xor eax, ebx
  xor edx, ecx
  mov dword ptr [esp+920], eax
  mov dword ptr [esp+920+4], edx
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  add eax, esi
  adc edx, edi
  mov dword ptr [esp+920], eax
  mov dword ptr [esp+920+4], edx
  mov esi, dword ptr [esp+888]
  mov edi, dword ptr [esp+888+4]
  mov ebx, dword ptr [esp+888]
  mov ecx, dword ptr [esp+888+4]
  mov dword ptr [esp+1000], esi
  shrd esi, edi, 14
  mov eax, dword ptr [esp+1000]
  shrd edi, eax, 14
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 18
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 18
  xor esi, ebx
  xor edi, ecx
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 23
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 23
  xor esi, ebx
  xor edi, ecx
  mov ebx, dword ptr [esp+896]
  mov ecx, dword ptr [esp+896+4]
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  and ebx, eax
  and ecx, edx
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  add esi, eax
  adc edi, edx
  add esi, ebx
  adc edi, ecx
  add esi, dword ptr [ebp+24]
  adc edi, dword ptr [ebp+24+4]
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  add eax, esi
  adc edx, edi
  mov dword ptr [esp+880], eax
  mov dword ptr [esp+880+4], edx
  mov ebx, dword ptr [esp+920]
  mov ecx, dword ptr [esp+920+4]
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  mov dword ptr [esp+912], eax
  mov dword ptr [esp+912+4], edx
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 28
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 28
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  xchg eax, edx
  mov dword ptr [esp+1000], eax
  shrd eax, edx, 2
  mov dword ptr [esp+1004], eax
  mov eax, dword ptr [esp+1000]
  shrd edx, eax, 2
  mov eax, dword ptr [esp+1004]
  mov dword ptr [esp+912], eax
  mov dword ptr [esp+912+4], edx
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  mov dword ptr [esp+1000], eax
  shrd eax, edx, 5
  mov dword ptr [esp+1004], eax
  mov eax, dword ptr [esp+1000]
  shrd edx, eax, 5
  mov eax, dword ptr [esp+1004]
  mov dword ptr [esp+912], eax
  mov dword ptr [esp+912+4], edx
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  xor ebx, eax
  xor ecx, edx
  add esi, ebx
  adc edi, ecx
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  mov dword ptr [esp+912], eax
  mov dword ptr [esp+912+4], edx
  mov eax, dword ptr [esp+928]
  mov dword ptr [esp+1008], eax
  mov eax, dword ptr [esp+928+4]
  mov dword ptr [esp+1008+4], eax
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  and eax, dword ptr [esp+1008]
  and edx, dword ptr [esp+1008+4]
  mov dword ptr [esp+912], eax
  mov dword ptr [esp+912+4], edx
  mov ebx, dword ptr [esp+920]
  mov ecx, dword ptr [esp+920+4]
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  and ebx, eax
  and ecx, edx
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  xor eax, ebx
  xor edx, ecx
  mov dword ptr [esp+912], eax
  mov dword ptr [esp+912+4], edx
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  add eax, esi
  adc edx, edi
  mov dword ptr [esp+912], eax
  mov dword ptr [esp+912+4], edx
  mov esi, dword ptr [esp+880]
  mov edi, dword ptr [esp+880+4]
  mov ebx, dword ptr [esp+880]
  mov ecx, dword ptr [esp+880+4]
  mov dword ptr [esp+1000], esi
  shrd esi, edi, 14
  mov eax, dword ptr [esp+1000]
  shrd edi, eax, 14
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 18
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 18
  xor esi, ebx
  xor edi, ecx
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 23
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 23
  xor esi, ebx
  xor edi, ecx
  mov ebx, dword ptr [esp+888]
  mov ecx, dword ptr [esp+888+4]
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  and ebx, eax
  and ecx, edx
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  add esi, eax
  adc edi, edx
  add esi, ebx
  adc edi, ecx
  add esi, dword ptr [ebp+32]
  adc edi, dword ptr [ebp+32+4]
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  add eax, esi
  adc edx, edi
  mov dword ptr [esp+936], eax
  mov dword ptr [esp+936+4], edx
  mov ebx, dword ptr [esp+912]
  mov ecx, dword ptr [esp+912+4]
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  mov dword ptr [esp+904], eax
  mov dword ptr [esp+904+4], edx
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 28
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 28
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  xchg eax, edx
  mov dword ptr [esp+1000], eax
  shrd eax, edx, 2
  mov dword ptr [esp+1004], eax
  mov eax, dword ptr [esp+1000]
  shrd edx, eax, 2
  mov eax, dword ptr [esp+1004]
  mov dword ptr [esp+904], eax
  mov dword ptr [esp+904+4], edx
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  mov dword ptr [esp+1000], eax
  shrd eax, edx, 5
  mov dword ptr [esp+1004], eax
  mov eax, dword ptr [esp+1000]
  shrd edx, eax, 5
  mov eax, dword ptr [esp+1004]
  mov dword ptr [esp+904], eax
  mov dword ptr [esp+904+4], edx
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  xor ebx, eax
  xor ecx, edx
  add esi, ebx
  adc edi, ecx
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  mov dword ptr [esp+904], eax
  mov dword ptr [esp+904+4], edx
  mov eax, dword ptr [esp+920]
  mov dword ptr [esp+1008], eax
  mov eax, dword ptr [esp+920+4]
  mov dword ptr [esp+1008+4], eax
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  and eax, dword ptr [esp+1008]
  and edx, dword ptr [esp+1008+4]
  mov dword ptr [esp+904], eax
  mov dword ptr [esp+904+4], edx
  mov ebx, dword ptr [esp+912]
  mov ecx, dword ptr [esp+912+4]
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  and ebx, eax
  and ecx, edx
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  xor eax, ebx
  xor edx, ecx
  mov dword ptr [esp+904], eax
  mov dword ptr [esp+904+4], edx
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  add eax, esi
  adc edx, edi
  mov dword ptr [esp+904], eax
  mov dword ptr [esp+904+4], edx
  mov esi, dword ptr [esp+936]
  mov edi, dword ptr [esp+936+4]
  mov ebx, dword ptr [esp+936]
  mov ecx, dword ptr [esp+936+4]
  mov dword ptr [esp+1000], esi
  shrd esi, edi, 14
  mov eax, dword ptr [esp+1000]
  shrd edi, eax, 14
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 18
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 18
  xor esi, ebx
  xor edi, ecx
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 23
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 23
  xor esi, ebx
  xor edi, ecx
  mov ebx, dword ptr [esp+880]
  mov ecx, dword ptr [esp+880+4]
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  and ebx, eax
  and ecx, edx
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  add esi, eax
  adc edi, edx
  add esi, ebx
  adc edi, ecx
  add esi, dword ptr [ebp+40]
  adc edi, dword ptr [ebp+40+4]
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  add eax, esi
  adc edx, edi
  mov dword ptr [esp+928], eax
  mov dword ptr [esp+928+4], edx
  mov ebx, dword ptr [esp+904]
  mov ecx, dword ptr [esp+904+4]
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  mov dword ptr [esp+896], eax
  mov dword ptr [esp+896+4], edx
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 28
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 28
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  xchg eax, edx
  mov dword ptr [esp+1000], eax
  shrd eax, edx, 2
  mov dword ptr [esp+1004], eax
  mov eax, dword ptr [esp+1000]
  shrd edx, eax, 2
  mov eax, dword ptr [esp+1004]
  mov dword ptr [esp+896], eax
  mov dword ptr [esp+896+4], edx
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  mov dword ptr [esp+1000], eax
  shrd eax, edx, 5
  mov dword ptr [esp+1004], eax
  mov eax, dword ptr [esp+1000]
  shrd edx, eax, 5
  mov eax, dword ptr [esp+1004]
  mov dword ptr [esp+896], eax
  mov dword ptr [esp+896+4], edx
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  xor ebx, eax
  xor ecx, edx
  add esi, ebx
  adc edi, ecx
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  mov dword ptr [esp+896], eax
  mov dword ptr [esp+896+4], edx
  mov eax, dword ptr [esp+912]
  mov dword ptr [esp+1008], eax
  mov eax, dword ptr [esp+912+4]
  mov dword ptr [esp+1008+4], eax
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  and eax, dword ptr [esp+1008]
  and edx, dword ptr [esp+1008+4]
  mov dword ptr [esp+896], eax
  mov dword ptr [esp+896+4], edx
  mov ebx, dword ptr [esp+904]
  mov ecx, dword ptr [esp+904+4]
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  and ebx, eax
  and ecx, edx
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  xor eax, ebx
  xor edx, ecx
  mov dword ptr [esp+896], eax
  mov dword ptr [esp+896+4], edx
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  add eax, esi
  adc edx, edi
  mov dword ptr [esp+896], eax
  mov dword ptr [esp+896+4], edx
  mov esi, dword ptr [esp+928]
  mov edi, dword ptr [esp+928+4]
  mov ebx, dword ptr [esp+928]
  mov ecx, dword ptr [esp+928+4]
  mov dword ptr [esp+1000], esi
  shrd esi, edi, 14
  mov eax, dword ptr [esp+1000]
  shrd edi, eax, 14
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 18
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 18
  xor esi, ebx
  xor edi, ecx
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 23
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 23
  xor esi, ebx
  xor edi, ecx
  mov ebx, dword ptr [esp+936]
  mov ecx, dword ptr [esp+936+4]
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  and ebx, eax
  and ecx, edx
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  add esi, eax
  adc edi, edx
  add esi, ebx
  adc edi, ecx
  add esi, dword ptr [ebp+48]
  adc edi, dword ptr [ebp+48+4]
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  add eax, esi
  adc edx, edi
  mov dword ptr [esp+920], eax
  mov dword ptr [esp+920+4], edx
  mov ebx, dword ptr [esp+896]
  mov ecx, dword ptr [esp+896+4]
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  mov dword ptr [esp+888], eax
  mov dword ptr [esp+888+4], edx
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 28
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 28
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  xchg eax, edx
  mov dword ptr [esp+1000], eax
  shrd eax, edx, 2
  mov dword ptr [esp+1004], eax
  mov eax, dword ptr [esp+1000]
  shrd edx, eax, 2
  mov eax, dword ptr [esp+1004]
  mov dword ptr [esp+888], eax
  mov dword ptr [esp+888+4], edx
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  mov dword ptr [esp+1000], eax
  shrd eax, edx, 5
  mov dword ptr [esp+1004], eax
  mov eax, dword ptr [esp+1000]
  shrd edx, eax, 5
  mov eax, dword ptr [esp+1004]
  mov dword ptr [esp+888], eax
  mov dword ptr [esp+888+4], edx
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  xor ebx, eax
  xor ecx, edx
  add esi, ebx
  adc edi, ecx
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  mov dword ptr [esp+888], eax
  mov dword ptr [esp+888+4], edx
  mov eax, dword ptr [esp+904]
  mov dword ptr [esp+1008], eax
  mov eax, dword ptr [esp+904+4]
  mov dword ptr [esp+1008+4], eax
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  and eax, dword ptr [esp+1008]
  and edx, dword ptr [esp+1008+4]
  mov dword ptr [esp+888], eax
  mov dword ptr [esp+888+4], edx
  mov ebx, dword ptr [esp+896]
  mov ecx, dword ptr [esp+896+4]
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  and ebx, eax
  and ecx, edx
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  xor eax, ebx
  xor edx, ecx
  mov dword ptr [esp+888], eax
  mov dword ptr [esp+888+4], edx
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  add eax, esi
  adc edx, edi
  mov dword ptr [esp+888], eax
  mov dword ptr [esp+888+4], edx
  mov esi, dword ptr [esp+920]
  mov edi, dword ptr [esp+920+4]
  mov ebx, dword ptr [esp+920]
  mov ecx, dword ptr [esp+920+4]
  mov dword ptr [esp+1000], esi
  shrd esi, edi, 14
  mov eax, dword ptr [esp+1000]
  shrd edi, eax, 14
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 18
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 18
  xor esi, ebx
  xor edi, ecx
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 23
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 23
  xor esi, ebx
  xor edi, ecx
  mov ebx, dword ptr [esp+928]
  mov ecx, dword ptr [esp+928+4]
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  and ebx, eax
  and ecx, edx
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  add esi, eax
  adc edi, edx
  add esi, ebx
  adc edi, ecx
  add esi, dword ptr [ebp+56]
  adc edi, dword ptr [ebp+56+4]
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  add eax, esi
  adc edx, edi
  mov dword ptr [esp+912], eax
  mov dword ptr [esp+912+4], edx
  mov ebx, dword ptr [esp+888]
  mov ecx, dword ptr [esp+888+4]
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  mov dword ptr [esp+880], eax
  mov dword ptr [esp+880+4], edx
  mov dword ptr [esp+1000], ebx
  shrd ebx, ecx, 28
  mov eax, dword ptr [esp+1000]
  shrd ecx, eax, 28
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  xchg eax, edx
  mov dword ptr [esp+1000], eax
  shrd eax, edx, 2
  mov dword ptr [esp+1004], eax
  mov eax, dword ptr [esp+1000]
  shrd edx, eax, 2
  mov eax, dword ptr [esp+1004]
  mov dword ptr [esp+880], eax
  mov dword ptr [esp+880+4], edx
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  mov dword ptr [esp+1000], eax
  shrd eax, edx, 5
  mov dword ptr [esp+1004], eax
  mov eax, dword ptr [esp+1000]
  shrd edx, eax, 5
  mov eax, dword ptr [esp+1004]
  mov dword ptr [esp+880], eax
  mov dword ptr [esp+880+4], edx
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  xor ebx, eax
  xor ecx, edx
  add esi, ebx
  adc edi, ecx
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  mov dword ptr [esp+880], eax
  mov dword ptr [esp+880+4], edx
  mov eax, dword ptr [esp+896]
  mov dword ptr [esp+1008], eax
  mov eax, dword ptr [esp+896+4]
  mov dword ptr [esp+1008+4], eax
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  and eax, dword ptr [esp+1008]
  and edx, dword ptr [esp+1008+4]
  mov dword ptr [esp+880], eax
  mov dword ptr [esp+880+4], edx
  mov ebx, dword ptr [esp+888]
  mov ecx, dword ptr [esp+888+4]
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  xor ebx, eax
  xor ecx, edx
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  and ebx, eax
  and ecx, edx
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  xor eax, ebx
  xor edx, ecx
  mov dword ptr [esp+880], eax
  mov dword ptr [esp+880+4], edx
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  add eax, esi
  adc edx, edi
  mov dword ptr [esp+880], eax
  mov dword ptr [esp+880+4], edx
  add ebp, $40
  mov eax, dword ptr [esp + $3BC]
  cmp ebp, eax
  jb @sse2_512_round_loop
  mov esi, dword ptr [esp+$20]
  mov eax, dword ptr [esp+880]
  mov edx, dword ptr [esp+880+4]
  add dword ptr [esi+$0], eax
  adc dword ptr [esi+$0+4], edx
  mov eax, dword ptr [esp+888]
  mov edx, dword ptr [esp+888+4]
  add dword ptr [esi+$8], eax
  adc dword ptr [esi+$8+4], edx
  mov eax, dword ptr [esp+896]
  mov edx, dword ptr [esp+896+4]
  add dword ptr [esi+$10], eax
  adc dword ptr [esi+$10+4], edx
  mov eax, dword ptr [esp+904]
  mov edx, dword ptr [esp+904+4]
  add dword ptr [esi+$18], eax
  adc dword ptr [esi+$18+4], edx
  mov eax, dword ptr [esp+912]
  mov edx, dword ptr [esp+912+4]
  add dword ptr [esi+$20], eax
  adc dword ptr [esi+$20+4], edx
  mov eax, dword ptr [esp+920]
  mov edx, dword ptr [esp+920+4]
  add dword ptr [esi+$28], eax
  adc dword ptr [esi+$28+4], edx
  mov eax, dword ptr [esp+928]
  mov edx, dword ptr [esp+928+4]
  add dword ptr [esi+$30], eax
  adc dword ptr [esi+$30+4], edx
  mov eax, dword ptr [esp+936]
  mov edx, dword ptr [esp+936+4]
  add dword ptr [esi+$38], eax
  adc dword ptr [esi+$38+4], edx

  mov esi, dword ptr [esp+$24]
  add esi, $80
  mov dword ptr [esp+$24], esi
  dec dword ptr [esp+$28]
  jnz @sse2_512_block_loop

@sse2_512_done:
{$IFDEF MSWINDOWS}
  movdqu xmm6, oword ptr [esp]
  movdqu xmm7, oword ptr [esp + $10]
{$ENDIF}
  mov ebp, dword ptr [esp + $30]
  add esp, 1016
  pop edi
  pop esi
  pop ebx
