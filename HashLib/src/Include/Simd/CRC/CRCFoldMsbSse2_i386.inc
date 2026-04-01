// MSB-first 64-bit CRC: 16-byte slice (IA-32; SSE2 not required — same as x64 MSB path).
// x64 counterpart: CRCFoldMsbSse2_x86_64.inc (Width/CrcMask at +224/+228).
// After SimdProc4Begin_i386: ebx = AData, esi = ALength, edi = AState, eax = Ctx.
// Offsets (packed TCRCFoldRuntimeCtx64, 32-bit ptrs): TableRow +96, Width +160,
//   CrcMask +164 (x86-64 uses +224/+228 because TableRow entries are 8 bytes).
// Result UInt64 in edx:eax.

  push ebp
  mov ebp, eax

  sub esp, 40
  // [esp+0..7]   LTempCopy
  // [esp+8..15]  CrcMask
  // [esp+16]     LCrcBytes
  // [esp+20]     shift count (Width - 8)
  // [esp+24..31] LNewTemp
  // [esp+32]     LBIdx
  // [esp+36]     saved esi (remaining length)

@MsbSse2_outer:
  cmp esi, 16
  jb @MsbSse2_done

  mov dword ptr [esp + 36], esi

  mov eax, dword ptr [ebp + 160]
  add eax, 7
  shr eax, 3
  mov dword ptr [esp + 16], eax

  mov eax, dword ptr [ebp + 160]
  sub eax, 8
  mov dword ptr [esp + 20], eax

  mov eax, dword ptr [ebp + 164]
  mov dword ptr [esp + 8], eax
  mov eax, dword ptr [ebp + 168]
  mov dword ptr [esp + 12], eax

  mov eax, dword ptr [edi]
  mov edx, dword ptr [edi + 4]
  mov dword ptr [esp], eax
  mov dword ptr [esp + 4], edx

  xor eax, eax
  mov dword ptr [esp + 24], eax
  mov dword ptr [esp + 28], eax
  mov dword ptr [esp + 32], 0

@MsbSse2_m1:
  mov eax, dword ptr [esp + 32]
  cmp eax, dword ptr [esp + 16]
  jge @MsbSse2_m2

  mov eax, dword ptr [esp]
  mov edx, dword ptr [esp + 4]
  mov ecx, dword ptr [esp + 20]
  cmp ecx, 32
  jae @MsbSse2_m1_sh_hi
  shrd eax, edx, cl
  shr edx, cl
  jmp @MsbSse2_m1_sh_done
@MsbSse2_m1_sh_hi:
  sub ecx, 32
  mov eax, edx
  xor edx, edx
  shr eax, cl
@MsbSse2_m1_sh_done:
  movzx eax, al

  mov ecx, dword ptr [esp + 32]
  movzx ecx, byte ptr [ebx + ecx]
  xor eax, ecx

  mov ecx, 15
  sub ecx, dword ptr [esp + 32]
  mov esi, dword ptr [ebp + 96 + ecx * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 24], ecx
  xor dword ptr [esp + 28], edx

  mov eax, dword ptr [esp]
  mov edx, dword ptr [esp + 4]
  shld edx, eax, 8
  shl eax, 8
  and eax, dword ptr [esp + 8]
  and edx, dword ptr [esp + 12]
  mov dword ptr [esp], eax
  mov dword ptr [esp + 4], edx

  inc dword ptr [esp + 32]
  jmp @MsbSse2_m1

@MsbSse2_m2:
  mov eax, dword ptr [esp + 32]
  cmp eax, 16
  jge @MsbSse2_blkend

  mov ecx, dword ptr [esp + 32]
  movzx eax, byte ptr [ebx + ecx]
  mov ecx, 15
  sub ecx, dword ptr [esp + 32]
  mov esi, dword ptr [ebp + 96 + ecx * 4]
  mov ecx, dword ptr [esi + eax * 8]
  mov edx, dword ptr [esi + eax * 8 + 4]
  xor dword ptr [esp + 24], ecx
  xor dword ptr [esp + 28], edx

  inc dword ptr [esp + 32]
  jmp @MsbSse2_m2

@MsbSse2_blkend:
  mov eax, dword ptr [esp + 24]
  mov edx, dword ptr [esp + 28]
  mov dword ptr [edi], eax
  mov dword ptr [edi + 4], edx

  mov esi, dword ptr [esp + 36]
  add ebx, 16
  sub esi, 16
  jmp @MsbSse2_outer

@MsbSse2_done:
  mov eax, dword ptr [edi]
  mov edx, dword ptr [edi + 4]
  add esp, 40
  pop ebp
  pop edi
  pop esi
  pop ebx
