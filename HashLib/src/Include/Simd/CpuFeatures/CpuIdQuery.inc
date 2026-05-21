// CPUID query: executes CPUID with leaf=ALeaf, subleaf=ASubLeaf,
// stores EAX/EBX/ECX/EDX into the TCpuIdResult record at AResult.
// IA-32 fastcall entry: EAX=ALeaf, EDX=ASubLeaf, ECX=AResult.
// x86-64 entry (per OS ABI):
//   Windows (MS ABI):   RCX=ALeaf, RDX=ASubLeaf, R8=AResult.
//   Unix    (SysV ABI): RDI=ALeaf, RSI=ASubLeaf, RDX=AResult.
// CPUID clobbers EBX, so RBX is preserved across the call.
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
{$IFDEF HASHLIB_I386_ASM}
  push ebx
  push esi
  mov esi, ecx       // save AResult (was in ECX) across cpuid
  mov ecx, edx       // ECX := ASubLeaf
  cpuid              // EAX already holds ALeaf
  mov [esi], eax
  mov [esi + 4], ebx
  mov [esi + 8], ecx
  mov [esi + 12], edx
  pop esi
  pop ebx
{$ELSE}
  // x86-64: normalize to EAX=ALeaf, ECX=ASubLeaf, R8=AResult, then cpuid.
  // Preserve RBX (CPUID clobbers it).
  {$IFDEF FPC}
  push rbx
  {$ELSE}
  .PUSHNV RBX
  {$ENDIF}
  {$IFDEF HASHLIB_SYSV_X64_ABI}
  // SysV ABI entry: RDI=ALeaf, RSI=ASubLeaf, RDX=AResult.
  mov eax, edi       // EAX := ALeaf
  mov ecx, esi       // ECX := ASubLeaf
  mov r8, rdx        // R8  := AResult
  {$ELSE}
  // MS ABI entry: RCX=ALeaf, RDX=ASubLeaf, R8=AResult.
  mov eax, ecx       // EAX := ALeaf
  mov ecx, edx       // ECX := ASubLeaf
  {$ENDIF}
  cpuid
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], ebx
  mov dword ptr [r8 + 8], ecx
  mov dword ptr [r8 + 12], edx
  {$IFDEF FPC}
  pop rbx
  {$ENDIF}
{$ENDIF}
