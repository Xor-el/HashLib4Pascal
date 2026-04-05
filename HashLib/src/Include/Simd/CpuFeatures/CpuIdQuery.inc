// CPUID query: executes CPUID with leaf=ALeaf, subleaf=ASubLeaf,
// stores EAX/EBX/ECX/EDX into the TCpuIdResult record at AResult.
// IA-32 (HASHLIB_I386_ASM): preserves EBX; ESI = AResult, ECX = ASubLeaf, EAX = ALeaf.
// x86-64: preserves RBX; MS ABI ecx=ALeaf, edx=ASubLeaf, r8=AResult;
//   FPC non-Windows remaps edi, esi, rdx -> leaf, subleaf, result.
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
{$IFDEF HASHLIB_I386_ASM}
  push ebx
  push esi
  mov esi, ecx
  mov ecx, edx
  cpuid
  mov [esi], eax
  mov [esi + 4], ebx
  mov [esi + 8], ecx
  mov [esi + 12], edx
  pop esi
  pop ebx
{$ELSE}
  {$IFDEF FPC}
  push rbx
  {$IFDEF MSWINDOWS}
  mov eax, ecx
  mov ecx, edx
  cpuid
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], ebx
  mov dword ptr [r8 + 8], ecx
  mov dword ptr [r8 + 12], edx
  {$ELSE}
  mov eax, edi
  mov ecx, esi
  mov r8, rdx
  cpuid
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], ebx
  mov dword ptr [r8 + 8], ecx
  mov dword ptr [r8 + 12], edx
  {$ENDIF}
  pop rbx
  {$ELSE}
  .PUSHNV RBX
  mov eax, ecx
  mov ecx, edx
  cpuid
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], ebx
  mov dword ptr [r8 + 8], ecx
  mov dword ptr [r8 + 12], edx
  {$ENDIF}
{$ENDIF}
