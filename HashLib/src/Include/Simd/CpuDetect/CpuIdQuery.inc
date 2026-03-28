// CPUID query: executes CPUID with leaf=ALeaf, subleaf=ASubLeaf,
// stores EAX/EBX/ECX/EDX into the TCpuIdResult record at AResult.
// RBX must be preserved (CPUID clobbers it).
// Expects MS x64 ABI: ecx = ALeaf, edx = ASubLeaf, r8 = AResult.
// On FPC non-Windows (System V ABI), remaps edi,esi,rdx -> ecx,edx,r8.
{$IFDEF FPC}
  assembler; nostackframe;
asm
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
asm
  .PUSHNV RBX
  mov eax, ecx
  mov ecx, edx
  cpuid
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], ebx
  mov dword ptr [r8 + 8], ecx
  mov dword ptr [r8 + 12], edx
{$ENDIF}
