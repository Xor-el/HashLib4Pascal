// CPUID query: executes CPUID with leaf=ALeaf, subleaf=ASubLeaf,
// stores EAX/EBX/ECX/EDX into the TCpuIdResult record at AResult.
// CPUID clobbers EAX/EBX/ECX/EDX; this stub preserves callee-saved EBX (same role as RBX on x86-64).
// Same contract as CpuIdQuery.inc on x86-64, mapped to IA-32 registers / stack.
//
// FPC i386: ALeaf=EAX, ASubLeaf=EDX, AResult=ECX at asm entry (Windows and Unix).
// Delphi: same.
{$IFDEF FPC}
  assembler; nostackframe;
asm
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
asm
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
{$ENDIF}
