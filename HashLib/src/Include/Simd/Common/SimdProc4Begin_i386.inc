// Shared SIMD procedure prologue for 4-parameter assembly functions.
// After inclusion: ebx = param1, esi = param2, edi = param3, eax = param4
//   (first three in EAX, EDX, ECX at entry; param4 from stack).
// Callee-saved EBX, ESI, EDI - epilogue must pop EDI, ESI, EBX.
// Delphi i386 only ships on Windows; param4 lives at [ebp + 8].
// FPC i386 has no stack frame; param4 lives at [esp + 8] when read after
// the EBX push but before the ESI / EDI pushes (see asm).
// Usage:
//   procedure MyProc(P1, P2, P3: Pointer; P4: Int32);
//     {$I SimdProc4Begin_i386.inc}
//     // ... SIMD instructions using ebx, esi, edi, eax ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  push ebx
  mov ebx, eax
  mov eax, dword ptr [esp + 8]
  push esi
  mov esi, edx
  push edi
  mov edi, ecx
{$ELSE}
asm
  push ebx
  mov ebx, eax
  mov eax, dword ptr [ebp + 8]
  push esi
  mov esi, edx
  push edi
  mov edi, ecx
{$ENDIF}
