// Shared SIMD procedure prologue for 3-parameter assembly functions.
// After inclusion: ebx = param1, esi = param2, edi = param3 (EAX, EDX, ECX at entry).
// FPC: Windows and Unix i386 use the same parameter entry layout.
// Usage:
//   procedure MyProc(P1, P2, P3: Pointer);
//     {$I SimdProc3Begin_i386.inc}
//     // ... SIMD instructions using ebx, esi, edi ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  push ebx
  push esi
  push edi
  mov ebx, eax
  mov esi, edx
  mov edi, ecx
{$ELSE}
asm
  push ebx
  push esi
  push edi
  mov ebx, eax
  mov esi, edx
  mov edi, ecx
{$ENDIF}
