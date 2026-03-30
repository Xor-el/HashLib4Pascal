// Shared SIMD procedure prologue for 2-parameter assembly functions.
// After inclusion: ebx = param1, esi = param2 (EAX, EDX at entry; callee saves EBX, ESI).
// FPC: Windows and Unix i386 use the same parameter entry layout.
// Usage:
//   procedure MyProc(P1, P2: Pointer);
//     {$I SimdProc2Begin_i386.inc}
//     // ... SIMD instructions using ebx, esi ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  push ebx
  push esi
  mov ebx, eax
  mov esi, edx
{$ELSE}
asm
  push ebx
  push esi
  mov ebx, eax
  mov esi, edx
{$ENDIF}
