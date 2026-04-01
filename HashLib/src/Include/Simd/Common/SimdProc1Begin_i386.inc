// Shared SIMD procedure prologue for 1-parameter assembly functions.
// After inclusion: ebx = param1 (from EAX at entry).
// FPC: Windows and Unix i386 use the same parameter entry layout.
// Usage:
//   procedure MyProc(P1: Pointer);
//     {$I SimdProc1Begin_i386.inc}
//     // ... SIMD instructions using ebx ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  mov ebx, eax
{$ELSE}
asm
  mov ebx, eax
{$ENDIF}
