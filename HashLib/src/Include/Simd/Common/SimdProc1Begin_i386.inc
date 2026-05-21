// Shared SIMD procedure prologue for 1-parameter assembly functions.
// After inclusion: ebx = param1 (from EAX at entry).
// FPC and Delphi Win32 share the same i386 register convention here.
// Usage:
//   procedure MyProc(P1: Pointer);
//     {$I SimdProc1Begin_i386.inc}
//     // ... SIMD instructions using ebx ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
  mov ebx, eax
