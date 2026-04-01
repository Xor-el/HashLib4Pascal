// Shared SIMD procedure prologue for 1-parameter assembly functions.
// After inclusion: rcx = param1 (MS x64 ABI).
// On FPC non-Windows (Unix ABI), remaps rdi -> rcx.
// Usage:
//   procedure MyProc(P1: Pointer);
//     {$I SimdProc1Begin_x86_64.inc}
//     // ... SIMD instructions using rcx ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  {$IFNDEF MSWINDOWS}
  mov rcx, rdi
  {$ENDIF}
{$ELSE}
asm
  .noframe
{$ENDIF}
