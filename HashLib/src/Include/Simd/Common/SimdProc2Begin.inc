// Shared SIMD procedure prologue for 2-parameter assembly functions.
// After inclusion: rcx = param1, rdx = param2 (MS x64 ABI).
// On FPC non-Windows (Unix ABI), remaps rdi,rsi -> rcx,rdx.
// Usage:
//   procedure MyProc(P1, P2: Pointer);
//     {$I SimdProc2Begin.inc}
//     // ... SIMD instructions using rcx, rdx ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  {$IFNDEF MSWINDOWS}
  mov rdx, rsi
  mov rcx, rdi
  {$ENDIF}
{$ELSE}
asm
  .noframe
{$ENDIF}
