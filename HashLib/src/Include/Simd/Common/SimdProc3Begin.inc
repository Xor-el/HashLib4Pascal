// Shared SIMD procedure prologue for 3-parameter assembly functions.
// After inclusion: rcx = param1, rdx = param2, r8 = param3 (MS x64 ABI).
// On FPC non-Windows (Unix ABI), remaps rdi,rsi,rdx -> rcx,rdx,r8.
// Move order avoids register clobbering: save rdx before overwriting.
// Usage:
//   procedure MyProc(P1, P2, P3: Pointer);
//     {$I SimdProc3Begin.inc}
//     // ... SIMD instructions using rcx, rdx, r8 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  {$IFNDEF MSWINDOWS}
  mov r8, rdx
  mov rdx, rsi
  mov rcx, rdi
  {$ENDIF}
{$ELSE}
asm
  .noframe
{$ENDIF}
