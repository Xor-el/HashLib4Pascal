// Shared SIMD procedure prologue for 4-parameter assembly functions.
// After inclusion: rcx = param1, rdx = param2, r8 = param3, r9 = param4
// (MS x64 ABI).
// On FPC non-Windows (Unix ABI), remaps rdi,rsi,rdx,rcx -> rcx,rdx,r8,r9.
// Move order avoids register clobbering: save rcx and rdx first.
// Usage:
//   procedure MyProc(P1, P2, P3: Pointer; P4: Int32);
//     {$I SimdProc4Begin.inc}
//     // ... SIMD instructions using rcx, rdx, r8, r9 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  {$IFNDEF MSWINDOWS}
  mov r9, rcx
  mov r8, rdx
  mov rdx, rsi
  mov rcx, rdi
  {$ENDIF}
{$ELSE}
asm
  .noframe
{$ENDIF}
