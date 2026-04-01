// Shared SIMD procedure prologue for 5-parameter assembly functions.
// After inclusion: rcx = param1, rdx = param2, r8 = param3, r9 = param4, r10 = param5
// (MS x64 ABI).
// On FPC non-Windows (Unix ABI), remaps rdi,rsi,rdx,rcx,r8 -> rcx,rdx,r8,r9,r10.
// Move order avoids register clobbering.
// On MS x64, param5 is loaded from [rsp+40] (after shadow space).
// Usage:
//   procedure MyProc(P1, P2: Pointer; P3, P4: Int32; P5: Pointer);
//     {$I SimdProc5Begin.inc}
//     // ... SIMD instructions using rcx, rdx, r8, r9, r10 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  {$IFNDEF MSWINDOWS}
  mov r10, r8
  mov r9, rcx
  mov r8, rdx
  mov rdx, rsi
  mov rcx, rdi
  {$ELSE}
  mov r10, [rsp + 40]
  {$ENDIF}
{$ELSE}
asm
  .noframe
  mov r10, [rsp + 40]
{$ENDIF}
