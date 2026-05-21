// Shared SIMD procedure prologue for 2-parameter assembly functions.
// After inclusion: rcx = param1, rdx = param2 (MS x64 ABI).
// When HASHLIB_SYSV_X64_ABI is defined, remaps rdi,rsi -> rcx,rdx.
// Usage:
//   procedure MyProc(P1, P2: Pointer);
//     {$I SimdProc2Begin_x86_64.inc}
//     // ... SIMD instructions using rcx, rdx ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
{$IFNDEF FPC}
  .noframe
{$ENDIF}
{$IFDEF HASHLIB_SYSV_X64_ABI}
  mov rdx, rsi
  mov rcx, rdi
{$ENDIF}
