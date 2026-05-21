// Shared SIMD procedure prologue for 1-parameter assembly functions.
// After inclusion: rcx = param1 (MS x64 ABI).
// When HASHLIB_SYSV_X64_ABI is defined, remaps rdi -> rcx.
// Usage:
//   procedure MyProc(P1: Pointer);
//     {$I SimdProc1Begin_x86_64.inc}
//     // ... SIMD instructions using rcx ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
{$IFNDEF FPC}
  .noframe
{$ENDIF}
{$IFDEF HASHLIB_SYSV_X64_ABI}
  mov rcx, rdi
{$ENDIF}
