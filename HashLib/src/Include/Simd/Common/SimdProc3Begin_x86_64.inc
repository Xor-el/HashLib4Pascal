// Shared SIMD procedure prologue for 3-parameter assembly functions.
// After inclusion: rcx = param1, rdx = param2, r8 = param3 (MS x64 ABI).
// When HASHLIB_SYSV_X64_ABI is defined, remaps rdi,rsi,rdx -> rcx,rdx,r8.
// Move order avoids register clobbering: save rdx before overwriting.
// Usage:
//   procedure MyProc(P1, P2, P3: Pointer);
//     {$I SimdProc3Begin_x86_64.inc}
//     // ... SIMD instructions using rcx, rdx, r8 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
{$IFNDEF FPC}
  .noframe
{$ENDIF}
{$IFDEF HASHLIB_SYSV_X64_ABI}
  mov r8, rdx
  mov rdx, rsi
  mov rcx, rdi
{$ENDIF}
