// Shared SIMD procedure prologue for 4-parameter assembly functions.
// After inclusion: rcx = param1, rdx = param2, r8 = param3, r9 = param4
// (MS x64 ABI).
// When HASHLIB_SYSV_X64_ABI is defined, remaps rdi,rsi,rdx,rcx -> rcx,rdx,r8,r9.
// Move order avoids register clobbering: save rcx and rdx first.
// Usage:
//   procedure MyProc(P1, P2, P3: Pointer; P4: Int32);
//     {$I SimdProc4Begin_x86_64.inc}
//     // ... SIMD instructions using rcx, rdx, r8, r9 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
{$IFNDEF FPC}
  .noframe
{$ENDIF}
{$IFDEF HASHLIB_SYSV_X64_ABI}
  mov r9, rcx
  mov r8, rdx
  mov rdx, rsi
  mov rcx, rdi
{$ENDIF}
