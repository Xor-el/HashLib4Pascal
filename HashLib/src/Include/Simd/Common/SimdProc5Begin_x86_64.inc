// Shared SIMD procedure prologue for 5-parameter assembly functions.
// After inclusion: rcx = param1, rdx = param2, r8 = param3, r9 = param4, r10 = param5
// (MS x64 ABI).
// When HASHLIB_SYSV_X64_ABI is defined, remaps rdi,rsi,rdx,rcx,r8 -> rcx,rdx,r8,r9,r10.
// On MS x64, param5 is loaded from [rsp+40] (above 32-byte shadow space + 8-byte return addr).
// Usage:
//   procedure MyProc(P1, P2: Pointer; P3, P4: Int32; P5: Pointer);
//     {$I SimdProc5Begin_x86_64.inc}
//     // ... SIMD instructions using rcx, rdx, r8, r9, r10 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
{$IFNDEF FPC}
  .noframe
{$ENDIF}
{$IFDEF HASHLIB_SYSV_X64_ABI}
  mov r10, r8
  mov r9, rcx
  mov r8, rdx
  mov rdx, rsi
  mov rcx, rdi
{$ELSE}
  mov r10, [rsp + 40]
{$ENDIF}
