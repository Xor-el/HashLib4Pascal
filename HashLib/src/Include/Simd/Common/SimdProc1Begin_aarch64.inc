// Shared SIMD procedure prologue for 1-parameter assembly functions (AArch64).
// After inclusion: x0 = param1 (AAPCS64).
// Matches the x86 SimdProc1 signature order: (AState); AAPCS64 already delivers
//   the param in x0, so no register remapping (unlike the x86 SysV/MS variants)
//   is needed.
// Usage:
//   procedure MyProc(P1: Pointer);
//     {$I SimdProc1Begin_aarch64.inc}
//     // ... SIMD instructions using x0 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
