// Shared SIMD procedure prologue for 2-parameter assembly functions (AArch64).
// After inclusion: x0 = param1, x1 = param2 (AAPCS64).
// Matches the x86 SimdProc2 signature order: (AState, AData); AAPCS64 already
//   delivers the params in x0,x1, so no register remapping (unlike the x86
//   SysV/MS variants) is needed.
// Usage:
//   procedure MyProc(P1, P2: Pointer);
//     {$I HlpSimdProc2Begin_aarch64.inc}
//     // ... SIMD instructions using x0, x1 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
