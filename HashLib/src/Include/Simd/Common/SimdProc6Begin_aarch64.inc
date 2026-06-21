// Shared SIMD procedure prologue for 6-parameter assembly functions (AArch64).
// After inclusion: x0 = param1, x1 = param2, x2 = param3, x3 = param4,
//   x4 = param5, x5 = param6 (AAPCS64).
// Matches the x86 SimdProc6 signature order: (AInput, AKey, AOut, ANumChunks,
//   ACounter, AFlags). AAPCS64 passes the first 8 integer/pointer arguments in
//   x0-x7, so params 5 and 6 arrive in x4 and x5 -- no register remapping and no
//   stack loads (unlike the x86 MS variant's [rsp+40]/[rsp+48]) are needed;
//   32-bit parameters (e.g. ANumChunks, AFlags) are read through the wN view of
//   the same register.
// Usage:
//   procedure MyProc(P1, P2, P3: Pointer; P4: Int32; P5: UInt64; P6: UInt32);
//     {$I SimdProc6Begin_aarch64.inc}
//     // ... SIMD instructions using x0, x1, x2, x3, x4, x5 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
