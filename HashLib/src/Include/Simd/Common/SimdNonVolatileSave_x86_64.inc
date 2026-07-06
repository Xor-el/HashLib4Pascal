// Shared nonvolatile-XMM save (x86-64). Opt-in by inclusion: a kernel that uses
// any of xmm6..xmm15 includes this at its save point (before it first writes
// those registers), and the matching SimdNonVolatileRestore_x86_64.inc at its restore
// point (after the last use, before returning). Light kernels that touch only
// xmm0..xmm5 do NOT include it.
//
// The Microsoft x64 ABI makes xmm6..xmm15 callee-saved (nonvolatile); a kernel
// that clobbers them must preserve them for the caller. All ten are saved with
// one fixed 160-byte frame (a multiple of 16, so it does not disturb a kernel's
// own stack usage). AVX2 kernels only need the low 128 bits preserved (the upper
// halves of ymm are always volatile on Win64), so this 128-bit save covers them
// too. Save with legacy movups is safe: it runs before the first VEX instruction,
// and the matching restore runs after vzeroupper (see the restore include).
//
// On SysV x86-64 (Linux/macOS) xmm6..xmm15 are volatile, so nothing is emitted.
// Save and restore MUST be paired within the same procedure.
{$IFNDEF HASHLIB_SYSV_X64_ABI}
  sub       rsp, 160
  movups    [rsp], xmm6
  movups    [rsp + 16], xmm7
  movups    [rsp + 32], xmm8
  movups    [rsp + 48], xmm9
  movups    [rsp + 64], xmm10
  movups    [rsp + 80], xmm11
  movups    [rsp + 96], xmm12
  movups    [rsp + 112], xmm13
  movups    [rsp + 128], xmm14
  movups    [rsp + 144], xmm15
{$ENDIF}
