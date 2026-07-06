// Shared nonvolatile-SIMD save (AArch64). Opt-in by inclusion: a kernel that
// clobbers any of v8..v15 includes this at its save point (before it first
// writes those registers), and the matching SimdNonVolatileRestore_aarch64.inc
// at its restore point (after the last use, before returning). Kernels that
// touch only v0..v7 / v16..v31 do NOT include it.
//
// AAPCS64 makes the low 64 bits of v8..v15 (d8..d15) callee-saved; a kernel
// that clobbers them must preserve them for the caller. Only the low 64 bits
// are callee-saved (the upper halves of v8..v15 are caller-saved), so restoring
// d8..d15 - which zeroes the upper halves - is sufficient. All eight are saved
// with one fixed 64-byte frame (a multiple of 16, keeping sp 16-byte aligned).
//
// Unlike x86-64 there is no ABI split: the d8..d15 rule is uniform across
// Linux/macOS/Windows, so this always emits (no platform guard).
// Save and restore MUST be paired within the same procedure.
  .long 0x6dbc27e8                    // stp d8, d9, [sp, #-64]!
  .long 0x6d012fea                    // stp d10, d11, [sp, #16]
  .long 0x6d0237ec                    // stp d12, d13, [sp, #32]
  .long 0x6d033fee                    // stp d14, d15, [sp, #48]
