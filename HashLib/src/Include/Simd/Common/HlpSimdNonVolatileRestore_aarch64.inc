// Shared nonvolatile-SIMD restore (AArch64). Mirror of HlpSimdNonVolatileSave_aarch64.inc:
// restores d8..d15 and frees the 64-byte save frame. Include it at the kernel's
// restore point (after the last use of v8..v15, before returning), in any
// procedure that included HlpSimdNonVolatileSave_aarch64.inc. Restoring d8..d15
// zeroes the upper halves of v8..v15, which is fine since those are caller-saved.
  .long 0x6d412fea                    // ldp d10, d11, [sp, #16]
  .long 0x6d4237ec                    // ldp d12, d13, [sp, #32]
  .long 0x6d433fee                    // ldp d14, d15, [sp, #48]
  .long 0x6cc427e8                    // ldp d8, d9, [sp], #64
