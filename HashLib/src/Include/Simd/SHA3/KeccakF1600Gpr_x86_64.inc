// Keccak-f[1600] permutation for x86-64, pure 64-bit GPR code (no SIMD
// registers at all) - the fastest non-AVX2 form of Keccak on x86-64.
// Reference: OpenSSL CRYPTOGAMS keccak1600-x86_64.pl by Andy Polyakov.
//
// The inner routine works in the LANE-COMPLEMENTED domain (lanes 1, 2, 8,
// 12, 17 and 20 stored inverted to save NOTs in chi); this wrapper converts
// in and out around the call. The original loop terminated on a 256-aligned
// iotas table (test r15, 255) which a Pascal const cannot guarantee - the
// termination is patched to compare against an end pointer stashed at
// [rsp] (the inner sees it at [rsp + 8] across the call).
//
// After HlpSimdProc2Begin_x86_64: rcx = AState (25 x UInt64, standard
// layout), rdx = AConstants (iotas: 24 x UInt64 round constants).
// The inner keeps the original called shape; frame mirrors the OpenSSL
// wrapper: 200-byte scratch plane (+16 for the sentinel slot), rdi/rsi
// biased by +100, r15 = iotas. Clobbers rax-rdx, r8-r15, rsi, rdi (all
// GPRs); every callee-saved one is pushed here.

  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15

  lea rdi, [rcx + 100]            // biased state pointer
  mov r15, rdx                    // iotas
  sub rsp, 216
  lea rax, [rdx + 192]
  mov qword [rsp], rax            // iotas end sentinel (inner: [rsp + 8])
  lea rsi, [rsp + 116]            // scratch plane, biased by +100

  // enter the complemented-lane domain (lanes 1, 2, 8, 12, 17, 20)
  not qword [rdi - 92]
  not qword [rdi - 84]
  not qword [rdi - 36]
  not qword [rdi - 4]
  not qword [rdi + 36]
  not qword [rdi + 60]

  call @keccak_inner

  // leave the complemented-lane domain
  not qword [rdi - 92]
  not qword [rdi - 84]
  not qword [rdi - 36]
  not qword [rdi - 4]
  not qword [rdi + 36]
  not qword [rdi + 60]

  add rsp, 216
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
  jmp @keccak_done

@keccak_inner:
  mov    rax, qword [rdi + $3C]
  mov    rbx, qword [rdi + $44]
  mov    rcx, qword [rdi + $4C]
  mov    rdx, qword [rdi + $54]
  mov    rbp, qword [rdi + $5C]
  jmp @keccak_round_loop

@keccak_round_loop:
  mov    r8, qword [rdi - $64]
  mov    r9, qword [rdi - $34]
  mov    r10, qword [rdi - $4]
  mov    r11, qword [rdi + $2C]
  xor    rcx, qword [rdi - $54]
  xor    rdx, qword [rdi - $4C]
  xor    rax, r8
  xor    rbx, qword [rdi - $5C]
  xor    rcx, qword [rdi - $2C]
  xor    rax, qword [rdi - $3C]
  mov    r12, rbp
  xor    rbp, qword [rdi - $44]
  xor    rcx, r10
  xor    rax, qword [rdi - $14]
  xor    rdx, qword [rdi - $24]
  xor    rbx, r9
  xor    rbp, qword [rdi - $1C]
  xor    rcx, qword [rdi + $24]
  xor    rax, qword [rdi + $14]
  xor    rdx, qword [rdi + $4]
  xor    rbx, qword [rdi - $C]
  xor    rbp, qword [rdi + $C]
  mov    r13, rcx
  rol    rcx, 1
  xor    rcx, rax
  xor    rdx, r11
  rol    rax, 1
  xor    rax, rdx
  xor    rbx, qword [rdi + $1C]
  rol    rdx, 1
  xor    rdx, rbx
  xor    rbp, qword [rdi + $34]
  rol    rbx, 1
  xor    rbx, rbp
  rol    rbp, 1
  xor    rbp, r13
  xor    r9, rcx
  xor    r10, rdx
  rol    r9, $2C
  xor    r11, rbp
  xor    r12, rax
  rol    r10, $2B
  xor    r8, rbx
  mov    r13, r9
  rol    r11, $15
  or     r9, r10
  xor    r9, r8
  rol    r12, $E
  xor    r9, qword [r15]
  lea    r15, [r15 + $8]
  mov    r14, r12
  and    r12, r11
  mov    qword [rsi - $64], r9
  xor    r12, r10
  not    r10
  mov    qword [rsi - $54], r12
  or     r10, r11
  mov    r12, qword [rdi + $4C]
  xor    r10, r13
  mov    qword [rsi - $5C], r10
  and    r13, r8
  mov    r9, qword [rdi - $1C]
  xor    r13, r14
  mov    r10, qword [rdi - $14]
  mov    qword [rsi - $44], r13
  or     r14, r8
  mov    r8, qword [rdi - $4C]
  xor    r14, r11
  mov    r11, qword [rdi + $1C]
  mov    qword [rsi - $4C], r14
  xor    r8, rbp
  xor    r12, rdx
  rol    r8, $1C
  xor    r11, rcx
  xor    r9, rax
  rol    r12, $3D
  rol    r11, $2D
  xor    r10, rbx
  rol    r9, $14
  mov    r13, r8
  or     r8, r12
  rol    r10, $3
  xor    r8, r11
  mov    qword [rsi - $24], r8
  mov    r14, r9
  and    r9, r13
  mov    r8, qword [rdi - $5C]
  xor    r9, r12
  not    r12
  mov    qword [rsi - $1C], r9
  or     r12, r11
  mov    r9, qword [rdi - $2C]
  xor    r12, r10
  mov    qword [rsi - $2C], r12
  and    r11, r10
  mov    r12, qword [rdi + $3C]
  xor    r11, r14
  mov    qword [rsi - $34], r11
  or     r14, r10
  mov    r10, qword [rdi + $4]
  xor    r14, r13
  mov    r11, qword [rdi + $34]
  mov    qword [rsi - $3C], r14
  xor    r10, rbp
  xor    r11, rax
  rol    r10, $19
  xor    r9, rdx
  rol    r11, $8
  xor    r12, rbx
  rol    r9, $6
  xor    r8, rcx
  rol    r12, $12
  mov    r13, r10
  and    r10, r11
  rol    r8, 1
  not    r11
  xor    r10, r9
  mov    qword [rsi - $C], r10
  mov    r14, r12
  and    r12, r11
  mov    r10, qword [rdi - $C]
  xor    r12, r13
  mov    qword [rsi - $4], r12
  or     r13, r9
  mov    r12, qword [rdi + $54]
  xor    r13, r8
  mov    qword [rsi - $14], r13
  and    r9, r8
  xor    r9, r14
  mov    qword [rsi + $C], r9
  or     r14, r8
  mov    r9, qword [rdi - $3C]
  xor    r14, r11
  mov    r11, qword [rdi + $24]
  mov    qword [rsi + $4], r14
  mov    r8, qword [rdi - $44]
  xor    r10, rcx
  xor    r11, rdx
  rol    r10, $A
  xor    r9, rbx
  rol    r11, $F
  xor    r12, rbp
  rol    r9, $24
  xor    r8, rax
  rol    r12, $38
  mov    r13, r10
  or     r10, r11
  rol    r8, $1B
  not    r11
  xor    r10, r9
  mov    qword [rsi + $1C], r10
  mov    r14, r12
  or     r12, r11
  xor    r12, r13
  mov    qword [rsi + $24], r12
  and    r13, r9
  xor    r13, r8
  mov    qword [rsi + $14], r13
  or     r9, r8
  xor    r9, r14
  mov    qword [rsi + $34], r9
  and    r8, r14
  xor    r8, r11
  mov    qword [rsi + $2C], r8
  xor    rdx, qword [rdi - $54]
  xor    rbp, qword [rdi - $24]
  rol    rdx, $3E
  xor    rcx, qword [rdi + $44]
  rol    rbp, $37
  xor    rax, qword [rdi + $C]
  rol    rcx, $2
  xor    rbx, qword [rdi + $14]
  xchg   rdi, rsi
  rol    rax, $27
  rol    rbx, $29
  mov    r13, rdx
  and    rdx, rbp
  not    rbp
  xor    rdx, rcx
  mov    qword [rdi + $5C], rdx
  mov    r14, rax
  and    rax, rbp
  xor    rax, r13
  mov    qword [rdi + $3C], rax
  or     r13, rcx
  xor    r13, rbx
  mov    qword [rdi + $54], r13
  and    rcx, rbx
  xor    rcx, r14
  mov    qword [rdi + $4C], rcx
  or     rbx, r14
  xor    rbx, rbp
  mov    qword [rdi + $44], rbx
  mov    rbp, rdx
  mov    rdx, r13
  cmp    r15, qword [rsp + $8]
  jb @keccak_round_loop
  lea    r15, [r15 - $C0]
  ret

@keccak_done:
