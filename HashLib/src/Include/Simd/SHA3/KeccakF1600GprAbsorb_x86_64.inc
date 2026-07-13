// Gpr implementation of the Keccak-f[1600] multi-block absorb (pure 64-bit
// GPR code) - the asm twin of the AVX2 absorb: XORs whole blocks into the
// state and permutes, keeping the state in the lane-complemented domain
// across the entire batch (the NOT conversion is hoisted out of the block
// loop - the standalone permute pays it per call). The permutation body is
// the same inner as KeccakF1600Gpr_x86_64.inc (embedded again because
// local labels cannot cross include files), with the same end-pointer loop
// termination via the sentinel at [rsp].
// ABI (after HlpSimdProc5Begin_x86_64.inc): rcx = AState (25 x UInt64,
//   standard layout), rdx = AData, r8 = ABlockCount, r9 = ABlockSize (both
//   Int32 - upper halves undefined, zero-extended here), r10 = AConstants
//   (iotas: 24 x UInt64).
// Frame: 200-byte scratch plane at [rsp+16] (rsi biased +100), sentinel at
//   [rsp], spills at [rsi+100..116].
// Saves: every callee-saved GPR is pushed here (clobbers all GPRs).
// Reference: OpenSSL CRYPTOGAMS keccak1600-x86_64.pl (SHA3_absorb) by
// Andy Polyakov.

  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15

  mov r11d, r9d           // ABlockSize, zero-extended
  mov eax, r8d            // ABlockCount, zero-extended
  imul rax, r11           // total length in bytes

  lea rdi, [rcx + 100]    // biased state pointer
  mov r9, rdx             // input pointer
  mov rdx, rax            // remaining length
  mov rcx, r11            // block size in bytes
  mov r15, r10            // iotas

  sub rsp, 240
  lea rsi, [rsp + 116]    // scratch plane, biased by +100
  lea rax, [r15 + 192]
  mov qword [rsp], rax    // iotas end sentinel (inner: [rsp + 8])
  mov qword [rsi + 116], rcx   // block size, reloaded after each permute

  // enter the complemented-lane domain once for the whole batch
  not qword [rdi - 92]
  not qword [rdi - 84]
  not qword [rdi - 36]
  not qword [rdi - 4]
  not qword [rdi + 36]
  not qword [rdi + 60]

@absorb_loop:
  cmp rdx, rcx
  jb @absorb_done

  shr rcx, 3
  lea r8, [rdi - 100]

@absorb_block:
  mov rax, qword [r9]
  lea r9, [r9 + 8]
  xor rax, qword [r8]
  lea r8, [r8 + 8]
  sub rdx, 8
  mov qword [r8 - 8], rax
  sub rcx, 1
  jnz @absorb_block

  mov qword [rsi + 100], r9
  mov qword [rsi + 108], rdx
  call @keccak_inner
  mov r9, qword [rsi + 100]
  mov rdx, qword [rsi + 108]
  mov rcx, qword [rsi + 116]
  jmp @absorb_loop

@absorb_done:
  // leave the complemented-lane domain
  not qword [rdi - 92]
  not qword [rdi - 84]
  not qword [rdi - 36]
  not qword [rdi - 4]
  not qword [rdi + 36]
  not qword [rdi + 60]

  add rsp, 240
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
  jmp @absorb_end

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

@absorb_end:
