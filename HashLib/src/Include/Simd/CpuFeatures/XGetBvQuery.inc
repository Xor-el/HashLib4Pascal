// XGETBV query: executes XGETBV with ECX=0, stores EAX:EDX into the
// UInt64 at AResult.
// IA-32 fastcall entry: EAX=AResult.
// x86-64 entry (per OS ABI):
//   Windows (MS ABI):   RCX=AResult.
//   Unix    (SysV ABI): RDI=AResult.
// XGETBV does not clobber RBX, so no preservation is needed on x86-64.
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
{$IFDEF HASHLIB_I386_ASM}
  push ebx
  mov ebx, eax       // save AResult (was in EAX) across xgetbv
  xor ecx, ecx       // XCR index 0
  db $0F, $01, $D0   // xgetbv -> EDX:EAX
  mov [ebx], eax
  mov [ebx + 4], edx
  pop ebx
{$ELSE}
  // x86-64: normalize to R8=AResult, then xgetbv.

  {$IFNDEF FPC}
  .noframe
  {$ENDIF}

  {$IFDEF HASHLIB_SYSV_X64_ABI}
  // SysV ABI entry: RDI=AResult.
  mov r8, rdi        // R8 := AResult
  {$ELSE}
  // MS ABI entry: RCX=AResult.
  mov r8, rcx        // R8 := AResult
  {$ENDIF}

  xor ecx, ecx       // XCR index 0
  db $0F, $01, $D0   // xgetbv -> EDX:EAX
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], edx
{$ENDIF}
