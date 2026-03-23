unit HlpSimd;

{$I ..\Include\HashLib.inc}

interface

type
  TSimdLevel = (Scalar, SSE2, AVX2);

  TSimd = class sealed
  private
    class var FDetectedLevel: TSimdLevel;
    class function CPUHasSSE2(): Boolean; static;
    class function CPUHasAVX2(): Boolean; static;
    class procedure DetectFeatures(); static;
  public
    class function GetActiveLevel(): TSimdLevel; static;
  end;

implementation

{$IFDEF HASHLIB_X86_64}

type
  TCpuIdResult = record
    RegEAX, RegEBX, RegECX, RegEDX: UInt32;
  end;

{$IFDEF FPC}
procedure CpuIdQuery(ALeaf, ASubLeaf: UInt32; AResult: Pointer);
  assembler; nostackframe;
asm
  push rbx
  {$IFDEF MSWINDOWS}
  mov eax, ecx
  mov ecx, edx
  cpuid
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], ebx
  mov dword ptr [r8 + 8], ecx
  mov dword ptr [r8 + 12], edx
  {$ELSE}
  mov eax, edi
  mov ecx, esi
  mov r8, rdx
  cpuid
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], ebx
  mov dword ptr [r8 + 8], ecx
  mov dword ptr [r8 + 12], edx
  {$ENDIF}
  pop rbx
end;
{$ELSE}
procedure CpuIdQuery(ALeaf, ASubLeaf: UInt32; AResult: Pointer);
asm
  .PUSHNV RBX
  mov eax, ecx
  mov ecx, edx
  cpuid
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], ebx
  mov dword ptr [r8 + 8], ecx
  mov dword ptr [r8 + 12], edx
end;
{$ENDIF}

{$IFDEF FPC}
procedure XGetBvQuery(AResult: Pointer);
  assembler; nostackframe;
asm
  {$IFDEF MSWINDOWS}
  mov r8, rcx
  {$ELSE}
  mov r8, rdi
  {$ENDIF}
  xor ecx, ecx
  xgetbv
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], edx
end;
{$ELSE}
procedure XGetBvQuery(AResult: Pointer);
asm
  .noframe
  mov r8, rcx
  xor ecx, ecx
  xgetbv
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], edx
end;
{$ENDIF}

{$ENDIF HASHLIB_X86_64}

{ TSimd }

class function TSimd.CPUHasSSE2(): Boolean;
{$IFDEF HASHLIB_X86_64}
var
  LCpuId: TCpuIdResult;
{$ENDIF}
begin
{$IFDEF HASHLIB_X86_64}
  CpuIdQuery(1, 0, @LCpuId);
  Result := (LCpuId.RegEDX and (1 shl 26)) <> 0;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TSimd.CPUHasAVX2(): Boolean;
{$IFDEF HASHLIB_X86_64}
var
  LCpuId: TCpuIdResult;
  LXcr0: UInt64;
{$ENDIF}
begin
{$IFDEF HASHLIB_X86_64}
  CpuIdQuery(1, 0, @LCpuId);

  // OSXSAVE: ECX bit 27 (required for OS AVX state saving)
  if (LCpuId.RegECX and (1 shl 27)) = 0 then
    Exit(False);

  // XCR0 bits 1 and 2 must be set for AVX state support
  LXcr0 := 0;
  XGetBvQuery(@LXcr0);
  if (UInt32(LXcr0) and $06) <> $06 then
    Exit(False);

  CpuIdQuery(7, 0, @LCpuId);

  // AVX2: EBX bit 5
  Result := (LCpuId.RegEBX and (1 shl 5)) <> 0;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class procedure TSimd.DetectFeatures();
begin
  FDetectedLevel := TSimdLevel.Scalar;

  if CPUHasSSE2() then
  begin
    FDetectedLevel := TSimdLevel.SSE2;
    if CPUHasAVX2() then
      FDetectedLevel := TSimdLevel.AVX2;
  end;

  // Cap based on compiler assembler capability
{$IFNDEF HASHLIB_AVX2_ASM_SUPPORTED}
  if FDetectedLevel > TSimdLevel.SSE2 then
    FDetectedLevel := TSimdLevel.SSE2;
{$ENDIF}

  // Cap based on user force defines
{$IF DEFINED(HASHLIB_FORCE_SCALAR)}
  FDetectedLevel := TSimdLevel.Scalar;
{$ELSEIF DEFINED(HASHLIB_FORCE_SSE2)}
  if FDetectedLevel > TSimdLevel.SSE2 then
    FDetectedLevel := TSimdLevel.SSE2;
{$IFEND}
end;

class function TSimd.GetActiveLevel(): TSimdLevel;
begin
  Result := FDetectedLevel;
end;

initialization
  TSimd.DetectFeatures();

end.
