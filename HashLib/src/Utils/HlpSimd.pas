unit HlpSimd;

{$I ..\Include\HashLib.inc}

interface

type
  TSimdLevel = (Scalar, SSE2, SSSE3, AVX2);

  TSimd = class sealed
  private
    class var FDetectedLevel: TSimdLevel;
    class var FHasSHANI: Boolean;
    class var FHasPCLMULQDQ: Boolean;
    class var FHasVPCLMULQDQ: Boolean;
    class function CPUHasSSE2(): Boolean; static;
    class function CPUHasSSSE3(): Boolean; static;
    class function CPUHasAVX2(): Boolean; static;
    class function CPUHasSHANI(): Boolean; static;
    class function CPUHasPCLMULQDQ(): Boolean; static;
    class function CPUHasVPCLMULQDQ(): Boolean; static;
    class procedure DetectFeatures(); static;
  public
    class function GetActiveLevel(): TSimdLevel; static;
    class function HasSHANI(): Boolean; static;
    class function HasPCLMULQDQ(): Boolean; static;
    class function HasVPCLMULQDQ(): Boolean; static;
  end;

implementation

{$IFDEF HASHLIB_X86_SIMD}

type
  TCpuIdResult = record
    RegEAX, RegEBX, RegECX, RegEDX: UInt32;
  end;

procedure CpuIdQuery(ALeaf, ASubLeaf: UInt32; AResult: Pointer);
  {$I ..\Include\Simd\CpuDetect\CpuIdQuery.inc}
end;

procedure XGetBvQuery(AResult: Pointer);
  {$I ..\Include\Simd\CpuDetect\XGetBvQuery.inc}
end;

{$ENDIF}

{ TSimd }

class function TSimd.CPUHasSSE2(): Boolean;
{$IFDEF HASHLIB_X86_SIMD}
var
  LCpuId: TCpuIdResult;
{$ENDIF}
begin
{$IFDEF HASHLIB_X86_SIMD}
  CpuIdQuery(1, 0, @LCpuId);
  Result := (LCpuId.RegEDX and (1 shl 26)) <> 0;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TSimd.CPUHasSSSE3(): Boolean;
{$IFDEF HASHLIB_X86_SIMD}
var
  LCpuId: TCpuIdResult;
{$ENDIF}
begin
{$IFDEF HASHLIB_X86_SIMD}
  CpuIdQuery(1, 0, @LCpuId);
  // SSSE3: ECX bit 9
  Result := (LCpuId.RegECX and (1 shl 9)) <> 0;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TSimd.CPUHasAVX2(): Boolean;
{$IFDEF HASHLIB_X86_SIMD}
var
  LCpuId: TCpuIdResult;
  LXcr0: UInt64;
{$ENDIF}
begin
{$IFNDEF HASHLIB_X86_SIMD}
  Result := False;
{$ELSE}
  {$IFDEF HASHLIB_I386_ASM}
  Result := False;
  {$ELSE}
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
  {$ENDIF}
{$ENDIF}
end;

class function TSimd.CPUHasSHANI(): Boolean;
{$IFDEF HASHLIB_X86_SIMD}
var
  LCpuId: TCpuIdResult;
{$ENDIF}
begin
{$IFNDEF HASHLIB_X86_SIMD}
  Result := False;
{$ELSE}
  {$IFDEF HASHLIB_I386_ASM}
  Result := False;
  {$ELSE}
  CpuIdQuery(7, 0, @LCpuId);
  // SHA-NI: EBX bit 29
  Result := (LCpuId.RegEBX and (1 shl 29)) <> 0;
  {$ENDIF}
{$ENDIF}
end;

class function TSimd.CPUHasPCLMULQDQ(): Boolean;
{$IFDEF HASHLIB_X86_SIMD}
var
  LCpuId: TCpuIdResult;
{$ENDIF}
begin
{$IFDEF HASHLIB_X86_SIMD}
  CpuIdQuery(1, 0, @LCpuId);
  // PCLMULQDQ: ECX bit 1
  Result := (LCpuId.RegECX and (1 shl 1)) <> 0;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TSimd.CPUHasVPCLMULQDQ(): Boolean;
{$IFDEF HASHLIB_X86_SIMD}
var
  LCpuId: TCpuIdResult;
{$ENDIF}
begin
{$IFDEF HASHLIB_X86_SIMD}
  CpuIdQuery(7, 0, @LCpuId);
  // VPCLMULQDQ: ECX bit 10
  Result := (LCpuId.RegECX and (1 shl 10)) <> 0;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class procedure TSimd.DetectFeatures();
begin
  FDetectedLevel := TSimdLevel.Scalar;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;

  if CPUHasSSE2() then
  begin
    FDetectedLevel := TSimdLevel.SSE2;
    FHasPCLMULQDQ := CPUHasPCLMULQDQ();
    if CPUHasSSSE3() then
    begin
      FDetectedLevel := TSimdLevel.SSSE3;
      if CPUHasAVX2() then
      begin
        FDetectedLevel := TSimdLevel.AVX2;
        FHasVPCLMULQDQ := CPUHasVPCLMULQDQ();
      end;
    end;
  end;

  FHasSHANI := CPUHasSHANI();

  // Cap based on user force defines
{$IF DEFINED(HASHLIB_FORCE_SCALAR)}
  FDetectedLevel := TSimdLevel.Scalar;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;
{$ELSEIF DEFINED(HASHLIB_FORCE_SSE2)}
  if FDetectedLevel > TSimdLevel.SSE2 then
    FDetectedLevel := TSimdLevel.SSE2;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;
{$ELSEIF DEFINED(HASHLIB_FORCE_SSSE3)}
  if FDetectedLevel > TSimdLevel.SSSE3 then
    FDetectedLevel := TSimdLevel.SSSE3;
  FHasVPCLMULQDQ := False;
{$IFEND}
end;

class function TSimd.GetActiveLevel(): TSimdLevel;
begin
  Result := FDetectedLevel;
end;

class function TSimd.HasSHANI(): Boolean;
begin
  Result := FHasSHANI;
end;

class function TSimd.HasPCLMULQDQ(): Boolean;
begin
  Result := FHasPCLMULQDQ;
end;

class function TSimd.HasVPCLMULQDQ(): Boolean;
begin
  Result := FHasVPCLMULQDQ;
end;

initialization
  TSimd.DetectFeatures();

end.
