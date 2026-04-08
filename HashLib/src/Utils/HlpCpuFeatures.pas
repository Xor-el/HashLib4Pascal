unit HlpCpuFeatures;

{$I ..\Include\HashLib.inc}

interface

type
  TCpuSimdLevel = (Scalar, SSE2, SSSE3, AVX2);

  TCpuFeatures = class sealed
  private
    class var FDetectedLevel: TCpuSimdLevel;
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
    class function GetActiveLevel(): TCpuSimdLevel; static;
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
  {$I ..\Include\Simd\CpuFeatures\CpuIdQuery.inc}
end;

procedure XGetBvQuery(AResult: Pointer);
  {$I ..\Include\Simd\CpuFeatures\XGetBvQuery.inc}
end;

{$ENDIF}

{ TCpuFeatures }

class function TCpuFeatures.CPUHasSSE2(): Boolean;
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

class function TCpuFeatures.CPUHasSSSE3(): Boolean;
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

class function TCpuFeatures.CPUHasAVX2(): Boolean;
{$IFDEF HASHLIB_X86_SIMD}
var
  LCpuId: TCpuIdResult;
  LXcr0: UInt64;
{$ENDIF}
begin
{$IFDEF HASHLIB_X86_SIMD}
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

class function TCpuFeatures.CPUHasSHANI(): Boolean;
{$IFDEF HASHLIB_X86_SIMD}
var
  LCpuId: TCpuIdResult;
{$ENDIF}
begin
{$IFDEF HASHLIB_X86_SIMD}
  CpuIdQuery(7, 0, @LCpuId);
  // SHA-NI: EBX bit 29
  Result := (LCpuId.RegEBX and (1 shl 29)) <> 0;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TCpuFeatures.CPUHasPCLMULQDQ(): Boolean;
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

class function TCpuFeatures.CPUHasVPCLMULQDQ(): Boolean;
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

class procedure TCpuFeatures.DetectFeatures();
begin
  FDetectedLevel := TCpuSimdLevel.Scalar;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;

  if CPUHasSSE2() then
  begin
    FDetectedLevel := TCpuSimdLevel.SSE2;
    FHasPCLMULQDQ := CPUHasPCLMULQDQ();
    if CPUHasSSSE3() then
    begin
      FDetectedLevel := TCpuSimdLevel.SSSE3;
      if CPUHasAVX2() then
      begin
        FDetectedLevel := TCpuSimdLevel.AVX2;
        FHasVPCLMULQDQ := CPUHasVPCLMULQDQ();
      end;
    end;
  end;

  FHasSHANI := CPUHasSHANI();

  // Cap based on user force defines
{$IF DEFINED(HASHLIB_FORCE_SCALAR)}
  FDetectedLevel := TCpuSimdLevel.Scalar;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;
{$ELSEIF DEFINED(HASHLIB_FORCE_SSE2)}
  if FDetectedLevel > TCpuSimdLevel.SSE2 then
    FDetectedLevel := TCpuSimdLevel.SSE2;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;
{$ELSEIF DEFINED(HASHLIB_FORCE_SSSE3)}
  if FDetectedLevel > TCpuSimdLevel.SSSE3 then
    FDetectedLevel := TCpuSimdLevel.SSSE3;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;
{$IFEND}
end;

class function TCpuFeatures.GetActiveLevel(): TCpuSimdLevel;
begin
  Result := FDetectedLevel;
end;

class function TCpuFeatures.HasSHANI(): Boolean;
begin
  Result := FHasSHANI;
end;

class function TCpuFeatures.HasPCLMULQDQ(): Boolean;
begin
  Result := FHasPCLMULQDQ;
end;

class function TCpuFeatures.HasVPCLMULQDQ(): Boolean;
begin
  Result := FHasVPCLMULQDQ;
end;

initialization
  TCpuFeatures.DetectFeatures();

end.
