unit HlpX86SimdFeatures;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpSimdLevels;

type
  TX86SimdFeatures = class sealed
  strict private
  type
    TCpuIdResult = record
      RegEAX, RegEBX, RegECX, RegEDX: UInt32;
    end;

  strict private
  class var
    FSimdLevel: TX86SimdLevel;
    FHasSHANI: Boolean;
    FHasPCLMULQDQ: Boolean;
    FHasVPCLMULQDQ: Boolean;
    FHasAESNI: Boolean;

  strict private
    class function CPUHasSSE2(): Boolean; static;
    class function CPUHasSSSE3(): Boolean; static;
    class function CPUHasAVX2(): Boolean; static;
    class function CPUHasSHANI(): Boolean; static;
    class function CPUHasPCLMULQDQ(): Boolean; static;
    class function CPUHasVPCLMULQDQ(): Boolean; static;
    class function CPUHasAESNI(): Boolean; static;

  private
    class procedure ProbeHardwareAndCache(); static;
    class procedure ApplyBuildOverrides(); static;

  public
    class function GetSimdLevel(): TX86SimdLevel; static;
    class function HasSSE2(): Boolean; static;
    class function HasSSSE3(): Boolean; static;
    class function HasAVX2(): Boolean; static;
    class function HasSHANI(): Boolean; static;
    class function HasPCLMULQDQ(): Boolean; static;
    class function HasVPCLMULQDQ(): Boolean; static;
    class function HasAESNI(): Boolean; static;
  end;

implementation

{$IFDEF HASHLIB_X86_SIMD}

procedure CpuIdQuery(ALeaf, ASubLeaf: UInt32; AResult: Pointer);
  {$I ..\Include\Simd\CpuFeatures\CpuIdQuery.inc}
end;

procedure XGetBvQuery(AResult: Pointer);
  {$I ..\Include\Simd\CpuFeatures\XGetBvQuery.inc}
end;

{$ENDIF}

{ TX86SimdFeatures }

class function TX86SimdFeatures.CPUHasSSE2(): Boolean;
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

class function TX86SimdFeatures.CPUHasSSSE3(): Boolean;
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

class function TX86SimdFeatures.CPUHasAVX2(): Boolean;
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

class function TX86SimdFeatures.CPUHasSHANI(): Boolean;
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

class function TX86SimdFeatures.CPUHasPCLMULQDQ(): Boolean;
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

class function TX86SimdFeatures.CPUHasVPCLMULQDQ(): Boolean;
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

class function TX86SimdFeatures.CPUHasAESNI(): Boolean;
{$IFDEF HASHLIB_X86_SIMD}
var
  LCpuId: TCpuIdResult;
{$ENDIF}
begin
{$IFDEF HASHLIB_X86_SIMD}
  CpuIdQuery(1, 0, @LCpuId);
  // AES-NI: ECX bit 25
  Result := (LCpuId.RegECX and (1 shl 25)) <> 0;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class procedure TX86SimdFeatures.ProbeHardwareAndCache();
begin
  FSimdLevel := TX86SimdLevel.Scalar;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;
  FHasAESNI := False;

  if CPUHasSSE2() then
  begin
    FSimdLevel := TX86SimdLevel.SSE2;
    FHasPCLMULQDQ := CPUHasPCLMULQDQ();
    if CPUHasSSSE3() then
    begin
      FSimdLevel := TX86SimdLevel.SSSE3;
      if CPUHasAVX2() then
      begin
        FSimdLevel := TX86SimdLevel.AVX2;
        FHasVPCLMULQDQ := CPUHasVPCLMULQDQ();
      end;
    end;
  end;

  FHasSHANI := CPUHasSHANI();
  FHasAESNI := CPUHasAESNI();
end;

class procedure TX86SimdFeatures.ApplyBuildOverrides();
begin
{$IF DEFINED(HASHLIB_FORCE_SCALAR)}
  FSimdLevel := TX86SimdLevel.Scalar;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;
  FHasAESNI := False;
{$ELSEIF DEFINED(HASHLIB_FORCE_SSE2)}
  if FSimdLevel > TX86SimdLevel.SSE2 then
    FSimdLevel := TX86SimdLevel.SSE2;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;
  FHasAESNI := False;
{$ELSEIF DEFINED(HASHLIB_FORCE_SSSE3)}
  if FSimdLevel > TX86SimdLevel.SSSE3 then
    FSimdLevel := TX86SimdLevel.SSSE3;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;
  FHasAESNI := False;
{$IFEND}
end;

class function TX86SimdFeatures.GetSimdLevel(): TX86SimdLevel;
begin
  Result := FSimdLevel;
end;

class function TX86SimdFeatures.HasSSE2(): Boolean;
begin
  Result := FSimdLevel >= TX86SimdLevel.SSE2;
end;

class function TX86SimdFeatures.HasSSSE3(): Boolean;
begin
  Result := FSimdLevel >= TX86SimdLevel.SSSE3;
end;

class function TX86SimdFeatures.HasAVX2(): Boolean;
begin
  Result := FSimdLevel >= TX86SimdLevel.AVX2;
end;

class function TX86SimdFeatures.HasSHANI(): Boolean;
begin
  Result := FHasSHANI;
end;

class function TX86SimdFeatures.HasPCLMULQDQ(): Boolean;
begin
  Result := FHasPCLMULQDQ;
end;

class function TX86SimdFeatures.HasVPCLMULQDQ(): Boolean;
begin
  Result := FHasVPCLMULQDQ;
end;

class function TX86SimdFeatures.HasAESNI(): Boolean;
begin
  Result := FHasAESNI;
end;

initialization
  TX86SimdFeatures.ProbeHardwareAndCache();
  TX86SimdFeatures.ApplyBuildOverrides();

end.
