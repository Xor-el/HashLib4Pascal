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
    FActiveSimdLevel: TX86SimdLevel;
    FHasSHANI: Boolean;
    FHasPCLMULQDQ: Boolean;
    FHasVPCLMULQDQ: Boolean;
    FHasAESNI: Boolean;

  strict private
    class function CPUHasSSE2(): Boolean; static;
    class function CPUHasSSE3(): Boolean; static;
    class function CPUHasSSSE3(): Boolean; static;
    class function CPUHasSSE41(): Boolean; static;
    class function CPUHasSSE42(): Boolean; static;
    class function CPUHasAVX2(): Boolean; static;
    class function CPUHasSHANI(): Boolean; static;
    class function CPUHasPCLMULQDQ(): Boolean; static;
    class function CPUHasVPCLMULQDQ(): Boolean; static;
    class function CPUHasAESNI(): Boolean; static;

  private
    class procedure ProbeHardwareAndCache(); static;
    class procedure ApplyBuildOverrides(); static;

  public
    class function GetActiveSimdLevel(): TX86SimdLevel; static;
    class function HasSSE2(): Boolean; static;
    class function HasSSE3(): Boolean; static;
    class function HasSSSE3(): Boolean; static;
    class function HasSSE41(): Boolean; static;
    class function HasSSE42(): Boolean; static;
    class function HasAVX2(): Boolean; static;
    class function HasSHANI(): Boolean; static;
    class function HasPCLMULQDQ(): Boolean; static;
    class function HasVPCLMULQDQ(): Boolean; static;
    class function HasAESNI(): Boolean; static;

    // Picks the highest declared tier in ATiers that is <= the cached
    // FActiveSimdLevel. Falls back to TX86SimdLevel.Scalar when no tier
    // matches or ATiers is empty. Dispatch units use this overload.
    class function SelectSlot(const ATiers: array of TX86SimdLevel)
      : TX86SimdLevel; overload; static;

    // Pure overload: reasons over any caller-supplied active level.
    // Used by tests to deterministically exercise fallback semantics
    // without depending on the host CPU.
    class function SelectSlot(AActiveLevel: TX86SimdLevel;
      const ATiers: array of TX86SimdLevel): TX86SimdLevel; overload; static;
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

class function TX86SimdFeatures.CPUHasSSE3(): Boolean;
{$IFDEF HASHLIB_X86_SIMD}
var
  LCpuId: TCpuIdResult;
{$ENDIF}
begin
{$IFDEF HASHLIB_X86_SIMD}
  CpuIdQuery(1, 0, @LCpuId);
  // SSE3: ECX bit 0
  Result := (LCpuId.RegECX and (1 shl 0)) <> 0;
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

class function TX86SimdFeatures.CPUHasSSE41(): Boolean;
{$IFDEF HASHLIB_X86_SIMD}
var
  LCpuId: TCpuIdResult;
{$ENDIF}
begin
{$IFDEF HASHLIB_X86_SIMD}
  CpuIdQuery(1, 0, @LCpuId);
  // SSE4.1: ECX bit 19
  Result := (LCpuId.RegECX and (1 shl 19)) <> 0;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TX86SimdFeatures.CPUHasSSE42(): Boolean;
{$IFDEF HASHLIB_X86_SIMD}
var
  LCpuId: TCpuIdResult;
{$ENDIF}
begin
{$IFDEF HASHLIB_X86_SIMD}
  CpuIdQuery(1, 0, @LCpuId);
  // SSE4.2: ECX bit 20
  Result := (LCpuId.RegECX and (1 shl 20)) <> 0;
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
var
  LHasSSE2, LHasSSE3, LHasSSSE3, LHasSSE41, LHasSSE42, LHasAVX2: Boolean;
begin
  // Probe once, reason later
  LHasSSE2  := CPUHasSSE2();
  LHasSSE3  := CPUHasSSE3()  and LHasSSE2;
  LHasSSSE3 := CPUHasSSSE3() and LHasSSE3;   // enforce invariant defensively
  LHasSSE41 := CPUHasSSE41() and LHasSSSE3;
  LHasSSE42 := CPUHasSSE42() and LHasSSE41;
  LHasAVX2  := CPUHasAVX2()  and LHasSSE42;  // AVX2 implies full SSE lineage

  // Pick the highest tier the CPU can sustain
  if LHasAVX2 then
    FActiveSimdLevel := TX86SimdLevel.AVX2
  else if LHasSSE42 then
    FActiveSimdLevel := TX86SimdLevel.SSE42
  else if LHasSSE41 then
    FActiveSimdLevel := TX86SimdLevel.SSE41
  else if LHasSSSE3 then
    FActiveSimdLevel := TX86SimdLevel.SSSE3
  else if LHasSSE3 then
    FActiveSimdLevel := TX86SimdLevel.SSE3
  else if LHasSSE2 then
    FActiveSimdLevel := TX86SimdLevel.SSE2
  else
    FActiveSimdLevel := TX86SimdLevel.Scalar;

  // Independent feature bits - not tied to the SIMD tier ladder
  FHasAESNI      := CPUHasAESNI();
  FHasSHANI      := CPUHasSHANI();
  FHasPCLMULQDQ  := CPUHasPCLMULQDQ();
  FHasVPCLMULQDQ := CPUHasVPCLMULQDQ() and LHasAVX2;  // VPCLMULQDQ needs AVX/AVX2 lanes
end;

class procedure TX86SimdFeatures.ApplyBuildOverrides();
begin
{$IF DEFINED(HASHLIB_FORCE_SCALAR)}
  FActiveSimdLevel := TX86SimdLevel.Scalar;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;
  FHasAESNI := False;
{$ELSEIF DEFINED(HASHLIB_FORCE_SSE2)}
  if FActiveSimdLevel > TX86SimdLevel.SSE2 then
    FActiveSimdLevel := TX86SimdLevel.SSE2;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;
  FHasAESNI := False;
{$ELSEIF DEFINED(HASHLIB_FORCE_SSE3)}
  if FActiveSimdLevel > TX86SimdLevel.SSE3 then
    FActiveSimdLevel := TX86SimdLevel.SSE3;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;
  FHasAESNI := False;
{$ELSEIF DEFINED(HASHLIB_FORCE_SSSE3)}
  if FActiveSimdLevel > TX86SimdLevel.SSSE3 then
    FActiveSimdLevel := TX86SimdLevel.SSSE3;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;
  FHasAESNI := False;
{$ELSEIF DEFINED(HASHLIB_FORCE_SSE41)}
  if FActiveSimdLevel > TX86SimdLevel.SSE41 then
    FActiveSimdLevel := TX86SimdLevel.SSE41;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;
  FHasAESNI := False;
{$ELSEIF DEFINED(HASHLIB_FORCE_SSE42)}
  if FActiveSimdLevel > TX86SimdLevel.SSE42 then
    FActiveSimdLevel := TX86SimdLevel.SSE42;
  FHasSHANI := False;
  FHasPCLMULQDQ := False;
  FHasVPCLMULQDQ := False;
  FHasAESNI := False;
{$IFEND}
end;

class function TX86SimdFeatures.GetActiveSimdLevel(): TX86SimdLevel;
begin
  Result := FActiveSimdLevel;
end;

class function TX86SimdFeatures.HasSSE2(): Boolean;
begin
  Result := FActiveSimdLevel >= TX86SimdLevel.SSE2;
end;

class function TX86SimdFeatures.HasSSE3(): Boolean;
begin
  Result := FActiveSimdLevel >= TX86SimdLevel.SSE3;
end;

class function TX86SimdFeatures.HasSSSE3(): Boolean;
begin
  Result := FActiveSimdLevel >= TX86SimdLevel.SSSE3;
end;

class function TX86SimdFeatures.HasSSE41(): Boolean;
begin
  Result := FActiveSimdLevel >= TX86SimdLevel.SSE41;
end;

class function TX86SimdFeatures.HasSSE42(): Boolean;
begin
  Result := FActiveSimdLevel >= TX86SimdLevel.SSE42;
end;

class function TX86SimdFeatures.HasAVX2(): Boolean;
begin
  Result := FActiveSimdLevel >= TX86SimdLevel.AVX2;
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

class function TX86SimdFeatures.SelectSlot(const ATiers
  : array of TX86SimdLevel): TX86SimdLevel;
begin
  Result := SelectSlot(FActiveSimdLevel, ATiers);
end;

class function TX86SimdFeatures.SelectSlot(AActiveLevel: TX86SimdLevel;
  const ATiers: array of TX86SimdLevel): TX86SimdLevel;
var
  I: Integer;
  LTier, LBest: TX86SimdLevel;
  LFound: Boolean;
begin
  // Walk all declared tiers, keep the highest one that is <= AActiveLevel.
  // Order of ATiers is irrelevant. Empty ATiers or no matching tier yields
  // TX86SimdLevel.Scalar so dispatch units cleanly fall through to scalar.
  LBest := TX86SimdLevel.Scalar;
  LFound := False;
  for I := 0 to System.Length(ATiers) - 1 do
  begin
    LTier := ATiers[I];
    if (LTier <= AActiveLevel) and ((not LFound) or (LTier > LBest)) then
    begin
      LBest := LTier;
      LFound := True;
    end;
  end;
  if LFound then
    Result := LBest
  else
    Result := TX86SimdLevel.Scalar;
end;

initialization
  TX86SimdFeatures.ProbeHardwareAndCache();
  TX86SimdFeatures.ApplyBuildOverrides();

end.
