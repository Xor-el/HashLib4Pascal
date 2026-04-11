unit HlpArmSimdFeatures;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpSimdLevels;

type
  TArmSimdFeatures = class sealed
  strict private
  class var
    FSimdLevel: TArmSimdLevel;
    FHasAES: Boolean;
    FHasSHA1: Boolean;
    FHasSHA256: Boolean;
    FHasSHA512: Boolean;
    FHasSHA3: Boolean;
    FHasPMULL: Boolean;

  strict private
    class function CPUHasNEON(): Boolean; static;
    class function CPUHasSVE(): Boolean; static;
    class function CPUHasSVE2(): Boolean; static;
    class function CPUHasAES(): Boolean; static;
    class function CPUHasSHA1(): Boolean; static;
    class function CPUHasSHA256(): Boolean; static;
    class function CPUHasSHA512(): Boolean; static;
    class function CPUHasSHA3(): Boolean; static;
    class function CPUHasPMULL(): Boolean; static;

  private
    class procedure ProbeHardwareAndCache(); static;
    class procedure ApplyBuildOverrides(); static;

  public
    class function GetSimdLevel(): TArmSimdLevel; static;
    class function HasNEON(): Boolean; static;
    class function HasSVE(): Boolean; static;
    class function HasSVE2(): Boolean; static;
    class function HasAES(): Boolean; static;
    class function HasSHA1(): Boolean; static;
    class function HasSHA256(): Boolean; static;
    class function HasSHA512(): Boolean; static;
    class function HasSHA3(): Boolean; static;
    class function HasPMULL(): Boolean; static;
  end;

implementation

{ TArmSimdFeatures }

class function TArmSimdFeatures.CPUHasNEON(): Boolean;
begin
  // TODO: implement platform-specific NEON detection
  Result := False;
end;

class function TArmSimdFeatures.CPUHasSVE(): Boolean;
begin
  // TODO: implement platform-specific SVE detection
  Result := False;
end;

class function TArmSimdFeatures.CPUHasSVE2(): Boolean;
begin
  // TODO: implement platform-specific SVE2 detection
  Result := False;
end;

class function TArmSimdFeatures.CPUHasAES(): Boolean;
begin
  // TODO: implement platform-specific AES extension detection
  Result := False;
end;

class function TArmSimdFeatures.CPUHasSHA1(): Boolean;
begin
  // TODO: implement platform-specific SHA1 extension detection
  Result := False;
end;

class function TArmSimdFeatures.CPUHasSHA256(): Boolean;
begin
  // TODO: implement platform-specific SHA256 extension detection
  Result := False;
end;

class function TArmSimdFeatures.CPUHasSHA512(): Boolean;
begin
  // TODO: implement platform-specific SHA512 extension detection
  Result := False;
end;

class function TArmSimdFeatures.CPUHasSHA3(): Boolean;
begin
  // TODO: implement platform-specific SHA3 extension detection
  Result := False;
end;

class function TArmSimdFeatures.CPUHasPMULL(): Boolean;
begin
  // TODO: implement platform-specific PMULL extension detection
  Result := False;
end;

class procedure TArmSimdFeatures.ProbeHardwareAndCache();
begin
  FSimdLevel := TArmSimdLevel.Scalar;
  FHasAES := False;
  FHasSHA1 := False;
  FHasSHA256 := False;
  FHasSHA512 := False;
  FHasSHA3 := False;
  FHasPMULL := False;

  if CPUHasNEON() then
  begin
    FSimdLevel := TArmSimdLevel.NEON;

    FHasAES := CPUHasAES();
    FHasSHA1 := CPUHasSHA1();
    FHasSHA256 := CPUHasSHA256();
    FHasSHA512 := CPUHasSHA512();
    FHasSHA3 := CPUHasSHA3();
    FHasPMULL := CPUHasPMULL();

    if CPUHasSVE() then
    begin
      FSimdLevel := TArmSimdLevel.SVE;
      if CPUHasSVE2() then
        FSimdLevel := TArmSimdLevel.SVE2;
    end;
  end;
end;

class procedure TArmSimdFeatures.ApplyBuildOverrides();
begin
{$IF DEFINED(HASHLIB_FORCE_SCALAR)}
  FSimdLevel := TArmSimdLevel.Scalar;
  FHasAES := False;
  FHasSHA1 := False;
  FHasSHA256 := False;
  FHasSHA512 := False;
  FHasSHA3 := False;
  FHasPMULL := False;
{$ELSEIF DEFINED(HASHLIB_FORCE_NEON)}
  if FSimdLevel > TArmSimdLevel.NEON then
    FSimdLevel := TArmSimdLevel.NEON;
{$ELSEIF DEFINED(HASHLIB_FORCE_SVE)}
  if FSimdLevel > TArmSimdLevel.SVE then
    FSimdLevel := TArmSimdLevel.SVE;
{$IFEND}
end;

class function TArmSimdFeatures.GetSimdLevel(): TArmSimdLevel;
begin
  Result := FSimdLevel;
end;

class function TArmSimdFeatures.HasNEON(): Boolean;
begin
  Result := FSimdLevel >= TArmSimdLevel.NEON;
end;

class function TArmSimdFeatures.HasSVE(): Boolean;
begin
  Result := FSimdLevel >= TArmSimdLevel.SVE;
end;

class function TArmSimdFeatures.HasSVE2(): Boolean;
begin
  Result := FSimdLevel >= TArmSimdLevel.SVE2;
end;

class function TArmSimdFeatures.HasAES(): Boolean;
begin
  Result := FHasAES;
end;

class function TArmSimdFeatures.HasSHA1(): Boolean;
begin
  Result := FHasSHA1;
end;

class function TArmSimdFeatures.HasSHA256(): Boolean;
begin
  Result := FHasSHA256;
end;

class function TArmSimdFeatures.HasSHA512(): Boolean;
begin
  Result := FHasSHA512;
end;

class function TArmSimdFeatures.HasSHA3(): Boolean;
begin
  Result := FHasSHA3;
end;

class function TArmSimdFeatures.HasPMULL(): Boolean;
begin
  Result := FHasPMULL;
end;

initialization
  TArmSimdFeatures.ProbeHardwareAndCache();
  TArmSimdFeatures.ApplyBuildOverrides();

end.
