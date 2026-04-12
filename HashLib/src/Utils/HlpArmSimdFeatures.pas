unit HlpArmSimdFeatures;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpSimdLevels
{$IF DEFINED(HASHLIB_ARM)}
  , HlpArmHwCapProvider
  {$IF DEFINED(HASHLIB_MACOS) OR DEFINED(HASHLIB_IOS)}
  , HlpDarwinSysCtl
  {$IFEND}
{$IFEND}
  ;

type
  TArmSimdFeatures = class sealed
  strict private
  class var
    FActiveSimdLevel: TArmSimdLevel;
    FHasAES: Boolean;
    FHasSHA1: Boolean;
    FHasSHA256: Boolean;
    FHasSHA512: Boolean;
    FHasSHA3: Boolean;
    FHasCRC32: Boolean;
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
    class function CPUHasCRC32(): Boolean; static;
    class function CPUHasPMULL(): Boolean; static;

  private
    class procedure ProbeHardwareAndCache(); static;
    class procedure ApplyBuildOverrides(); static;

  public
    class function GetActiveSimdLevel(): TArmSimdLevel; static;
    class function HasNEON(): Boolean; static;
    class function HasSVE(): Boolean; static;
    class function HasSVE2(): Boolean; static;
    class function HasAES(): Boolean; static;
    class function HasSHA1(): Boolean; static;
    class function HasSHA256(): Boolean; static;
    class function HasSHA512(): Boolean; static;
    class function HasSHA3(): Boolean; static;
    class function HasCRC32(): Boolean; static;
    class function HasPMULL(): Boolean; static;
  end;

implementation

{ TArmSimdFeatures }

{ ========================= CPUHas* Detection Methods ======================== }

class function TArmSimdFeatures.CPUHasNEON(): Boolean;
begin
{$IF DEFINED(HASHLIB_ARM)}

  {$IF DEFINED(HASHLIB_MSWINDOWS)}
    // NEON is mandatory on Windows ARM64, but we verify for safety
    Result := TArmHwCapProvider.HasProcessorFeature(PF_ARM_NEON_INSTRUCTIONS_AVAILABLE);

  {$ELSEIF DEFINED(HASHLIB_LINUX) OR DEFINED(HASHLIB_ANDROID) OR DEFINED(HASHLIB_BSD)}
    {$IF DEFINED(HASHLIB_AARCH64)}
      // NEON (ASIMD) is mandatory on AArch64, but we verify for safety
      Result := TArmHwCapProvider.GetHwCap() and HWCAP_ASIMD <> 0;
    {$ELSE}
      Result := TArmHwCapProvider.GetHwCap() and HWCAP_NEON <> 0;
    {$IFEND}

  {$ELSEIF DEFINED(HASHLIB_MACOS) OR DEFINED(HASHLIB_IOS)}
    // NEON is mandatory on AArch64 Apple Silicon, but we verify for safety
    Result := TDarwinSysCtl.HasFeature('hw.optional.arm.FEAT_AdvSIMD', 'hw.optional.neon');

  {$ELSE}
    Result := False;
  {$IFEND}

{$ELSE}
  Result := False;
{$IFEND}
end;

class function TArmSimdFeatures.CPUHasSVE(): Boolean;
begin
{$IF DEFINED(HASHLIB_ARM)}
  {$IF DEFINED(HASHLIB_AARCH64)}

    {$IF DEFINED(HASHLIB_MSWINDOWS)}
      // Windows ARM64 does not currently expose SVE detection
      Result := False;

    {$ELSEIF DEFINED(HASHLIB_LINUX) OR DEFINED(HASHLIB_ANDROID) OR DEFINED(HASHLIB_BSD)}
      Result := TArmHwCapProvider.GetHwCap() and HWCAP_SVE <> 0;

    {$ELSEIF DEFINED(HASHLIB_MACOS) OR DEFINED(HASHLIB_IOS)}
      // Apple Silicon does not implement SVE, but we check anyway for future-proofing
      Result := TDarwinSysCtl.HasFeature('hw.optional.arm.FEAT_SVE');

    {$ELSE}
      Result := False;
    {$IFEND}

  {$ELSE}
    // SVE is AArch64-only
    Result := False;
  {$IFEND}
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TArmSimdFeatures.CPUHasSVE2(): Boolean;
begin
{$IF DEFINED(HASHLIB_ARM)}
  {$IF DEFINED(HASHLIB_AARCH64)}

    {$IF DEFINED(HASHLIB_MSWINDOWS)}
      // Windows ARM64 does not currently expose SVE2 detection
      Result := False;

    {$ELSEIF DEFINED(HASHLIB_LINUX) OR DEFINED(HASHLIB_ANDROID) OR DEFINED(HASHLIB_BSD)}
      Result := TArmHwCapProvider.GetHwCap2() and HWCAP2_SVE2 <> 0;

    {$ELSEIF DEFINED(HASHLIB_MACOS) OR DEFINED(HASHLIB_IOS)}
      // Apple Silicon does not implement SVE2, but we check anyway for future-proofing
      Result := TDarwinSysCtl.HasFeature('hw.optional.arm.FEAT_SVE2');

    {$ELSE}
      Result := False;
    {$IFEND}

  {$ELSE}
    // SVE2 is AArch64-only
    Result := False;
  {$IFEND}
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TArmSimdFeatures.CPUHasAES(): Boolean;
begin
{$IF DEFINED(HASHLIB_ARM)}

  {$IF DEFINED(HASHLIB_MSWINDOWS)}
    // AES is bundled with crypto on Windows ARM64, but we verify for safety
    Result := TArmHwCapProvider.HasProcessorFeature(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE);

  {$ELSEIF DEFINED(HASHLIB_LINUX) OR DEFINED(HASHLIB_ANDROID) OR DEFINED(HASHLIB_BSD)}
    {$IF DEFINED(HASHLIB_AARCH64)}
      Result := TArmHwCapProvider.GetHwCap() and HWCAP_AES <> 0;
    {$ELSE}
      Result := TArmHwCapProvider.GetHwCap2() and HWCAP2_AES <> 0;
    {$IFEND}

  {$ELSEIF DEFINED(HASHLIB_MACOS) OR DEFINED(HASHLIB_IOS)}
    // AES is present on all Apple Silicon, but we verify for safety
    Result := TDarwinSysCtl.HasFeature('hw.optional.arm.FEAT_AES');

  {$ELSE}
    Result := False;
  {$IFEND}

{$ELSE}
  Result := False;
{$IFEND}
end;

class function TArmSimdFeatures.CPUHasSHA1(): Boolean;
begin
{$IF DEFINED(HASHLIB_ARM)}

  {$IF DEFINED(HASHLIB_MSWINDOWS)}
    // SHA1 is bundled with crypto on Windows ARM64, but we verify for safety
    Result := TArmHwCapProvider.HasProcessorFeature(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE);

  {$ELSEIF DEFINED(HASHLIB_LINUX) OR DEFINED(HASHLIB_ANDROID) OR DEFINED(HASHLIB_BSD)}
    {$IF DEFINED(HASHLIB_AARCH64)}
      Result := TArmHwCapProvider.GetHwCap() and HWCAP_SHA1 <> 0;
    {$ELSE}
      Result := TArmHwCapProvider.GetHwCap2() and HWCAP2_SHA1 <> 0;
    {$IFEND}

  {$ELSEIF DEFINED(HASHLIB_MACOS) OR DEFINED(HASHLIB_IOS)}
    // SHA1 is present on all Apple Silicon, but we verify for safety
    Result := TDarwinSysCtl.HasFeature('hw.optional.arm.FEAT_SHA1');

  {$ELSE}
    Result := False;
  {$IFEND}

{$ELSE}
  Result := False;
{$IFEND}
end;

class function TArmSimdFeatures.CPUHasSHA256(): Boolean;
begin
{$IF DEFINED(HASHLIB_ARM)}

  {$IF DEFINED(HASHLIB_MSWINDOWS)}
    // SHA256 is bundled with crypto on Windows ARM64, but we verify for safety
    Result := TArmHwCapProvider.HasProcessorFeature(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE);

  {$ELSEIF DEFINED(HASHLIB_LINUX) OR DEFINED(HASHLIB_ANDROID) OR DEFINED(HASHLIB_BSD)}
    {$IF DEFINED(HASHLIB_AARCH64)}
      Result := TArmHwCapProvider.GetHwCap() and HWCAP_SHA2 <> 0;
    {$ELSE}
      Result := TArmHwCapProvider.GetHwCap2() and HWCAP2_SHA2 <> 0;
    {$IFEND}

  {$ELSEIF DEFINED(HASHLIB_MACOS) OR DEFINED(HASHLIB_IOS)}
    // SHA256 is present on all Apple Silicon, but we verify for safety
    Result := TDarwinSysCtl.HasFeature('hw.optional.arm.FEAT_SHA256');

  {$ELSE}
    Result := False;
  {$IFEND}

{$ELSE}
  Result := False;
{$IFEND}
end;

class function TArmSimdFeatures.CPUHasSHA512(): Boolean;
begin
{$IF DEFINED(HASHLIB_ARM)}
  {$IF DEFINED(HASHLIB_AARCH64)}

    {$IF DEFINED(HASHLIB_MSWINDOWS)}
      Result := TArmHwCapProvider.HasProcessorFeature(PF_ARM_V82_SHA512_INSTRUCTIONS_AVAILABLE);

    {$ELSEIF DEFINED(HASHLIB_LINUX) OR DEFINED(HASHLIB_ANDROID) OR DEFINED(HASHLIB_BSD)}
      Result := TArmHwCapProvider.GetHwCap() and HWCAP_SHA512 <> 0;

    {$ELSEIF DEFINED(HASHLIB_MACOS) OR DEFINED(HASHLIB_IOS)}
      Result := TDarwinSysCtl.HasFeature('hw.optional.arm.FEAT_SHA512', 'hw.optional.armv8_2_sha512');

    {$ELSE}
      Result := False;
    {$IFEND}

  {$ELSE}
    // SHA512 acceleration is AArch64-only (ARMv8.2)
    Result := False;
  {$IFEND}
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TArmSimdFeatures.CPUHasSHA3(): Boolean;
begin
{$IF DEFINED(HASHLIB_ARM)}
  {$IF DEFINED(HASHLIB_AARCH64)}

    {$IF DEFINED(HASHLIB_MSWINDOWS)}
      Result := TArmHwCapProvider.HasProcessorFeature(PF_ARM_V82_SHA3_INSTRUCTIONS_AVAILABLE);

    {$ELSEIF DEFINED(HASHLIB_LINUX) OR DEFINED(HASHLIB_ANDROID) OR DEFINED(HASHLIB_BSD)}
      Result := TArmHwCapProvider.GetHwCap() and HWCAP_SHA3 <> 0;

    {$ELSEIF DEFINED(HASHLIB_MACOS) OR DEFINED(HASHLIB_IOS)}
      Result := TDarwinSysCtl.HasFeature('hw.optional.arm.FEAT_SHA3', 'hw.optional.armv8_2_sha3');

    {$ELSE}
      Result := False;
    {$IFEND}

  {$ELSE}
    // SHA3 acceleration is AArch64-only (ARMv8.2)
    Result := False;
  {$IFEND}
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TArmSimdFeatures.CPUHasCRC32(): Boolean;
begin
{$IF DEFINED(HASHLIB_ARM)}

  {$IF DEFINED(HASHLIB_MSWINDOWS)}
    // CRC32 is mandatory on Windows ARM64, but we verify for safety
    Result := TArmHwCapProvider.HasProcessorFeature(PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE);

  {$ELSEIF DEFINED(HASHLIB_LINUX) OR DEFINED(HASHLIB_ANDROID) OR DEFINED(HASHLIB_BSD)}
    {$IF DEFINED(HASHLIB_AARCH64)}
      Result := TArmHwCapProvider.GetHwCap() and HWCAP_CRC32 <> 0;
    {$ELSE}
      Result := TArmHwCapProvider.GetHwCap2() and HWCAP2_CRC32 <> 0;
    {$IFEND}

  {$ELSEIF DEFINED(HASHLIB_MACOS) OR DEFINED(HASHLIB_IOS)}
    // CRC32 is present on all Apple Silicon, but we verify for safety
    Result := TDarwinSysCtl.HasFeature('hw.optional.armv8_crc32');

  {$ELSE}
    Result := False;
  {$IFEND}

{$ELSE}
  Result := False;
{$IFEND}
end;

class function TArmSimdFeatures.CPUHasPMULL(): Boolean;
begin
{$IF DEFINED(HASHLIB_ARM)}

  {$IF DEFINED(HASHLIB_MSWINDOWS)}
    // PMULL is bundled with crypto on Windows ARM64, but we verify for safety
    Result := TArmHwCapProvider.HasProcessorFeature(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE);

  {$ELSEIF DEFINED(HASHLIB_LINUX) OR DEFINED(HASHLIB_ANDROID) OR DEFINED(HASHLIB_BSD)}
    {$IF DEFINED(HASHLIB_AARCH64)}
      Result := TArmHwCapProvider.GetHwCap() and HWCAP_PMULL <> 0;
    {$ELSE}
      Result := TArmHwCapProvider.GetHwCap2() and HWCAP2_PMULL <> 0;
    {$IFEND}

  {$ELSEIF DEFINED(HASHLIB_MACOS) OR DEFINED(HASHLIB_IOS)}
    // PMULL is present on all Apple Silicon, but we verify for safety
    Result := TDarwinSysCtl.HasFeature('hw.optional.arm.FEAT_PMULL');

  {$ELSE}
    Result := False;
  {$IFEND}

{$ELSE}
  Result := False;
{$IFEND}
end;

{ ========================= Probe & Override ================================= }

class procedure TArmSimdFeatures.ProbeHardwareAndCache();
begin
  FActiveSimdLevel := TArmSimdLevel.Scalar;
  FHasAES := False;
  FHasSHA1 := False;
  FHasSHA256 := False;
  FHasSHA512 := False;
  FHasSHA3 := False;
  FHasCRC32 := False;
  FHasPMULL := False;

  if CPUHasNEON() then
  begin
    FActiveSimdLevel := TArmSimdLevel.NEON;

    FHasAES := CPUHasAES();
    FHasSHA1 := CPUHasSHA1();
    FHasSHA256 := CPUHasSHA256();
    FHasSHA512 := CPUHasSHA512();
    FHasSHA3 := CPUHasSHA3();
    FHasCRC32 := CPUHasCRC32();
    FHasPMULL := CPUHasPMULL();

    if CPUHasSVE() then
    begin
      FActiveSimdLevel := TArmSimdLevel.SVE;
      if CPUHasSVE2() then
        FActiveSimdLevel := TArmSimdLevel.SVE2;
    end;
  end;
end;

class procedure TArmSimdFeatures.ApplyBuildOverrides();
begin
{$IF DEFINED(HASHLIB_FORCE_SCALAR)}
  FActiveSimdLevel := TArmSimdLevel.Scalar;
  FHasAES := False;
  FHasSHA1 := False;
  FHasSHA256 := False;
  FHasSHA512 := False;
  FHasSHA3 := False;
  FHasCRC32 := False;
  FHasPMULL := False;
{$ELSEIF DEFINED(HASHLIB_FORCE_NEON)}
  if FActiveSimdLevel > TArmSimdLevel.NEON then
    FActiveSimdLevel := TArmSimdLevel.NEON;
{$ELSEIF DEFINED(HASHLIB_FORCE_SVE)}
  if FActiveSimdLevel > TArmSimdLevel.SVE then
    FActiveSimdLevel := TArmSimdLevel.SVE;
{$IFEND}
end;

{ ========================= Public Accessors ================================= }

class function TArmSimdFeatures.GetActiveSimdLevel(): TArmSimdLevel;
begin
  Result := FActiveSimdLevel;
end;

class function TArmSimdFeatures.HasNEON(): Boolean;
begin
  Result := FActiveSimdLevel >= TArmSimdLevel.NEON;
end;

class function TArmSimdFeatures.HasSVE(): Boolean;
begin
  Result := FActiveSimdLevel >= TArmSimdLevel.SVE;
end;

class function TArmSimdFeatures.HasSVE2(): Boolean;
begin
  Result := FActiveSimdLevel >= TArmSimdLevel.SVE2;
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

class function TArmSimdFeatures.HasCRC32(): Boolean;
begin
  Result := FHasCRC32;
end;

class function TArmSimdFeatures.HasPMULL(): Boolean;
begin
  Result := FHasPMULL;
end;

initialization
  TArmSimdFeatures.ProbeHardwareAndCache();
  TArmSimdFeatures.ApplyBuildOverrides();

end.
