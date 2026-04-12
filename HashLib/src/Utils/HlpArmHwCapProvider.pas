unit HlpArmHwCapProvider;

{$I ..\Include\HashLib.inc}

interface

{$IF DEFINED(HASHLIB_ARM)}

{$IF DEFINED(HASHLIB_LINUX) OR DEFINED(HASHLIB_ANDROID) OR DEFINED(HASHLIB_BSD)}
uses
  {$IFDEF FPC}
  dl;
  {$ELSE}
  Posix.Dlfcn;
  {$ENDIF}
{$IFEND}

{$IF DEFINED(HASHLIB_MSWINDOWS)}
uses
  Windows;
{$IFEND}

{ ===== AArch64 HWCAP bit definitions (from asm/hwcap.h) ===== }
{ These constants are shared by Linux, Android, and BSD on AArch64. }

{$IF DEFINED(HASHLIB_LINUX) OR DEFINED(HASHLIB_ANDROID) OR DEFINED(HASHLIB_BSD)}

{$IF DEFINED(HASHLIB_AARCH64)}
const
  AT_HWCAP  = 16;
  AT_HWCAP2 = 26;

  HWCAP_ASIMD  = UInt64(1) shl 1;
  HWCAP_AES    = UInt64(1) shl 3;
  HWCAP_PMULL  = UInt64(1) shl 4;
  HWCAP_SHA1   = UInt64(1) shl 5;
  HWCAP_SHA2   = UInt64(1) shl 6;
  HWCAP_CRC32  = UInt64(1) shl 7;
  HWCAP_SHA3   = UInt64(1) shl 17;
  HWCAP_SHA512 = UInt64(1) shl 21;
  HWCAP_SVE    = UInt64(1) shl 22;

  HWCAP2_SVE2  = UInt64(1) shl 1;
{$IFEND}

{ ===== ARM32 HWCAP bit definitions (from asm/hwcap.h) ===== }
{ These constants are shared by Linux, Android, and BSD on ARM32. }

{$IF DEFINED(HASHLIB_ARM32)}
const
  AT_HWCAP  = 16;
  AT_HWCAP2 = 26;

  HWCAP_NEON    = UInt64(1) shl 12;

  HWCAP2_AES    = UInt64(1) shl 0;
  HWCAP2_PMULL  = UInt64(1) shl 1;
  HWCAP2_SHA1   = UInt64(1) shl 2;
  HWCAP2_SHA2   = UInt64(1) shl 3;
  HWCAP2_CRC32  = UInt64(1) shl 4;
{$IFEND}

{$IFEND} // HASHLIB_LINUX OR HASHLIB_ANDROID OR HASHLIB_BSD

{ ===== Windows ARM64 PF_ARM_* constants ===== }

{$IF DEFINED(HASHLIB_MSWINDOWS)}
const
  // Standard constants (always available)
  PF_ARM_NEON_INSTRUCTIONS_AVAILABLE       = 19;
  PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE  = 30; // Bundles AES, PMULL, SHA1, SHA256
  PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE   = 31;
  // Newer constants (SDK 22621+, defined here to avoid SDK version dependency)
  PF_ARM_V82_SHA3_INSTRUCTIONS_AVAILABLE   = 46;
  PF_ARM_V82_SHA512_INSTRUCTIONS_AVAILABLE = 47;
{$IFEND}

type
  /// <summary>
  /// Provides ARM hardware capability information across platforms.
  /// Linux/Android: resolves getauxval via dlsym.
  /// BSD: resolves elf_aux_info / _elf_aux_info via dlsym.
  /// Windows: wraps IsProcessorFeaturePresent from the Windows unit.
  /// </summary>
  TArmHwCapProvider = class sealed

{$IF DEFINED(HASHLIB_LINUX) OR DEFINED(HASHLIB_ANDROID)}
  strict private
  type
    TGetAuxValFunc = function(AType: UInt64): UInt64; cdecl;

  strict private
  class var
    FGetAuxVal: TGetAuxValFunc;
    FResolved: Boolean;

  strict private
    class procedure ResolveOnce(); static;

  public
    class function GetHwCap(): UInt64; static;
    class function GetHwCap2(): UInt64; static;
{$IFEND}

{$IF DEFINED(HASHLIB_BSD)}
  strict private
  type
    TElfAuxInfoFunc = function(AAuxType: Int32; ABuf: Pointer; ABufLen: Int32): Int32; cdecl;

  strict private
  class var
    FElfAuxInfo: TElfAuxInfoFunc;
    FResolved: Boolean;

  strict private
    class procedure ResolveOnce(); static;

  public
    class function GetHwCap(): UInt64; static;
    class function GetHwCap2(): UInt64; static;
{$IFEND}

{$IF DEFINED(HASHLIB_MSWINDOWS)}
  public
    class function HasProcessorFeature(AFeature: UInt32): Boolean; static;
{$IFEND}

  end;

{$IFEND} // HASHLIB_ARM

implementation

{$IF DEFINED(HASHLIB_ARM)}

{ TArmHwCapProvider }

{ ===== Linux / Android: getauxval ===== }

{$IF DEFINED(HASHLIB_LINUX) OR DEFINED(HASHLIB_ANDROID)}

class procedure TArmHwCapProvider.ResolveOnce();
var
  LHandle: Pointer;
begin
  if FResolved then
    Exit;

  FGetAuxVal := nil;
  FResolved := True;

  LHandle := dlopen(nil, RTLD_NOW);
  if LHandle = nil then
    Exit;

  try
    // getauxval is available in glibc (Linux) and Bionic (Android API 18+)
    FGetAuxVal := TGetAuxValFunc(dlsym(LHandle, 'getauxval'));
  finally
    dlclose(LHandle);
  end;
end;

class function TArmHwCapProvider.GetHwCap(): UInt64;
begin
  ResolveOnce();
  if System.Assigned(FGetAuxVal) then
    Result := FGetAuxVal(AT_HWCAP)
  else
    Result := 0;
end;

class function TArmHwCapProvider.GetHwCap2(): UInt64;
begin
  ResolveOnce();
  if System.Assigned(FGetAuxVal) then
    Result := FGetAuxVal(AT_HWCAP2)
  else
    Result := 0;
end;

{$IFEND} // HASHLIB_LINUX OR HASHLIB_ANDROID

{ ===== BSD: elf_aux_info / _elf_aux_info ===== }

{$IF DEFINED(HASHLIB_BSD)}

class procedure TArmHwCapProvider.ResolveOnce();
var
  LHandle: Pointer;
begin
  if FResolved then
    Exit;

  FElfAuxInfo := nil;
  FResolved := True;

  LHandle := dlopen(nil, RTLD_NOW);
  if LHandle = nil then
    Exit;

  try
    // FreeBSD exposes elf_aux_info
    FElfAuxInfo := TElfAuxInfoFunc(dlsym(LHandle, 'elf_aux_info'));
    if not System.Assigned(FElfAuxInfo) then
    begin
      // NetBSD and DragonFlyBSD use the underscore-prefixed variant
      FElfAuxInfo := TElfAuxInfoFunc(dlsym(LHandle, '_elf_aux_info'));
    end;
  finally
    dlclose(LHandle);
  end;
end;

class function TArmHwCapProvider.GetHwCap(): UInt64;
var
  LValue: UInt64;
begin
  ResolveOnce();
  if System.Assigned(FElfAuxInfo) then
  begin
    LValue := 0;
    if FElfAuxInfo(Int32(AT_HWCAP), @LValue, SizeOf(LValue)) = 0 then
      Result := LValue
    else
      Result := 0;
  end
  else
    Result := 0;
end;

class function TArmHwCapProvider.GetHwCap2(): UInt64;
var
  LValue: UInt64;
begin
  ResolveOnce();
  if System.Assigned(FElfAuxInfo) then
  begin
    LValue := 0;
    if FElfAuxInfo(Int32(AT_HWCAP2), @LValue, SizeOf(LValue)) = 0 then
      Result := LValue
    else
      Result := 0;
  end
  else
    Result := 0;
end;

{$IFEND} // HASHLIB_BSD

{ ===== Windows: IsProcessorFeaturePresent ===== }

{$IF DEFINED(HASHLIB_MSWINDOWS)}

class function TArmHwCapProvider.HasProcessorFeature(AFeature: UInt32): Boolean;
begin
  Result := IsProcessorFeaturePresent(AFeature);
end;

{$IFEND} // HASHLIB_MSWINDOWS

{$IFEND} // HASHLIB_ARM

end.
