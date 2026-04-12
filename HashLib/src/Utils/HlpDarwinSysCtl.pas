unit HlpDarwinSysCtl;

{$I ..\Include\HashLib.inc}

interface

{$IF DEFINED(HASHLIB_ARM)}
{$IF DEFINED(HASHLIB_MACOS) OR DEFINED(HASHLIB_IOS)}

uses
{$IFDEF FPC}
  dl
{$ELSE}
  Posix.Dlfcn
{$ENDIF}
  ;

type
  /// <summary>
  /// Resolves sysctlbyname from the already-loaded process image via
  /// dlopen(nil) + dlsym, avoiding any static import of Posix.SysSysctl.
  /// Provides a simple Boolean query for ARM feature detection on Darwin
  /// (macOS and iOS).
  /// </summary>
  TDarwinSysCtl = class sealed
  strict private
  type
    TSysCtlByNameFunc = function(AName: PAnsiChar; AOldP: Pointer;
      AOldLenP: Pointer; ANewP: Pointer; ANewLen: NativeUInt): Int32; cdecl;

  strict private
  class var
    FSysCtlByName: TSysCtlByNameFunc;
    FResolved: Boolean;

  strict private
    class procedure ResolveOnce(); static;

    /// <summary>
    /// Queries a single sysctl key. Returns True if the key exists and
    /// its integer value is >= 1.
    /// </summary>
    class function QueryKey(const AName: PAnsiChar): Boolean; static;

  public
    /// <summary>
    /// Returns True if the named sysctl feature is available.
    /// Tries AModernName first (macOS 12+ FEAT_* keys). If that key does
    /// not exist or returns 0, falls back to ALegacyName (macOS 11 keys).
    /// If ALegacyName is nil, no fallback is attempted.
    /// </summary>
    class function HasFeature(const AModernName: PAnsiChar;
      const ALegacyName: PAnsiChar = nil): Boolean; static;
  end;

{$IFEND} // HASHLIB_MACOS OR HASHLIB_IOS
{$IFEND} // HASHLIB_ARM

implementation

{$IF DEFINED(HASHLIB_ARM)}
{$IF DEFINED(HASHLIB_MACOS) OR DEFINED(HASHLIB_IOS)}

{ TDarwinSysCtl }

class procedure TDarwinSysCtl.ResolveOnce();
var
  LHandle: Pointer;
begin
  if FResolved then
    Exit;

  FSysCtlByName := nil;
  FResolved := True;

  LHandle := dlopen(nil, RTLD_NOW);
  if LHandle = nil then
    Exit;

  try
    FSysCtlByName := TSysCtlByNameFunc(dlsym(LHandle, 'sysctlbyname'));
  finally
    dlclose(LHandle);
  end;
end;

class function TDarwinSysCtl.QueryKey(const AName: PAnsiChar): Boolean;
var
  LValue: Int32;
  LLen: NativeUInt;
begin
  if (AName = nil) or (not System.Assigned(FSysCtlByName)) then
  begin
    Result := False;
    Exit;
  end;

  LValue := 0;
  LLen := SizeOf(LValue);

  if FSysCtlByName(AName, @LValue, @LLen, nil, 0) = 0 then
    Result := LValue >= 1
  else
    Result := False;
end;

class function TDarwinSysCtl.HasFeature(const AModernName: PAnsiChar;
  const ALegacyName: PAnsiChar): Boolean;
begin
  ResolveOnce();

  if not System.Assigned(FSysCtlByName) then
  begin
    Result := False;
    Exit;
  end;

  // Try the modern FEAT_* key first (available on macOS 12+)
  Result := QueryKey(AModernName);

  // If the modern key was not found or returned 0, try the legacy key
  if (not Result) and (ALegacyName <> nil) then
    Result := QueryKey(ALegacyName);
end;

{$IFEND} // HASHLIB_MACOS OR HASHLIB_IOS
{$IFEND} // HASHLIB_ARM

end.
