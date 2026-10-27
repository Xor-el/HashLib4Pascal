library HashLibAndroidTests;

{$mode objfpc}{$H+}

uses
  cthreads,
  cwstring,
  jni,
  AndroidTestHost,
  HashLibTestBase,
  HashLibTestResourceLoader,
  CsvVectorParser,
  JsonVectorParser,
  CsvVectorLoaderBase,
  Blake2KatVectors,
  Blake3Vectors,
  Argon2Vectors,
  ScryptVectors,
  Pbkdf2Vectors,
  ChecksumTests,
  NullDigestTests,
  Hash32Tests,
  Hash64Tests,
  Hash128Tests,
  CryptoTests,
  PBKDF2_HMACTests,
  PBKDF_Argon2Tests,
  PBKDF_ScryptTests,
  CRCTests,
  SimdSelectSlotTests;

function JNI_OnLoad(AVm: PJavaVM; AReserved: Pointer): jint; cdecl;
begin
  Result := TAndroidTestHost.RegisterHost(AVm);
end;

exports
  JNI_OnLoad;

begin
end.
