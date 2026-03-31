unit HlpCRC32Fast;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpHash,
  HlpIHash,
  HlpIHashInfo,
  HlpHashResult,
  HlpIHashResult,
  HlpConverters,
  HlpCRCDispatch;

type

  TCRC32Fast = class(THash, IChecksum, IHash32, ITransformBlock)

  strict protected
  var
    FCurrentCRC: UInt32;

  public

    constructor Create();

    procedure Initialize(); override;
    function TransformFinal(): IHashResult; override;

  end;

  TCRC32_PKZIP = class sealed(TCRC32Fast)

  strict private

  const
    Crc32PkzipPolynomial = UInt32($EDB88320); // Polynomial Reversed
    Crc32PkzipMsbPoly = UInt32($04C11DB7);    // MSB-first form

    class var
      FCrc32PkzipTable: THashLibMatrixUInt32Array;
      FCrc32PkzipFoldRuntime: TCRCFoldRuntimeCtx32;

    class constructor Crc32Pkzip();

  public
    constructor Create();
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;
    function Clone(): IHash; override;

  end;

  TCRC32_CASTAGNOLI = class sealed(TCRC32Fast)

  strict private

  const
    Crc32CastagnoliPolynomial = UInt32($82F63B78); // Polynomial Reversed
    Crc32CastagnoliMsbPoly = UInt32($1EDC6F41);    // MSB-first form

    class var
      FCrc32CastagnoliTable: THashLibMatrixUInt32Array;
      FCrc32CastagnoliFoldRuntime: TCRCFoldRuntimeCtx32;

    class constructor Crc32Castagnoli();

  public
    constructor Create();
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;
    function Clone(): IHash; override;

  end;

implementation

procedure CRC32FastInitFoldTables(const AReflectedPoly, AMsbPoly: UInt32;
  var ATable: THashLibMatrixUInt32Array; var ACtx: TCRCFoldRuntimeCtx32);
begin
  ATable := CRCDispatch_BuildSlicingTable32Reflect(AReflectedPoly);
  CRCDispatch_InitRuntimeCtx32(ATable, AMsbPoly, ACtx);
end;

{ TCRC32Fast }

constructor TCRC32Fast.Create();
begin
  inherited Create(4, 1);
end;

procedure TCRC32Fast.Initialize;
begin
  FCurrentCRC := 0;
end;

function TCRC32Fast.TransformFinal: IHashResult;
var
  LBufferBytes: THashLibByteArray;
begin
  System.SetLength(LBufferBytes, HashSize);
  TConverters.ReadUInt32AsBytesBE(FCurrentCRC, LBufferBytes, 0);

  Result := THashResult.Create(LBufferBytes);
  Initialize();
end;

{ TCRC32_PKZIP }

function TCRC32_PKZIP.Clone(): IHash;
var
  LHashInstance: TCRC32_PKZIP;
begin
  LHashInstance := TCRC32_PKZIP.Create();
  LHashInstance.FCurrentCRC := FCurrentCRC;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TCRC32_PKZIP.Create;
begin
  inherited Create();
end;

procedure TCRC32_PKZIP.TransformBytes(const AData: THashLibByteArray;
  AIndex, ALength: Int32);
begin
  CRCDispatch_UpdateReflectedCrc32(FCurrentCRC, PByte(AData) + AIndex,
    UInt32(ALength), @FCrc32PkzipFoldRuntime);
end;

class constructor TCRC32_PKZIP.Crc32Pkzip();
begin
  CRC32FastInitFoldTables(Crc32PkzipPolynomial, Crc32PkzipMsbPoly,
    FCrc32PkzipTable, FCrc32PkzipFoldRuntime);
end;

{ TCRC32_CASTAGNOLI }

function TCRC32_CASTAGNOLI.Clone(): IHash;
var
  LHashInstance: TCRC32_CASTAGNOLI;
begin
  LHashInstance := TCRC32_CASTAGNOLI.Create();
  LHashInstance.FCurrentCRC := FCurrentCRC;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TCRC32_CASTAGNOLI.Create;
begin
  inherited Create();
end;

procedure TCRC32_CASTAGNOLI.TransformBytes(const AData: THashLibByteArray;
  AIndex, ALength: Int32);
begin
  CRCDispatch_UpdateReflectedCrc32(FCurrentCRC, PByte(AData) + AIndex,
    UInt32(ALength), @FCrc32CastagnoliFoldRuntime);
end;

class constructor TCRC32_CASTAGNOLI.Crc32Castagnoli();
begin
  CRC32FastInitFoldTables(Crc32CastagnoliPolynomial, Crc32CastagnoliMsbPoly,
    FCrc32CastagnoliTable, FCrc32CastagnoliFoldRuntime);
end;

end.
