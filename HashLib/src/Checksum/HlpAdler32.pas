unit HlpAdler32;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpIHashInfo,
  HlpHash,
  HlpIHash,
  HlpHashResult,
  HlpIHashResult,
  HlpConverters;

type
  TAdler32 = class sealed(THash, IChecksum, IHash32, ITransformBlock)

  strict private
  var
    FSumA, FSumB: UInt32;

  const
    ModAdler = UInt32(65521);

  public
    constructor Create();
    procedure Initialize(); override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;
    function TransformFinal: IHashResult; override;
    function Clone(): IHash; override;

  end;

implementation

{ TAdler32 }

function TAdler32.Clone(): IHash;
var
  LHashInstance: TAdler32;
begin
  LHashInstance := TAdler32.Create();
  LHashInstance.FSumA := FSumA;
  LHashInstance.FSumB := FSumB;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TAdler32.Create;
begin
  inherited Create(4, 1);
end;

procedure TAdler32.Initialize;
begin
  FSumA := 1;
  FSumB := 0;
end;

procedure TAdler32.TransformBytes(const AData: THashLibByteArray;
  AIndex, ALength: Int32);
var
  LChunkLength: Int32;
  LPtrData: PByte;
  LSumA, LSumB: UInt32;
begin
{$IFDEF DEBUG}
  System.Assert(AIndex >= 0);
  System.Assert(ALength >= 0);
  System.Assert(AIndex + ALength <= System.Length(AData));
{$ENDIF DEBUG}
  LPtrData := PByte(AData) + AIndex;

  {
    LSumA := FSumA;
    LSumB := FSumB;
    while ALength > 0 do
    begin
    LSumA := (LSumA + LPtrData^) mod ModAdler;
    LSumB := (LSumB + LSumA) mod ModAdler;
    System.Inc(LPtrData);
    System.Dec(ALength);
    end;
    FSumA := LSumA;
    FSumB := LSumB;
  }

  // lifted from PngEncoder Adler32.cs

  while ALength > 0 do
  begin
    // We can defer the modulo operation:
    // FSumA maximally grows from 65521 to 65521 + 255 * 3800
    // FSumB maximally grows by 3800 * median(FSumA) = 2090079800 < 2^31
    LChunkLength := 3800;
    if (LChunkLength > ALength) then
    begin
      LChunkLength := ALength;
    end;
    ALength := ALength - LChunkLength;

    LSumA := FSumA;
    LSumB := FSumB;
    while (LChunkLength - 1) >= 0 do
    begin
      LSumA := (LSumA + LPtrData^);
      LSumB := (LSumB + LSumA);
      System.Inc(LPtrData);
      System.Dec(LChunkLength);
    end;
    LSumA := LSumA mod ModAdler;
    LSumB := LSumB mod ModAdler;

    FSumA := LSumA;
    FSumB := LSumB;
  end;
end;

function TAdler32.TransformFinal: IHashResult;
var
  LBufferBytes: THashLibByteArray;
begin
  System.SetLength(LBufferBytes, HashSize);
  TConverters.ReadUInt32AsBytesBE(UInt32((FSumB shl 16) or FSumA), LBufferBytes, 0);

  Result := THashResult.Create(LBufferBytes);
  Initialize();
end;

end.
