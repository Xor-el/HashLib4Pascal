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

  public
    constructor Create();
    procedure Initialize(); override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;
    function TransformFinal: IHashResult; override;
    function Clone(): IHash; override;

  end;

implementation

uses
  HlpAdler32Dispatch;

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
  LSums: array [0 .. 1] of UInt32;
begin
{$IFDEF DEBUG}
  System.Assert(AIndex >= 0);
  System.Assert(ALength >= 0);
  System.Assert(AIndex + ALength <= System.Length(AData));
{$ENDIF DEBUG}
  LSums[0] := FSumA;
  LSums[1] := FSumB;
  Adler32_Update(PByte(AData) + AIndex, UInt32(ALength), @LSums[0]);
  FSumA := LSums[0];
  FSumB := LSums[1];
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
