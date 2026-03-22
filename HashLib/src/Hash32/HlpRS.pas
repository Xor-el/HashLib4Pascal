unit HlpRS;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpHash,
  HlpIHash,
  HlpIHashInfo,
  HlpHashResult,
  HlpIHashResult;

type
  TRS = class sealed(THash, IHash32, ITransformBlock)
  strict private
  var
    FHash, FMultiplier: UInt32;

  const
    CMul = UInt32(378551);

  public
    constructor Create();
    procedure Initialize(); override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;
    function TransformFinal(): IHashResult; override;
    function Clone(): IHash; override;
  end;

implementation

{ TRS }

function TRS.Clone(): IHash;
var
  LHashInstance: TRS;
begin
  LHashInstance := TRS.Create();
  LHashInstance.FHash := FHash;
  LHashInstance.FMultiplier := FMultiplier;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TRS.Create;
begin
  inherited Create(4, 1);
end;

procedure TRS.Initialize;
begin
  FHash := 0;
  FMultiplier := 63689;
end;

procedure TRS.TransformBytes(const AData: THashLibByteArray;
  AIndex, ALength: Int32);
var
  LIdx: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(AIndex >= 0);
  System.Assert(ALength >= 0);
  System.Assert(AIndex + ALength <= System.Length(AData));
{$ENDIF DEBUG}
  LIdx := AIndex;
  while ALength > 0 do
  begin
    FHash := (FHash * FMultiplier) + AData[LIdx];
    FMultiplier := FMultiplier * CMul;
    System.Inc(LIdx);
    System.Dec(ALength);
  end;

end;

function TRS.TransformFinal: IHashResult;
begin
  Result := THashResult.Create(FHash);
  Initialize();
end;

end.
