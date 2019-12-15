unit HlpBlake2BIvBuilder;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpConverters,
  HlpBlake2BTreeConfig,
  HlpIBlake2BConfig,
  HlpIBlake2BTreeConfig,
  HlpHashLibTypes;

resourcestring
  SInvalidHashSize =
    'BLAKE2B HashSize must be restricted to one of the following [1 .. 64], "%d"';
  SInvalidKeyLength = '"Key" Length Must Not Be Greater Than 64, "%d"';
  SInvalidPersonalisationLength =
    '"Personalisation" Length Must Be Equal To 16, "%d"';
  SInvalidSaltLength = '"Salt" Length Must Be Equal To 16, "%d"';
  STreeIncorrectInnerHashSize =
    'Tree Inner Hash Size Must Not Be Greater Than 64, "%d"';

type
  TBlake2BIvBuilder = class sealed(TObject)

  strict private

    class procedure VerifyConfigB(const AConfig: IBlake2BConfig;
      const ATreeConfig: IBlake2BTreeConfig; AIsSequential: Boolean); static;

  public
    class function ConfigB(const AConfig: IBlake2BConfig;
      var ATreeConfig: IBlake2BTreeConfig): THashLibUInt64Array; static;

  end;

implementation

{ TBlake2BIvBuilder }

class procedure TBlake2BIvBuilder.VerifyConfigB(const AConfig: IBlake2BConfig;
  const ATreeConfig: IBlake2BTreeConfig; AIsSequential: Boolean);
begin

  // digest length
  if ((AConfig.HashSize <= 0) or (AConfig.HashSize > 64)) then
  begin
    raise EArgumentOutOfRangeHashLibException.CreateResFmt(@SInvalidHashSize,
      [AConfig.HashSize]);
  end;

  // Key length
  if (AConfig.Key <> Nil) then
  begin
    if (System.Length(AConfig.Key) > 64) then
    begin
      raise EArgumentOutOfRangeHashLibException.CreateResFmt(@SInvalidKeyLength,
        [System.Length(AConfig.Key)]);
    end;
  end;

  // Personalisation length
  if (AConfig.Personalisation <> Nil) then
  begin
    if (System.Length(AConfig.Personalisation) <> 16) then
    begin
      raise EArgumentOutOfRangeHashLibException.CreateResFmt
        (@SInvalidPersonalisationLength,
        [System.Length(AConfig.Personalisation)]);
    end;
  end;

  // Salt length
  if (AConfig.Salt <> Nil) then
  begin
    if (System.Length(AConfig.Salt) <> 16) then
    begin
      raise EArgumentOutOfRangeHashLibException.CreateResFmt
        (@SInvalidSaltLength, [System.Length(AConfig.Salt)]);
    end;
  end;

  // Tree InnerHashSize
  if (ATreeConfig <> Nil) then
  begin

    if ((AIsSequential) and ((ATreeConfig.InnerHashSize <> 0))) then
    begin
      raise EArgumentOutOfRangeHashLibException.Create
        ('treeConfig.TreeIntermediateHashSize');
    end;

    if (ATreeConfig.InnerHashSize > 64) then
    begin
      raise EArgumentOutOfRangeHashLibException.CreateResFmt
        (@STreeIncorrectInnerHashSize, [ATreeConfig.InnerHashSize]);
    end;
  end;

end;

class function TBlake2BIvBuilder.ConfigB(const AConfig: IBlake2BConfig;
  var ATreeConfig: IBlake2BTreeConfig): THashLibUInt64Array;
var
  LIsSequential: Boolean;
  LBuffer: THashLibByteArray;
begin
  LIsSequential := ATreeConfig = Nil;
  if (LIsSequential) then
  begin
    ATreeConfig := TBlake2BTreeConfig.SequentialTreeConfig;
  end;

  VerifyConfigB(AConfig, ATreeConfig, LIsSequential);

  System.SetLength(LBuffer, 64);

  LBuffer[0] := AConfig.HashSize;
  LBuffer[1] := System.Length(AConfig.Key);

  if ATreeConfig <> Nil then
  begin
    LBuffer[2] := ATreeConfig.FanOut;
    LBuffer[3] := ATreeConfig.MaxDepth;
    TConverters.ReadUInt32AsBytesLE(ATreeConfig.LeafSize, LBuffer, 4);
    TConverters.ReadUInt64AsBytesLE(ATreeConfig.NodeOffset, LBuffer, 8);
    LBuffer[16] := ATreeConfig.NodeDepth;
    LBuffer[17] := ATreeConfig.InnerHashSize;
  end;

  if AConfig.Salt <> Nil then
  begin
    System.Move(AConfig.Salt[0], LBuffer[32], 16 * System.SizeOf(Byte));
  end;

  if AConfig.Personalisation <> Nil then
  begin
    System.Move(AConfig.Personalisation[0], LBuffer[48],
      16 * System.SizeOf(Byte));
  end;

  System.SetLength(Result, 8);
  TConverters.le64_copy(PByte(LBuffer), 0, PUInt64(Result), 0,
    System.Length(LBuffer) * System.SizeOf(Byte));
end;

end.
