unit HlpBlake2S;

{$I ..\Include\HashLib.inc}

interface

uses
{$IFDEF DELPHI2010}
  SysUtils, // to get rid of compiler hint "not inlined" on Delphi 2010.
{$ENDIF DELPHI2010}
  HlpBits,
{$IFDEF DELPHI}
  HlpHashBuffer,
  HlpBitConverter,
{$ENDIF DELPHI}
  HlpHash,
  HlpHashResult,
  HlpIHashResult,
  HlpIBlake2SConfig,
  HlpBlake2SConfig,
  HlpBlake2SIvBuilder,
  HlpIHashInfo,
  HlpConverters,
  HlpHashLibTypes;

resourcestring
  SInvalidConfigLength = 'Config Length Must Be 8 Words';

type
  TBlake2S = class sealed(THash, ICryptoNotBuildIn, ITransformBlock)
  strict private

{$REGION 'Consts'}
  const

    NumberOfRounds = Int32(10);
    BlockSizeInBytes = Int32(64);

    IV0 = UInt32($66A09E667);
    IV1 = UInt32($BB67AE85);
    IV2 = UInt32($3C6EF372);
    IV3 = UInt32($A54FF53A);
    IV4 = UInt32($510E527F);
    IV5 = UInt32($9B05688C);
    IV6 = UInt32($1F83D9AB);
    IV7 = UInt32($5BE0CD19);

    Sigma: array [0 .. 9, 0 .. 15] of Byte = ((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
      11, 12, 13, 14, 15), (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5,
      3), (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
      (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
      (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
      (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
      (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
      (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
      (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
      (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0));

{$ENDREGION}
    class var

      FDefaultConfig: IBlake2SConfig;

  var
    FrawConfig, Fm_state: THashLibUInt32Array;
    FKey, F_buf: THashLibByteArray;
    F_m, F_v: array [0 .. 15] of UInt32;
    F_bufferFilled: Int32;

    F_counter0, F_counter1, F_finalizationFlag0, F_finalizationFlag1: UInt32;

    class constructor Blake2SConfig();

    procedure G(a, b, c, d, r, i: Int32); inline;
    procedure Compress(block: PByte; start: Int32); inline;

    procedure Finish(); inline;

  strict protected

    FHashSize, FBlockSize: Int32;

  public
    constructor Create(); overload;
    constructor Create(config: IBlake2SConfig); overload;
    procedure Initialize; override;
    procedure TransformBytes(a_data: THashLibByteArray;
      a_index, a_data_length: Int32); override;
    function TransformFinal: IHashResult; override;

  end;

implementation

{ TBlake2S }

class constructor TBlake2S.Blake2SConfig;
begin
  FDefaultConfig := TBlake2SConfig.Create();
end;

constructor TBlake2S.Create();
begin
  Create(TBlake2SConfig.Create());
end;

procedure TBlake2S.G(a, b, c, d, r, i: Int32);
begin

  F_v[a] := F_v[a] + (F_v[b] + F_m[Sigma[r][2 * i + 0]]);
  F_v[d] := TBits.RotateRight32(F_v[d] xor F_v[a], 16);
  F_v[c] := F_v[c] + F_v[d];
  F_v[b] := TBits.RotateRight32(F_v[b] xor F_v[c], 12);
  F_v[a] := F_v[a] + (F_v[b] + F_m[Sigma[r][2 * i + 1]]);
  F_v[d] := TBits.RotateRight32(F_v[d] xor F_v[a], 8);
  F_v[c] := F_v[c] + F_v[d];
  F_v[b] := TBits.RotateRight32(F_v[b] xor F_v[c], 7);
end;

procedure TBlake2S.Compress(block: PByte; start: Int32);
var
  i, r: Int32;
begin
  TConverters.le32_copy(block, start, @(F_m[0]), 0, FBlockSize);

  F_v[0] := Fm_state[0];
  F_v[1] := Fm_state[1];
  F_v[2] := Fm_state[2];
  F_v[3] := Fm_state[3];
  F_v[4] := Fm_state[4];
  F_v[5] := Fm_state[5];
  F_v[6] := Fm_state[6];
  F_v[7] := Fm_state[7];

  F_v[8] := IV0;
  F_v[9] := IV1;
  F_v[10] := IV2;
  F_v[11] := IV3;
  F_v[12] := IV4 xor F_counter0;
  F_v[13] := IV5 xor F_counter1;

  F_v[14] := IV6 xor F_finalizationFlag0;

  F_v[15] := IV7 xor F_finalizationFlag1;

  for r := 0 to System.Pred(NumberOfRounds) do

  begin
    G(0, 4, 8, 12, r, 0);
    G(1, 5, 9, 13, r, 1);
    G(2, 6, 10, 14, r, 2);
    G(3, 7, 11, 15, r, 3);
    G(0, 5, 10, 15, r, 4);
    G(1, 6, 11, 12, r, 5);
    G(2, 7, 8, 13, r, 6);
    G(3, 4, 9, 14, r, 7);

  end;

  for i := 0 to 7 do
  begin
    Fm_state[i] := Fm_state[i] xor (F_v[i] xor F_v[i + 8]);
  end;

end;

constructor TBlake2S.Create(config: IBlake2SConfig);
begin

  FBlockSize := BlockSizeInBytes;

  if (config = Nil) then
  begin
    config := FDefaultConfig;
  end;

  FrawConfig := TBlake2SIvBuilder.ConfigS(config, Nil);
  if ((config.Key <> Nil) and (System.Length(config.Key) <> 0)) then
  begin
    System.SetLength(FKey, FBlockSize);

    FKey := Copy(config.Key, Low(config.Key), Length(config.Key));

    System.SetLength(FKey, FBlockSize);

  end;
  FHashSize := config.HashSize;

  System.SetLength(Fm_state, 8);

  Inherited Create(FHashSize, FBlockSize);

end;

procedure TBlake2S.Finish;

begin

  // Last compression

  F_counter0 := F_counter0 + UInt32(F_bufferFilled);

  F_finalizationFlag0 := System.High(UInt32);

  System.FillChar(F_buf[F_bufferFilled],
    (System.Length(F_buf) - F_bufferFilled), Byte(0));

  Compress(PByte(F_buf), 0);

end;

procedure TBlake2S.Initialize;
var
  i: Integer;
begin
  if (FrawConfig = Nil) then
    raise EArgumentNilHashLibException.Create('config');
  if (System.Length(FrawConfig) <> 8) then
  begin
    raise EArgumentHashLibException.CreateRes(@SInvalidConfigLength);
  end;

  Fm_state[0] := IV0;
  Fm_state[1] := IV1;
  Fm_state[2] := IV2;
  Fm_state[3] := IV3;
  Fm_state[4] := IV4;
  Fm_state[5] := IV5;
  Fm_state[6] := IV6;
  Fm_state[7] := IV7;

  F_counter0 := 0;
  F_counter1 := 0;
  F_finalizationFlag0 := 0;
  F_finalizationFlag1 := 0;

  F_bufferFilled := 0;

  System.SetLength(F_buf, BlockSizeInBytes);

  for i := 0 to 7 do
  begin
    Fm_state[i] := Fm_state[i] xor FrawConfig[i];
  end;

  if (FKey <> Nil) then
  begin

    TransformBytes(FKey, 0, System.Length(FKey));

  end;

end;

procedure TBlake2S.TransformBytes(a_data: THashLibByteArray;
  a_index, a_data_length: Int32);
var
  offset, bufferRemaining: Int32;

begin
  offset := a_index;
  bufferRemaining := BlockSizeInBytes - F_bufferFilled;

  if ((F_bufferFilled > 0) and (a_data_length > bufferRemaining)) then
  begin

    System.Move(a_data[offset], F_buf[F_bufferFilled], bufferRemaining);
    F_counter0 := F_counter0 + UInt32(BlockSizeInBytes);
    if (F_counter0 = 0) then
    begin
      System.Inc(F_counter1);
    end;
    Compress(PByte(F_buf), 0);
    offset := offset + bufferRemaining;
    a_data_length := a_data_length - bufferRemaining;
    F_bufferFilled := 0;
  end;

  while (a_data_length > BlockSizeInBytes) do
  begin
    F_counter0 := F_counter0 + UInt32(BlockSizeInBytes);
    if (F_counter0 = 0) then
    begin
      System.Inc(F_counter1);
    end;
    Compress(PByte(a_data), offset);
    offset := offset + BlockSizeInBytes;
    a_data_length := a_data_length - BlockSizeInBytes;
  end;

  if (a_data_length > 0) then
  begin

    System.Move(a_data[offset], F_buf[F_bufferFilled], a_data_length);

    F_bufferFilled := F_bufferFilled + a_data_length;

  end;
end;

function TBlake2S.TransformFinal: IHashResult;
var
  tempRes: THashLibByteArray;
begin

  Finish();

  System.SetLength(tempRes, FHashSize);

  TConverters.le32_copy(PCardinal(Fm_state), 0, PByte(tempRes), 0,
    System.Length(tempRes));

  result := THashResult.Create(tempRes);

  Initialize();

end;

end.
