unit HlpBlake2B;

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
  HlpIBlake2BConfig,
  HlpBlake2BConfig,
  HlpBlake2BIvBuilder,
  HlpIHashInfo,
  HlpConverters,
  HlpHashLibTypes;

resourcestring
  SInvalidConfigLength = 'Config Length Must Be 8 Words';

type
  TBlake2B = class sealed(THash, ICryptoNotBuildIn, ITransformBlock)
  strict private

{$REGION 'Consts'}
  const

    NumberOfRounds = Int32(12);
    BlockSizeInBytes = Int32(128);

    IV0 = UInt64($6A09E667F3BCC908);
    IV1 = UInt64($BB67AE8584CAA73B);
    IV2 = UInt64($3C6EF372FE94F82B);
    IV3 = UInt64($A54FF53A5F1D36F1);
    IV4 = UInt64($510E527FADE682D1);
    IV5 = UInt64($9B05688C2B3E6C1F);
    IV6 = UInt64($1F83D9ABFB41BD6B);
    IV7 = UInt64($5BE0CD19137E2179);

    Sigma: array [0 .. ((NumberOfRounds * 16) - 1)] of Int32 = (0, 1, 2, 3, 4,
      5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12,
      0, 2, 11, 7, 5, 3, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
      7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8, 9, 0, 5, 7, 2, 4,
      10, 15, 14, 1, 11, 12, 6, 8, 3, 13, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7,
      5, 15, 14, 1, 9, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11, 13,
      11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10, 6, 15, 14, 9, 11, 3, 0,
      8, 12, 2, 13, 7, 1, 4, 10, 5, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3,
      12, 13, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10,
      4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);

{$ENDREGION}
    class var

      FDefaultConfig: IBlake2BConfig;

  var
    FrawConfig, Fm_state: THashLibUInt64Array;
    FKey, F_buf: THashLibByteArray;
    F_m, F_v: array [0 .. 15] of UInt64;
    F_bufferFilled: Int32;

    F_counter0, F_counter1, F_finalizationFlag0, F_finalizationFlag1: UInt64;

    class constructor Blake2BConfig();

    procedure G(a, b, c, d, r, i: Int32); inline;
    procedure Compress(block: PByte; start: Int32); inline;

    procedure Finish(); inline;

  strict protected

    FHashSize, FBlockSize: Int32;

  public
    constructor Create(); overload;
    constructor Create(config: IBlake2BConfig); overload;
    procedure Initialize; override;
    procedure TransformBytes(a_data: THashLibByteArray;
      a_index, a_data_length: Int32); override;
    function TransformFinal: IHashResult; override;

  end;

implementation

{ TBlake2B }

class constructor TBlake2B.Blake2BConfig;
begin
  FDefaultConfig := TBlake2BConfig.Create();
end;

constructor TBlake2B.Create();
begin
  Create(TBlake2BConfig.Create());
end;

procedure TBlake2B.G(a, b, c, d, r, i: Int32);
var
  p, p0, p1: Int32;
begin
  p := (r shl 4) + i;
  p0 := Sigma[p];
  p1 := Sigma[p + 1];

  F_v[a] := F_v[a] + (F_v[b] + F_m[p0]);
  F_v[d] := TBits.RotateRight64(F_v[d] xor F_v[a], 32);
  F_v[c] := F_v[c] + F_v[d];
  F_v[b] := TBits.RotateRight64(F_v[b] xor F_v[c], 24);
  F_v[a] := F_v[a] + (F_v[b] + F_m[p1]);
  F_v[d] := TBits.RotateRight64(F_v[d] xor F_v[a], 16);
  F_v[c] := F_v[c] + F_v[d];
  F_v[b] := TBits.RotateRight64(F_v[b] xor F_v[c], 63);
end;

procedure TBlake2B.Compress(block: PByte; start: Int32);
var
  i, r: Int32;
begin
  TConverters.le64_copy(block, start, @(F_m[0]), 0, FBlockSize);

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
    G(1, 5, 9, 13, r, 2);
    G(2, 6, 10, 14, r, 4);
    G(3, 7, 11, 15, r, 6);
    G(3, 4, 9, 14, r, 14);
    G(2, 7, 8, 13, r, 12);
    G(0, 5, 10, 15, r, 8);
    G(1, 6, 11, 12, r, 10);
  end;

  for i := 0 to 7 do
  begin
    Fm_state[i] := Fm_state[i] xor (F_v[i] xor F_v[i + 8]);
  end;

end;

constructor TBlake2B.Create(config: IBlake2BConfig);
begin

  FBlockSize := BlockSizeInBytes;

  if (config = Nil) then
  begin
    config := FDefaultConfig;
  end;

  FrawConfig := TBlake2BIvBuilder.ConfigB(config, Nil);
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

procedure TBlake2B.Finish;

begin

  // Last compression

  F_counter0 := F_counter0 + UInt64(F_bufferFilled);

  F_finalizationFlag0 := System.High(UInt64);

  System.FillChar(F_buf[F_bufferFilled],
    (System.Length(F_buf) - F_bufferFilled), Byte(0));

  Compress(PByte(F_buf), 0);

end;

procedure TBlake2B.Initialize;
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

procedure TBlake2B.TransformBytes(a_data: THashLibByteArray;
  a_index, a_data_length: Int32);
var
  offset, bufferRemaining: Int32;

begin
  offset := a_index;
  bufferRemaining := BlockSizeInBytes - F_bufferFilled;

  if ((F_bufferFilled > 0) and (a_data_length > bufferRemaining)) then
  begin

    System.Move(a_data[offset], F_buf[F_bufferFilled], bufferRemaining);
    F_counter0 := F_counter0 + BlockSizeInBytes;
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
    F_counter0 := F_counter0 + BlockSizeInBytes;
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

function TBlake2B.TransformFinal: IHashResult;
var
  tempRes: THashLibByteArray;
begin

  Finish();

  System.SetLength(tempRes, FHashSize);

  TConverters.le64_copy(PUInt64(Fm_state), 0, PByte(tempRes), 0,
    System.Length(tempRes));

  result := THashResult.Create(tempRes);

  Initialize();

end;

end.
