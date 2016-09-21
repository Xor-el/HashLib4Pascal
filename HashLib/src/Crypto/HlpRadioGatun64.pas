unit HlpRadioGatun64;

{$I ..\Include\HashLib.inc}

interface

uses
{$IFNDEF DELPHIXE7_UP}
{$IFDEF HAS_UNITSCOPE}
  System.TypInfo,
{$ELSE}
  TypInfo,
{$ENDIF HAS_UNITSCOPE}
{$ENDIF DELPHIXE7_UP}
  HlpHashLibTypes,
  HlpArrayExtensions,
  HlpBits,
  HlpConverters,
  HlpIHashInfo,
  HlpHashCryptoNotBuildIn;

type
  TRadioGatun64 = class sealed(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

  strict private

    Fm_mill: THashLibUInt64Array;

    Fm_belt: THashLibMatrixUInt64Array;

  const
    MILL_SIZE = Int32(19);
    BELT_WIDTH = Int32(3);
    BELT_LENGTH = Int32(13);
    NUMBER_OF_BLANK_ITERATIONS = Int32(16);

    procedure RoundFunction();

  strict protected
    procedure Finish(); override;
    function GetResult(): THashLibByteArray; override;
    procedure TransformBlock(a_data: THashLibByteArray;
      a_index: Int32); override;

  public
    constructor Create();
    procedure Initialize(); override;

  end;

implementation

{ TRadioGatun64 }

constructor TRadioGatun64.Create;
var
  i: Int32;
begin

  Inherited Create(32, 8 * BELT_WIDTH);
  System.SetLength(Fm_mill, MILL_SIZE);

  System.SetLength(Fm_belt, BELT_LENGTH);
  i := 0;
  while i < BELT_LENGTH do
  begin
    System.SetLength(Fm_belt[i], BELT_WIDTH);

    System.Inc(i);
  end;

end;

procedure TRadioGatun64.Finish;
var
  padding_size, i: Int32;
  pad: THashLibByteArray;
begin
  padding_size := BlockSize - ((Int32(Fm_processed_bytes)) mod BlockSize);

  System.SetLength(pad, padding_size);
  pad[0] := $01;
  TransformBytes(pad, 0, padding_size);
  i := 0;
  while i < NUMBER_OF_BLANK_ITERATIONS do
  begin
    RoundFunction();
    System.Inc(i);
  end;

end;

function TRadioGatun64.GetResult: THashLibByteArray;
var
  tempRes: THashLibUInt64Array;
  i: Int32;
begin
  System.SetLength(tempRes, HashSize div 8);
  i := 0;

  while i < (HashSize div 16) do
  begin
    RoundFunction();

    THashLibArrayHelper<UInt64>.Copy(THashLibGenericArray<UInt64>(Fm_mill), 1,
      THashLibGenericArray<UInt64>(tempRes), i * 2, 2);
    System.Inc(i);
  end;

  result := TConverters.ConvertUInt64ToBytes(tempRes);
end;

procedure TRadioGatun64.Initialize;
var
  i: Int32;
begin
  THashLibArrayHelper<UInt64>.Clear(THashLibGenericArray<UInt64>(Fm_mill),
    UInt64(0));

  i := 0;
  while i < BELT_LENGTH do
  begin

    THashLibArrayHelper<UInt64>.Clear(THashLibGenericArray<UInt64>(Fm_belt[i]),
      UInt64(0));
    System.Inc(i);
  end;

  Inherited Initialize();

end;

procedure TRadioGatun64.RoundFunction;
var
  q, a: THashLibUInt64Array;
  i: Int32;
begin

  q := Fm_belt[BELT_LENGTH - 1];
  i := BELT_LENGTH - 1;
  while i > 0 do
  begin
    Fm_belt[i] := Fm_belt[i - 1];
    System.Dec(i);
  end;

  Fm_belt[0] := q;

  i := 0;
  while i < 12 do
  begin
    Fm_belt[i + 1][i mod BELT_WIDTH] := Fm_belt[i + 1][i mod BELT_WIDTH]
      xor Fm_mill[i + 1];
    System.Inc(i);
  end;

  System.SetLength(a, MILL_SIZE);

  i := 0;
  while i < MILL_SIZE do
  begin
    a[i] := Fm_mill[i] xor (Fm_mill[(i + 1) mod MILL_SIZE] or
      not Fm_mill[(i + 2) mod MILL_SIZE]);
    System.Inc(i);
  end;

  i := 0;
  while i < MILL_SIZE do
  begin
    Fm_mill[i] := TBits.RotateRight64(a[(7 * i) mod MILL_SIZE],
      i * (i + 1) div 2);
    System.Inc(i);
  end;

  i := 0;
  while i < MILL_SIZE do
  begin
    a[i] := Fm_mill[i] xor Fm_mill[(i + 1) mod MILL_SIZE] xor Fm_mill
      [(i + 4) mod MILL_SIZE];
    System.Inc(i);
  end;

  a[0] := a[0] xor 1;

  i := 0;
  while i < MILL_SIZE do
  begin
    Fm_mill[i] := a[i];
    System.Inc(i);
  end;

  i := 0;
  while i < BELT_WIDTH do
  begin
    Fm_mill[i + 13] := Fm_mill[i + 13] xor q[i];
    System.Inc(i);
  end;

end;

procedure TRadioGatun64.TransformBlock(a_data: THashLibByteArray;
  a_index: Int32);
var
  data: THashLibUInt64Array;
  i: Int32;
begin
  data := TConverters.ConvertBytesToUInt64(a_data, a_index, BlockSize);
  i := 0;
  while i < BELT_WIDTH do
  begin
    Fm_mill[i + 16] := Fm_mill[i + 16] xor data[i];
    Fm_belt[0][i] := Fm_belt[0][i] xor data[i];

    System.Inc(i);
  end;

  RoundFunction();
end;

end.
