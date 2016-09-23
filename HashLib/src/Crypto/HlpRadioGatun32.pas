unit HlpRadioGatun32;

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
  TRadioGatun32 = class sealed(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

  strict private

    Fm_mill: THashLibUInt32Array;

    Fm_belt: THashLibMatrixUInt32Array;

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

{ TRadioGatun32 }

constructor TRadioGatun32.Create;
var
  i: Int32;
begin

  Inherited Create(32, 4 * BELT_WIDTH);
  System.SetLength(Fm_mill, MILL_SIZE);

  System.SetLength(Fm_belt, BELT_LENGTH);
  i := 0;
  while i < BELT_LENGTH do
  begin
    System.SetLength(Fm_belt[i], BELT_WIDTH);

    System.Inc(i);
  end;

end;

procedure TRadioGatun32.Finish;
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

function TRadioGatun32.GetResult: THashLibByteArray;
var
  tempRes: THashLibUInt32Array;
  i: Int32;
begin
  // System.SetLength(tempRes, HashSize div 4);
  System.SetLength(tempRes, HashSize shr 2);
  i := 0;

  // while i < (HashSize div 8) do
  while i < (HashSize shr 3) do
  begin
    RoundFunction();

    THashLibArrayHelper<UInt32>.Copy(THashLibGenericArray<UInt32>(Fm_mill), 1,
      THashLibGenericArray<UInt32>(tempRes), i * 2, 2);
    System.Inc(i);
  end;

  result := TConverters.ConvertUInt32ToBytes(tempRes);
end;

procedure TRadioGatun32.Initialize;
var
  i: Int32;
begin
  THashLibArrayHelper<UInt32>.Clear(THashLibGenericArray<UInt32>(Fm_mill),
    UInt32(0));

  i := 0;
  while i < BELT_LENGTH do
  begin

    THashLibArrayHelper<UInt32>.Clear(THashLibGenericArray<UInt32>(Fm_belt[i]),
      UInt32(0));
    System.Inc(i);
  end;

  Inherited Initialize();

end;

procedure TRadioGatun32.RoundFunction;
var
  q, a: THashLibUInt32Array;
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
    // Fm_mill[i] := TBits.RotateRight32(a[(7 * i) mod MILL_SIZE],
    // i * (i + 1) div 2);
    Fm_mill[i] := TBits.RotateRight32(a[(7 * i) mod MILL_SIZE],
      (i * (i + 1)) shr 1);
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

procedure TRadioGatun32.TransformBlock(a_data: THashLibByteArray;
  a_index: Int32);
var
  data: THashLibUInt32Array;
  i: Int32;
begin
  data := TConverters.ConvertBytesToUInt32(a_data, a_index, BlockSize);
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
