unit HlpSHA0;

{$I ..\Include\HashLib.inc}

interface

uses

  HlpHashLibTypes,
  HlpConverters,
  HlpIHashInfo,
  HlpHashCryptoNotBuildIn;

type
  TSHA0 = class(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

  strict protected

    Fm_state: THashLibUInt32Array;

{$REGION 'Consts'}

  const

    C1 = UInt32($5A827999);
    C2 = UInt32($6ED9EBA1);
    C3 = UInt32($8F1BBCDC);
    C4 = UInt32($CA62C1D6);

{$ENDREGION}
    procedure Finish(); override;
    procedure Expand(a_data: THashLibUInt32Array); virtual;
    procedure TransformBlock(a_data: THashLibByteArray;
      a_index: Int32); override;
    function GetResult(): THashLibByteArray; override;

  public
    constructor Create();
    procedure Initialize(); override;

  end;

implementation

{ TSHA0 }

constructor TSHA0.Create;
begin
  Inherited Create(20, 64);
  System.SetLength(Fm_state, 5);
end;

procedure TSHA0.Expand(a_data: THashLibUInt32Array);
var
  j: Int32;
begin
  j := $10;
  while j < 80 do
  begin
    a_data[j] := ((a_data[j - 3] xor a_data[j - 8]) xor a_data[j - 14])
      xor a_data[j - $10];
    System.Inc(j);
  end;

end;

procedure TSHA0.Finish;
var
  bits: UInt64;
  padindex: Int32;
  pad: THashLibByteArray;
begin
  bits := Fm_processed_bytes * 8;
  if (Fm_buffer.Pos < 56) then

    padindex := (56 - Fm_buffer.Pos)
  else
    padindex := (120 - Fm_buffer.Pos);

  System.SetLength(pad, padindex + 8);

  pad[0] := $80;

  TConverters.ConvertUInt64ToBytesSwapOrder(bits, pad, padindex);
  padindex := padindex + 8;

  TransformBytes(pad, 0, padindex);

end;

function TSHA0.GetResult: THashLibByteArray;
begin
  result := TConverters.ConvertUInt32ToBytesSwapOrder(Fm_state);
end;

procedure TSHA0.Initialize;
begin

  Fm_state[0] := $67452301;
  Fm_state[1] := $EFCDAB89;
  Fm_state[2] := $98BADCFE;
  Fm_state[3] := $10325476;
  Fm_state[4] := $C3D2E1F0;

  Inherited Initialize();

end;

procedure TSHA0.TransformBlock(a_data: THashLibByteArray; a_index: Int32);
var
  data: THashLibUInt32Array;
  A, B, C, D, E, T1, X7, T2, X8, T3, X1, T4, X2, T5, X3, T6, X4, T7, X5, T8,
    X6: UInt32;
  r: Int32;
begin
  System.SetLength(data, 80);
  TConverters.ConvertBytesToUInt32SwapOrder(a_data, a_index, BlockSize,
    data, 0);

  Expand(data);

  A := Fm_state[0];
  B := Fm_state[1];
  C := Fm_state[2];
  D := Fm_state[3];
  E := Fm_state[4];

  r := 0;

  T1 := data[r] + C1 + ((A shl 5) or (A shr (32 - 5))) +
    ((B and C) or (not B and D)) + E;
  System.Inc(r);
  X7 := ((B shl 30) or (B shr (32 - 30)));
  T2 := data[r] + C1 + ((T1 shl 5) or (T1 shr (32 - 5))) +
    ((A and X7) or (not A and C)) + D;
  System.Inc(r);
  X8 := ((A shl 30) or (A shr (32 - 30)));
  T3 := data[r] + C1 + ((T2 shl 5) or (T2 shr (32 - 5))) +
    ((T1 and X8) or (not T1 and X7)) + C;
  System.Inc(r);
  X1 := ((T1 shl 30) or (T1 shr (32 - 30)));
  T4 := data[r] + C1 + ((T3 shl 5) or (T3 shr (32 - 5))) +
    ((T2 and X1) or (not T2 and X8)) + X7;
  System.Inc(r);
  X2 := ((T2 shl 30) or (T2 shr (32 - 30)));
  T5 := data[r] + C1 + ((T4 shl 5) or (T4 shr (32 - 5))) +
    ((T3 and X2) or (not T3 and X1)) + X8;
  System.Inc(r);
  X3 := ((T3 shl 30) or (T3 shr (32 - 30)));
  T6 := data[r] + C1 + ((T5 shl 5) or (T5 shr (32 - 5))) +
    ((T4 and X3) or (not T4 and X2)) + X1;
  System.Inc(r);
  X4 := ((T4 shl 30) or (T4 shr (32 - 30)));
  T7 := data[r] + C1 + ((T6 shl 5) or (T6 shr (32 - 5))) +
    ((T5 and X4) or (not T5 and X3)) + X2;
  System.Inc(r);
  X5 := ((T5 shl 30) or (T5 shr (32 - 30)));
  T8 := data[r] + C1 + ((T7 shl 5) or (T7 shr (32 - 5))) +
    ((T6 and X5) or (not T6 and X4)) + X3;
  System.Inc(r);
  X6 := ((T6 shl 30) or (T6 shr (32 - 30)));
  T1 := data[r] + C1 + ((T8 shl 5) or (T8 shr (32 - 5))) +
    ((T7 and X6) or (not T7 and X5)) + X4;
  System.Inc(r);
  X7 := ((T7 shl 30) or (T7 shr (32 - 30)));
  T2 := data[r] + C1 + ((T1 shl 5) or (T1 shr (32 - 5))) +
    ((T8 and X7) or (not T8 and X6)) + X5;
  System.Inc(r);
  X8 := ((T8 shl 30) or (T8 shr (32 - 30)));
  T3 := data[r] + C1 + ((T2 shl 5) or (T2 shr (32 - 5))) +
    ((T1 and X8) or (not T1 and X7)) + X6;
  System.Inc(r);
  X1 := ((T1 shl 30) or (T1 shr (32 - 30)));
  T4 := data[r] + C1 + ((T3 shl 5) or (T3 shr (32 - 5))) +
    ((T2 and X1) or (not T2 and X8)) + X7;
  System.Inc(r);
  X2 := ((T2 shl 30) or (T2 shr (32 - 30)));
  T5 := data[r] + C1 + ((T4 shl 5) or (T4 shr (32 - 5))) +
    ((T3 and X2) or (not T3 and X1)) + X8;
  System.Inc(r);
  X3 := ((T3 shl 30) or (T3 shr (32 - 30)));
  T6 := data[r] + C1 + ((T5 shl 5) or (T5 shr (32 - 5))) +
    ((T4 and X3) or (not T4 and X2)) + X1;
  System.Inc(r);
  X4 := ((T4 shl 30) or (T4 shr (32 - 30)));
  T7 := data[r] + C1 + ((T6 shl 5) or (T6 shr (32 - 5))) +
    ((T5 and X4) or (not T5 and X3)) + X2;
  System.Inc(r);
  X5 := ((T5 shl 30) or (T5 shr (32 - 30)));
  T8 := data[r] + C1 + ((T7 shl 5) or (T7 shr (32 - 5))) +
    ((T6 and X5) or (not T6 and X4)) + X3;
  System.Inc(r);
  X6 := ((T6 shl 30) or (T6 shr (32 - 30)));
  T1 := data[r] + C1 + ((T8 shl 5) or (T8 shr (32 - 5))) +
    ((T7 and X6) or (not T7 and X5)) + X4;
  System.Inc(r);
  X7 := ((T7 shl 30) or (T7 shr (32 - 30)));
  T2 := data[r] + C1 + ((T1 shl 5) or (T1 shr (32 - 5))) +
    ((T8 and X7) or (not T8 and X6)) + X5;
  System.Inc(r);
  X8 := ((T8 shl 30) or (T8 shr (32 - 30)));
  T3 := data[r] + C1 + ((T2 shl 5) or (T2 shr (32 - 5))) +
    ((T1 and X8) or (not T1 and X7)) + X6;
  System.Inc(r);
  X1 := ((T1 shl 30) or (T1 shr (32 - 30)));
  T4 := data[r] + C1 + ((T3 shl 5) or (T3 shr (32 - 5))) +
    ((T2 and X1) or (not T2 and X8)) + X7;
  System.Inc(r);
  X2 := ((T2 shl 30) or (T2 shr (32 - 30)));
  T5 := data[r] + C2 + ((T4 shl 5) or (T4 shr (32 - 5))) +
    (T3 xor X2 xor X1) + X8;
  System.Inc(r);
  X3 := ((T3 shl 30) or (T3 shr (32 - 30)));
  T6 := data[r] + C2 + ((T5 shl 5) or (T5 shr (32 - 5))) +
    (T4 xor X3 xor X2) + X1;
  System.Inc(r);
  X4 := ((T4 shl 30) or (T4 shr (32 - 30)));
  T7 := data[r] + C2 + ((T6 shl 5) or (T6 shr (32 - 5))) +
    (T5 xor X4 xor X3) + X2;
  System.Inc(r);
  X5 := ((T5 shl 30) or (T5 shr (32 - 30)));
  T8 := data[r] + C2 + ((T7 shl 5) or (T7 shr (32 - 5))) +
    (T6 xor X5 xor X4) + X3;
  System.Inc(r);
  X6 := ((T6 shl 30) or (T6 shr (32 - 30)));
  T1 := data[r] + C2 + ((T8 shl 5) or (T8 shr (32 - 5))) +
    (T7 xor X6 xor X5) + X4;
  System.Inc(r);
  X7 := ((T7 shl 30) or (T7 shr (32 - 30)));
  T2 := data[r] + C2 + ((T1 shl 5) or (T1 shr (32 - 5))) +
    (T8 xor X7 xor X6) + X5;
  System.Inc(r);
  X8 := ((T8 shl 30) or (T8 shr (32 - 30)));
  T3 := data[r] + C2 + ((T2 shl 5) or (T2 shr (32 - 5))) +
    (T1 xor X8 xor X7) + X6;
  System.Inc(r);
  X1 := ((T1 shl 30) or (T1 shr (32 - 30)));
  T4 := data[r] + C2 + ((T3 shl 5) or (T3 shr (32 - 5))) +
    (T2 xor X1 xor X8) + X7;
  System.Inc(r);
  X2 := ((T2 shl 30) or (T2 shr (32 - 30)));
  T5 := data[r] + C2 + ((T4 shl 5) or (T4 shr (32 - 5))) +
    (T3 xor X2 xor X1) + X8;
  System.Inc(r);
  X3 := ((T3 shl 30) or (T3 shr (32 - 30)));
  T6 := data[r] + C2 + ((T5 shl 5) or (T5 shr (32 - 5))) +
    (T4 xor X3 xor X2) + X1;
  System.Inc(r);
  X4 := ((T4 shl 30) or (T4 shr (32 - 30)));
  T7 := data[r] + C2 + ((T6 shl 5) or (T6 shr (32 - 5))) +
    (T5 xor X4 xor X3) + X2;
  System.Inc(r);
  X5 := ((T5 shl 30) or (T5 shr (32 - 30)));
  T8 := data[r] + C2 + ((T7 shl 5) or (T7 shr (32 - 5))) +
    (T6 xor X5 xor X4) + X3;
  System.Inc(r);
  X6 := ((T6 shl 30) or (T6 shr (32 - 30)));
  T1 := data[r] + C2 + ((T8 shl 5) or (T8 shr (32 - 5))) +
    (T7 xor X6 xor X5) + X4;
  System.Inc(r);
  X7 := ((T7 shl 30) or (T7 shr (32 - 30)));
  T2 := data[r] + C2 + ((T1 shl 5) or (T1 shr (32 - 5))) +
    (T8 xor X7 xor X6) + X5;
  System.Inc(r);
  X8 := ((T8 shl 30) or (T8 shr (32 - 30)));
  T3 := data[r] + C2 + ((T2 shl 5) or (T2 shr (32 - 5))) +
    (T1 xor X8 xor X7) + X6;
  System.Inc(r);
  X1 := ((T1 shl 30) or (T1 shr (32 - 30)));
  T4 := data[r] + C2 + ((T3 shl 5) or (T3 shr (32 - 5))) +
    (T2 xor X1 xor X8) + X7;
  System.Inc(r);
  X2 := ((T2 shl 30) or (T2 shr (32 - 30)));
  T5 := data[r] + C2 + ((T4 shl 5) or (T4 shr (32 - 5))) +
    (T3 xor X2 xor X1) + X8;
  System.Inc(r);
  X3 := ((T3 shl 30) or (T3 shr (32 - 30)));
  T6 := data[r] + C2 + ((T5 shl 5) or (T5 shr (32 - 5))) +
    (T4 xor X3 xor X2) + X1;
  System.Inc(r);
  X4 := ((T4 shl 30) or (T4 shr (32 - 30)));
  T7 := data[r] + C2 + ((T6 shl 5) or (T6 shr (32 - 5))) +
    (T5 xor X4 xor X3) + X2;
  System.Inc(r);
  X5 := ((T5 shl 30) or (T5 shr (32 - 30)));
  T8 := data[r] + C2 + ((T7 shl 5) or (T7 shr (32 - 5))) +
    (T6 xor X5 xor X4) + X3;
  System.Inc(r);
  X6 := ((T6 shl 30) or (T6 shr (32 - 30)));
  T1 := data[r] + C3 + ((T8 shl 5) or (T8 shr (32 - 5))) +
    ((T7 and X6) or (T7 and X5) or (X6 and X5)) + X4;
  System.Inc(r);
  X7 := ((T7 shl 30) or (T7 shr (32 - 30)));
  T2 := data[r] + C3 + ((T1 shl 5) or (T1 shr (32 - 5))) +
    ((T8 and X7) or (T8 and X6) or (X7 and X6)) + X5;
  System.Inc(r);
  X8 := ((T8 shl 30) or (T8 shr (32 - 30)));
  T3 := data[r] + C3 + ((T2 shl 5) or (T2 shr (32 - 5))) +
    ((T1 and X8) or (T1 and X7) or (X8 and X7)) + X6;
  System.Inc(r);
  X1 := ((T1 shl 30) or (T1 shr (32 - 30)));
  T4 := data[r] + C3 + ((T3 shl 5) or (T3 shr (32 - 5))) +
    ((T2 and X1) or (T2 and X8) or (X1 and X8)) + X7;
  System.Inc(r);
  X2 := ((T2 shl 30) or (T2 shr (32 - 30)));
  T5 := data[r] + C3 + ((T4 shl 5) or (T4 shr (32 - 5))) +
    ((T3 and X2) or (T3 and X1) or (X2 and X1)) + X8;
  System.Inc(r);
  X3 := ((T3 shl 30) or (T3 shr (32 - 30)));
  T6 := data[r] + C3 + ((T5 shl 5) or (T5 shr (32 - 5))) +
    ((T4 and X3) or (T4 and X2) or (X3 and X2)) + X1;
  System.Inc(r);
  X4 := ((T4 shl 30) or (T4 shr (32 - 30)));
  T7 := data[r] + C3 + ((T6 shl 5) or (T6 shr (32 - 5))) +
    ((T5 and X4) or (T5 and X3) or (X4 and X3)) + X2;
  System.Inc(r);
  X5 := ((T5 shl 30) or (T5 shr (32 - 30)));
  T8 := data[r] + C3 + ((T7 shl 5) or (T7 shr (32 - 5))) +
    ((T6 and X5) or (T6 and X4) or (X5 and X4)) + X3;
  System.Inc(r);
  X6 := ((T6 shl 30) or (T6 shr (32 - 30)));
  T1 := data[r] + C3 + ((T8 shl 5) or (T8 shr (32 - 5))) +
    ((T7 and X6) or (T7 and X5) or (X6 and X5)) + X4;
  System.Inc(r);
  X7 := ((T7 shl 30) or (T7 shr (32 - 30)));
  T2 := data[r] + C3 + ((T1 shl 5) or (T1 shr (32 - 5))) +
    ((T8 and X7) or (T8 and X6) or (X7 and X6)) + X5;
  System.Inc(r);
  X8 := ((T8 shl 30) or (T8 shr (32 - 30)));
  T3 := data[r] + C3 + ((T2 shl 5) or (T2 shr (32 - 5))) +
    ((T1 and X8) or (T1 and X7) or (X8 and X7)) + X6;
  System.Inc(r);
  X1 := ((T1 shl 30) or (T1 shr (32 - 30)));
  T4 := data[r] + C3 + ((T3 shl 5) or (T3 shr (32 - 5))) +
    ((T2 and X1) or (T2 and X8) or (X1 and X8)) + X7;
  System.Inc(r);
  X2 := ((T2 shl 30) or (T2 shr (32 - 30)));
  T5 := data[r] + C3 + ((T4 shl 5) or (T4 shr (32 - 5))) +
    ((T3 and X2) or (T3 and X1) or (X2 and X1)) + X8;
  System.Inc(r);
  X3 := ((T3 shl 30) or (T3 shr (32 - 30)));
  T6 := data[r] + C3 + ((T5 shl 5) or (T5 shr (32 - 5))) +
    ((T4 and X3) or (T4 and X2) or (X3 and X2)) + X1;
  System.Inc(r);
  X4 := ((T4 shl 30) or (T4 shr (32 - 30)));
  T7 := data[r] + C3 + ((T6 shl 5) or (T6 shr (32 - 5))) +
    ((T5 and X4) or (T5 and X3) or (X4 and X3)) + X2;
  System.Inc(r);
  X5 := ((T5 shl 30) or (T5 shr (32 - 30)));
  T8 := data[r] + C3 + ((T7 shl 5) or (T7 shr (32 - 5))) +
    ((T6 and X5) or (T6 and X4) or (X5 and X4)) + X3;
  System.Inc(r);
  X6 := ((T6 shl 30) or (T6 shr (32 - 30)));
  T1 := data[r] + C3 + ((T8 shl 5) or (T8 shr (32 - 5))) +
    ((T7 and X6) or (T7 and X5) or (X6 and X5)) + X4;
  System.Inc(r);
  X7 := ((T7 shl 30) or (T7 shr (32 - 30)));
  T2 := data[r] + C3 + ((T1 shl 5) or (T1 shr (32 - 5))) +
    ((T8 and X7) or (T8 and X6) or (X7 and X6)) + X5;
  System.Inc(r);
  X8 := ((T8 shl 30) or (T8 shr (32 - 30)));
  T3 := data[r] + C3 + ((T2 shl 5) or (T2 shr (32 - 5))) +
    ((T1 and X8) or (T1 and X7) or (X8 and X7)) + X6;
  System.Inc(r);
  X1 := ((T1 shl 30) or (T1 shr (32 - 30)));
  T4 := data[r] + C3 + ((T3 shl 5) or (T3 shr (32 - 5))) +
    ((T2 and X1) or (T2 and X8) or (X1 and X8)) + X7;
  System.Inc(r);
  X2 := ((T2 shl 30) or (T2 shr (32 - 30)));
  T5 := data[r] + C4 + ((T4 shl 5) or (T4 shr (32 - 5))) +
    (T3 xor X2 xor X1) + X8;
  System.Inc(r);
  X3 := ((T3 shl 30) or (T3 shr (32 - 30)));
  T6 := data[r] + C4 + ((T5 shl 5) or (T5 shr (32 - 5))) +
    (T4 xor X3 xor X2) + X1;
  System.Inc(r);
  X4 := ((T4 shl 30) or (T4 shr (32 - 30)));
  T7 := data[r] + C4 + ((T6 shl 5) or (T6 shr (32 - 5))) +
    (T5 xor X4 xor X3) + X2;
  System.Inc(r);
  X5 := ((T5 shl 30) or (T5 shr (32 - 30)));
  T8 := data[r] + C4 + ((T7 shl 5) or (T7 shr (32 - 5))) +
    (T6 xor X5 xor X4) + X3;
  System.Inc(r);
  X6 := ((T6 shl 30) or (T6 shr (32 - 30)));
  T1 := data[r] + C4 + ((T8 shl 5) or (T8 shr (32 - 5))) +
    (T7 xor X6 xor X5) + X4;
  System.Inc(r);
  X7 := ((T7 shl 30) or (T7 shr (32 - 30)));
  T2 := data[r] + C4 + ((T1 shl 5) or (T1 shr (32 - 5))) +
    (T8 xor X7 xor X6) + X5;
  System.Inc(r);
  X8 := ((T8 shl 30) or (T8 shr (32 - 30)));
  T3 := data[r] + C4 + ((T2 shl 5) or (T2 shr (32 - 5))) +
    (T1 xor X8 xor X7) + X6;
  System.Inc(r);
  X1 := ((T1 shl 30) or (T1 shr (32 - 30)));
  T4 := data[r] + C4 + ((T3 shl 5) or (T3 shr (32 - 5))) +
    (T2 xor X1 xor X8) + X7;
  System.Inc(r);
  X2 := ((T2 shl 30) or (T2 shr (32 - 30)));
  T5 := data[r] + C4 + ((T4 shl 5) or (T4 shr (32 - 5))) +
    (T3 xor X2 xor X1) + X8;
  System.Inc(r);
  X3 := ((T3 shl 30) or (T3 shr (32 - 30)));
  T6 := data[r] + C4 + ((T5 shl 5) or (T5 shr (32 - 5))) +
    (T4 xor X3 xor X2) + X1;
  System.Inc(r);
  X4 := ((T4 shl 30) or (T4 shr (32 - 30)));
  T7 := data[r] + C4 + ((T6 shl 5) or (T6 shr (32 - 5))) +
    (T5 xor X4 xor X3) + X2;
  System.Inc(r);
  X5 := ((T5 shl 30) or (T5 shr (32 - 30)));
  T8 := data[r] + C4 + ((T7 shl 5) or (T7 shr (32 - 5))) +
    (T6 xor X5 xor X4) + X3;
  System.Inc(r);
  X6 := ((T6 shl 30) or (T6 shr (32 - 30)));
  T1 := data[r] + C4 + ((T8 shl 5) or (T8 shr (32 - 5))) +
    (T7 xor X6 xor X5) + X4;
  System.Inc(r);
  X7 := ((T7 shl 30) or (T7 shr (32 - 30)));
  T2 := data[r] + C4 + ((T1 shl 5) or (T1 shr (32 - 5))) +
    (T8 xor X7 xor X6) + X5;
  System.Inc(r);
  X8 := ((T8 shl 30) or (T8 shr (32 - 30)));
  T3 := data[r] + C4 + ((T2 shl 5) or (T2 shr (32 - 5))) +
    (T1 xor X8 xor X7) + X6;
  System.Inc(r);
  X1 := ((T1 shl 30) or (T1 shr (32 - 30)));
  T4 := data[r] + C4 + ((T3 shl 5) or (T3 shr (32 - 5))) +
    (T2 xor X1 xor X8) + X7;
  System.Inc(r);
  X2 := ((T2 shl 30) or (T2 shr (32 - 30)));
  T5 := data[r] + C4 + ((T4 shl 5) or (T4 shr (32 - 5))) +
    (T3 xor X2 xor X1) + X8;
  System.Inc(r);
  X3 := ((T3 shl 30) or (T3 shr (32 - 30)));
  T6 := data[r] + C4 + ((T5 shl 5) or (T5 shr (32 - 5))) +
    (T4 xor X3 xor X2) + X1;
  System.Inc(r);
  X4 := ((T4 shl 30) or (T4 shr (32 - 30)));
  T7 := data[r] + C4 + ((T6 shl 5) or (T6 shr (32 - 5))) +
    (T5 xor X4 xor X3) + X2;
  System.Inc(r);
  X5 := ((T5 shl 30) or (T5 shr (32 - 30)));

  Fm_state[0] := Fm_state[0] + (data[r] + C4 + ((T7 shl 5) or (T7 shr (32 - 5)))
    + (T6 xor X5 xor X4) + X3);
  Fm_state[1] := Fm_state[1] + T7;
  Fm_state[2] := Fm_state[2] + ((T6 shl 30) or (T6 shr (32 - 30)));
  Fm_state[3] := Fm_state[3] + X5;
  Fm_state[4] := Fm_state[4] + X4;

end;

end.
