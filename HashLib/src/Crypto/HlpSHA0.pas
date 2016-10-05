unit HlpSHA0;

{$I ..\Include\HashLib.inc}

interface

uses
{$IFDEF DELPHI2010}
  SysUtils, // to get rid of compiler hint "not inlined" on Delphi 2010.
{$ENDIF DELPHI2010}
  HlpBits,
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

  T1 := data[r] + C1 + TBits.RotateLeft32(A, 5) +
    ((B and C) or (not B and D)) + E;
  System.Inc(r);
  X7 := TBits.RotateLeft32(B, 30);
  T2 := data[r] + C1 + TBits.RotateLeft32(T1, 5) +
    ((A and X7) or (not A and C)) + D;
  System.Inc(r);
  X8 := TBits.RotateLeft32(A, 30);
  T3 := data[r] + C1 + TBits.RotateLeft32(T2, 5) +
    ((T1 and X8) or (not T1 and X7)) + C;
  System.Inc(r);
  X1 := TBits.RotateLeft32(T1, 30);
  T4 := data[r] + C1 + TBits.RotateLeft32(T3, 5) +
    ((T2 and X1) or (not T2 and X8)) + X7;
  System.Inc(r);
  X2 := TBits.RotateLeft32(T2, 30);
  T5 := data[r] + C1 + TBits.RotateLeft32(T4, 5) +
    ((T3 and X2) or (not T3 and X1)) + X8;
  System.Inc(r);
  X3 := TBits.RotateLeft32(T3, 30);
  T6 := data[r] + C1 + TBits.RotateLeft32(T5, 5) +
    ((T4 and X3) or (not T4 and X2)) + X1;
  System.Inc(r);
  X4 := TBits.RotateLeft32(T4, 30);
  T7 := data[r] + C1 + TBits.RotateLeft32(T6, 5) +
    ((T5 and X4) or (not T5 and X3)) + X2;
  System.Inc(r);
  X5 := TBits.RotateLeft32(T5, 30);
  T8 := data[r] + C1 + TBits.RotateLeft32(T7, 5) +
    ((T6 and X5) or (not T6 and X4)) + X3;
  System.Inc(r);
  X6 := TBits.RotateLeft32(T6, 30);
  T1 := data[r] + C1 + TBits.RotateLeft32(T8, 5) +
    ((T7 and X6) or (not T7 and X5)) + X4;
  System.Inc(r);
  X7 := TBits.RotateLeft32(T7, 30);
  T2 := data[r] + C1 + TBits.RotateLeft32(T1, 5) +
    ((T8 and X7) or (not T8 and X6)) + X5;
  System.Inc(r);
  X8 := TBits.RotateLeft32(T8, 30);
  T3 := data[r] + C1 + TBits.RotateLeft32(T2, 5) +
    ((T1 and X8) or (not T1 and X7)) + X6;
  System.Inc(r);
  X1 := TBits.RotateLeft32(T1, 30);
  T4 := data[r] + C1 + TBits.RotateLeft32(T3, 5) +
    ((T2 and X1) or (not T2 and X8)) + X7;
  System.Inc(r);
  X2 := TBits.RotateLeft32(T2, 30);
  T5 := data[r] + C1 + TBits.RotateLeft32(T4, 5) +
    ((T3 and X2) or (not T3 and X1)) + X8;
  System.Inc(r);
  X3 := TBits.RotateLeft32(T3, 30);
  T6 := data[r] + C1 + TBits.RotateLeft32(T5, 5) +
    ((T4 and X3) or (not T4 and X2)) + X1;
  System.Inc(r);
  X4 := TBits.RotateLeft32(T4, 30);
  T7 := data[r] + C1 + TBits.RotateLeft32(T6, 5) +
    ((T5 and X4) or (not T5 and X3)) + X2;
  System.Inc(r);
  X5 := TBits.RotateLeft32(T5, 30);
  T8 := data[r] + C1 + TBits.RotateLeft32(T7, 5) +
    ((T6 and X5) or (not T6 and X4)) + X3;
  System.Inc(r);
  X6 := TBits.RotateLeft32(T6, 30);
  T1 := data[r] + C1 + TBits.RotateLeft32(T8, 5) +
    ((T7 and X6) or (not T7 and X5)) + X4;
  System.Inc(r);
  X7 := TBits.RotateLeft32(T7, 30);
  T2 := data[r] + C1 + TBits.RotateLeft32(T1, 5) +
    ((T8 and X7) or (not T8 and X6)) + X5;
  System.Inc(r);
  X8 := TBits.RotateLeft32(T8, 30);
  T3 := data[r] + C1 + TBits.RotateLeft32(T2, 5) +
    ((T1 and X8) or (not T1 and X7)) + X6;
  System.Inc(r);
  X1 := TBits.RotateLeft32(T1, 30);
  T4 := data[r] + C1 + TBits.RotateLeft32(T3, 5) +
    ((T2 and X1) or (not T2 and X8)) + X7;
  System.Inc(r);
  X2 := TBits.RotateLeft32(T2, 30);
  T5 := data[r] + C2 + TBits.RotateLeft32(T4, 5) + (T3 xor X2 xor X1) + X8;
  System.Inc(r);
  X3 := TBits.RotateLeft32(T3, 30);
  T6 := data[r] + C2 + TBits.RotateLeft32(T5, 5) + (T4 xor X3 xor X2) + X1;
  System.Inc(r);
  X4 := TBits.RotateLeft32(T4, 30);
  T7 := data[r] + C2 + TBits.RotateLeft32(T6, 5) + (T5 xor X4 xor X3) + X2;
  System.Inc(r);
  X5 := TBits.RotateLeft32(T5, 30);
  T8 := data[r] + C2 + TBits.RotateLeft32(T7, 5) + (T6 xor X5 xor X4) + X3;
  System.Inc(r);
  X6 := TBits.RotateLeft32(T6, 30);
  T1 := data[r] + C2 + TBits.RotateLeft32(T8, 5) + (T7 xor X6 xor X5) + X4;
  System.Inc(r);
  X7 := TBits.RotateLeft32(T7, 30);
  T2 := data[r] + C2 + TBits.RotateLeft32(T1, 5) + (T8 xor X7 xor X6) + X5;
  System.Inc(r);
  X8 := TBits.RotateLeft32(T8, 30);
  T3 := data[r] + C2 + TBits.RotateLeft32(T2, 5) + (T1 xor X8 xor X7) + X6;
  System.Inc(r);
  X1 := TBits.RotateLeft32(T1, 30);
  T4 := data[r] + C2 + TBits.RotateLeft32(T3, 5) + (T2 xor X1 xor X8) + X7;
  System.Inc(r);
  X2 := TBits.RotateLeft32(T2, 30);
  T5 := data[r] + C2 + TBits.RotateLeft32(T4, 5) + (T3 xor X2 xor X1) + X8;
  System.Inc(r);
  X3 := TBits.RotateLeft32(T3, 30);
  T6 := data[r] + C2 + TBits.RotateLeft32(T5, 5) + (T4 xor X3 xor X2) + X1;
  System.Inc(r);
  X4 := TBits.RotateLeft32(T4, 30);
  T7 := data[r] + C2 + TBits.RotateLeft32(T6, 5) + (T5 xor X4 xor X3) + X2;
  System.Inc(r);
  X5 := TBits.RotateLeft32(T5, 30);
  T8 := data[r] + C2 + TBits.RotateLeft32(T7, 5) + (T6 xor X5 xor X4) + X3;
  System.Inc(r);
  X6 := TBits.RotateLeft32(T6, 30);
  T1 := data[r] + C2 + TBits.RotateLeft32(T8, 5) + (T7 xor X6 xor X5) + X4;
  System.Inc(r);
  X7 := TBits.RotateLeft32(T7, 30);
  T2 := data[r] + C2 + TBits.RotateLeft32(T1, 5) + (T8 xor X7 xor X6) + X5;
  System.Inc(r);
  X8 := TBits.RotateLeft32(T8, 30);
  T3 := data[r] + C2 + TBits.RotateLeft32(T2, 5) + (T1 xor X8 xor X7) + X6;
  System.Inc(r);
  X1 := TBits.RotateLeft32(T1, 30);
  T4 := data[r] + C2 + TBits.RotateLeft32(T3, 5) + (T2 xor X1 xor X8) + X7;
  System.Inc(r);
  X2 := TBits.RotateLeft32(T2, 30);
  T5 := data[r] + C2 + TBits.RotateLeft32(T4, 5) + (T3 xor X2 xor X1) + X8;
  System.Inc(r);
  X3 := TBits.RotateLeft32(T3, 30);
  T6 := data[r] + C2 + TBits.RotateLeft32(T5, 5) + (T4 xor X3 xor X2) + X1;
  System.Inc(r);
  X4 := TBits.RotateLeft32(T4, 30);
  T7 := data[r] + C2 + TBits.RotateLeft32(T6, 5) + (T5 xor X4 xor X3) + X2;
  System.Inc(r);
  X5 := TBits.RotateLeft32(T5, 30);
  T8 := data[r] + C2 + TBits.RotateLeft32(T7, 5) + (T6 xor X5 xor X4) + X3;
  System.Inc(r);
  X6 := TBits.RotateLeft32(T6, 30);
  T1 := data[r] + C3 + TBits.RotateLeft32(T8, 5) +
    ((T7 and X6) or (T7 and X5) or (X6 and X5)) + X4;
  System.Inc(r);
  X7 := TBits.RotateLeft32(T7, 30);
  T2 := data[r] + C3 + TBits.RotateLeft32(T1, 5) +
    ((T8 and X7) or (T8 and X6) or (X7 and X6)) + X5;
  System.Inc(r);
  X8 := TBits.RotateLeft32(T8, 30);
  T3 := data[r] + C3 + TBits.RotateLeft32(T2, 5) +
    ((T1 and X8) or (T1 and X7) or (X8 and X7)) + X6;
  System.Inc(r);
  X1 := TBits.RotateLeft32(T1, 30);
  T4 := data[r] + C3 + TBits.RotateLeft32(T3, 5) +
    ((T2 and X1) or (T2 and X8) or (X1 and X8)) + X7;
  System.Inc(r);
  X2 := TBits.RotateLeft32(T2, 30);
  T5 := data[r] + C3 + TBits.RotateLeft32(T4, 5) +
    ((T3 and X2) or (T3 and X1) or (X2 and X1)) + X8;
  System.Inc(r);
  X3 := TBits.RotateLeft32(T3, 30);
  T6 := data[r] + C3 + TBits.RotateLeft32(T5, 5) +
    ((T4 and X3) or (T4 and X2) or (X3 and X2)) + X1;
  System.Inc(r);
  X4 := TBits.RotateLeft32(T4, 30);
  T7 := data[r] + C3 + TBits.RotateLeft32(T6, 5) +
    ((T5 and X4) or (T5 and X3) or (X4 and X3)) + X2;
  System.Inc(r);
  X5 := TBits.RotateLeft32(T5, 30);
  T8 := data[r] + C3 + TBits.RotateLeft32(T7, 5) +
    ((T6 and X5) or (T6 and X4) or (X5 and X4)) + X3;
  System.Inc(r);
  X6 := TBits.RotateLeft32(T6, 30);
  T1 := data[r] + C3 + TBits.RotateLeft32(T8, 5) +
    ((T7 and X6) or (T7 and X5) or (X6 and X5)) + X4;
  System.Inc(r);
  X7 := TBits.RotateLeft32(T7, 30);
  T2 := data[r] + C3 + TBits.RotateLeft32(T1, 5) +
    ((T8 and X7) or (T8 and X6) or (X7 and X6)) + X5;
  System.Inc(r);
  X8 := TBits.RotateLeft32(T8, 30);
  T3 := data[r] + C3 + TBits.RotateLeft32(T2, 5) +
    ((T1 and X8) or (T1 and X7) or (X8 and X7)) + X6;
  System.Inc(r);
  X1 := TBits.RotateLeft32(T1, 30);
  T4 := data[r] + C3 + TBits.RotateLeft32(T3, 5) +
    ((T2 and X1) or (T2 and X8) or (X1 and X8)) + X7;
  System.Inc(r);
  X2 := TBits.RotateLeft32(T2, 30);
  T5 := data[r] + C3 + TBits.RotateLeft32(T4, 5) +
    ((T3 and X2) or (T3 and X1) or (X2 and X1)) + X8;
  System.Inc(r);
  X3 := TBits.RotateLeft32(T3, 30);
  T6 := data[r] + C3 + TBits.RotateLeft32(T5, 5) +
    ((T4 and X3) or (T4 and X2) or (X3 and X2)) + X1;
  System.Inc(r);
  X4 := TBits.RotateLeft32(T4, 30);
  T7 := data[r] + C3 + TBits.RotateLeft32(T6, 5) +
    ((T5 and X4) or (T5 and X3) or (X4 and X3)) + X2;
  System.Inc(r);
  X5 := TBits.RotateLeft32(T5, 30);
  T8 := data[r] + C3 + TBits.RotateLeft32(T7, 5) +
    ((T6 and X5) or (T6 and X4) or (X5 and X4)) + X3;
  System.Inc(r);
  X6 := TBits.RotateLeft32(T6, 30);
  T1 := data[r] + C3 + TBits.RotateLeft32(T8, 5) +
    ((T7 and X6) or (T7 and X5) or (X6 and X5)) + X4;
  System.Inc(r);
  X7 := TBits.RotateLeft32(T7, 30);
  T2 := data[r] + C3 + TBits.RotateLeft32(T1, 5) +
    ((T8 and X7) or (T8 and X6) or (X7 and X6)) + X5;
  System.Inc(r);
  X8 := TBits.RotateLeft32(T8, 30);
  T3 := data[r] + C3 + TBits.RotateLeft32(T2, 5) +
    ((T1 and X8) or (T1 and X7) or (X8 and X7)) + X6;
  System.Inc(r);
  X1 := TBits.RotateLeft32(T1, 30);
  T4 := data[r] + C3 + TBits.RotateLeft32(T3, 5) +
    ((T2 and X1) or (T2 and X8) or (X1 and X8)) + X7;
  System.Inc(r);
  X2 := TBits.RotateLeft32(T2, 30);
  T5 := data[r] + C4 + TBits.RotateLeft32(T4, 5) + (T3 xor X2 xor X1) + X8;
  System.Inc(r);
  X3 := TBits.RotateLeft32(T3, 30);
  T6 := data[r] + C4 + TBits.RotateLeft32(T5, 5) + (T4 xor X3 xor X2) + X1;
  System.Inc(r);
  X4 := TBits.RotateLeft32(T4, 30);
  T7 := data[r] + C4 + TBits.RotateLeft32(T6, 5) + (T5 xor X4 xor X3) + X2;
  System.Inc(r);
  X5 := TBits.RotateLeft32(T5, 30);
  T8 := data[r] + C4 + TBits.RotateLeft32(T7, 5) + (T6 xor X5 xor X4) + X3;
  System.Inc(r);
  X6 := TBits.RotateLeft32(T6, 30);
  T1 := data[r] + C4 + TBits.RotateLeft32(T8, 5) + (T7 xor X6 xor X5) + X4;
  System.Inc(r);
  X7 := TBits.RotateLeft32(T7, 30);
  T2 := data[r] + C4 + TBits.RotateLeft32(T1, 5) + (T8 xor X7 xor X6) + X5;
  System.Inc(r);
  X8 := TBits.RotateLeft32(T8, 30);
  T3 := data[r] + C4 + TBits.RotateLeft32(T2, 5) + (T1 xor X8 xor X7) + X6;
  System.Inc(r);
  X1 := TBits.RotateLeft32(T1, 30);
  T4 := data[r] + C4 + TBits.RotateLeft32(T3, 5) + (T2 xor X1 xor X8) + X7;
  System.Inc(r);
  X2 := TBits.RotateLeft32(T2, 30);
  T5 := data[r] + C4 + TBits.RotateLeft32(T4, 5) + (T3 xor X2 xor X1) + X8;
  System.Inc(r);
  X3 := TBits.RotateLeft32(T3, 30);
  T6 := data[r] + C4 + TBits.RotateLeft32(T5, 5) + (T4 xor X3 xor X2) + X1;
  System.Inc(r);
  X4 := TBits.RotateLeft32(T4, 30);
  T7 := data[r] + C4 + TBits.RotateLeft32(T6, 5) + (T5 xor X4 xor X3) + X2;
  System.Inc(r);
  X5 := TBits.RotateLeft32(T5, 30);
  T8 := data[r] + C4 + TBits.RotateLeft32(T7, 5) + (T6 xor X5 xor X4) + X3;
  System.Inc(r);
  X6 := TBits.RotateLeft32(T6, 30);
  T1 := data[r] + C4 + TBits.RotateLeft32(T8, 5) + (T7 xor X6 xor X5) + X4;
  System.Inc(r);
  X7 := TBits.RotateLeft32(T7, 30);
  T2 := data[r] + C4 + TBits.RotateLeft32(T1, 5) + (T8 xor X7 xor X6) + X5;
  System.Inc(r);
  X8 := TBits.RotateLeft32(T8, 30);
  T3 := data[r] + C4 + TBits.RotateLeft32(T2, 5) + (T1 xor X8 xor X7) + X6;
  System.Inc(r);
  X1 := TBits.RotateLeft32(T1, 30);
  T4 := data[r] + C4 + TBits.RotateLeft32(T3, 5) + (T2 xor X1 xor X8) + X7;
  System.Inc(r);
  X2 := TBits.RotateLeft32(T2, 30);
  T5 := data[r] + C4 + TBits.RotateLeft32(T4, 5) + (T3 xor X2 xor X1) + X8;
  System.Inc(r);
  X3 := TBits.RotateLeft32(T3, 30);
  T6 := data[r] + C4 + TBits.RotateLeft32(T5, 5) + (T4 xor X3 xor X2) + X1;
  System.Inc(r);
  X4 := TBits.RotateLeft32(T4, 30);
  T7 := data[r] + C4 + TBits.RotateLeft32(T6, 5) + (T5 xor X4 xor X3) + X2;
  System.Inc(r);
  X5 := TBits.RotateLeft32(T5, 30);

  Fm_state[0] := Fm_state[0] + (data[r] + C4 + TBits.RotateLeft32(T7, 5) +
    (T6 xor X5 xor X4) + X3);
  Fm_state[1] := Fm_state[1] + T7;
  Fm_state[2] := Fm_state[2] + TBits.RotateLeft32(T6, 30);
  Fm_state[3] := Fm_state[3] + X5;
  Fm_state[4] := Fm_state[4] + X4;

end;

end.
