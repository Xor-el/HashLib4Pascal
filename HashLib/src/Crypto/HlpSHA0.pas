unit HlpSHA0;

{$I ..\Include\HashLib.inc}

interface

uses
{$IFDEF DELPHI2010}
  SysUtils, // to get rid of compiler hint "not inlined" on Delphi 2010.
{$ENDIF DELPHI2010}
  HlpHashBuffer,
  HlpBits,
  HlpHashLibTypes,
  HlpConverters,
  HlpIHashInfo,
  HlpHashCryptoNotBuildIn;

type
  TSHA0 = class(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

  strict protected

    Fm_state, Fdata: THashLibUInt32Array;
    Fptr_Fm_state, Fptr_Fdata: PCardinal;

{$REGION 'Consts'}

  const

    C1 = UInt32($5A827999);
    C2 = UInt32($6ED9EBA1);
    C3 = UInt32($8F1BBCDC);
    C4 = UInt32($CA62C1D6);

{$ENDREGION}
    procedure Finish(); override;
    procedure Expand(a_data: PCardinal); virtual;
    procedure TransformBlock(a_data: PByte; a_data_length: Int32;
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
  Fptr_Fm_state := PCardinal(Fm_state);
  System.SetLength(Fdata, 80);
  Fptr_Fdata := PCardinal(Fdata);
end;

procedure TSHA0.Expand(a_data: PCardinal);
// var
// j: Int32;
begin
  {
    for j := 16 to 79 do
    begin
    a_data[j] := ((a_data[j - 3] xor a_data[j - 8]) xor a_data[j - 14])
    xor a_data[j - 16];

    end; }

  a_data[16] := ((a_data[16 - 3] xor a_data[16 - 8]) xor a_data[16 - 14])
    xor a_data[16 - 16];
  a_data[17] := ((a_data[17 - 3] xor a_data[17 - 8]) xor a_data[17 - 14])
    xor a_data[17 - 16];
  a_data[18] := ((a_data[18 - 3] xor a_data[18 - 8]) xor a_data[18 - 14])
    xor a_data[18 - 16];
  a_data[19] := ((a_data[19 - 3] xor a_data[19 - 8]) xor a_data[19 - 14])
    xor a_data[19 - 16];
  a_data[20] := ((a_data[20 - 3] xor a_data[20 - 8]) xor a_data[20 - 14])
    xor a_data[20 - 16];
  a_data[21] := ((a_data[21 - 3] xor a_data[21 - 8]) xor a_data[21 - 14])
    xor a_data[21 - 16];
  a_data[22] := ((a_data[22 - 3] xor a_data[22 - 8]) xor a_data[22 - 14])
    xor a_data[22 - 16];
  a_data[23] := ((a_data[23 - 3] xor a_data[23 - 8]) xor a_data[23 - 14])
    xor a_data[23 - 16];
  a_data[24] := ((a_data[24 - 3] xor a_data[24 - 8]) xor a_data[24 - 14])
    xor a_data[24 - 16];
  a_data[25] := ((a_data[25 - 3] xor a_data[25 - 8]) xor a_data[25 - 14])
    xor a_data[25 - 16];
  a_data[26] := ((a_data[26 - 3] xor a_data[26 - 8]) xor a_data[26 - 14])
    xor a_data[26 - 16];
  a_data[27] := ((a_data[27 - 3] xor a_data[27 - 8]) xor a_data[27 - 14])
    xor a_data[27 - 16];
  a_data[28] := ((a_data[28 - 3] xor a_data[28 - 8]) xor a_data[28 - 14])
    xor a_data[28 - 16];
  a_data[29] := ((a_data[29 - 3] xor a_data[29 - 8]) xor a_data[29 - 14])
    xor a_data[29 - 16];
  a_data[30] := ((a_data[30 - 3] xor a_data[30 - 8]) xor a_data[30 - 14])
    xor a_data[30 - 16];
  a_data[31] := ((a_data[31 - 3] xor a_data[31 - 8]) xor a_data[31 - 14])
    xor a_data[31 - 16];
  a_data[32] := ((a_data[32 - 3] xor a_data[32 - 8]) xor a_data[32 - 14])
    xor a_data[32 - 16];
  a_data[33] := ((a_data[33 - 3] xor a_data[33 - 8]) xor a_data[33 - 14])
    xor a_data[33 - 16];
  a_data[34] := ((a_data[34 - 3] xor a_data[34 - 8]) xor a_data[34 - 14])
    xor a_data[34 - 16];
  a_data[35] := ((a_data[35 - 3] xor a_data[35 - 8]) xor a_data[35 - 14])
    xor a_data[35 - 16];
  a_data[36] := ((a_data[36 - 3] xor a_data[36 - 8]) xor a_data[36 - 14])
    xor a_data[36 - 16];
  a_data[37] := ((a_data[37 - 3] xor a_data[37 - 8]) xor a_data[37 - 14])
    xor a_data[37 - 16];
  a_data[38] := ((a_data[38 - 3] xor a_data[38 - 8]) xor a_data[38 - 14])
    xor a_data[38 - 16];
  a_data[39] := ((a_data[39 - 3] xor a_data[39 - 8]) xor a_data[39 - 14])
    xor a_data[39 - 16];
  a_data[40] := ((a_data[40 - 3] xor a_data[40 - 8]) xor a_data[40 - 14])
    xor a_data[40 - 16];
  a_data[41] := ((a_data[41 - 3] xor a_data[41 - 8]) xor a_data[41 - 14])
    xor a_data[41 - 16];
  a_data[42] := ((a_data[42 - 3] xor a_data[42 - 8]) xor a_data[42 - 14])
    xor a_data[42 - 16];
  a_data[43] := ((a_data[43 - 3] xor a_data[43 - 8]) xor a_data[43 - 14])
    xor a_data[43 - 16];
  a_data[44] := ((a_data[44 - 3] xor a_data[44 - 8]) xor a_data[44 - 14])
    xor a_data[44 - 16];
  a_data[45] := ((a_data[45 - 3] xor a_data[45 - 8]) xor a_data[45 - 14])
    xor a_data[45 - 16];
  a_data[46] := ((a_data[46 - 3] xor a_data[46 - 8]) xor a_data[46 - 14])
    xor a_data[46 - 16];
  a_data[47] := ((a_data[47 - 3] xor a_data[47 - 8]) xor a_data[47 - 14])
    xor a_data[47 - 16];
  a_data[48] := ((a_data[48 - 3] xor a_data[48 - 8]) xor a_data[48 - 14])
    xor a_data[48 - 16];
  a_data[49] := ((a_data[49 - 3] xor a_data[49 - 8]) xor a_data[49 - 14])
    xor a_data[49 - 16];
  a_data[50] := ((a_data[50 - 3] xor a_data[50 - 8]) xor a_data[50 - 14])
    xor a_data[50 - 16];
  a_data[51] := ((a_data[51 - 3] xor a_data[51 - 8]) xor a_data[51 - 14])
    xor a_data[51 - 16];
  a_data[52] := ((a_data[52 - 3] xor a_data[52 - 8]) xor a_data[52 - 14])
    xor a_data[52 - 16];
  a_data[53] := ((a_data[53 - 3] xor a_data[53 - 8]) xor a_data[53 - 14])
    xor a_data[53 - 16];
  a_data[54] := ((a_data[54 - 3] xor a_data[54 - 8]) xor a_data[54 - 14])
    xor a_data[54 - 16];
  a_data[55] := ((a_data[55 - 3] xor a_data[55 - 8]) xor a_data[55 - 14])
    xor a_data[55 - 16];
  a_data[56] := ((a_data[56 - 3] xor a_data[56 - 8]) xor a_data[56 - 14])
    xor a_data[56 - 16];
  a_data[57] := ((a_data[57 - 3] xor a_data[57 - 8]) xor a_data[57 - 14])
    xor a_data[57 - 16];
  a_data[58] := ((a_data[58 - 3] xor a_data[58 - 8]) xor a_data[58 - 14])
    xor a_data[58 - 16];
  a_data[59] := ((a_data[59 - 3] xor a_data[59 - 8]) xor a_data[59 - 14])
    xor a_data[59 - 16];
  a_data[60] := ((a_data[60 - 3] xor a_data[60 - 8]) xor a_data[60 - 14])
    xor a_data[60 - 16];
  a_data[61] := ((a_data[61 - 3] xor a_data[61 - 8]) xor a_data[61 - 14])
    xor a_data[61 - 16];
  a_data[62] := ((a_data[62 - 3] xor a_data[62 - 8]) xor a_data[62 - 14])
    xor a_data[62 - 16];
  a_data[63] := ((a_data[63 - 3] xor a_data[63 - 8]) xor a_data[63 - 14])
    xor a_data[63 - 16];
  a_data[64] := ((a_data[64 - 3] xor a_data[64 - 8]) xor a_data[64 - 14])
    xor a_data[64 - 16];
  a_data[65] := ((a_data[65 - 3] xor a_data[65 - 8]) xor a_data[65 - 14])
    xor a_data[65 - 16];
  a_data[66] := ((a_data[66 - 3] xor a_data[66 - 8]) xor a_data[66 - 14])
    xor a_data[66 - 16];
  a_data[67] := ((a_data[67 - 3] xor a_data[67 - 8]) xor a_data[67 - 14])
    xor a_data[67 - 16];
  a_data[68] := ((a_data[68 - 3] xor a_data[68 - 8]) xor a_data[68 - 14])
    xor a_data[68 - 16];
  a_data[69] := ((a_data[69 - 3] xor a_data[69 - 8]) xor a_data[69 - 14])
    xor a_data[69 - 16];
  a_data[70] := ((a_data[70 - 3] xor a_data[70 - 8]) xor a_data[70 - 14])
    xor a_data[70 - 16];
  a_data[71] := ((a_data[71 - 3] xor a_data[71 - 8]) xor a_data[71 - 14])
    xor a_data[71 - 16];
  a_data[72] := ((a_data[72 - 3] xor a_data[72 - 8]) xor a_data[72 - 14])
    xor a_data[72 - 16];
  a_data[73] := ((a_data[73 - 3] xor a_data[73 - 8]) xor a_data[73 - 14])
    xor a_data[73 - 16];
  a_data[74] := ((a_data[74 - 3] xor a_data[74 - 8]) xor a_data[74 - 14])
    xor a_data[74 - 16];
  a_data[75] := ((a_data[75 - 3] xor a_data[75 - 8]) xor a_data[75 - 14])
    xor a_data[75 - 16];
  a_data[76] := ((a_data[76 - 3] xor a_data[76 - 8]) xor a_data[76 - 14])
    xor a_data[76 - 16];
  a_data[77] := ((a_data[77 - 3] xor a_data[77 - 8]) xor a_data[77 - 14])
    xor a_data[77 - 16];
  a_data[78] := ((a_data[78 - 3] xor a_data[78 - 8]) xor a_data[78 - 14])
    xor a_data[78 - 16];
  a_data[79] := ((a_data[79 - 3] xor a_data[79 - 8]) xor a_data[79 - 14])
    xor a_data[79 - 16];

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

  Fptr_Fm_state[0] := $67452301;
  Fptr_Fm_state[1] := $EFCDAB89;
  Fptr_Fm_state[2] := $98BADCFE;
  Fptr_Fm_state[3] := $10325476;
  Fptr_Fm_state[4] := $C3D2E1F0;

  Inherited Initialize();

end;

procedure TSHA0.TransformBlock(a_data: PByte; a_data_length: Int32;
  a_index: Int32);
var
  A, B, C, D, E, T1, X7, T2, X8, T3, X1, T4, X2, T5, X3, T6, X4, T7, X5, T8,
    X6: UInt32;

begin
  TConverters.ConvertBytesToUInt32SwapOrder(a_data, a_index, 64, Fptr_Fdata, 0);

  Expand(Fptr_Fdata);

  A := Fptr_Fm_state[0];
  B := Fptr_Fm_state[1];
  C := Fptr_Fm_state[2];
  D := Fptr_Fm_state[3];
  E := Fptr_Fm_state[4];

  T1 := Fptr_Fdata[0] + C1 + TBits.RotateLeft32(A, 5) +
    ((B and C) or (not B and D)) + E;

  X7 := TBits.RotateLeft32(B, 30);
  T2 := Fptr_Fdata[1] + C1 + TBits.RotateLeft32(T1, 5) +
    ((A and X7) or (not A and C)) + D;

  X8 := TBits.RotateLeft32(A, 30);
  T3 := Fptr_Fdata[2] + C1 + TBits.RotateLeft32(T2, 5) +
    ((T1 and X8) or (not T1 and X7)) + C;

  X1 := TBits.RotateLeft32(T1, 30);
  T4 := Fptr_Fdata[3] + C1 + TBits.RotateLeft32(T3, 5) +
    ((T2 and X1) or (not T2 and X8)) + X7;

  X2 := TBits.RotateLeft32(T2, 30);
  T5 := Fptr_Fdata[4] + C1 + TBits.RotateLeft32(T4, 5) +
    ((T3 and X2) or (not T3 and X1)) + X8;

  X3 := TBits.RotateLeft32(T3, 30);
  T6 := Fptr_Fdata[5] + C1 + TBits.RotateLeft32(T5, 5) +
    ((T4 and X3) or (not T4 and X2)) + X1;

  X4 := TBits.RotateLeft32(T4, 30);
  T7 := Fptr_Fdata[6] + C1 + TBits.RotateLeft32(T6, 5) +
    ((T5 and X4) or (not T5 and X3)) + X2;

  X5 := TBits.RotateLeft32(T5, 30);
  T8 := Fptr_Fdata[7] + C1 + TBits.RotateLeft32(T7, 5) +
    ((T6 and X5) or (not T6 and X4)) + X3;

  X6 := TBits.RotateLeft32(T6, 30);
  T1 := Fptr_Fdata[8] + C1 + TBits.RotateLeft32(T8, 5) +
    ((T7 and X6) or (not T7 and X5)) + X4;

  X7 := TBits.RotateLeft32(T7, 30);
  T2 := Fptr_Fdata[9] + C1 + TBits.RotateLeft32(T1, 5) +
    ((T8 and X7) or (not T8 and X6)) + X5;

  X8 := TBits.RotateLeft32(T8, 30);
  T3 := Fptr_Fdata[10] + C1 + TBits.RotateLeft32(T2, 5) +
    ((T1 and X8) or (not T1 and X7)) + X6;

  X1 := TBits.RotateLeft32(T1, 30);
  T4 := Fptr_Fdata[11] + C1 + TBits.RotateLeft32(T3, 5) +
    ((T2 and X1) or (not T2 and X8)) + X7;

  X2 := TBits.RotateLeft32(T2, 30);
  T5 := Fptr_Fdata[12] + C1 + TBits.RotateLeft32(T4, 5) +
    ((T3 and X2) or (not T3 and X1)) + X8;

  X3 := TBits.RotateLeft32(T3, 30);
  T6 := Fptr_Fdata[13] + C1 + TBits.RotateLeft32(T5, 5) +
    ((T4 and X3) or (not T4 and X2)) + X1;

  X4 := TBits.RotateLeft32(T4, 30);
  T7 := Fptr_Fdata[14] + C1 + TBits.RotateLeft32(T6, 5) +
    ((T5 and X4) or (not T5 and X3)) + X2;

  X5 := TBits.RotateLeft32(T5, 30);
  T8 := Fptr_Fdata[15] + C1 + TBits.RotateLeft32(T7, 5) +
    ((T6 and X5) or (not T6 and X4)) + X3;

  X6 := TBits.RotateLeft32(T6, 30);
  T1 := Fptr_Fdata[16] + C1 + TBits.RotateLeft32(T8, 5) +
    ((T7 and X6) or (not T7 and X5)) + X4;

  X7 := TBits.RotateLeft32(T7, 30);
  T2 := Fptr_Fdata[17] + C1 + TBits.RotateLeft32(T1, 5) +
    ((T8 and X7) or (not T8 and X6)) + X5;

  X8 := TBits.RotateLeft32(T8, 30);
  T3 := Fptr_Fdata[18] + C1 + TBits.RotateLeft32(T2, 5) +
    ((T1 and X8) or (not T1 and X7)) + X6;

  X1 := TBits.RotateLeft32(T1, 30);
  T4 := Fptr_Fdata[19] + C1 + TBits.RotateLeft32(T3, 5) +
    ((T2 and X1) or (not T2 and X8)) + X7;

  X2 := TBits.RotateLeft32(T2, 30);
  T5 := Fptr_Fdata[20] + C2 + TBits.RotateLeft32(T4, 5) +
    (T3 xor X2 xor X1) + X8;

  X3 := TBits.RotateLeft32(T3, 30);
  T6 := Fptr_Fdata[21] + C2 + TBits.RotateLeft32(T5, 5) +
    (T4 xor X3 xor X2) + X1;

  X4 := TBits.RotateLeft32(T4, 30);
  T7 := Fptr_Fdata[22] + C2 + TBits.RotateLeft32(T6, 5) +
    (T5 xor X4 xor X3) + X2;

  X5 := TBits.RotateLeft32(T5, 30);
  T8 := Fptr_Fdata[23] + C2 + TBits.RotateLeft32(T7, 5) +
    (T6 xor X5 xor X4) + X3;

  X6 := TBits.RotateLeft32(T6, 30);
  T1 := Fptr_Fdata[24] + C2 + TBits.RotateLeft32(T8, 5) +
    (T7 xor X6 xor X5) + X4;

  X7 := TBits.RotateLeft32(T7, 30);
  T2 := Fptr_Fdata[25] + C2 + TBits.RotateLeft32(T1, 5) +
    (T8 xor X7 xor X6) + X5;

  X8 := TBits.RotateLeft32(T8, 30);
  T3 := Fptr_Fdata[26] + C2 + TBits.RotateLeft32(T2, 5) +
    (T1 xor X8 xor X7) + X6;

  X1 := TBits.RotateLeft32(T1, 30);
  T4 := Fptr_Fdata[27] + C2 + TBits.RotateLeft32(T3, 5) +
    (T2 xor X1 xor X8) + X7;

  X2 := TBits.RotateLeft32(T2, 30);
  T5 := Fptr_Fdata[28] + C2 + TBits.RotateLeft32(T4, 5) +
    (T3 xor X2 xor X1) + X8;

  X3 := TBits.RotateLeft32(T3, 30);
  T6 := Fptr_Fdata[29] + C2 + TBits.RotateLeft32(T5, 5) +
    (T4 xor X3 xor X2) + X1;

  X4 := TBits.RotateLeft32(T4, 30);
  T7 := Fptr_Fdata[30] + C2 + TBits.RotateLeft32(T6, 5) +
    (T5 xor X4 xor X3) + X2;

  X5 := TBits.RotateLeft32(T5, 30);
  T8 := Fptr_Fdata[31] + C2 + TBits.RotateLeft32(T7, 5) +
    (T6 xor X5 xor X4) + X3;

  X6 := TBits.RotateLeft32(T6, 30);
  T1 := Fptr_Fdata[32] + C2 + TBits.RotateLeft32(T8, 5) +
    (T7 xor X6 xor X5) + X4;

  X7 := TBits.RotateLeft32(T7, 30);
  T2 := Fptr_Fdata[33] + C2 + TBits.RotateLeft32(T1, 5) +
    (T8 xor X7 xor X6) + X5;

  X8 := TBits.RotateLeft32(T8, 30);
  T3 := Fptr_Fdata[34] + C2 + TBits.RotateLeft32(T2, 5) +
    (T1 xor X8 xor X7) + X6;

  X1 := TBits.RotateLeft32(T1, 30);
  T4 := Fptr_Fdata[35] + C2 + TBits.RotateLeft32(T3, 5) +
    (T2 xor X1 xor X8) + X7;

  X2 := TBits.RotateLeft32(T2, 30);
  T5 := Fptr_Fdata[36] + C2 + TBits.RotateLeft32(T4, 5) +
    (T3 xor X2 xor X1) + X8;

  X3 := TBits.RotateLeft32(T3, 30);
  T6 := Fptr_Fdata[37] + C2 + TBits.RotateLeft32(T5, 5) +
    (T4 xor X3 xor X2) + X1;

  X4 := TBits.RotateLeft32(T4, 30);
  T7 := Fptr_Fdata[38] + C2 + TBits.RotateLeft32(T6, 5) +
    (T5 xor X4 xor X3) + X2;

  X5 := TBits.RotateLeft32(T5, 30);
  T8 := Fptr_Fdata[39] + C2 + TBits.RotateLeft32(T7, 5) +
    (T6 xor X5 xor X4) + X3;

  X6 := TBits.RotateLeft32(T6, 30);
  T1 := Fptr_Fdata[40] + C3 + TBits.RotateLeft32(T8, 5) +
    ((T7 and X6) or (T7 and X5) or (X6 and X5)) + X4;

  X7 := TBits.RotateLeft32(T7, 30);
  T2 := Fptr_Fdata[41] + C3 + TBits.RotateLeft32(T1, 5) +
    ((T8 and X7) or (T8 and X6) or (X7 and X6)) + X5;

  X8 := TBits.RotateLeft32(T8, 30);
  T3 := Fptr_Fdata[42] + C3 + TBits.RotateLeft32(T2, 5) +
    ((T1 and X8) or (T1 and X7) or (X8 and X7)) + X6;

  X1 := TBits.RotateLeft32(T1, 30);
  T4 := Fptr_Fdata[43] + C3 + TBits.RotateLeft32(T3, 5) +
    ((T2 and X1) or (T2 and X8) or (X1 and X8)) + X7;

  X2 := TBits.RotateLeft32(T2, 30);
  T5 := Fptr_Fdata[44] + C3 + TBits.RotateLeft32(T4, 5) +
    ((T3 and X2) or (T3 and X1) or (X2 and X1)) + X8;

  X3 := TBits.RotateLeft32(T3, 30);
  T6 := Fptr_Fdata[45] + C3 + TBits.RotateLeft32(T5, 5) +
    ((T4 and X3) or (T4 and X2) or (X3 and X2)) + X1;

  X4 := TBits.RotateLeft32(T4, 30);
  T7 := Fptr_Fdata[46] + C3 + TBits.RotateLeft32(T6, 5) +
    ((T5 and X4) or (T5 and X3) or (X4 and X3)) + X2;

  X5 := TBits.RotateLeft32(T5, 30);
  T8 := Fptr_Fdata[47] + C3 + TBits.RotateLeft32(T7, 5) +
    ((T6 and X5) or (T6 and X4) or (X5 and X4)) + X3;

  X6 := TBits.RotateLeft32(T6, 30);
  T1 := Fptr_Fdata[48] + C3 + TBits.RotateLeft32(T8, 5) +
    ((T7 and X6) or (T7 and X5) or (X6 and X5)) + X4;

  X7 := TBits.RotateLeft32(T7, 30);
  T2 := Fptr_Fdata[49] + C3 + TBits.RotateLeft32(T1, 5) +
    ((T8 and X7) or (T8 and X6) or (X7 and X6)) + X5;

  X8 := TBits.RotateLeft32(T8, 30);
  T3 := Fptr_Fdata[50] + C3 + TBits.RotateLeft32(T2, 5) +
    ((T1 and X8) or (T1 and X7) or (X8 and X7)) + X6;

  X1 := TBits.RotateLeft32(T1, 30);
  T4 := Fptr_Fdata[51] + C3 + TBits.RotateLeft32(T3, 5) +
    ((T2 and X1) or (T2 and X8) or (X1 and X8)) + X7;

  X2 := TBits.RotateLeft32(T2, 30);
  T5 := Fptr_Fdata[52] + C3 + TBits.RotateLeft32(T4, 5) +
    ((T3 and X2) or (T3 and X1) or (X2 and X1)) + X8;

  X3 := TBits.RotateLeft32(T3, 30);
  T6 := Fptr_Fdata[53] + C3 + TBits.RotateLeft32(T5, 5) +
    ((T4 and X3) or (T4 and X2) or (X3 and X2)) + X1;

  X4 := TBits.RotateLeft32(T4, 30);
  T7 := Fptr_Fdata[54] + C3 + TBits.RotateLeft32(T6, 5) +
    ((T5 and X4) or (T5 and X3) or (X4 and X3)) + X2;

  X5 := TBits.RotateLeft32(T5, 30);
  T8 := Fptr_Fdata[55] + C3 + TBits.RotateLeft32(T7, 5) +
    ((T6 and X5) or (T6 and X4) or (X5 and X4)) + X3;

  X6 := TBits.RotateLeft32(T6, 30);
  T1 := Fptr_Fdata[56] + C3 + TBits.RotateLeft32(T8, 5) +
    ((T7 and X6) or (T7 and X5) or (X6 and X5)) + X4;

  X7 := TBits.RotateLeft32(T7, 30);
  T2 := Fptr_Fdata[57] + C3 + TBits.RotateLeft32(T1, 5) +
    ((T8 and X7) or (T8 and X6) or (X7 and X6)) + X5;

  X8 := TBits.RotateLeft32(T8, 30);
  T3 := Fptr_Fdata[58] + C3 + TBits.RotateLeft32(T2, 5) +
    ((T1 and X8) or (T1 and X7) or (X8 and X7)) + X6;

  X1 := TBits.RotateLeft32(T1, 30);
  T4 := Fptr_Fdata[59] + C3 + TBits.RotateLeft32(T3, 5) +
    ((T2 and X1) or (T2 and X8) or (X1 and X8)) + X7;

  X2 := TBits.RotateLeft32(T2, 30);
  T5 := Fptr_Fdata[60] + C4 + TBits.RotateLeft32(T4, 5) +
    (T3 xor X2 xor X1) + X8;

  X3 := TBits.RotateLeft32(T3, 30);
  T6 := Fptr_Fdata[61] + C4 + TBits.RotateLeft32(T5, 5) +
    (T4 xor X3 xor X2) + X1;

  X4 := TBits.RotateLeft32(T4, 30);
  T7 := Fptr_Fdata[62] + C4 + TBits.RotateLeft32(T6, 5) +
    (T5 xor X4 xor X3) + X2;

  X5 := TBits.RotateLeft32(T5, 30);
  T8 := Fptr_Fdata[63] + C4 + TBits.RotateLeft32(T7, 5) +
    (T6 xor X5 xor X4) + X3;

  X6 := TBits.RotateLeft32(T6, 30);
  T1 := Fptr_Fdata[64] + C4 + TBits.RotateLeft32(T8, 5) +
    (T7 xor X6 xor X5) + X4;

  X7 := TBits.RotateLeft32(T7, 30);
  T2 := Fptr_Fdata[65] + C4 + TBits.RotateLeft32(T1, 5) +
    (T8 xor X7 xor X6) + X5;

  X8 := TBits.RotateLeft32(T8, 30);
  T3 := Fptr_Fdata[66] + C4 + TBits.RotateLeft32(T2, 5) +
    (T1 xor X8 xor X7) + X6;

  X1 := TBits.RotateLeft32(T1, 30);
  T4 := Fptr_Fdata[67] + C4 + TBits.RotateLeft32(T3, 5) +
    (T2 xor X1 xor X8) + X7;

  X2 := TBits.RotateLeft32(T2, 30);
  T5 := Fptr_Fdata[68] + C4 + TBits.RotateLeft32(T4, 5) +
    (T3 xor X2 xor X1) + X8;

  X3 := TBits.RotateLeft32(T3, 30);
  T6 := Fptr_Fdata[69] + C4 + TBits.RotateLeft32(T5, 5) +
    (T4 xor X3 xor X2) + X1;

  X4 := TBits.RotateLeft32(T4, 30);
  T7 := Fptr_Fdata[70] + C4 + TBits.RotateLeft32(T6, 5) +
    (T5 xor X4 xor X3) + X2;

  X5 := TBits.RotateLeft32(T5, 30);
  T8 := Fptr_Fdata[71] + C4 + TBits.RotateLeft32(T7, 5) +
    (T6 xor X5 xor X4) + X3;

  X6 := TBits.RotateLeft32(T6, 30);
  T1 := Fptr_Fdata[72] + C4 + TBits.RotateLeft32(T8, 5) +
    (T7 xor X6 xor X5) + X4;

  X7 := TBits.RotateLeft32(T7, 30);
  T2 := Fptr_Fdata[73] + C4 + TBits.RotateLeft32(T1, 5) +
    (T8 xor X7 xor X6) + X5;

  X8 := TBits.RotateLeft32(T8, 30);
  T3 := Fptr_Fdata[74] + C4 + TBits.RotateLeft32(T2, 5) +
    (T1 xor X8 xor X7) + X6;

  X1 := TBits.RotateLeft32(T1, 30);
  T4 := Fptr_Fdata[75] + C4 + TBits.RotateLeft32(T3, 5) +
    (T2 xor X1 xor X8) + X7;

  X2 := TBits.RotateLeft32(T2, 30);
  T5 := Fptr_Fdata[76] + C4 + TBits.RotateLeft32(T4, 5) +
    (T3 xor X2 xor X1) + X8;

  X3 := TBits.RotateLeft32(T3, 30);
  T6 := Fptr_Fdata[77] + C4 + TBits.RotateLeft32(T5, 5) +
    (T4 xor X3 xor X2) + X1;

  X4 := TBits.RotateLeft32(T4, 30);
  T7 := Fptr_Fdata[78] + C4 + TBits.RotateLeft32(T6, 5) +
    (T5 xor X4 xor X3) + X2;

  X5 := TBits.RotateLeft32(T5, 30);

  Fptr_Fm_state[0] := Fptr_Fm_state[0] +
    (Fptr_Fdata[79] + C4 + TBits.RotateLeft32(T7, 5) + (T6 xor X5 xor X4) + X3);
  Fptr_Fm_state[1] := Fptr_Fm_state[1] + T7;
  Fptr_Fm_state[2] := Fptr_Fm_state[2] + TBits.RotateLeft32(T6, 30);
  Fptr_Fm_state[3] := Fptr_Fm_state[3] + X5;
  Fptr_Fm_state[4] := Fptr_Fm_state[4] + X4;

end;

end.
