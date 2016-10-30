unit HlpPanama;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpBits,
  HlpConverters,
  HlpIHashInfo,
  HlpHashCryptoNotBuildIn;

type
  TPanama = class sealed(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

  strict private

    Fm_state, Ftheta, Fgamma, Fpi: THashLibUInt32Array;

    Fm_stages: THashLibMatrixUInt32Array;

    Fptr_Fm_state, Fptr_Ftheta, Fptr_Fgamma, Fptr_Fpi: PCardinal;

    Fm_tap: Int32;

    procedure GPT(a_theta: PCardinal);

  const

    COLUMNS = Int32(17);

  strict protected
    procedure Finish(); override;
    procedure TransformBlock(a_data: PByte; a_data_length: Int32;
      a_index: Int32); override;
    function GetResult(): THashLibByteArray; override;

  public
    constructor Create();
    procedure Initialize(); override;

  end;

implementation

{ TPanama }

constructor TPanama.Create;
var
  i: Int32;
begin
  Inherited Create(32, 32);
  System.SetLength(Fm_state, COLUMNS);

  Fptr_Fm_state := PCardinal(Fm_state);

  System.SetLength(Fm_stages, 32);
  i := 0;
  while i <= System.High(Fm_stages) do
  begin
    System.SetLength(Fm_stages[i], 8);
    System.Inc(i);
  end;

  System.SetLength(Ftheta, COLUMNS);

  Fptr_Ftheta := PCardinal(Ftheta);

  System.SetLength(Fgamma, COLUMNS);

  Fptr_Fgamma := PCardinal(Fgamma);

  System.SetLength(Fpi, COLUMNS);

  Fptr_Fpi := PCardinal(Fpi);
end;

procedure TPanama.Finish;
var
  padding_size, i, tap4, tap16, tap25: Int32;
  pad: THashLibByteArray;
  theta: THashLibUInt32Array;
  ptr_theta: PCardinal;
begin

  padding_size := 32 - ((Int32(Fm_processed_bytes)) and 31);

  System.SetLength(pad, padding_size);

  pad[0] := $01;
  TransformBytes(pad, 0, padding_size);

  System.SetLength(theta, COLUMNS);

  ptr_theta := PCardinal(theta);

  i := 0;
  while i < 32 do
  begin
    tap4 := (Fm_tap + 4) and $1F;
    tap16 := (Fm_tap + 16) and $1F;

    Fm_tap := (Fm_tap - 1) and $1F;
    tap25 := (Fm_tap + 25) and $1F;

    GPT(ptr_theta);

    Fm_stages[tap25, 0] := Fm_stages[tap25, 0] xor Fm_stages[Fm_tap, 2];
    Fm_stages[tap25, 1] := Fm_stages[tap25, 1] xor Fm_stages[Fm_tap, 3];
    Fm_stages[tap25, 2] := Fm_stages[tap25, 2] xor Fm_stages[Fm_tap, 4];
    Fm_stages[tap25, 3] := Fm_stages[tap25, 3] xor Fm_stages[Fm_tap, 5];
    Fm_stages[tap25, 4] := Fm_stages[tap25, 4] xor Fm_stages[Fm_tap, 6];
    Fm_stages[tap25, 5] := Fm_stages[tap25, 5] xor Fm_stages[Fm_tap, 7];
    Fm_stages[tap25, 6] := Fm_stages[tap25, 6] xor Fm_stages[Fm_tap, 0];
    Fm_stages[tap25, 7] := Fm_stages[tap25, 7] xor Fm_stages[Fm_tap, 1];
    Fm_stages[Fm_tap, 0] := Fm_stages[Fm_tap, 0] xor Fptr_Fm_state[1];
    Fm_stages[Fm_tap, 1] := Fm_stages[Fm_tap, 1] xor Fptr_Fm_state[2];
    Fm_stages[Fm_tap, 2] := Fm_stages[Fm_tap, 2] xor Fptr_Fm_state[3];
    Fm_stages[Fm_tap, 3] := Fm_stages[Fm_tap, 3] xor Fptr_Fm_state[4];
    Fm_stages[Fm_tap, 4] := Fm_stages[Fm_tap, 4] xor Fptr_Fm_state[5];
    Fm_stages[Fm_tap, 5] := Fm_stages[Fm_tap, 5] xor Fptr_Fm_state[6];
    Fm_stages[Fm_tap, 6] := Fm_stages[Fm_tap, 6] xor Fptr_Fm_state[7];
    Fm_stages[Fm_tap, 7] := Fm_stages[Fm_tap, 7] xor Fptr_Fm_state[8];

    Fptr_Fm_state[0] := ptr_theta[0] xor $01;
    Fptr_Fm_state[1] := ptr_theta[1] xor Fm_stages[tap4, 0];
    Fptr_Fm_state[2] := ptr_theta[2] xor Fm_stages[tap4, 1];
    Fptr_Fm_state[3] := ptr_theta[3] xor Fm_stages[tap4, 2];
    Fptr_Fm_state[4] := ptr_theta[4] xor Fm_stages[tap4, 3];
    Fptr_Fm_state[5] := ptr_theta[5] xor Fm_stages[tap4, 4];
    Fptr_Fm_state[6] := ptr_theta[6] xor Fm_stages[tap4, 5];
    Fptr_Fm_state[7] := ptr_theta[7] xor Fm_stages[tap4, 6];
    Fptr_Fm_state[8] := ptr_theta[8] xor Fm_stages[tap4, 7];
    Fptr_Fm_state[9] := ptr_theta[9] xor Fm_stages[tap16, 0];
    Fptr_Fm_state[10] := ptr_theta[10] xor Fm_stages[tap16, 1];
    Fptr_Fm_state[11] := ptr_theta[11] xor Fm_stages[tap16, 2];
    Fptr_Fm_state[12] := ptr_theta[12] xor Fm_stages[tap16, 3];
    Fptr_Fm_state[13] := ptr_theta[13] xor Fm_stages[tap16, 4];
    Fptr_Fm_state[14] := ptr_theta[14] xor Fm_stages[tap16, 5];
    Fptr_Fm_state[15] := ptr_theta[15] xor Fm_stages[tap16, 6];
    Fptr_Fm_state[16] := ptr_theta[16] xor Fm_stages[tap16, 7];

    System.Inc(i);
  end;

end;

function TPanama.GetResult: THashLibByteArray;
begin
  result := TConverters.ConvertUInt32ToBytes(Fm_state, 9, 8);
end;

procedure TPanama.GPT(a_theta: PCardinal);
begin

  Fptr_Fgamma[0] := Fptr_Fm_state[0] xor (Fptr_Fm_state[1] or
    not Fptr_Fm_state[2]);
  Fptr_Fgamma[1] := Fptr_Fm_state[1] xor (Fptr_Fm_state[2] or
    not Fptr_Fm_state[3]);
  Fptr_Fgamma[2] := Fptr_Fm_state[2] xor (Fptr_Fm_state[3] or
    not Fptr_Fm_state[4]);
  Fptr_Fgamma[3] := Fptr_Fm_state[3] xor (Fptr_Fm_state[4] or
    not Fptr_Fm_state[5]);
  Fptr_Fgamma[4] := Fptr_Fm_state[4] xor (Fptr_Fm_state[5] or
    not Fptr_Fm_state[6]);
  Fptr_Fgamma[5] := Fptr_Fm_state[5] xor (Fptr_Fm_state[6] or
    not Fptr_Fm_state[7]);
  Fptr_Fgamma[6] := Fptr_Fm_state[6] xor (Fptr_Fm_state[7] or
    not Fptr_Fm_state[8]);
  Fptr_Fgamma[7] := Fptr_Fm_state[7] xor (Fptr_Fm_state[8] or
    not Fptr_Fm_state[9]);
  Fptr_Fgamma[8] := Fptr_Fm_state[8] xor (Fptr_Fm_state[9] or
    not Fptr_Fm_state[10]);
  Fptr_Fgamma[9] := Fptr_Fm_state[9] xor (Fptr_Fm_state[10] or
    not Fptr_Fm_state[11]);
  Fptr_Fgamma[10] := Fptr_Fm_state[10] xor (Fptr_Fm_state[11] or
    not Fptr_Fm_state[12]);
  Fptr_Fgamma[11] := Fptr_Fm_state[11] xor (Fptr_Fm_state[12] or
    not Fptr_Fm_state[13]);
  Fptr_Fgamma[12] := Fptr_Fm_state[12] xor (Fptr_Fm_state[13] or
    not Fptr_Fm_state[14]);
  Fptr_Fgamma[13] := Fptr_Fm_state[13] xor (Fptr_Fm_state[14] or
    not Fptr_Fm_state[15]);
  Fptr_Fgamma[14] := Fptr_Fm_state[14] xor (Fptr_Fm_state[15] or
    not Fptr_Fm_state[16]);
  Fptr_Fgamma[15] := Fptr_Fm_state[15] xor (Fptr_Fm_state[16] or
    not Fptr_Fm_state[0]);
  Fptr_Fgamma[16] := Fptr_Fm_state[16] xor (Fptr_Fm_state[0] or
    not Fptr_Fm_state[1]);

  Fptr_Fpi[0] := Fptr_Fgamma[0];
  Fptr_Fpi[1] := TBits.RotateLeft32(Fptr_Fgamma[7], 1);
  Fptr_Fpi[2] := TBits.RotateLeft32(Fptr_Fgamma[14], 3);
  Fptr_Fpi[3] := TBits.RotateLeft32(Fptr_Fgamma[4], 6);
  Fptr_Fpi[4] := TBits.RotateLeft32(Fptr_Fgamma[11], 10);
  Fptr_Fpi[5] := TBits.RotateLeft32(Fptr_Fgamma[1], 15);
  Fptr_Fpi[6] := TBits.RotateLeft32(Fptr_Fgamma[8], 21);
  Fptr_Fpi[7] := TBits.RotateLeft32(Fptr_Fgamma[15], 28);
  Fptr_Fpi[8] := TBits.RotateLeft32(Fptr_Fgamma[5], 4);
  Fptr_Fpi[9] := TBits.RotateLeft32(Fptr_Fgamma[12], 13);
  Fptr_Fpi[10] := TBits.RotateLeft32(Fptr_Fgamma[2], 23);
  Fptr_Fpi[11] := TBits.RotateLeft32(Fptr_Fgamma[9], 2);
  Fptr_Fpi[12] := TBits.RotateLeft32(Fptr_Fgamma[16], 14);
  Fptr_Fpi[13] := TBits.RotateLeft32(Fptr_Fgamma[6], 27);
  Fptr_Fpi[14] := TBits.RotateLeft32(Fptr_Fgamma[13], 9);
  Fptr_Fpi[15] := TBits.RotateLeft32(Fptr_Fgamma[3], 24);
  Fptr_Fpi[16] := TBits.RotateLeft32(Fptr_Fgamma[10], 8);

  a_theta[0] := Fptr_Fpi[0] xor Fptr_Fpi[1] xor Fptr_Fpi[4];
  a_theta[1] := Fptr_Fpi[1] xor Fptr_Fpi[2] xor Fptr_Fpi[5];
  a_theta[2] := Fptr_Fpi[2] xor Fptr_Fpi[3] xor Fptr_Fpi[6];
  a_theta[3] := Fptr_Fpi[3] xor Fptr_Fpi[4] xor Fptr_Fpi[7];
  a_theta[4] := Fptr_Fpi[4] xor Fptr_Fpi[5] xor Fptr_Fpi[8];
  a_theta[5] := Fptr_Fpi[5] xor Fptr_Fpi[6] xor Fptr_Fpi[9];
  a_theta[6] := Fptr_Fpi[6] xor Fptr_Fpi[7] xor Fptr_Fpi[10];
  a_theta[7] := Fptr_Fpi[7] xor Fptr_Fpi[8] xor Fptr_Fpi[11];
  a_theta[8] := Fptr_Fpi[8] xor Fptr_Fpi[9] xor Fptr_Fpi[12];
  a_theta[9] := Fptr_Fpi[9] xor Fptr_Fpi[10] xor Fptr_Fpi[13];
  a_theta[10] := Fptr_Fpi[10] xor Fptr_Fpi[11] xor Fptr_Fpi[14];
  a_theta[11] := Fptr_Fpi[11] xor Fptr_Fpi[12] xor Fptr_Fpi[15];
  a_theta[12] := Fptr_Fpi[12] xor Fptr_Fpi[13] xor Fptr_Fpi[16];
  a_theta[13] := Fptr_Fpi[13] xor Fptr_Fpi[14] xor Fptr_Fpi[0];
  a_theta[14] := Fptr_Fpi[14] xor Fptr_Fpi[15] xor Fptr_Fpi[1];
  a_theta[15] := Fptr_Fpi[15] xor Fptr_Fpi[16] xor Fptr_Fpi[2];
  a_theta[16] := Fptr_Fpi[16] xor Fptr_Fpi[0] xor Fptr_Fpi[3];

end;

procedure TPanama.Initialize;
var
  i: Int32;
begin
  System.FillChar(Fm_state[0], System.Length(Fm_state) * System.SizeOf(UInt32),
    UInt32(0));

  for i := System.Low(Fm_stages) to System.High(Fm_stages) do
  begin
    System.FillChar(Fm_stages[i, 0], System.Length(Fm_stages[i]) *
      System.SizeOf(UInt32), UInt32(0));

  end;

  Inherited Initialize();

end;

procedure TPanama.TransformBlock(a_data: PByte; a_data_length: Int32;
  a_index: Int32);
var
  work_buffer: THashLibUInt32Array;
  tap16, tap25: Int32;
begin

  work_buffer := TConverters.ConvertBytesToUInt32(a_data, a_data_length,
    a_index, 32);

  tap16 := (Fm_tap + 16) and $1F;

  Fm_tap := (Fm_tap - 1) and $1F;
  tap25 := (Fm_tap + 25) and $1F;

  GPT(Fptr_Ftheta);

  Fm_stages[tap25, 0] := Fm_stages[tap25, 0] xor Fm_stages[Fm_tap, 2];
  Fm_stages[tap25, 1] := Fm_stages[tap25, 1] xor Fm_stages[Fm_tap, 3];
  Fm_stages[tap25, 2] := Fm_stages[tap25, 2] xor Fm_stages[Fm_tap, 4];
  Fm_stages[tap25, 3] := Fm_stages[tap25, 3] xor Fm_stages[Fm_tap, 5];
  Fm_stages[tap25, 4] := Fm_stages[tap25, 4] xor Fm_stages[Fm_tap, 6];
  Fm_stages[tap25, 5] := Fm_stages[tap25, 5] xor Fm_stages[Fm_tap, 7];
  Fm_stages[tap25, 6] := Fm_stages[tap25, 6] xor Fm_stages[Fm_tap, 0];
  Fm_stages[tap25, 7] := Fm_stages[tap25, 7] xor Fm_stages[Fm_tap, 1];
  Fm_stages[Fm_tap, 0] := Fm_stages[Fm_tap, 0] xor work_buffer[0];
  Fm_stages[Fm_tap, 1] := Fm_stages[Fm_tap, 1] xor work_buffer[1];
  Fm_stages[Fm_tap, 2] := Fm_stages[Fm_tap, 2] xor work_buffer[2];
  Fm_stages[Fm_tap, 3] := Fm_stages[Fm_tap, 3] xor work_buffer[3];
  Fm_stages[Fm_tap, 4] := Fm_stages[Fm_tap, 4] xor work_buffer[4];
  Fm_stages[Fm_tap, 5] := Fm_stages[Fm_tap, 5] xor work_buffer[5];
  Fm_stages[Fm_tap, 6] := Fm_stages[Fm_tap, 6] xor work_buffer[6];
  Fm_stages[Fm_tap, 7] := Fm_stages[Fm_tap, 7] xor work_buffer[7];

  Fptr_Fm_state[0] := Fptr_Ftheta[0] xor $01;
  Fptr_Fm_state[1] := Fptr_Ftheta[1] xor work_buffer[0];
  Fptr_Fm_state[2] := Fptr_Ftheta[2] xor work_buffer[1];
  Fptr_Fm_state[3] := Fptr_Ftheta[3] xor work_buffer[2];
  Fptr_Fm_state[4] := Fptr_Ftheta[4] xor work_buffer[3];
  Fptr_Fm_state[5] := Fptr_Ftheta[5] xor work_buffer[4];
  Fptr_Fm_state[6] := Fptr_Ftheta[6] xor work_buffer[5];
  Fptr_Fm_state[7] := Fptr_Ftheta[7] xor work_buffer[6];
  Fptr_Fm_state[8] := Fptr_Ftheta[8] xor work_buffer[7];
  Fptr_Fm_state[9] := Fptr_Ftheta[9] xor Fm_stages[tap16, 0];
  Fptr_Fm_state[10] := Fptr_Ftheta[10] xor Fm_stages[tap16, 1];
  Fptr_Fm_state[11] := Fptr_Ftheta[11] xor Fm_stages[tap16, 2];
  Fptr_Fm_state[12] := Fptr_Ftheta[12] xor Fm_stages[tap16, 3];
  Fptr_Fm_state[13] := Fptr_Ftheta[13] xor Fm_stages[tap16, 4];
  Fptr_Fm_state[14] := Fptr_Ftheta[14] xor Fm_stages[tap16, 5];
  Fptr_Fm_state[15] := Fptr_Ftheta[15] xor Fm_stages[tap16, 6];
  Fptr_Fm_state[16] := Fptr_Ftheta[16] xor Fm_stages[tap16, 7];

end;

end.
