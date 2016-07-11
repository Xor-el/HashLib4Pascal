unit uPanama;

{$I ..\..\Include\HashLib.inc}

interface

uses
  uHashLibTypes,
  uBits,
  uArrayExtensions,
  uConverters,
  uIHashInfo,
  uHashCryptoNotBuildIn;

type
  TPanama = class sealed(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

  strict private

    Fm_state: THashLibUInt32Array;

    Fm_stages: THashLibMatrixUInt32Array;

    Fm_tap: Int32;

    procedure GPT(theta: THashLibUInt32Array);

  const

    COLUMNS = Int32(17);

  strict protected
    procedure Finish(); override;
    procedure TransformBlock(a_data: THashLibByteArray;
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
  System.SetLength(Fm_stages, 32);
  i := 0;
  while i <= System.High(Fm_stages) do
  begin
    System.SetLength(Fm_stages[i], 8);
    System.Inc(i);
  end;
end;

procedure TPanama.Finish;
var
  padding_size, i, tap4, tap16, tap25: Int32;
  pad: THashLibByteArray;
  theta: THashLibUInt32Array;
begin

  padding_size := BlockSize - ((Int32(Fm_processed_bytes)) mod BlockSize);

  System.SetLength(pad, padding_size);

  pad[0] := $01;
  TransformBytes(pad, 0, padding_size);

  System.SetLength(theta, COLUMNS);

  i := 0;
  while i < 32 do
  begin
    tap4 := (Fm_tap + 4) and $1F;
    tap16 := (Fm_tap + 16) and $1F;

    Fm_tap := (Fm_tap - 1) and $1F;
    tap25 := (Fm_tap + 25) and $1F;

    GPT(theta);

    Fm_stages[tap25, 0] := Fm_stages[tap25, 0] xor Fm_stages[Fm_tap, 2];
    Fm_stages[tap25, 1] := Fm_stages[tap25, 1] xor Fm_stages[Fm_tap, 3];
    Fm_stages[tap25, 2] := Fm_stages[tap25, 2] xor Fm_stages[Fm_tap, 4];
    Fm_stages[tap25, 3] := Fm_stages[tap25, 3] xor Fm_stages[Fm_tap, 5];
    Fm_stages[tap25, 4] := Fm_stages[tap25, 4] xor Fm_stages[Fm_tap, 6];
    Fm_stages[tap25, 5] := Fm_stages[tap25, 5] xor Fm_stages[Fm_tap, 7];
    Fm_stages[tap25, 6] := Fm_stages[tap25, 6] xor Fm_stages[Fm_tap, 0];
    Fm_stages[tap25, 7] := Fm_stages[tap25, 7] xor Fm_stages[Fm_tap, 1];
    Fm_stages[Fm_tap, 0] := Fm_stages[Fm_tap, 0] xor Fm_state[1];
    Fm_stages[Fm_tap, 1] := Fm_stages[Fm_tap, 1] xor Fm_state[2];
    Fm_stages[Fm_tap, 2] := Fm_stages[Fm_tap, 2] xor Fm_state[3];
    Fm_stages[Fm_tap, 3] := Fm_stages[Fm_tap, 3] xor Fm_state[4];
    Fm_stages[Fm_tap, 4] := Fm_stages[Fm_tap, 4] xor Fm_state[5];
    Fm_stages[Fm_tap, 5] := Fm_stages[Fm_tap, 5] xor Fm_state[6];
    Fm_stages[Fm_tap, 6] := Fm_stages[Fm_tap, 6] xor Fm_state[7];
    Fm_stages[Fm_tap, 7] := Fm_stages[Fm_tap, 7] xor Fm_state[8];

    Fm_state[0] := theta[0] xor $01;
    Fm_state[1] := theta[1] xor Fm_stages[tap4, 0];
    Fm_state[2] := theta[2] xor Fm_stages[tap4, 1];
    Fm_state[3] := theta[3] xor Fm_stages[tap4, 2];
    Fm_state[4] := theta[4] xor Fm_stages[tap4, 3];
    Fm_state[5] := theta[5] xor Fm_stages[tap4, 4];
    Fm_state[6] := theta[6] xor Fm_stages[tap4, 5];
    Fm_state[7] := theta[7] xor Fm_stages[tap4, 6];
    Fm_state[8] := theta[8] xor Fm_stages[tap4, 7];
    Fm_state[9] := theta[9] xor Fm_stages[tap16, 0];
    Fm_state[10] := theta[10] xor Fm_stages[tap16, 1];
    Fm_state[11] := theta[11] xor Fm_stages[tap16, 2];
    Fm_state[12] := theta[12] xor Fm_stages[tap16, 3];
    Fm_state[13] := theta[13] xor Fm_stages[tap16, 4];
    Fm_state[14] := theta[14] xor Fm_stages[tap16, 5];
    Fm_state[15] := theta[15] xor Fm_stages[tap16, 6];
    Fm_state[16] := theta[16] xor Fm_stages[tap16, 7];

    System.Inc(i);
  end;

end;

function TPanama.GetResult: THashLibByteArray;
begin
  result := TConverters.ConvertUInt32ToBytes(Fm_state, 9, 8);
end;

procedure TPanama.GPT(theta: THashLibUInt32Array);
var
  gamma, pi: THashLibUInt32Array;
begin
  System.SetLength(gamma, COLUMNS);
  System.SetLength(pi, COLUMNS);

  gamma[0] := Fm_state[0] xor (Fm_state[1] or not Fm_state[2]);
  gamma[1] := Fm_state[1] xor (Fm_state[2] or not Fm_state[3]);
  gamma[2] := Fm_state[2] xor (Fm_state[3] or not Fm_state[4]);
  gamma[3] := Fm_state[3] xor (Fm_state[4] or not Fm_state[5]);
  gamma[4] := Fm_state[4] xor (Fm_state[5] or not Fm_state[6]);
  gamma[5] := Fm_state[5] xor (Fm_state[6] or not Fm_state[7]);
  gamma[6] := Fm_state[6] xor (Fm_state[7] or not Fm_state[8]);
  gamma[7] := Fm_state[7] xor (Fm_state[8] or not Fm_state[9]);
  gamma[8] := Fm_state[8] xor (Fm_state[9] or not Fm_state[10]);
  gamma[9] := Fm_state[9] xor (Fm_state[10] or not Fm_state[11]);
  gamma[10] := Fm_state[10] xor (Fm_state[11] or not Fm_state[12]);
  gamma[11] := Fm_state[11] xor (Fm_state[12] or not Fm_state[13]);
  gamma[12] := Fm_state[12] xor (Fm_state[13] or not Fm_state[14]);
  gamma[13] := Fm_state[13] xor (Fm_state[14] or not Fm_state[15]);
  gamma[14] := Fm_state[14] xor (Fm_state[15] or not Fm_state[16]);
  gamma[15] := Fm_state[15] xor (Fm_state[16] or not Fm_state[0]);
  gamma[16] := Fm_state[16] xor (Fm_state[0] or not Fm_state[1]);

  pi[0] := gamma[0];
  pi[1] := TBits.RotateLeft32(gamma[7], 1);
  pi[2] := TBits.RotateLeft32(gamma[14], 3);
  pi[3] := TBits.RotateLeft32(gamma[4], 6);
  pi[4] := TBits.RotateLeft32(gamma[11], 10);
  pi[5] := TBits.RotateLeft32(gamma[1], 15);
  pi[6] := TBits.RotateLeft32(gamma[8], 21);
  pi[7] := TBits.RotateLeft32(gamma[15], 28);
  pi[8] := TBits.RotateLeft32(gamma[5], 4);
  pi[9] := TBits.RotateLeft32(gamma[12], 13);
  pi[10] := TBits.RotateLeft32(gamma[2], 23);
  pi[11] := TBits.RotateLeft32(gamma[9], 2);
  pi[12] := TBits.RotateLeft32(gamma[16], 14);
  pi[13] := TBits.RotateLeft32(gamma[6], 27);
  pi[14] := TBits.RotateLeft32(gamma[13], 9);
  pi[15] := TBits.RotateLeft32(gamma[3], 24);
  pi[16] := TBits.RotateLeft32(gamma[10], 8);

  theta[0] := pi[0] xor pi[1] xor pi[4];
  theta[1] := pi[1] xor pi[2] xor pi[5];
  theta[2] := pi[2] xor pi[3] xor pi[6];
  theta[3] := pi[3] xor pi[4] xor pi[7];
  theta[4] := pi[4] xor pi[5] xor pi[8];
  theta[5] := pi[5] xor pi[6] xor pi[9];
  theta[6] := pi[6] xor pi[7] xor pi[10];
  theta[7] := pi[7] xor pi[8] xor pi[11];
  theta[8] := pi[8] xor pi[9] xor pi[12];
  theta[9] := pi[9] xor pi[10] xor pi[13];
  theta[10] := pi[10] xor pi[11] xor pi[14];
  theta[11] := pi[11] xor pi[12] xor pi[15];
  theta[12] := pi[12] xor pi[13] xor pi[16];
  theta[13] := pi[13] xor pi[14] xor pi[0];
  theta[14] := pi[14] xor pi[15] xor pi[1];
  theta[15] := pi[15] xor pi[16] xor pi[2];
  theta[16] := pi[16] xor pi[0] xor pi[3];

end;

procedure TPanama.Initialize;
begin
  THashLibArrayHelper<UInt32>.Clear(THashLibGenericArray<UInt32>(Fm_state),
    UInt32(0));
  THashLibArrayHelper<UInt32>.Clear(THashLibMatrixGenericArray<UInt32>
    (Fm_stages), UInt32(0));

  Inherited Initialize();

end;

procedure TPanama.TransformBlock(a_data: THashLibByteArray; a_index: Int32);
var
  work_buffer, theta: THashLibUInt32Array;
  tap16, tap25: Int32;
begin

  work_buffer := TConverters.ConvertBytesToUInt32(a_data, a_index, BlockSize);
  System.SetLength(theta, COLUMNS);

  tap16 := (Fm_tap + 16) and $1F;

  Fm_tap := (Fm_tap - 1) and $1F;
  tap25 := (Fm_tap + 25) and $1F;

  GPT(theta);

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

  Fm_state[0] := theta[0] xor $01;
  Fm_state[1] := theta[1] xor work_buffer[0];
  Fm_state[2] := theta[2] xor work_buffer[1];
  Fm_state[3] := theta[3] xor work_buffer[2];
  Fm_state[4] := theta[4] xor work_buffer[3];
  Fm_state[5] := theta[5] xor work_buffer[4];
  Fm_state[6] := theta[6] xor work_buffer[5];
  Fm_state[7] := theta[7] xor work_buffer[6];
  Fm_state[8] := theta[8] xor work_buffer[7];
  Fm_state[9] := theta[9] xor Fm_stages[tap16, 0];
  Fm_state[10] := theta[10] xor Fm_stages[tap16, 1];
  Fm_state[11] := theta[11] xor Fm_stages[tap16, 2];
  Fm_state[12] := theta[12] xor Fm_stages[tap16, 3];
  Fm_state[13] := theta[13] xor Fm_stages[tap16, 4];
  Fm_state[14] := theta[14] xor Fm_stages[tap16, 5];
  Fm_state[15] := theta[15] xor Fm_stages[tap16, 6];
  Fm_state[16] := theta[16] xor Fm_stages[tap16, 7];

end;

end.
