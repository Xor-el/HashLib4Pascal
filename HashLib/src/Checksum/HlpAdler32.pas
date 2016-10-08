unit HlpAdler32;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpIHashInfo,
  HlpHash,
  HlpHashResult,
  HlpIHashResult;

type
  TAdler32 = class sealed(THash, IChecksum, IBlockHash, IHash32,
    ITransformBlock)

  strict private

    Fm_a, Fm_b: UInt32;

  const
    MOD_ADLER = UInt32(65521);

  public
    constructor Create();
    procedure Initialize(); override;
    procedure TransformBytes(a_data: THashLibByteArray;
      a_index, a_length: Int32); override;
    function TransformFinal: IHashResult; override;

  end;

implementation

{ TAdler32 }

constructor TAdler32.Create;
begin
  Inherited Create(4, 1);

end;

procedure TAdler32.Initialize;
begin
  Fm_a := 1;
  Fm_b := 0;

end;

procedure TAdler32.TransformBytes(a_data: THashLibByteArray;
  a_index, a_length: Int32);
var
  i: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(a_index >= 0);
  System.Assert(a_length >= 0);
  System.Assert(a_index + a_length <= System.Length(a_data));
{$ENDIF DEBUG}
  i := a_index;
  while a_length > 0 do
  begin
    Fm_a := (Fm_a + a_data[i]) mod MOD_ADLER;
    Fm_b := (Fm_b + Fm_a) mod MOD_ADLER;
    System.Inc(i);
    System.Dec(a_length);
  end;
end;

function TAdler32.TransformFinal: IHashResult;
begin
  result := THashResult.Create(UInt32((Fm_b shl 16) or Fm_a));
  Initialize();
end;

end.
