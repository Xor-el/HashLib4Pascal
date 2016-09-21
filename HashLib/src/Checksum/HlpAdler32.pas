unit HlpAdler32;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
{$IFDEF DELPHI}
  HlpBits,
{$ENDIF DELPHI}
  HlpConverters,
  HlpHashCryptoNotBuildIn,
  HlpIHashInfo;

type
  TAdler32 = class sealed(TBlockHash, IChecksum, IHash32, ITransformBlock)

  strict private

    Fm_a, Fm_b, Fm_res: UInt32;

  const
    MOD_ADLER = UInt32(65521);

  strict protected
    procedure TransformBlock(a_data: THashLibByteArray;
      a_index: Int32); override;
    procedure Finish(); override;
    function GetResult(): THashLibByteArray; override;

  public
    constructor Create();
    procedure Initialize(); override;

  end;

implementation

{ TAdler32 }

constructor TAdler32.Create;
begin
  Inherited Create(4, 1);

end;

procedure TAdler32.Initialize;
begin
  Inherited Initialize();
  Fm_a := 1;
  Fm_b := 0;

end;

procedure TAdler32.TransformBlock(a_data: THashLibByteArray; a_index: Int32);

begin
  Fm_a := (Fm_a + a_data[a_index]) mod MOD_ADLER;
  Fm_b := (Fm_b + Fm_a) mod MOD_ADLER;
end;

procedure TAdler32.Finish;
begin
  Fm_res := UInt32((Fm_b shl 16) or Fm_a);
end;

function TAdler32.GetResult: THashLibByteArray;
begin
{$IFDEF FPC}
  Fm_res := BEtoN(Fm_res);
{$ENDIF FPC}
{$IFDEF DELPHI}
  // since Delphi compiles to just Little Endian CPU'S, we can blindly assume
  // Little Endian and Swap.
  Fm_res := TBits.ReverseBytesUInt32(Fm_res);
{$ENDIF DELPHI}
  result := TConverters.ConvertUInt32ToBytes(Fm_res);
end;

end.
