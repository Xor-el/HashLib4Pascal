unit uSHA2_224;

{$I ..\Include\HashLib.inc}

interface

uses
  uHashLibTypes,
  uSHA2_256Base,
  uConverters;

type
  TSHA2_224 = class sealed(TSHA2_256Base)

  strict protected
    function GetResult(): THashLibByteArray; override;

  public
    constructor Create();
    procedure Initialize(); override;

  end;

implementation

{ TSHA2_224 }

constructor TSHA2_224.Create;
begin
  Inherited Create(28);
end;

function TSHA2_224.GetResult: THashLibByteArray;
begin
  result := TConverters.ConvertUInt32ToBytesSwapOrder(Fm_state, 0, 7);
end;

procedure TSHA2_224.Initialize;
begin
  Fm_state[0] := $C1059ED8;
  Fm_state[1] := $367CD507;
  Fm_state[2] := $3070DD17;
  Fm_state[3] := $F70E5939;
  Fm_state[4] := $FFC00B31;
  Fm_state[5] := $68581511;
  Fm_state[6] := $64F98FA7;
  Fm_state[7] := $BEFA4FA4;

  Inherited Initialize();

end;

end.
