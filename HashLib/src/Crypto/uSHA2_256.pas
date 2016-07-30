unit uSHA2_256;

{$I ..\Include\HashLib.inc}

interface

uses
  uHashLibTypes,
  uSHA2_256Base,
  uConverters;

type
  TSHA2_256 = class sealed(TSHA2_256Base)

  strict protected
    function GetResult(): THashLibByteArray; override;

  public
    constructor Create();
    procedure Initialize(); override;

  end;

implementation

{ TSHA2_256 }

constructor TSHA2_256.Create;
begin
  Inherited Create(32);
end;

function TSHA2_256.GetResult: THashLibByteArray;
begin
  result := TConverters.ConvertUInt32ToBytesSwapOrder(Fm_state);
end;

procedure TSHA2_256.Initialize;
begin
  Fm_state[0] := $6A09E667;
  Fm_state[1] := $BB67AE85;
  Fm_state[2] := $3C6EF372;
  Fm_state[3] := $A54FF53A;
  Fm_state[4] := $510E527F;
  Fm_state[5] := $9B05688C;
  Fm_state[6] := $1F83D9AB;
  Fm_state[7] := $5BE0CD19;

  Inherited Initialize();

end;

end.
