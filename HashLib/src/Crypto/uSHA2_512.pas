unit uSHA2_512;

{$I ..\Include\HashLib.inc}

interface

uses
  uHashLibTypes,
  uSHA2_512Base,
  uConverters;

type
  TSHA2_512 = class sealed(TSHA2_512Base)

  strict protected
    function GetResult(): THashLibByteArray; override;

  public
    constructor Create();
    procedure Initialize(); override;

  end;

implementation

{ TSHA2_512 }

constructor TSHA2_512.Create;
begin
  Inherited Create(64);
end;

function TSHA2_512.GetResult: THashLibByteArray;
begin
  result := TConverters.ConvertUInt64ToBytesSwapOrder(Fm_state);
end;

procedure TSHA2_512.Initialize;
begin
{$WARNINGS OFF}
{$R-}
  Fm_state[0] := $6A09E667F3BCC908;
  Fm_state[1] := $BB67AE8584CAA73B;
  Fm_state[2] := $3C6EF372FE94F82B;
  Fm_state[3] := $A54FF53A5F1D36F1;
  Fm_state[4] := $510E527FADE682D1;
  Fm_state[5] := $9B05688C2B3E6C1F;
  Fm_state[6] := $1F83D9ABFB41BD6B;
  Fm_state[7] := $5BE0CD19137E2179;
{$R+}
{$WARNINGS ON}
  Inherited Initialize();

end;

end.
