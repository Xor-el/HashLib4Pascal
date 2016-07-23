unit uSHA1;

{$I ..\Include\HashLib.inc}

interface

uses
  uHashLibTypes,
  uSHA0;

type
  TSHA1 = class(TSHA0)

  strict protected
    procedure Expand(a_data: THashLibUInt32Array); override;

  public
    // Not really needed because there is an Intristic default constructor always
    // called for classes if none is defined by the developer but I just put it
    // for readability reasons.
    constructor Create();

  end;

implementation

{ TSHA1 }

constructor TSHA1.Create;
begin
  Inherited Create();
end;

procedure TSHA1.Expand(a_data: THashLibUInt32Array);
var
  i: Int32;
  T: UInt32;
begin
  i := $10;
  while i < 80 do
  begin
    T := a_data[i - 3] xor a_data[i - 8] xor a_data[i - 14] xor a_data[i - 16];
    a_data[i] := ((T shl 1) or (T shr 31));
    System.Inc(i);
  end;

end;

end.
