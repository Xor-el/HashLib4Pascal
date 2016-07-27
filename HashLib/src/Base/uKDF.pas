unit uKDF;

{$I ..\Include\HashLib.inc}

interface

uses
  uIKDF,
  uHashLibTypes;

type
  TKDF = class abstract(TInterfacedObject, IKDF)

  public

    // Not really needed because there is an Intristic default constructor always
    // called for classes if none is defined by the developer but I just put it
    // for readability reasons.
    constructor Create();

    /// <summary>
    /// Returns the pseudo-random bytes for this object.
    /// </summary>
    /// <param name="bc">The number of pseudo-random key bytes to generate.</param>
    /// <returns>A byte array filled with pseudo-random key bytes.</returns>
    /// <exception cref="EArgumentOutOfRangeException">bc must be greater than zero.</exception>
    /// <exception cref="EArgumentException">invalid start index or end index of internal buffer.</exception>
    function GetBytes(bc: Int32): THashLibByteArray; virtual; abstract;

  end;

implementation

{ TKDF }

constructor TKDF.Create;
begin
  Inherited Create();
end;

end.
