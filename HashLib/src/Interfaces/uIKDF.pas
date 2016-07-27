unit uIKDF;

interface

uses
  uHashLibTypes;

type
  IKDF = interface(IInterface)
    ['{4697798C-9DC2-476C-A6C2-2D633B74D3FC}']
    /// <summary>
    /// Returns the pseudo-random bytes for this object.
    /// </summary>
    /// <param name="bc">The number of pseudo-random key bytes to generate.</param>
    /// <returns>A byte array filled with pseudo-random key bytes.</returns>
    /// <exception cref="EArgumentOutOfRangeException">bc must be greater than zero.</exception>
    /// <exception cref="EArgumentException">invalid start index or end index of internal buffer.</exception>
    function GetBytes(bc: Int32): THashLibByteArray;

  end;

implementation

end.
