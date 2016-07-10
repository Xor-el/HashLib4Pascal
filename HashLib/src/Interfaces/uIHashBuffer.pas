unit uIHashBuffer;

interface

uses
  uHashLibTypes;

type
  IHashBuffer = interface(IInterface)
    ['{2B281635-4892-4A4F-A2CB-1EE272CB5425}']
    function GetIsEmpty: Boolean;
    function GetIsFull: Boolean;
    function GetPos: Int32;
    function GetLength: Int32;

    procedure Initialize();
    function GetBytes(): THashLibByteArray;
    function GetBytesZeroPadded(): THashLibByteArray;
    function Feed(a_data: THashLibByteArray; var a_start_index: Int32;
      var a_length: Int32; var a_processed_bytes: UInt64): Boolean; overload;
    function Feed(a_data: THashLibByteArray; a_length: Int32): Boolean;
      overload;
    function ToString(): String;

    property IsEmpty: Boolean read GetIsEmpty;
    property IsFull: Boolean read GetIsFull;
    property Pos: Int32 read GetPos;
    property Length: Int32 read GetLength;
  end;

implementation

end.
