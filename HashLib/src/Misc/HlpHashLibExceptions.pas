unit HlpHashLibExceptions;

{$I ..\Include\HashLib.inc}

interface

uses
  SysUtils;

type
  EHashLibException = class(Exception);
  EInvalidOperationHashLibException = class(EHashLibException);
  EIndexOutOfRangeHashLibException = class(EHashLibException);
  EArgumentHashLibException = class(EHashLibException);
  EArgumentInvalidHashLibException = class(EHashLibException);
  EArgumentNilHashLibException = class(EHashLibException);
  EArgumentOutOfRangeHashLibException = class(EHashLibException);
  ENullReferenceHashLibException = class(EHashLibException);
  ENotImplementedHashLibException = class(EHashLibException);
  EUnsupportedTypeHashLibException = class(EHashLibException);

implementation

end.
