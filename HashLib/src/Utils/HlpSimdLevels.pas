unit HlpSimdLevels;

{$I ..\Include\HashLib.inc}

interface

type
  TX86SimdLevel = (Scalar, SSE2, SSSE3, AVX2);
  TArmSimdLevel = (Scalar, NEON, SVE, SVE2);

implementation

end.
