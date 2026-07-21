unit HlpSimdLevels;

{$I ..\Include\HashLib.inc}

interface

type
  TX86SimdLevel = (Scalar, SSE2, SSE3, SSSE3, SSE41, SSE42, AVX2);
  TArmSimdLevel = (Scalar, NEON, SVE, SVE2);

implementation

end.
