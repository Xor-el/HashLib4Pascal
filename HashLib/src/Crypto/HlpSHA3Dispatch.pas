unit HlpSHA3Dispatch;

{$I ..\Include\HashLib.inc}

interface

type
  TKeccakF1600Proc = procedure(AState: Pointer);
  TKeccakF1600AbsorbProc = procedure(AState: Pointer; AData: PByte;
    ABlockCount: Int32; ABlockSize: Int32);

var
  KeccakF1600_Permute: TKeccakF1600Proc;
  KeccakF1600_Absorb: TKeccakF1600AbsorbProc;

implementation

uses
  HlpBits,
  HlpConverters,
  HlpSimd;

// =============================================================================
// Round constants
// =============================================================================

const
  RC: array [0 .. 23] of UInt64 = (
    UInt64($0000000000000001), UInt64($0000000000008082),
    UInt64($800000000000808A), UInt64($8000000080008000),
    UInt64($000000000000808B), UInt64($0000000080000001),
    UInt64($8000000080008081), UInt64($8000000000008009),
    UInt64($000000000000008A), UInt64($0000000000000088),
    UInt64($0000000080008009), UInt64($000000008000000A),
    UInt64($000000008000808B), UInt64($800000000000008B),
    UInt64($8000000000008089), UInt64($8000000000008003),
    UInt64($8000000000008002), UInt64($8000000000000080),
    UInt64($000000000000800A), UInt64($800000008000000A),
    UInt64($8000000080008081), UInt64($8000000000008080),
    UInt64($0000000080000001), UInt64($8000000080008008));

// =============================================================================
// Scalar fallback implementation
// =============================================================================

procedure KeccakF1600_Scalar(AState: Pointer);
var
  LPState: PUInt64;
  LDa, LDe, LDi, LDo, LDu: UInt64;
{$IFDEF USE_UNROLLED_VARIANT}
  Aba, Abe, Abi, Abo, Abu, Aga, Age, Agi, Ago, Agu, Aka, Ake, Aki, Ako, Aku,
    Ama, Ame, Ami, Amo, Amu, Asa, Ase, Asi, Aso, Asu, BCa, BCe, BCi, BCo, BCu,
    Eba, Ebe, Ebi, Ebo, Ebu, Ega, Ege, Egi, Ego, Egu, Eka, Eke, Eki, Eko, Eku,
    Ema, Eme, Emi, Emo, Emu, Esa, Ese, Esi, Eso, Esu: UInt64;
  LRound: Int32;
{$ELSE}
  LColA, LColE, LColI, LColO, LColU: UInt64;
  LTemp: array [0 .. 24] of UInt64;
  LRound: Int32;
{$ENDIF USE_UNROLLED_VARIANT}
begin
  LPState := PUInt64(AState);

{$IFDEF USE_UNROLLED_VARIANT}
  Aba := LPState[0];
  Abe := LPState[1];
  Abi := LPState[2];
  Abo := LPState[3];
  Abu := LPState[4];
  Aga := LPState[5];
  Age := LPState[6];
  Agi := LPState[7];
  Ago := LPState[8];
  Agu := LPState[9];
  Aka := LPState[10];
  Ake := LPState[11];
  Aki := LPState[12];
  Ako := LPState[13];
  Aku := LPState[14];
  Ama := LPState[15];
  Ame := LPState[16];
  Ami := LPState[17];
  Amo := LPState[18];
  Amu := LPState[19];
  Asa := LPState[20];
  Ase := LPState[21];
  Asi := LPState[22];
  Aso := LPState[23];
  Asu := LPState[24];

  LRound := 0;
  while LRound < 24 do
  begin
    BCa := Aba xor Aga xor Aka xor Ama xor Asa;
    BCe := Abe xor Age xor Ake xor Ame xor Ase;
    BCi := Abi xor Agi xor Aki xor Ami xor Asi;
    BCo := Abo xor Ago xor Ako xor Amo xor Aso;
    BCu := Abu xor Agu xor Aku xor Amu xor Asu;

    LDa := BCu xor TBits.RotateLeft64(BCe, 1);
    LDe := BCa xor TBits.RotateLeft64(BCi, 1);
    LDi := BCe xor TBits.RotateLeft64(BCo, 1);
    LDo := BCi xor TBits.RotateLeft64(BCu, 1);
    LDu := BCo xor TBits.RotateLeft64(BCa, 1);

    Aba := Aba xor LDa;
    BCa := Aba;
    Age := Age xor LDe;
    BCe := TBits.RotateLeft64(Age, 44);
    Aki := Aki xor LDi;
    BCi := TBits.RotateLeft64(Aki, 43);
    Amo := Amo xor LDo;
    BCo := TBits.RotateLeft64(Amo, 21);
    Asu := Asu xor LDu;
    BCu := TBits.RotateLeft64(Asu, 14);
    Eba := BCa xor ((not BCe) and BCi);
    Eba := Eba xor UInt64(RC[LRound]);
    Ebe := BCe xor ((not BCi) and BCo);
    Ebi := BCi xor ((not BCo) and BCu);
    Ebo := BCo xor ((not BCu) and BCa);
    Ebu := BCu xor ((not BCa) and BCe);

    Abo := Abo xor LDo;
    BCa := TBits.RotateLeft64(Abo, 28);
    Agu := Agu xor LDu;
    BCe := TBits.RotateLeft64(Agu, 20);
    Aka := Aka xor LDa;
    BCi := TBits.RotateLeft64(Aka, 3);
    Ame := Ame xor LDe;
    BCo := TBits.RotateLeft64(Ame, 45);
    Asi := Asi xor LDi;
    BCu := TBits.RotateLeft64(Asi, 61);
    Ega := BCa xor ((not BCe) and BCi);
    Ege := BCe xor ((not BCi) and BCo);
    Egi := BCi xor ((not BCo) and BCu);
    Ego := BCo xor ((not BCu) and BCa);
    Egu := BCu xor ((not BCa) and BCe);

    Abe := Abe xor LDe;
    BCa := TBits.RotateLeft64(Abe, 1);
    Agi := Agi xor LDi;
    BCe := TBits.RotateLeft64(Agi, 6);
    Ako := Ako xor LDo;
    BCi := TBits.RotateLeft64(Ako, 25);
    Amu := Amu xor LDu;
    BCo := TBits.RotateLeft64(Amu, 8);
    Asa := Asa xor LDa;
    BCu := TBits.RotateLeft64(Asa, 18);
    Eka := BCa xor ((not BCe) and BCi);
    Eke := BCe xor ((not BCi) and BCo);
    Eki := BCi xor ((not BCo) and BCu);
    Eko := BCo xor ((not BCu) and BCa);
    Eku := BCu xor ((not BCa) and BCe);

    Abu := Abu xor LDu;
    BCa := TBits.RotateLeft64(Abu, 27);
    Aga := Aga xor LDa;
    BCe := TBits.RotateLeft64(Aga, 36);
    Ake := Ake xor LDe;
    BCi := TBits.RotateLeft64(Ake, 10);
    Ami := Ami xor LDi;
    BCo := TBits.RotateLeft64(Ami, 15);
    Aso := Aso xor LDo;
    BCu := TBits.RotateLeft64(Aso, 56);
    Ema := BCa xor ((not BCe) and BCi);
    Eme := BCe xor ((not BCi) and BCo);
    Emi := BCi xor ((not BCo) and BCu);
    Emo := BCo xor ((not BCu) and BCa);
    Emu := BCu xor ((not BCa) and BCe);

    Abi := Abi xor LDi;
    BCa := TBits.RotateLeft64(Abi, 62);
    Ago := Ago xor LDo;
    BCe := TBits.RotateLeft64(Ago, 55);
    Aku := Aku xor LDu;
    BCi := TBits.RotateLeft64(Aku, 39);
    Ama := Ama xor LDa;
    BCo := TBits.RotateLeft64(Ama, 41);
    Ase := Ase xor LDe;
    BCu := TBits.RotateLeft64(Ase, 2);
    Esa := BCa xor ((not BCe) and BCi);
    Ese := BCe xor ((not BCi) and BCo);
    Esi := BCi xor ((not BCo) and BCu);
    Eso := BCo xor ((not BCu) and BCa);
    Esu := BCu xor ((not BCa) and BCe);

    BCa := Eba xor Ega xor Eka xor Ema xor Esa;
    BCe := Ebe xor Ege xor Eke xor Eme xor Ese;
    BCi := Ebi xor Egi xor Eki xor Emi xor Esi;
    BCo := Ebo xor Ego xor Eko xor Emo xor Eso;
    BCu := Ebu xor Egu xor Eku xor Emu xor Esu;

    LDa := BCu xor TBits.RotateLeft64(BCe, 1);
    LDe := BCa xor TBits.RotateLeft64(BCi, 1);
    LDi := BCe xor TBits.RotateLeft64(BCo, 1);
    LDo := BCi xor TBits.RotateLeft64(BCu, 1);
    LDu := BCo xor TBits.RotateLeft64(BCa, 1);

    Eba := Eba xor LDa;
    BCa := Eba;
    Ege := Ege xor LDe;
    BCe := TBits.RotateLeft64(Ege, 44);
    Eki := Eki xor LDi;
    BCi := TBits.RotateLeft64(Eki, 43);
    Emo := Emo xor LDo;
    BCo := TBits.RotateLeft64(Emo, 21);
    Esu := Esu xor LDu;
    BCu := TBits.RotateLeft64(Esu, 14);
    Aba := BCa xor ((not BCe) and BCi);
    Aba := Aba xor UInt64(RC[LRound + 1]);
    Abe := BCe xor ((not BCi) and BCo);
    Abi := BCi xor ((not BCo) and BCu);
    Abo := BCo xor ((not BCu) and BCa);
    Abu := BCu xor ((not BCa) and BCe);

    Ebo := Ebo xor LDo;
    BCa := TBits.RotateLeft64(Ebo, 28);
    Egu := Egu xor LDu;
    BCe := TBits.RotateLeft64(Egu, 20);
    Eka := Eka xor LDa;
    BCi := TBits.RotateLeft64(Eka, 3);
    Eme := Eme xor LDe;
    BCo := TBits.RotateLeft64(Eme, 45);
    Esi := Esi xor LDi;
    BCu := TBits.RotateLeft64(Esi, 61);
    Aga := BCa xor ((not BCe) and BCi);
    Age := BCe xor ((not BCi) and BCo);
    Agi := BCi xor ((not BCo) and BCu);
    Ago := BCo xor ((not BCu) and BCa);
    Agu := BCu xor ((not BCa) and BCe);

    Ebe := Ebe xor LDe;
    BCa := TBits.RotateLeft64(Ebe, 1);
    Egi := Egi xor LDi;
    BCe := TBits.RotateLeft64(Egi, 6);
    Eko := Eko xor LDo;
    BCi := TBits.RotateLeft64(Eko, 25);
    Emu := Emu xor LDu;
    BCo := TBits.RotateLeft64(Emu, 8);
    Esa := Esa xor LDa;
    BCu := TBits.RotateLeft64(Esa, 18);
    Aka := BCa xor ((not BCe) and BCi);
    Ake := BCe xor ((not BCi) and BCo);
    Aki := BCi xor ((not BCo) and BCu);
    Ako := BCo xor ((not BCu) and BCa);
    Aku := BCu xor ((not BCa) and BCe);

    Ebu := Ebu xor LDu;
    BCa := TBits.RotateLeft64(Ebu, 27);
    Ega := Ega xor LDa;
    BCe := TBits.RotateLeft64(Ega, 36);
    Eke := Eke xor LDe;
    BCi := TBits.RotateLeft64(Eke, 10);
    Emi := Emi xor LDi;
    BCo := TBits.RotateLeft64(Emi, 15);
    Eso := Eso xor LDo;
    BCu := TBits.RotateLeft64(Eso, 56);
    Ama := BCa xor ((not BCe) and BCi);
    Ame := BCe xor ((not BCi) and BCo);
    Ami := BCi xor ((not BCo) and BCu);
    Amo := BCo xor ((not BCu) and BCa);
    Amu := BCu xor ((not BCa) and BCe);

    Ebi := Ebi xor LDi;
    BCa := TBits.RotateLeft64(Ebi, 62);
    Ego := Ego xor LDo;
    BCe := TBits.RotateLeft64(Ego, 55);
    Eku := Eku xor LDu;
    BCi := TBits.RotateLeft64(Eku, 39);
    Ema := Ema xor LDa;
    BCo := TBits.RotateLeft64(Ema, 41);
    Ese := Ese xor LDe;
    BCu := TBits.RotateLeft64(Ese, 2);
    Asa := BCa xor ((not BCe) and BCi);
    Ase := BCe xor ((not BCi) and BCo);
    Asi := BCi xor ((not BCo) and BCu);
    Aso := BCo xor ((not BCu) and BCa);
    Asu := BCu xor ((not BCa) and BCe);

    System.Inc(LRound, 2);
  end;

  LPState[0] := Aba;
  LPState[1] := Abe;
  LPState[2] := Abi;
  LPState[3] := Abo;
  LPState[4] := Abu;
  LPState[5] := Aga;
  LPState[6] := Age;
  LPState[7] := Agi;
  LPState[8] := Ago;
  LPState[9] := Agu;
  LPState[10] := Aka;
  LPState[11] := Ake;
  LPState[12] := Aki;
  LPState[13] := Ako;
  LPState[14] := Aku;
  LPState[15] := Ama;
  LPState[16] := Ame;
  LPState[17] := Ami;
  LPState[18] := Amo;
  LPState[19] := Amu;
  LPState[20] := Asa;
  LPState[21] := Ase;
  LPState[22] := Asi;
  LPState[23] := Aso;
  LPState[24] := Asu;

{$ELSE}
  for LRound := 0 to 23 do
  begin
    LColA := LPState[00] xor LPState[05] xor LPState[10] xor LPState[15]
      xor LPState[20];
    LColE := LPState[01] xor LPState[06] xor LPState[11] xor LPState[16]
      xor LPState[21];
    LColI := LPState[02] xor LPState[07] xor LPState[12] xor LPState[17]
      xor LPState[22];
    LColO := LPState[03] xor LPState[08] xor LPState[13] xor LPState[18]
      xor LPState[23];
    LColU := LPState[04] xor LPState[09] xor LPState[14] xor LPState[19]
      xor LPState[24];
    LDa := TBits.RotateLeft64(LColA, 1) xor LColO;
    LDe := TBits.RotateLeft64(LColE, 1) xor LColU;
    LDi := TBits.RotateLeft64(LColI, 1) xor LColA;
    LDo := TBits.RotateLeft64(LColO, 1) xor LColE;
    LDu := TBits.RotateLeft64(LColU, 1) xor LColI;
    LTemp[00] := LPState[00] xor LDe;
    LTemp[01] := TBits.RotateLeft64(LPState[06] xor LDi, 44);
    LTemp[02] := TBits.RotateLeft64(LPState[12] xor LDo, 43);
    LTemp[03] := TBits.RotateLeft64(LPState[18] xor LDu, 21);
    LTemp[04] := TBits.RotateLeft64(LPState[24] xor LDa, 14);
    LTemp[05] := TBits.RotateLeft64(LPState[03] xor LDu, 28);
    LTemp[06] := TBits.RotateLeft64(LPState[09] xor LDa, 20);
    LTemp[07] := TBits.RotateLeft64(LPState[10] xor LDe, 3);
    LTemp[08] := TBits.RotateLeft64(LPState[16] xor LDi, 45);
    LTemp[09] := TBits.RotateLeft64(LPState[22] xor LDo, 61);
    LTemp[10] := TBits.RotateLeft64(LPState[01] xor LDi, 1);
    LTemp[11] := TBits.RotateLeft64(LPState[07] xor LDo, 6);
    LTemp[12] := TBits.RotateLeft64(LPState[13] xor LDu, 25);
    LTemp[13] := TBits.RotateLeft64(LPState[19] xor LDa, 8);
    LTemp[14] := TBits.RotateLeft64(LPState[20] xor LDe, 18);
    LTemp[15] := TBits.RotateLeft64(LPState[04] xor LDa, 27);
    LTemp[16] := TBits.RotateLeft64(LPState[05] xor LDe, 36);
    LTemp[17] := TBits.RotateLeft64(LPState[11] xor LDi, 10);
    LTemp[18] := TBits.RotateLeft64(LPState[17] xor LDo, 15);
    LTemp[19] := TBits.RotateLeft64(LPState[23] xor LDu, 56);
    LTemp[20] := TBits.RotateLeft64(LPState[02] xor LDo, 62);
    LTemp[21] := TBits.RotateLeft64(LPState[08] xor LDu, 55);
    LTemp[22] := TBits.RotateLeft64(LPState[14] xor LDa, 39);
    LTemp[23] := TBits.RotateLeft64(LPState[15] xor LDe, 41);
    LTemp[24] := TBits.RotateLeft64(LPState[21] xor LDi, 2);
    LPState[00] := LTemp[00] xor ((not LTemp[01]) and LTemp[02]);
    LPState[01] := LTemp[01] xor ((not LTemp[02]) and LTemp[03]);
    LPState[02] := LTemp[02] xor ((not LTemp[03]) and LTemp[04]);
    LPState[03] := LTemp[03] xor ((not LTemp[04]) and LTemp[00]);
    LPState[04] := LTemp[04] xor ((not LTemp[00]) and LTemp[01]);
    LPState[05] := LTemp[05] xor ((not LTemp[06]) and LTemp[07]);
    LPState[06] := LTemp[06] xor ((not LTemp[07]) and LTemp[08]);
    LPState[07] := LTemp[07] xor ((not LTemp[08]) and LTemp[09]);
    LPState[08] := LTemp[08] xor ((not LTemp[09]) and LTemp[05]);
    LPState[09] := LTemp[09] xor ((not LTemp[05]) and LTemp[06]);
    LPState[10] := LTemp[10] xor ((not LTemp[11]) and LTemp[12]);
    LPState[11] := LTemp[11] xor ((not LTemp[12]) and LTemp[13]);
    LPState[12] := LTemp[12] xor ((not LTemp[13]) and LTemp[14]);
    LPState[13] := LTemp[13] xor ((not LTemp[14]) and LTemp[10]);
    LPState[14] := LTemp[14] xor ((not LTemp[10]) and LTemp[11]);
    LPState[15] := LTemp[15] xor ((not LTemp[16]) and LTemp[17]);
    LPState[16] := LTemp[16] xor ((not LTemp[17]) and LTemp[18]);
    LPState[17] := LTemp[17] xor ((not LTemp[18]) and LTemp[19]);
    LPState[18] := LTemp[18] xor ((not LTemp[19]) and LTemp[15]);
    LPState[19] := LTemp[19] xor ((not LTemp[15]) and LTemp[16]);
    LPState[20] := LTemp[20] xor ((not LTemp[21]) and LTemp[22]);
    LPState[21] := LTemp[21] xor ((not LTemp[22]) and LTemp[23]);
    LPState[22] := LTemp[22] xor ((not LTemp[23]) and LTemp[24]);
    LPState[23] := LTemp[23] xor ((not LTemp[24]) and LTemp[20]);
    LPState[24] := LTemp[24] xor ((not LTemp[20]) and LTemp[21]);
    LPState[00] := LPState[00] xor RC[LRound];
  end;

  System.FillChar(LTemp, System.SizeOf(LTemp), UInt64(0));
{$ENDIF USE_UNROLLED_VARIANT}
end;

// =============================================================================
// Scalar absorb: XOR + permute loop (no SIMD)
// =============================================================================

procedure KeccakF1600_Absorb_Scalar(AState: Pointer; AData: PByte;
  ABlockCount: Int32; ABlockSize: Int32);
var
  LPState: PUInt64;
  LData: array [0 .. 20] of UInt64;
  LBlockSizeWords, I, J: Int32;
begin
  LPState := PUInt64(AState);
  LBlockSizeWords := ABlockSize shr 3;
  for I := 0 to ABlockCount - 1 do
  begin
    TConverters.le64_copy(AData, 0, @LData[0], 0, ABlockSize);
    for J := 0 to LBlockSizeWords - 1 do
      LPState[J] := LPState[J] xor LData[J];
    KeccakF1600_Scalar(AState);
    System.Inc(AData, ABlockSize);
  end;
  System.FillChar(LData, System.SizeOf(LData), UInt64(0));
end;

// =============================================================================
// SIMD implementations (x86-64 only)
// =============================================================================

{$IFDEF HASHLIB_X86_64}

const
  K_KECCAK: packed record
    RhotatesLeft: array [0..23] of UInt64;
    RhotatesRight: array [0..23] of UInt64;
    Iotas: array [0..95] of UInt64;
    Jagged: array [0..24] of Int32;
  end = (
    RhotatesLeft: (
       3, 18, 36, 41,   //  ymm2: [2][0] [4][0] [1][0] [3][0]
       1, 62, 28, 27,   //  ymm1: [0][1] [0][2] [0][3] [0][4]
      45,  6, 56, 39,   //  ymm3: [3][1] [1][2] [4][3] [2][4]
      10, 61, 55,  8,   //  ymm4: [2][1] [4][2] [1][3] [3][4]
       2, 15, 25, 20,   //  ymm5: [4][1] [3][2] [2][3] [1][4]
      44, 43, 21, 14);  //  ymm6: [1][1] [2][2] [3][3] [4][4]
    RhotatesRight: (
      64- 3, 64-18, 64-36, 64-41,
      64- 1, 64-62, 64-28, 64-27,
      64-45, 64- 6, 64-56, 64-39,
      64-10, 64-61, 64-55, 64- 8,
      64- 2, 64-15, 64-25, 64-20,
      64-44, 64-43, 64-21, 64-14);
    Iotas: (
      UInt64($0000000000000001), UInt64($0000000000000001), UInt64($0000000000000001), UInt64($0000000000000001),
      UInt64($0000000000008082), UInt64($0000000000008082), UInt64($0000000000008082), UInt64($0000000000008082),
      UInt64($800000000000808A), UInt64($800000000000808A), UInt64($800000000000808A), UInt64($800000000000808A),
      UInt64($8000000080008000), UInt64($8000000080008000), UInt64($8000000080008000), UInt64($8000000080008000),
      UInt64($000000000000808B), UInt64($000000000000808B), UInt64($000000000000808B), UInt64($000000000000808B),
      UInt64($0000000080000001), UInt64($0000000080000001), UInt64($0000000080000001), UInt64($0000000080000001),
      UInt64($8000000080008081), UInt64($8000000080008081), UInt64($8000000080008081), UInt64($8000000080008081),
      UInt64($8000000000008009), UInt64($8000000000008009), UInt64($8000000000008009), UInt64($8000000000008009),
      UInt64($000000000000008A), UInt64($000000000000008A), UInt64($000000000000008A), UInt64($000000000000008A),
      UInt64($0000000000000088), UInt64($0000000000000088), UInt64($0000000000000088), UInt64($0000000000000088),
      UInt64($0000000080008009), UInt64($0000000080008009), UInt64($0000000080008009), UInt64($0000000080008009),
      UInt64($000000008000000A), UInt64($000000008000000A), UInt64($000000008000000A), UInt64($000000008000000A),
      UInt64($000000008000808B), UInt64($000000008000808B), UInt64($000000008000808B), UInt64($000000008000808B),
      UInt64($800000000000008B), UInt64($800000000000008B), UInt64($800000000000008B), UInt64($800000000000008B),
      UInt64($8000000000008089), UInt64($8000000000008089), UInt64($8000000000008089), UInt64($8000000000008089),
      UInt64($8000000000008003), UInt64($8000000000008003), UInt64($8000000000008003), UInt64($8000000000008003),
      UInt64($8000000000008002), UInt64($8000000000008002), UInt64($8000000000008002), UInt64($8000000000008002),
      UInt64($8000000000000080), UInt64($8000000000000080), UInt64($8000000000000080), UInt64($8000000000000080),
      UInt64($000000000000800A), UInt64($000000000000800A), UInt64($000000000000800A), UInt64($000000000000800A),
      UInt64($800000008000000A), UInt64($800000008000000A), UInt64($800000008000000A), UInt64($800000008000000A),
      UInt64($8000000080008081), UInt64($8000000080008081), UInt64($8000000080008081), UInt64($8000000080008081),
      UInt64($8000000000008080), UInt64($8000000000008080), UInt64($8000000000008080), UInt64($8000000000008080),
      UInt64($0000000080000001), UInt64($0000000080000001), UInt64($0000000080000001), UInt64($0000000080000001),
      UInt64($8000000080008008), UInt64($8000000080008008), UInt64($8000000080008008), UInt64($8000000080008008));
    Jagged: (
      0, 32, 40, 48, 56, 80, 192, 104, 144, 184,
      64, 128, 200, 176, 120, 88, 96, 168, 208, 152,
      72, 160, 136, 112, 216)
  );

procedure KeccakF1600_Avx2(AState: Pointer; AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc2Begin.inc}
  {$I ..\Include\Simd\SHA3\KeccakF1600Avx2.inc}
end;

procedure KeccakF1600_Avx2_Wrap(AState: Pointer);
begin
  KeccakF1600_Avx2(AState, @K_KECCAK);
end;

procedure KeccakF1600_Avx2_Absorb(AState: Pointer; AData: PByte;
  ABlockCount: Int32; ABlockSize: Int32; AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc5Begin.inc}
  {$I ..\Include\Simd\SHA3\KeccakF1600Avx2Absorb.inc}
end;

procedure KeccakF1600_Avx2_Absorb_Wrap(AState: Pointer; AData: PByte;
  ABlockCount: Int32; ABlockSize: Int32);
begin
  KeccakF1600_Avx2_Absorb(AState, AData, ABlockCount, ABlockSize, @K_KECCAK);
end;

{$ENDIF HASHLIB_X86_64}

// =============================================================================
// Dispatch initialization
// =============================================================================

procedure InitDispatch();
begin
  KeccakF1600_Permute := @KeccakF1600_Scalar;
  KeccakF1600_Absorb := @KeccakF1600_Absorb_Scalar;
{$IFDEF HASHLIB_X86_64}
  case TSimd.GetActiveLevel() of
    TSimdLevel.AVX2:
    begin
      KeccakF1600_Permute := @KeccakF1600_Avx2_Wrap;
      KeccakF1600_Absorb := @KeccakF1600_Avx2_Absorb_Wrap;
    end;
  end;
{$ENDIF}
end;

initialization
  InitDispatch();

end.
