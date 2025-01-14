program Make;
{$mode objfpc}{$H+}

uses
  Classes,
  SysUtils,
  StrUtils,
  FileUtil,
  Zipper,
  fphttpclient,
  openssl,
  opensslsockets,
  Process;

const
  Src: string = 'HashLib.Benchmark';
  Use: string = 'HashLib/src/Packages/FPC';
  Tst: string = 'HashLibConsole.Tests.lpi';
  Pkg: array of string = ();

var
  Each, Item, PackagePath, TempFile, Url: string;
  Output, Line: ansistring;
  List: TStringList;
  Zip: TStream;

begin
  InitSSLInterface;
  if FileExists('.gitmodules') then
    if RunCommand('git', ['submodule', 'update', '--init', '--recursive',
      '--force', '--remote'], Output) then
      Writeln(#27'[33m', Output, #27'[0m')
    else
    begin
      ExitCode += 1;
      Writeln(#27'[31m', Output, #27'[0m');
    end;
  List := FindAllFiles(Use, '*.lpk', True);
  try
    for Each in List do
      if RunCommand('lazbuild', ['--add-package-link', Each], Output) then
        Writeln(#27'[33m', 'added ', Each, #27'[0m')
      else
      begin
        ExitCode += 1;
        Writeln(#27'[31m', 'added ', Each, #27'[0m');
      end;
  finally
    List.Free;
  end;
  for Each in Pkg do
  begin
    PackagePath :=
      {$IFDEF MSWINDOWS}
      GetEnvironmentVariable('APPDATA') + '\.lazarus\onlinepackagemanager\packages\'
      {$ELSE}
      GetEnvironmentVariable('HOME') + '/.lazarus/onlinepackagemanager/packages/'
      {$ENDIF}
      + Each;
    TempFile := GetTempFileName;
    Url := 'https://packages.lazarus-ide.org/' + Each + '.zip';
    if not DirectoryExists(PackagePath) then
    begin
      Zip := TFileStream.Create(TempFile, fmCreate or fmOpenWrite);
      with TFPHttpClient.Create(nil) do
      begin
        try
          AddHeader('User-Agent', 'Mozilla/5.0 (compatible; fpweb)');
          AllowRedirect := True;
          Get(Url, Zip);
          WriteLn('Download from ', Url, ' to ', TempFile);
        finally
          Free;
        end;
      end;
      Zip.Free;
      CreateDir(PackagePath);
      with TUnZipper.Create do
      begin
        try
          FileName := TempFile;
          OutputPath := PackagePath;
          Examine;
          UnZipAllFiles;
          WriteLn('Unzip from ', TempFile, ' to ', PackagePath);
        finally
          Free;
        end;
      end;
      DeleteFile(TempFile);
      List := FindAllFiles(PackagePath, '*.lpk', True);
      try
        for Item in List do
          if RunCommand('lazbuild', ['--add-package-link', Item], Output) then
            Writeln(#27'[33m', 'added ', Item, #27'[0m')
          else
          begin
            ExitCode += 1;
            Writeln(#27'[31m', 'added ', Item, #27'[0m');
          end;
      finally
        List.Free;
      end;
    end;
  end;
  List := FindAllFiles('.', Tst, True);
  try
    for Each in List do
    begin
      Writeln(#27'[33m', 'build ', Each, #27'[0m');
      if RunCommand('lazbuild', ['--build-all', '--recursive',
        '--no-write-project', Each], Output) then
        for Line in SplitString(Output, LineEnding) do
        begin
          if Pos('Linking', Line) <> 0 then
          begin
            if not RunCommand({$IFDEF MSWINDOWS}'&'{$ELSE}'command'{$ENDIF}, [SplitString(Line, ' ')[2],
              '--all', '--format=plain', '--progress'], Output) then
              ExitCode += 1;
            WriteLn(Output);
          end;
        end
      else
        for Line in SplitString(Output, LineEnding) do
          if Pos('Fatal', Line) <> 0 or Pos('Error', Line) then
            Writeln(#27'[31m', Line, #27'[0m');
    end;
  finally
    List.Free;
  end;
  List := FindAllFiles(Src, '*.lpi', True);
  try
    for Each in List do
    begin
      Write(#27'[33m', 'build from ', Each, #27'[0m');
      if RunCommand('lazbuild', ['--build-all', '--recursive',
        '--no-write-project', Each], Output) then
        for Line in SplitString(Output, LineEnding) do
        begin
          if Pos('Linking', Line) <> 0 then
            Writeln(#27'[32m', ' to ', SplitString(Line, ' ')[2], #27'[0m');
        end
      else
      begin
        ExitCode += 1;
        for Line in SplitString(Output, LineEnding) do
          if Pos('Fatal:', Line) <> 0 or Pos('Error:', Line) then
          begin
            WriteLn();
            Writeln(#27'[31m', Line, #27'[0m');
          end;
      end;
    end;
  finally
    List.Free;
  end;
  WriteLn('Errors: ', ExitCode);
end.
