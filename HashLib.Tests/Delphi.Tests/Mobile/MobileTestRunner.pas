unit MobileTestRunner;

interface

uses
  System.SysUtils;

type
  TMobileTestStatusProc = reference to procedure(const AMessage: string);
  TMobileTestFinishedProc = reference to procedure;

function MobileTestsRunning: Boolean;
function LoadTestInsightBaseUrl: string;
procedure SaveTestInsightBaseUrl(const ABaseUrl: string);
function ProbeTestInsightServer(const ABaseUrl: string): Boolean;
procedure RunMobileTestsAsync(const ABaseUrl: string;
  const AOnStatus: TMobileTestStatusProc; const AOnFinished: TMobileTestFinishedProc);

implementation

uses
  System.Classes,
  System.IniFiles,
  System.IOUtils,
  System.SyncObjs,
  TestInsight.DUnit;

const
  TestInsightIniFileName = 'TestInsightSettings.ini';
  TestInsightIniSection = 'Config';
  TestInsightIniBaseUrlKey = 'BaseUrl';

type
  TSyncStatusInvoker = class
  private
    FOnStatus: TMobileTestStatusProc;
    FMessage: string;
  public
    constructor Create(const AOnStatus: TMobileTestStatusProc; const AMessage: string);
    procedure Invoke;
  end;

  TSyncFinishedInvoker = class
  private
    FOnFinished: TMobileTestFinishedProc;
  public
    constructor Create(const AOnFinished: TMobileTestFinishedProc);
    procedure Invoke;
  end;

  TMobileTestThread = class(TThread)
  private
    FBaseUrl: string;
    FOnStatus: TMobileTestStatusProc;
    FOnFinished: TMobileTestFinishedProc;
  protected
    procedure Execute; override;
  public
    constructor Create(const ABaseUrl: string; const AOnStatus: TMobileTestStatusProc;
      const AOnFinished: TMobileTestFinishedProc);
  end;

var
  GTestsRunning: Integer;

function TestInsightSettingsIniPath: string;
begin
  Result := TPath.Combine(TPath.GetDocumentsPath, TestInsightIniFileName);
end;

function ReadBaseUrlFromIni(const AIniPath: string): string;
var
  LIni: TIniFile;
begin
  Result := '';
  if not FileExists(AIniPath) then
    Exit;
  LIni := TIniFile.Create(AIniPath);
  try
    Result := Trim(LIni.ReadString(TestInsightIniSection, TestInsightIniBaseUrlKey, ''));
  finally
    LIni.Free;
  end;
end;

function MobileTestsRunning: Boolean;
begin
  Result := TInterlocked.CompareExchange(GTestsRunning, 0, 0) <> 0;
end;

constructor TSyncStatusInvoker.Create(const AOnStatus: TMobileTestStatusProc;
  const AMessage: string);
begin
  inherited Create;
  FOnStatus := AOnStatus;
  FMessage := AMessage;
end;

procedure TSyncStatusInvoker.Invoke;
begin
  if Assigned(FOnStatus) then
    FOnStatus(FMessage);
end;

constructor TSyncFinishedInvoker.Create(const AOnFinished: TMobileTestFinishedProc);
begin
  inherited Create;
  FOnFinished := AOnFinished;
end;

procedure TSyncFinishedInvoker.Invoke;
begin
  if Assigned(FOnFinished) then
    FOnFinished();
end;

constructor TMobileTestThread.Create(const ABaseUrl: string;
  const AOnStatus: TMobileTestStatusProc; const AOnFinished: TMobileTestFinishedProc);
begin
  inherited Create(True);
  FreeOnTerminate := True;
  FBaseUrl := Trim(ABaseUrl);
  FOnStatus := AOnStatus;
  FOnFinished := AOnFinished;
end;

procedure TMobileTestThread.Execute;
var
  LStatusInvoker: TSyncStatusInvoker;
  LFinishedInvoker: TSyncFinishedInvoker;
begin
  try
    try
      if FBaseUrl = '' then
        raise Exception.Create('TestInsight BaseUrl is empty. Enter a URL in the app and tap Save URL.');
      TestInsight.DUnit.RunRegisteredTests(FBaseUrl);
    except
      on E: Exception do
      begin
        if Assigned(FOnStatus) then
        begin
          LStatusInvoker := TSyncStatusInvoker.Create(FOnStatus, 'Error: ' + E.Message);
          try
            Synchronize(LStatusInvoker.Invoke);
          finally
            LStatusInvoker.Free;
          end;
        end;
      end;
    end;
  finally
    TInterlocked.Exchange(GTestsRunning, 0);
    if Assigned(FOnFinished) then
    begin
      LFinishedInvoker := TSyncFinishedInvoker.Create(FOnFinished);
      try
        Synchronize(LFinishedInvoker.Invoke);
      finally
        LFinishedInvoker.Free;
      end;
    end;
  end;
end;

function LoadTestInsightBaseUrl: string;
begin
  Result := ReadBaseUrlFromIni(TestInsightSettingsIniPath);
end;

procedure SaveTestInsightBaseUrl(const ABaseUrl: string);
var
  LIni: TIniFile;
  LPath: string;
begin
  LPath := TestInsightSettingsIniPath;
  ForceDirectories(TPath.GetDirectoryName(LPath));
  LIni := TIniFile.Create(LPath);
  try
    LIni.WriteString(TestInsightIniSection, TestInsightIniBaseUrlKey, Trim(ABaseUrl));
  finally
    LIni.Free;
  end;
end;

function ProbeTestInsightServer(const ABaseUrl: string): Boolean;
begin
  { TestInsight exposes no documented health URL; non-empty URL is the v1 check. }
  Result := Trim(ABaseUrl) <> '';
end;

procedure RunMobileTestsAsync(const ABaseUrl: string;
  const AOnStatus: TMobileTestStatusProc; const AOnFinished: TMobileTestFinishedProc);
begin
  if TInterlocked.CompareExchange(GTestsRunning, 1, 0) <> 0 then
    Exit;

  with TMobileTestThread.Create(ABaseUrl, AOnStatus, AOnFinished) do
    Start;
end;

end.
