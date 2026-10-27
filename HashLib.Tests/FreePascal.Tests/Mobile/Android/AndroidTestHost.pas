{ List before the test units: initialization enters the unpacked test data folder. }
unit AndroidTestHost;

{$mode objfpc}{$H+}

interface

uses
  SysUtils,
  Classes,
  jni,
  fpcunit,
  fphttpclient,
  testregistry,
  TestInsightClient,
  FpcUnitTestInsight,
  TestInsightProtocol,
  jsonparser;

type
  TAndroidTestHost = class sealed
  strict private
    class function SkipOutside(AResult: TTestResult; ASuite: TTest; AAllowed: TList; AInside: Boolean): Int32; static;
    class function FindAllowed(const ANames: string): TList; static;
    class function JavaToString(AEnv: PJNIEnv; AValue: jstring): string; static;
    class procedure RunRegistered(AClient: TAbstractTestInsightClient); static;
    class function NativeRun(AEnv: PJNIEnv; AThis: jobject; ABaseUrl: jstring): jint; cdecl; static;
  public
    class procedure LogLine(APriority: LongInt; const AText: string); static;
    /// <summary>Registers the host activity's native run method; call it from JNI_OnLoad.</summary>
    class function RegisterHost(AVm: PJavaVM): jint; static;
  end;

implementation

const
  HostClass = 'org/fpctests/host/MainActivity';
  WorkDirVariable = 'FPCTESTS_WORKDIR';
  LogTag = 'FpcTests';
  SettingsFile = 'TestInsightSettings.ini';
  MaxBatchResults = 100;
  MaxBatchMs = 1000;
  MaxFailedRequests = 2;
  LogInfo = 4;
  LogWarn = 5;
  LogError = 6;

{$linklib log}
function android_log_write(APriority: LongInt; ATag, AText: PAnsiChar): LongInt; cdecl;
  external 'log' name '__android_log_write';

type
  // logs each start, skip, failure and error to logcat so a run can be read without the IDE
  TLogcatListener = class(TInterfacedObject, ITestListener)
  public
    procedure AddFailure(ATest: TTest; AFailure: TTestFailure);
    procedure AddError(ATest: TTest; AError: TTestFailure);
    procedure StartTest(ATest: TTest);
    procedure EndTest(ATest: TTest);
    procedure StartTestSuite(ATestSuite: TTestSuite);
    procedure EndTestSuite(ATestSuite: TTestSuite);
  end;

  TBlockingTestInsightClient = class(TAbstractTestInsightClient)
  private
    FHttp: TFPHTTPClient;
    FInError: Boolean;
    FLastError: string;
    FBatch: string;
    FBatchCount: Int32;
    FBatchSentAt: QWord;
    FFailedRequests: Int32;
    procedure Send(const AUrl, AContent: string);
    procedure FlushResults;
    procedure Fail(AError: Exception);
  protected
    function GetHasError: Boolean; override;
    function GetLastErrorMessage: string; override;
    procedure ServerPost(aURL: string; const aContent: string = ''); override;
    function ServerGet(aURL: string): string; override;
    procedure ServerDelete(aURL: string); override;
  public
    constructor Create(const aBaseURL: string); override;
    destructor Destroy; override;
  end;

class procedure TAndroidTestHost.LogLine(APriority: LongInt; const AText: string);
begin
  android_log_write(APriority, LogTag, PAnsiChar(AnsiString(AText)));
end;

procedure TLogcatListener.AddFailure(ATest: TTest; AFailure: TTestFailure);
begin
  if AFailure.IsIgnoredTest then
    TAndroidTestHost.LogLine(LogInfo, 'SKIP ' + ATest.TestSuiteName + '.' + ATest.TestName + ': ' +
      AFailure.ExceptionMessage)
  else
    TAndroidTestHost.LogLine(LogWarn, 'FAIL ' + ATest.TestSuiteName + '.' + ATest.TestName + ': ' +
      AFailure.ExceptionMessage);
end;

procedure TLogcatListener.AddError(ATest: TTest; AError: TTestFailure);
begin
  TAndroidTestHost.LogLine(LogError, 'ERROR ' + ATest.TestSuiteName + '.' + ATest.TestName + ': ' +
    AError.ExceptionClassName + ': ' + AError.ExceptionMessage);
end;

procedure TLogcatListener.StartTest(ATest: TTest);
begin
  TAndroidTestHost.LogLine(LogInfo, 'START ' + ATest.TestSuiteName + '.' + ATest.TestName);
end;

procedure TLogcatListener.EndTest(ATest: TTest);
begin
end;

procedure TLogcatListener.StartTestSuite(ATestSuite: TTestSuite);
begin
end;

procedure TLogcatListener.EndTestSuite(ATestSuite: TTestSuite);
begin
end;

constructor TBlockingTestInsightClient.Create(const aBaseURL: string);
begin
  inherited Create(aBaseURL);
  FHttp := TFPHTTPClient.Create(nil);
  // a server that goes away mid-run must not hang the run for ever
  FHttp.ConnectTimeout := 0;
  FHttp.IOTimeout := 30000;
  FBatchSentAt := GetTickCount64;
end;

destructor TBlockingTestInsightClient.Destroy;
begin
  FlushResults;
  FHttp.Free;
  inherited Destroy;
end;

function TBlockingTestInsightClient.GetHasError: Boolean;
begin
  Result := FInError;
end;

function TBlockingTestInsightClient.GetLastErrorMessage: string;
begin
  Result := FLastError;
end;

procedure TBlockingTestInsightClient.Fail(AError: Exception);
begin
  FInError := True;
  FLastError := AError.ClassName + ': ' + AError.Message;
end;

procedure TBlockingTestInsightClient.FlushResults;
begin
  if FBatch = '' then
    Exit;
  Send(pathResults, '[' + FBatch + ']');
  FBatch := '';
  FBatchCount := 0;
  FBatchSentAt := GetTickCount64;
end;

// a request per test stops the IDE repainting
procedure TBlockingTestInsightClient.ServerPost(aURL: string; const aContent: string);
begin
  if (aURL <> pathResults) or (Length(aContent) <= 2) then
  begin
    FlushResults;
    Send(aURL, aContent);
    Exit;
  end;
  if FBatch <> '' then
    FBatch := FBatch + ',';
  FBatch := FBatch + Copy(aContent, 2, Length(aContent) - 2);
  Inc(FBatchCount);
  if (FBatchCount >= MaxBatchResults) or (GetTickCount64 - FBatchSentAt >= MaxBatchMs) then
    FlushResults;
end;

procedure TBlockingTestInsightClient.Send(const AUrl, AContent: string);
var
  LBody, LResponse: TStringStream;
begin
  // a server that stopped answering must not cost a timeout per request
  if FFailedRequests >= MaxFailedRequests then
    Exit;
  LBody := nil;
  LResponse := TStringStream.Create('');
  try
    if AContent <> '' then
      LBody := TStringStream.Create(AContent);
    FHttp.RequestBody := LBody;
    try
      FHttp.AddHeader('Content-Type', 'application/json');
      FHttp.Post(ConcatURL(AUrl), LResponse);
      FInError := False;
      FLastError := '';
      FFailedRequests := 0;
    except
      on E: Exception do
      begin
        Fail(E);
        Inc(FFailedRequests);
        if FFailedRequests = MaxFailedRequests then
          TAndroidTestHost.LogLine(LogWarn, 'TestInsight stopped answering (' + FLastError +
            '); the run goes on in logcat only');
      end;
    end;
  finally
    FHttp.RequestBody := nil;
    LResponse.Free;
    LBody.Free;
  end;
end;

function TBlockingTestInsightClient.ServerGet(aURL: string): string;
var
  LResponse: TStringStream;
begin
  Result := '';
  LResponse := TStringStream.Create('');
  try
    try
      FHttp.Get(ConcatURL(aURL), LResponse);
      Result := LResponse.DataString;
      FInError := False;
      FLastError := '';
    except
      on E: Exception do
        Fail(E);
    end;
  finally
    LResponse.Free;
  end;
end;

procedure TBlockingTestInsightClient.ServerDelete(aURL: string);
begin
  try
    FHttp.Delete(ConcatURL(aURL));
    FInError := False;
    FLastError := '';
  except
    on E: Exception do
      Fail(E);
  end;
end;

// returns how many test cases stay enabled
class function TAndroidTestHost.SkipOutside(AResult: TTestResult; ASuite: TTest; AAllowed: TList;
  AInside: Boolean): Int32;
var
  LI: Int32;
  LTest: TTest;
  LInside: Boolean;
begin
  Result := 0;
  for LI := 0 to ASuite.GetChildTestCount - 1 do
  begin
    LTest := ASuite.GetChildTest(LI);
    LInside := AInside or (AAllowed.IndexOf(LTest) >= 0);
    if LTest is TTestCase then
    begin
      if LInside then
        Inc(Result)
      else
        AResult.AddToSkipList(LTest as TTestCase);
    end
    else
      Inc(Result, SkipOutside(AResult, LTest, AAllowed, LInside));
  end;
end;

// the Suite setting names suites or tests, comma separated
class function TAndroidTestHost.FindAllowed(const ANames: string): TList;
var
  LNames: TStringList;
  LI: Int32;
  LTest: TTest;
begin
  Result := TList.Create;
  LNames := TStringList.Create;
  try
    LNames.CommaText := ANames;
    for LI := 0 to LNames.Count - 1 do
    begin
      LTest := GetTestRegistry.FindTest(LNames[LI]);
      if LTest <> nil then
        Result.Add(LTest)
      else
        LogLine(LogWarn, 'unknown suite ' + LNames[LI]);
    end;
  finally
    LNames.Free;
  end;
end;

class function TAndroidTestHost.JavaToString(AEnv: PJNIEnv; AValue: jstring): string;
var
  LChars: PAnsiChar;
begin
  Result := '';
  if AValue = nil then
    Exit;
  LChars := AEnv^^.GetStringUTFChars(AEnv, AValue, nil);
  if LChars = nil then
    Exit;
  try
    Result := LChars;
  finally
    AEnv^^.ReleaseStringUTFChars(AEnv, AValue, LChars);
  end;
end;

class procedure TAndroidTestHost.RunRegistered(AClient: TAbstractTestInsightClient);
var
  LListener, LLogListener: ITestListener;
  LResult: TTestResult;
  LAllowed: TList;
  LCount: Int32;
begin
  LListener := TTestInsightListener.Create(AClient, GetTestRegistry) as ITestListener;
  // the IDE asks for the test list alone when it only wants to discover
  if not AClient.Options.ExecuteTests then
    Exit;
  LResult := TTestResult.Create;
  try
    LCount := GetTestRegistry.CountTestCases;
    if AClient.Options.TestSuite <> '' then
    begin
      LAllowed := FindAllowed(AClient.Options.TestSuite);
      try
        LCount := SkipOutside(LResult, GetTestRegistry, LAllowed, False);
      finally
        LAllowed.Free;
      end;
    end;
    LogLine(LogInfo, 'running ' + IntToStr(LCount) + ' tests');
    LResult.AddListener(LListener);
    LLogListener := TLogcatListener.Create as ITestListener;
    LResult.AddListener(LLogListener);
    GetTestRegistry.Run(LResult);
  finally
    LResult.Free;
  end;
end;

class function TAndroidTestHost.NativeRun(AEnv: PJNIEnv; AThis: jobject; ABaseUrl: jstring): jint; cdecl;
var
  LClient: TBlockingTestInsightClient;
  LError: AnsiString;
  LException: jclass;
begin
  Result := 0;
  try
    LClient := TBlockingTestInsightClient.Create(JavaToString(AEnv, ABaseUrl));
    try
      LClient.GetServerOptions;
      if LClient.HasError then
      begin
        LError := LClient.LastErrorMessage;
        LException := AEnv^^.FindClass(AEnv, 'java/lang/RuntimeException');
        if LException = nil then
          Result := 1
        else
          AEnv^^.ThrowNew(AEnv, LException, PAnsiChar(LError));
        Exit;
      end;
      if FileExists(SettingsFile) then
        LClient.LoadConfig(SettingsFile);
      RunRegistered(LClient);
    finally
      LClient.Free;
    end;
  except
    on E: Exception do
    begin
      LogLine(LogError, 'run failed: ' + E.ClassName + ': ' + E.Message);
      Result := 1;
    end;
  end;
end;

class function TAndroidTestHost.RegisterHost(AVm: PJavaVM): jint;
var
  LEnv: PJNIEnv;
  LClass: jclass;
  LMethod: JNINativeMethod;
begin
  Result := JNI_ERR;
  if AVm^^.GetEnv(AVm, @LEnv, JNI_VERSION_1_6) <> JNI_OK then
    Exit;
  LClass := LEnv^^.FindClass(LEnv, HostClass);
  if LClass = nil then
    Exit;
  LMethod.name := 'nativeRun';
  LMethod.signature := '(Ljava/lang/String;)I';
  LMethod.fnPtr := @TAndroidTestHost.NativeRun;
  if LEnv^^.RegisterNatives(LEnv, LClass, @LMethod, 1) <> JNI_OK then
    Exit;
  Result := JNI_VERSION_1_6;
end;

initialization
  RaiseMaxFrameCount := 0;
  if GetEnvironmentVariable(WorkDirVariable) <> '' then
    SetCurrentDir(GetEnvironmentVariable(WorkDirVariable));

end.
