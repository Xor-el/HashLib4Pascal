unit MobileTestHostFormUnit;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  System.IOUtils,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.StdCtrls,
  FMX.Controls.Presentation, FMX.Edit, FMX.Memo.Types, FMX.ScrollBox, FMX.Memo,
  HashLibTestResourceLoader, MobileTestRunner;

type
  TMobileTestHostForm = class(TForm)
    lblBaseUrl: TLabel;
    edtBaseUrl: TEdit;
    btnSaveUrl: TButton;
    lblConnection: TLabel;
    btnRunTests: TButton;
    memLog: TMemo;
    procedure FormShow(Sender: TObject);
    procedure FormActivate(Sender: TObject);
    procedure edtBaseUrlChange(Sender: TObject);
    procedure btnSaveUrlClick(Sender: TObject);
    procedure btnRunTestsClick(Sender: TObject);
  private
    procedure RefreshDataRootSection;
    procedure AppendLog(const ALine: string);
    procedure UpdateConnectionLabel;
    procedure UpdateActionButtons;
  public
  end;

var
  MobileTestHostForm: TMobileTestHostForm;

implementation

{$R *.fmx}

procedure TMobileTestHostForm.AppendLog(const ALine: string);
begin
  if ALine <> '' then
    memLog.Lines.Add(ALine);
end;

procedure TMobileTestHostForm.UpdateConnectionLabel;
var
  LUrl: string;
begin
  LUrl := Trim(edtBaseUrl.Text);
  if not ProbeTestInsightServer(LUrl) then
    lblConnection.Text := 'IDE: enter TestInsight BaseUrl'
  else
    lblConnection.Text := 'IDE: URL set (open TestInsight Explorer)';
end;

procedure TMobileTestHostForm.UpdateActionButtons;
var
  LUrlOk: Boolean;
begin
  LUrlOk := ProbeTestInsightServer(edtBaseUrl.Text);
  btnSaveUrl.Enabled := LUrlOk;
  btnRunTests.Enabled := LUrlOk and not MobileTestsRunning;
end;

procedure TMobileTestHostForm.edtBaseUrlChange(Sender: TObject);
begin
  UpdateConnectionLabel;
  UpdateActionButtons;
end;

procedure TMobileTestHostForm.RefreshDataRootSection;
var
  LDataRoot, LSentinelPath: string;
  LFiles: TArray<string>;
begin
  LDataRoot := THashLibTestResourceLoader.DataRoot;
  memLog.Lines.BeginUpdate;
  try
    memLog.Lines.Clear;
    memLog.Lines.Add('=== Test data ===');
    memLog.Lines.Add('Data root: ' + LDataRoot);
    if LDataRoot = '' then
    begin
      memLog.Lines.Add('(path provider did not resolve a data root)');
      Exit;
    end;
    LSentinelPath := THashLibTestResourceLoader.ResolveRelativePath(LDataRoot,
      THashLibTestResourceLoader.HashLibTestDataSentinel);
    if FileExists(LSentinelPath) then
      memLog.Lines.Add('Sentinel ' + THashLibTestResourceLoader.HashLibTestDataSentinel + ': yes')
    else
      memLog.Lines.Add('Sentinel ' + THashLibTestResourceLoader.HashLibTestDataSentinel + ': no');
    if TDirectory.Exists(LDataRoot) then
    begin
      LFiles := TDirectory.GetFiles(LDataRoot, '*', TSearchOption.soAllDirectories);
      memLog.Lines.Add('file count: ' + IntToStr(Length(LFiles)));
    end
    else
      memLog.Lines.Add('(directory does not exist)');
    memLog.Lines.Add('');
    memLog.Lines.Add('=== Test log ===');
  finally
    memLog.Lines.EndUpdate;
  end;
end;

procedure TMobileTestHostForm.FormShow(Sender: TObject);
begin
  edtBaseUrl.Text := LoadTestInsightBaseUrl;
  UpdateConnectionLabel;
  UpdateActionButtons;
  RefreshDataRootSection;
end;

procedure TMobileTestHostForm.FormActivate(Sender: TObject);
begin
  RefreshDataRootSection;
end;

procedure TMobileTestHostForm.btnSaveUrlClick(Sender: TObject);
begin
  SaveTestInsightBaseUrl(edtBaseUrl.Text);
  UpdateConnectionLabel;
  AppendLog('Saved TestInsight BaseUrl.');
end;

procedure TMobileTestHostForm.btnRunTestsClick(Sender: TObject);
begin
  if MobileTestsRunning then
    Exit;

  SaveTestInsightBaseUrl(edtBaseUrl.Text);
  UpdateConnectionLabel;
  AppendLog('Running tests (TestInsight remote)…');

  RunMobileTestsAsync(edtBaseUrl.Text,
    procedure(const AMessage: string)
    begin
      AppendLog(AMessage);
    end,
    procedure
    begin
      UpdateActionButtons;
      AppendLog('Tests finished.');
    end);
  UpdateActionButtons;
end;

end.
