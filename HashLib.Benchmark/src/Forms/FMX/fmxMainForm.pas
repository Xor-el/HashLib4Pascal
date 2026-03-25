unit fmxMainForm;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes,
  System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.StdCtrls,
  FMX.Controls.Presentation, FMX.ScrollBox, FMX.Memo, uPerformanceBenchmark, FMX.Memo.Types;

type
  TMainForm = class(TForm)
    mmoBenchmarkLog: TMemo;
    DoBenchmark: TButton;
    procedure DoBenchmarkClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  MainForm: TMainForm;

implementation

{$R *.fmx}

var
  GMemoRef: TMemo;

procedure MemoLog(const AMessage: String);
var
  LMsg: String;
begin
  LMsg := AMessage;
  TThread.Queue(nil,
    procedure
    begin
      if Assigned(GMemoRef) then
        GMemoRef.Lines.Add(LMsg);
    end);
end;

procedure TMainForm.DoBenchmarkClick(Sender: TObject);
begin
  mmoBenchmarkLog.Lines.Clear;
  DoBenchmark.Enabled := False;
  GMemoRef := mmoBenchmarkLog;
  TThread.CreateAnonymousThread(
    procedure
    begin
      try
        TPerformanceBenchmark.Run(MemoLog);
      finally
        TThread.Queue(nil,
          procedure
          begin
            GMemoRef := nil;
            mmoBenchmarkLog.SelectAll;
            mmoBenchmarkLog.CopyToClipboard;
            mmoBenchmarkLog.Lines.Add('');
            mmoBenchmarkLog.Lines.Add('Benchmark results copied to clipboard.');
            DoBenchmark.Enabled := True;
          end);
      end;
    end).Start;
end;

end.
