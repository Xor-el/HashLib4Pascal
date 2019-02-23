unit fmxMainForm;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes,
  System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.StdCtrls,
  FMX.Controls.Presentation, FMX.ScrollBox, FMX.Memo, uPerformanceBenchmark;

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

procedure TMainForm.DoBenchmarkClick(Sender: TObject);
var
  StringList: TStringList;
begin
  mmoBenchmarkLog.SelectAll;
  mmoBenchmarkLog.DeleteSelection;
  mmoBenchmarkLog.Lines.Add('Please be patient, this might take some time' +
    SLineBreak);
  StringList := TStringList.Create;
  try
    TPerformanceBenchmark.DoBenchmark(StringList);
    mmoBenchmarkLog.Lines.AddStrings(StringList);
  finally
    StringList.Free;
  end;
  mmoBenchmarkLog.Lines.Add(SLineBreak + 'Performance Benchmark Finished');
  mmoBenchmarkLog.SelectAll;
  mmoBenchmarkLog.CopyToClipboard;
  mmoBenchmarkLog.Lines.Add(SLineBreak +
    'Benchmark Results Copied to Clipboard');
end;

end.
