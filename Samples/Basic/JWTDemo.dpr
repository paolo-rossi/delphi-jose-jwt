program JWTDemo;

uses
  Vcl.Forms,
  JWTDemo.Form.Main in 'JWTDemo.Form.Main.pas' {frmMain};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TfrmMain, frmMain);
  Application.Run;
end.
