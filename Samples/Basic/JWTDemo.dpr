{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

program JWTDemo;

uses
  Vcl.Forms,
  JWTDemo.Form.Main in 'JWTDemo.Form.Main.pas' {frmMain},
  JWTDemo.Form.Debugger in 'JWTDemo.Form.Debugger.pas' {frmDebugger},
  JWTDemo.Form.Misc in 'JWTDemo.Form.Misc.pas' {frmMisc},
  JWTDemo.Form.Simple in 'JWTDemo.Form.Simple.pas' {frmSimple},
  JWTDemo.Form.Consumer in 'JWTDemo.Form.Consumer.pas' {frmConsumer},
  JWTDemo.Form.Claims in 'JWTDemo.Form.Claims.pas' {frmClaims},
  JWTDemo.Form.OpenSSL in 'JWTDemo.Form.OpenSSL.pas' {frmOpenSSL};

{$R *.res}

begin
  {$IFDEF DEBUG}
  ReportMemoryLeaksOnShutdown := True;
  {$ENDIF }
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TfrmMain, frmMain);
  Application.Run;
end.
