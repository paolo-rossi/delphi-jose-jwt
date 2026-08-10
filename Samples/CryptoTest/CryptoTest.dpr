{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

program CryptoTest;

uses
  Vcl.Forms,
  JOSE.OpenSSL.Headers in '..\..\Source\Common\JOSE.OpenSSL.Headers.pas',
  JOSE.Signing.Base in '..\..\Source\Common\JOSE.Signing.Base.pas',
  Crypto.Form.SSL in 'Crypto.Form.SSL.pas' {frmCryptoSSL},
  Crypto.Form.ECDSA in 'Crypto.Form.ECDSA.pas' {frmCryptoECDSA},
  Crypto.Form.RSA in 'Crypto.Form.RSA.pas' {frmCryptoRSA},
  Crypto.Form.Main in 'Crypto.Form.Main.pas' {frmMain};

{$R *.res}

begin
  ReportMemoryLeaksOnShutdown := True;
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TfrmMain, frmMain);
  Application.Run;
end.
