{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015-2021 Paolo Rossi                                         }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{******************************************************************************}
{                                                                              }
{  Licensed under the Apache License, Version 2.0 (the "License");             }
{  you may not use this file except in compliance with the License.            }
{  You may obtain a copy of the License at                                     }
{                                                                              }
{      http://www.apache.org/licenses/LICENSE-2.0                              }
{                                                                              }
{  Unless required by applicable law or agreed to in writing, software         }
{  distributed under the License is distributed on an "AS IS" BASIS,           }
{  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    }
{  See the License for the specific language governing permissions and         }
{  limitations under the License.                                              }
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
