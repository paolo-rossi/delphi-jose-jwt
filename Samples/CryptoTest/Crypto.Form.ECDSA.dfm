object frmCryptoECDSA: TfrmCryptoECDSA
  Left = 0
  Top = 0
  Caption = 'frmCryptoECDSA'
  ClientHeight = 535
  ClientWidth = 975
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object btnSignECDSA: TButton
    Left = 16
    Top = 8
    Width = 99
    Height = 25
    Caption = 'Sign ECDSA'
    TabOrder = 0
    OnClick = btnSignECDSAClick
  end
  object memoPayload: TMemo
    Left = 121
    Top = 8
    Width = 417
    Height = 133
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    Lines.Strings = (
      
        'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw' +
        'ibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0')
    ParentFont = False
    TabOrder = 1
    WantReturns = False
    WordWrap = False
  end
  object memoPrivateKey: TMemo
    Left = 544
    Top = 147
    Width = 417
    Height = 157
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    Lines.Strings = (
      '-----BEGIN PRIVATE KEY-----'
      'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2'
      'OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r'
      '1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G'
      '-----END PRIVATE KEY-----')
    ParentFont = False
    TabOrder = 2
    WantReturns = False
    WordWrap = False
    OnDblClick = memoPrivateKeyDblClick
  end
  object memoSignature: TMemo
    Left = 121
    Top = 147
    Width = 417
    Height = 62
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    Lines.Strings = (
      
        'Mdek0-sDlsDnH2Xmab-5ewVp5bW7Tyo04fNy0PperuD0A7wGvXWxzKPSZglwdSJU' +
        'L5Obcp0BYdM7BEkdLnyiBA')
    ParentFont = False
    TabOrder = 3
    WantReturns = False
    WordWrap = False
  end
  object btnVerify: TButton
    Left = 16
    Top = 39
    Width = 99
    Height = 25
    Caption = 'Verify ECDSA'
    TabOrder = 4
    OnClick = btnVerifyClick
  end
  object memoPublicKey: TMemo
    Left = 544
    Top = 8
    Width = 417
    Height = 133
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    Lines.Strings = (
      '-----BEGIN PUBLIC KEY-----'
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9'
      'q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg=='
      '-----END PUBLIC KEY-----')
    ParentFont = False
    TabOrder = 5
    WantReturns = False
    WordWrap = False
    OnDblClick = memoPublicKeyDblClick
  end
  object memoCertificate: TMemo
    Left = 121
    Top = 310
    Width = 417
    Height = 201
    Lines.Strings = (
      '-----BEGIN CERTIFICATE-----'
      'MIICOTCCAeCgAwIBAgIUQWnyVhCiQKojopQxO9ALluTHt9MwCgYIKoZIzj0EAwIw'
      'dDELMAkGA1UEBhMCSVQxETAPBgNVBAgMCFBpYWNlbnphMREwDwYDVQQHDAhQaWFj'
      'ZW56YTEQMA4GA1UECgwHV2ludGVjaDEOMAwGA1UEAwwFUGFvbG8xHTAbBgkqhkiG'
      '9w0BCQEWDnBhb2xvQHBhb2xvLml0MB4XDTIwMTIyMjEwMzA1N1oXDTIxMTIxNzEw'
      'MzA1N1owdDELMAkGA1UEBhMCSVQxETAPBgNVBAgMCFBpYWNlbnphMREwDwYDVQQH'
      'DAhQaWFjZW56YTEQMA4GA1UECgwHV2ludGVjaDEOMAwGA1UEAwwFUGFvbG8xHTAb'
      'BgkqhkiG9w0BCQEWDnBhb2xvQHBhb2xvLml0MFYwEAYHKoZIzj0CAQYFK4EEAAoD'
      'QgAEGf0QWdIbR7ge3OWyjdkbPZwSiQgBI3Q8UZJx8r2h6as6sxtis7mGJCa0Y8U4'
      '59JBK7/NpA64v87RZrlhhjubKKNTMFEwHQYDVR0OBBYEFASBsmlnUbeJKKsAY2Xz'
      'DzUxnvAYMB8GA1UdIwQYMBaAFASBsmlnUbeJKKsAY2XzDzUxnvAYMA8GA1UdEwEB'
      '/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgGJd7eFlq/UzvICZLNK6omzUA41af'
      'bGxyCHzb347xo9cCIB8sdkJAAjQ82bgpOiDQWFOLmdyN1JYs1XV/vhMZppE8'
      '-----END CERTIFICATE-----')
    TabOrder = 6
    WantReturns = False
    WordWrap = False
    OnDblClick = memoCertificateDblClick
  end
  object btnCertificate: TButton
    Left = 16
    Top = 310
    Width = 99
    Height = 25
    Caption = 'Certificate'
    TabOrder = 7
    OnClick = btnCertificateClick
  end
  object memoPublicKey2: TMemo
    Left = 121
    Top = 215
    Width = 417
    Height = 89
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    Lines.Strings = (
      '-----BEGIN PUBLIC KEY-----'
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9'
      'q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg=='
      '-----END PUBLIC KEY-----')
    ParentFont = False
    TabOrder = 8
    WantReturns = False
    WordWrap = False
    OnDblClick = memoPublicKey2DblClick
  end
  object btnVerifyPublic: TButton
    Left = 16
    Top = 214
    Width = 99
    Height = 25
    Caption = 'Verify PublicKey'
    TabOrder = 9
    OnClick = btnVerifyPublicClick
  end
  object Button1: TButton
    Left = 32
    Top = 360
    Width = 75
    Height = 25
    Caption = 'Button1'
    TabOrder = 10
  end
  object dlgOpenPEMFile: TOpenTextFileDialog
    DefaultExt = '.pem'
    Filter = 'PEM File|*.pem'
    Left = 360
    Top = 288
  end
end
