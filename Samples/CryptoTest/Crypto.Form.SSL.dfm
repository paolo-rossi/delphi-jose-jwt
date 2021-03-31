object frmCryptoSSL: TfrmCryptoSSL
  Left = 0
  Top = 0
  Caption = 'frmCryptoSSL'
  ClientHeight = 488
  ClientWidth = 870
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object Button1: TButton
    Left = 8
    Top = 8
    Width = 75
    Height = 25
    Caption = 'Verify JWT'
    TabOrder = 0
    OnClick = Button1Click
  end
  object Memo1: TMemo
    Left = 0
    Top = 406
    Width = 870
    Height = 82
    Align = alBottom
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    Lines.Strings = (
      
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxOSIsImtpZCI6MTE' +
        'sImlzcyI6IlZhbGxleSBBZyBTb2Z0d2FyZSIsImV4cCI6MTUzNzg4ODc0NTczNSw' +
        'iaWF0IjoxNTM3ODg4MTQ1NzM1fQ.I3sKRx6eckfdk9kPW_qSG0KVBBI45Sbd0fVR' +
        'v52S3ty9SxuWutl5vruZs3Jb15Bh9qTjGnM2uQsI6UO-FffXM4IfWaDha72Z3dvW' +
        'x8E5QlDRICTo_nZVCVFz27EdXXmHI6MnNJR33AeTCW4xsN2AF7QUrrZNqfP4uDuT' +
        '2x6t-Q8')
    ParentFont = False
    TabOrder = 1
    WordWrap = False
  end
  object btnBuildKey: TButton
    Left = 89
    Top = 8
    Width = 75
    Height = 25
    Caption = 'Build Key'
    TabOrder = 2
    OnClick = btnBuildKeyClick
  end
  object Edit1: TEdit
    Left = 8
    Top = 101
    Width = 121
    Height = 21
    TabOrder = 3
    Text = 'sgjhlk6jp98ugp98up34hpexample'
  end
  object btnURLDecode: TButton
    Left = 135
    Top = 99
    Width = 75
    Height = 25
    Caption = 'URL Decode'
    TabOrder = 4
    OnClick = btnURLDecodeClick
  end
  object Edit2: TEdit
    Left = 216
    Top = 101
    Width = 121
    Height = 21
    TabOrder = 5
    Text = 'Edit2'
  end
  object edtJWTIO: TEdit
    Left = 8
    Top = 371
    Width = 849
    Height = 24
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    TabOrder = 6
    Text = 
      'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw' +
      'iYWRtaW4iOnRydWV9.NgquTGyA7sRTOpJqH8-XaUbjs68V_A9eaEvtTXpLwe48Jz' +
      'U9CKeDiRiyMQtdT0c41GaPRv0yH7-ftsQ852_6F1aSjLriwb-uTm_pLFuKbCKbNM' +
      'E13IhO03MZWEfDDV3NGyXke89botxlFQe9hTDXFvXrTQFeFtzYKcp0WBr4FJdwtv' +
      'gYsh5s2E9ovUfnM2SmMkoBqM4YbILNw5o7hWrmYfFxeMB0CgUI7zMcMPcNg5Gm8K' +
      '5iWXmODi2_ItaXQ8yUjjA5H8qeQjMC0dNAy00zXHFIkcigMPttU6Kw-uNGys77Wj' +
      'SMhC6ilgKGy9kuXPy8z9bIvtMgGePrVgGRtZceTg'
  end
  object memoPrivateKey: TMemo
    Left = 440
    Top = 147
    Width = 417
    Height = 133
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    Lines.Strings = (
      '-----BEGIN EC PRIVATE KEY-----'
      'MHcCAQEEIAmYAINcs/onN/yIgK+AUagHUPLnKAg/f+Tvo46JDhTBoAoGCCqGSM49'
      'AwEHoUQDQgAEpxD52WR65kGaNMX9dGl444fATtISwqqIE6SVqAZK+3xA0b5LW/SS'
      '8XTvmwGcPi4th1JuWvKpSWIGwQ3+6xh8hA=='
      '-----END EC PRIVATE KEY-----')
    ParentFont = False
    TabOrder = 7
    WantReturns = False
    WordWrap = False
  end
  object btnECDSASign: TButton
    Left = 170
    Top = 8
    Width = 75
    Height = 25
    Caption = 'ECDSA Sign'
    TabOrder = 8
    OnClick = btnECDSASignClick
  end
  object btnECDSAVerify: TButton
    Left = 170
    Top = 39
    Width = 75
    Height = 25
    Caption = 'ECDSA Verify'
    TabOrder = 9
    OnClick = btnECDSAVerifyClick
  end
  object memoSignature: TMemo
    Left = 440
    Top = 286
    Width = 417
    Height = 62
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    Lines.Strings = (
      'Signature')
    ParentFont = False
    TabOrder = 10
  end
  object memoPayload: TMemo
    Left = 440
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
    TabOrder = 11
    WantReturns = False
    WordWrap = False
  end
  object Button2: TButton
    Left = 8
    Top = 39
    Width = 75
    Height = 25
    Caption = 'B64URLEncode'
    TabOrder = 12
    OnClick = Button2Click
  end
  object btnSSLVersion: TButton
    Left = 89
    Top = 39
    Width = 75
    Height = 25
    Caption = 'SSL Version'
    TabOrder = 13
    OnClick = btnSSLVersionClick
  end
  object memoPublicKey: TMemo
    Left = 8
    Top = 149
    Width = 417
    Height = 133
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    Lines.Strings = (
      '-----BEGIN PUBLIC KEY-----'
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpxD52WR65kGaNMX9dGl444fATtIS'
      'wqqIE6SVqAZK+3xA0b5LW/SS8XTvmwGcPi4th1JuWvKpSWIGwQ3+6xh8hA=='
      '-----END PUBLIC KEY-----')
    ParentFont = False
    TabOrder = 14
    WantReturns = False
    WordWrap = False
  end
  object btnCertificate: TButton
    Left = 8
    Top = 70
    Width = 75
    Height = 25
    Caption = 'Certificate'
    TabOrder = 15
    OnClick = btnCertificateClick
  end
  object memoCertificate: TMemo
    Left = 8
    Top = 288
    Width = 417
    Height = 193
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
    TabOrder = 16
    WantReturns = False
    WordWrap = False
  end
  object btnPublicKeyFromCert: TButton
    Left = 89
    Top = 68
    Width = 156
    Height = 27
    Caption = 'Public Key From Cert'
    TabOrder = 17
    OnClick = btnPublicKeyFromCertClick
  end
end
