object frmClaims: TfrmClaims
  Left = 0
  Top = 0
  Caption = 'frmClaims'
  ClientHeight = 375
  ClientWidth = 635
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object Label3: TLabel
    Left = 12
    Top = 142
    Width = 46
    Height = 13
    Caption = 'Issued At'
  end
  object Label4: TLabel
    Left = 12
    Top = 185
    Width = 73
    Height = 13
    Caption = 'Expiration Time'
  end
  object Label5: TLabel
    Left = 12
    Top = 226
    Width = 52
    Height = 13
    Caption = 'Not Before'
  end
  object Label6: TLabel
    Left = 12
    Top = 269
    Width = 72
    Height = 13
    Caption = 'Hash Algorithm'
  end
  object edtIssuer: TLabeledEdit
    Left = 12
    Top = 21
    Width = 186
    Height = 21
    EditLabel.Width = 30
    EditLabel.Height = 13
    EditLabel.Caption = 'Issuer'
    TabOrder = 0
  end
  object edtIssuedAtTime: TDateTimePicker
    Left = 124
    Top = 160
    Width = 74
    Height = 21
    Date = 42207.710233020840000000
    Time = 42207.710233020840000000
    Kind = dtkTime
    TabOrder = 1
  end
  object edtNotBeforeDate: TDateTimePicker
    Left = 12
    Top = 242
    Width = 106
    Height = 21
    Date = 42207.710233020840000000
    Time = 42207.710233020840000000
    TabOrder = 2
  end
  object edtExpiresDate: TDateTimePicker
    Left = 12
    Top = 201
    Width = 106
    Height = 21
    Date = 42207.710233020840000000
    Time = 42207.710233020840000000
    TabOrder = 3
  end
  object chkIssuer: TCheckBox
    Left = 204
    Top = 23
    Width = 73
    Height = 17
    Caption = 'Include'
    TabOrder = 4
  end
  object chkIssuedAt: TCheckBox
    Left = 204
    Top = 162
    Width = 73
    Height = 17
    Caption = 'Include'
    TabOrder = 5
  end
  object chkExpires: TCheckBox
    Left = 204
    Top = 203
    Width = 73
    Height = 17
    Caption = 'Include'
    TabOrder = 6
  end
  object chkNotBefore: TCheckBox
    Left = 204
    Top = 245
    Width = 73
    Height = 17
    Caption = 'Include'
    TabOrder = 7
  end
  object btnCustomJWS: TButton
    Left = 12
    Top = 324
    Width = 113
    Height = 25
    Caption = 'Build Custom JWS'
    TabOrder = 8
    OnClick = btnCustomJWSClick
  end
  object edtIssuedAtDate: TDateTimePicker
    Left = 12
    Top = 160
    Width = 106
    Height = 21
    Date = 42207.710233020840000000
    Time = 42207.710233020840000000
    TabOrder = 9
  end
  object edtExpiresTime: TDateTimePicker
    Left = 124
    Top = 201
    Width = 74
    Height = 21
    Date = 42207.710233020840000000
    Time = 42207.710233020840000000
    Kind = dtkTime
    TabOrder = 10
  end
  object edtNotBeforeTime: TDateTimePicker
    Left = 124
    Top = 242
    Width = 74
    Height = 21
    Date = 42207.710233020840000000
    Time = 42207.710233020840000000
    Kind = dtkTime
    TabOrder = 11
  end
  object cbbAlgorithm: TComboBox
    Left = 12
    Top = 288
    Width = 186
    Height = 21
    Style = csDropDownList
    ItemIndex = 0
    TabOrder = 12
    Text = 'HMAC SHA256'
    Items.Strings = (
      'HMAC SHA256'
      'HMAC SHA384'
      'HMAC SHA512')
  end
  object Button1: TButton
    Left = 336
    Top = 8
    Width = 75
    Height = 25
    Caption = 'Button1'
    TabOrder = 13
    OnClick = Button1Click
  end
  object Button2: TButton
    Left = 417
    Top = 8
    Width = 75
    Height = 25
    Caption = 'Button2'
    TabOrder = 14
    OnClick = Button2Click
  end
  object Memo1: TMemo
    Left = 336
    Top = 41
    Width = 185
    Height = 89
    Lines.Strings = (
      'Memo1')
    TabOrder = 15
  end
  object btnConsumer: TButton
    Left = 344
    Top = 160
    Width = 75
    Height = 25
    Caption = 'btnConsumer'
    TabOrder = 16
  end
  object edtSubject: TLabeledEdit
    Left = 12
    Top = 67
    Width = 186
    Height = 21
    EditLabel.Width = 36
    EditLabel.Height = 13
    EditLabel.Caption = 'Subject'
    TabOrder = 17
  end
  object chkSubject: TCheckBox
    Left = 204
    Top = 69
    Width = 73
    Height = 17
    Caption = 'Include'
    TabOrder = 18
  end
  object edtAudience: TLabeledEdit
    Left = 12
    Top = 109
    Width = 186
    Height = 21
    EditLabel.Width = 44
    EditLabel.Height = 13
    EditLabel.Caption = 'Audience'
    TabOrder = 19
  end
  object chkAudience: TCheckBox
    Left = 204
    Top = 111
    Width = 73
    Height = 17
    Caption = 'Include'
    TabOrder = 20
  end
  object Button3: TButton
    Left = 432
    Top = 256
    Width = 75
    Height = 25
    Caption = 'Button3'
    TabOrder = 21
    OnClick = Button3Click
  end
end
