object frmClaims: TfrmClaims
  Left = 0
  Top = 0
  Caption = 'frmClaims'
  ClientHeight = 273
  ClientWidth = 635
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object Label3: TLabel
    Left = 12
    Top = 44
    Width = 46
    Height = 13
    Caption = 'Issued At'
  end
  object Label4: TLabel
    Left = 12
    Top = 87
    Width = 35
    Height = 13
    Caption = 'Expires'
  end
  object Label5: TLabel
    Left = 12
    Top = 128
    Width = 52
    Height = 13
    Caption = 'Not Before'
  end
  object Label6: TLabel
    Left = 12
    Top = 173
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
    Top = 62
    Width = 74
    Height = 21
    Date = 42207.710233020840000000
    Time = 42207.710233020840000000
    Kind = dtkTime
    TabOrder = 1
  end
  object edtNotBeforeDate: TDateTimePicker
    Left = 12
    Top = 144
    Width = 106
    Height = 21
    Date = 42207.710233020840000000
    Time = 42207.710233020840000000
    TabOrder = 2
  end
  object edtExpiresDate: TDateTimePicker
    Left = 12
    Top = 103
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
    Checked = True
    State = cbChecked
    TabOrder = 4
  end
  object chkIssuedAt: TCheckBox
    Left = 204
    Top = 64
    Width = 73
    Height = 17
    Caption = 'Include'
    Checked = True
    State = cbChecked
    TabOrder = 5
  end
  object chkExpires: TCheckBox
    Left = 204
    Top = 105
    Width = 73
    Height = 17
    Caption = 'Include'
    Checked = True
    State = cbChecked
    TabOrder = 6
  end
  object chkNotBefore: TCheckBox
    Left = 204
    Top = 147
    Width = 73
    Height = 17
    Caption = 'Include'
    Checked = True
    State = cbChecked
    TabOrder = 7
  end
  object btnCustomJWS: TButton
    Left = 12
    Top = 228
    Width = 113
    Height = 25
    Caption = 'Build Custom JWS'
    TabOrder = 8
  end
  object edtIssuedAtDate: TDateTimePicker
    Left = 12
    Top = 62
    Width = 106
    Height = 21
    Date = 42207.710233020840000000
    Time = 42207.710233020840000000
    TabOrder = 9
  end
  object edtExpiresTime: TDateTimePicker
    Left = 124
    Top = 103
    Width = 74
    Height = 21
    Date = 42207.710233020840000000
    Time = 42207.710233020840000000
    Kind = dtkTime
    TabOrder = 10
  end
  object edtNotBeforeTime: TDateTimePicker
    Left = 124
    Top = 144
    Width = 74
    Height = 21
    Date = 42207.710233020840000000
    Time = 42207.710233020840000000
    Kind = dtkTime
    TabOrder = 11
  end
  object cbbAlgorithm: TComboBox
    Left = 12
    Top = 192
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
end
