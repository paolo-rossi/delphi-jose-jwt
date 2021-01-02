object frmClaims: TfrmClaims
  Left = 0
  Top = 0
  Caption = 'frmClaims'
  ClientHeight = 560
  ClientWidth = 952
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  DesignSize = (
    952
    560)
  PixelsPerInch = 96
  TextHeight = 13
  object memoLog: TMemo
    Left = 0
    Top = 464
    Width = 952
    Height = 96
    Align = alBottom
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -12
    Font.Name = 'Courier New'
    Font.Style = []
    Lines.Strings = (
      'memoLog')
    ParentFont = False
    ScrollBars = ssVertical
    TabOrder = 0
  end
  object grpClaims: TGroupBox
    Left = 8
    Top = 8
    Width = 465
    Height = 449
    Caption = 'JWS Builder '
    TabOrder = 1
    object Label3: TLabel
      Left = 214
      Top = 68
      Width = 46
      Height = 13
      Caption = 'Issued At'
    end
    object Label4: TLabel
      Left = 214
      Top = 114
      Width = 73
      Height = 13
      Caption = 'Expiration Time'
    end
    object Label5: TLabel
      Left = 214
      Top = 156
      Width = 52
      Height = 13
      Caption = 'Not Before'
    end
    object Label6: TLabel
      Left = 215
      Top = 26
      Width = 72
      Height = 13
      Caption = 'Hash Algorithm'
    end
    object bvlClaims: TBevel
      Left = 12
      Top = 203
      Width = 443
      Height = 2
    end
    object lblClaims: TLabel
      Left = 174
      Top = 207
      Width = 92
      Height = 16
      Caption = 'Custom Claims'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -13
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object edtIssuer: TLabeledEdit
      Left = 12
      Top = 42
      Width = 117
      Height = 21
      EditLabel.Width = 30
      EditLabel.Height = 13
      EditLabel.Caption = 'Issuer'
      TabOrder = 0
      Text = 'delphi-jose-jwt'
    end
    object edtIssuedAtTime: TDateTimePicker
      Left = 326
      Top = 84
      Width = 74
      Height = 21
      Date = 42207.710233020840000000
      Time = 42207.710233020840000000
      Kind = dtkTime
      TabOrder = 1
    end
    object edtNotBeforeDate: TDateTimePicker
      Left = 214
      Top = 172
      Width = 106
      Height = 21
      Date = 42207.710233020840000000
      Time = 42207.710233020840000000
      TabOrder = 2
    end
    object edtExpiresDate: TDateTimePicker
      Left = 214
      Top = 130
      Width = 106
      Height = 21
      Date = 42757.710233020840000000
      Time = 42757.710233020840000000
      TabOrder = 3
    end
    object chkIssuer: TCheckBox
      Left = 135
      Top = 44
      Width = 73
      Height = 17
      Caption = 'Include'
      TabOrder = 4
    end
    object chkIssuedAt: TCheckBox
      Left = 406
      Top = 86
      Width = 51
      Height = 17
      Caption = 'Include'
      Checked = True
      State = cbChecked
      TabOrder = 5
    end
    object chkExpires: TCheckBox
      Left = 406
      Top = 132
      Width = 51
      Height = 17
      Caption = 'Include'
      Checked = True
      State = cbChecked
      TabOrder = 6
    end
    object chkNotBefore: TCheckBox
      Left = 406
      Top = 174
      Width = 51
      Height = 17
      Caption = 'Include'
      Checked = True
      State = cbChecked
      TabOrder = 7
    end
    object edtIssuedAtDate: TDateTimePicker
      Left = 214
      Top = 84
      Width = 106
      Height = 21
      Date = 42207.710233020840000000
      Time = 42207.710233020840000000
      TabOrder = 8
    end
    object edtExpiresTime: TDateTimePicker
      Left = 326
      Top = 130
      Width = 74
      Height = 21
      Date = 42207.427592592590000000
      Time = 42207.427592592590000000
      Kind = dtkTime
      TabOrder = 9
    end
    object edtNotBeforeTime: TDateTimePicker
      Left = 326
      Top = 172
      Width = 74
      Height = 21
      Date = 42207.710233020840000000
      Time = 42207.710233020840000000
      Kind = dtkTime
      TabOrder = 10
    end
    object cbbAlgorithm: TComboBox
      Left = 214
      Top = 42
      Width = 106
      Height = 21
      Style = csDropDownList
      ItemIndex = 0
      TabOrder = 11
      Text = 'HMAC SHA256'
      Items.Strings = (
        'HMAC SHA256'
        'HMAC SHA384'
        'HMAC SHA512')
    end
    object edtSubject: TLabeledEdit
      Left = 12
      Top = 84
      Width = 117
      Height = 21
      EditLabel.Width = 36
      EditLabel.Height = 13
      EditLabel.Caption = 'Subject'
      TabOrder = 12
      Text = 'paolo-rossi'
    end
    object chkSubject: TCheckBox
      Left = 135
      Top = 86
      Width = 73
      Height = 17
      Caption = 'Include'
      Checked = True
      State = cbChecked
      TabOrder = 13
    end
    object edtAudience: TLabeledEdit
      Left = 12
      Top = 130
      Width = 117
      Height = 21
      EditLabel.Width = 44
      EditLabel.Height = 13
      EditLabel.Caption = 'Audience'
      TabOrder = 14
      Text = 'Luca'
    end
    object chkAudience: TCheckBox
      Left = 135
      Top = 132
      Width = 73
      Height = 17
      Caption = 'Include'
      Checked = True
      State = cbChecked
      TabOrder = 15
    end
    object btnCustomJWS: TButton
      Left = 110
      Top = 283
      Width = 245
      Height = 28
      Caption = 'Build JWS'
      TabOrder = 16
      OnClick = actBuildJWSExecute
    end
    object edtJWTId: TLabeledEdit
      Left = 12
      Top = 172
      Width = 117
      Height = 21
      EditLabel.Width = 34
      EditLabel.Height = 13
      EditLabel.Caption = 'JWT Id'
      TabOrder = 17
      Text = 'xyz123abc456'
    end
    object chkJWTId: TCheckBox
      Left = 135
      Top = 174
      Width = 73
      Height = 17
      Caption = 'Include'
      Checked = True
      State = cbChecked
      TabOrder = 18
    end
    object edtSecret: TLabeledEdit
      Left = 326
      Top = 42
      Width = 131
      Height = 21
      EditLabel.Width = 31
      EditLabel.Height = 13
      EditLabel.Caption = 'Secret'
      TabOrder = 19
      Text = 'mysecretkey256bitwide(32characters)'
    end
    object edtHeader: TLabeledEdit
      Left = 12
      Top = 337
      Width = 445
      Height = 21
      EditLabel.Width = 80
      EditLabel.Height = 13
      EditLabel.Caption = 'Compact Header'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clRed
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = []
      ParentFont = False
      TabOrder = 20
    end
    object edtPayload: TLabeledEdit
      Left = 12
      Top = 377
      Width = 445
      Height = 21
      EditLabel.Width = 83
      EditLabel.Height = 13
      EditLabel.Caption = 'Compact Payload'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clFuchsia
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = []
      ParentFont = False
      TabOrder = 21
    end
    object edtSignature: TLabeledEdit
      Left = 12
      Top = 417
      Width = 445
      Height = 21
      EditLabel.Width = 91
      EditLabel.Height = 13
      EditLabel.Caption = 'Compact Signature'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clTeal
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = []
      ParentFont = False
      TabOrder = 22
    end
    object edtAppIssuer: TLabeledEdit
      Left = 14
      Top = 245
      Width = 115
      Height = 21
      EditLabel.Width = 52
      EditLabel.Height = 13
      EditLabel.Caption = 'App Issuer'
      TabOrder = 23
      Text = 'WiRL REST Library'
    end
    object edtAppSite: TLabeledEdit
      Left = 135
      Top = 245
      Width = 201
      Height = 21
      EditLabel.Width = 40
      EditLabel.Height = 13
      EditLabel.Caption = 'App Site'
      TabOrder = 24
      Text = 'https://github.com/delphi-blocks/WiRL'
    end
    object edtEmail: TLabeledEdit
      Left = 342
      Top = 245
      Width = 115
      Height = 21
      EditLabel.Width = 24
      EditLabel.Height = 13
      EditLabel.Caption = 'Email'
      TabOrder = 25
      Text = 'my@mail.com'
    end
  end
  object memoJSON: TMemo
    Left = 488
    Top = 15
    Width = 456
    Height = 443
    Anchors = [akLeft, akTop, akRight, akBottom]
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    ScrollBars = ssVertical
    TabOrder = 2
  end
end
