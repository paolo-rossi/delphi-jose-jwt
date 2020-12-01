object frmConsumer: TfrmConsumer
  Left = 0
  Top = 0
  Caption = 'frmConsumer'
  ClientHeight = 487
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
  PixelsPerInch = 96
  TextHeight = 13
  object memoLog: TMemo
    Left = 0
    Top = 391
    Width = 952
    Height = 96
    Align = alBottom
    Anchors = [akLeft, akTop, akRight, akBottom]
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -12
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    ScrollBars = ssVertical
    TabOrder = 0
  end
  object grpClaims: TGroupBox
    Left = 8
    Top = 8
    Width = 465
    Height = 377
    Caption = 'JWS Builder '
    TabOrder = 1
    object lblIssuedAt: TLabel
      Left = 214
      Top = 68
      Width = 46
      Height = 13
      Caption = 'Issued At'
    end
    object lblExpirationTime: TLabel
      Left = 214
      Top = 114
      Width = 73
      Height = 13
      Caption = 'Expiration Time'
    end
    object lblNotBefore: TLabel
      Left = 214
      Top = 156
      Width = 52
      Height = 13
      Caption = 'Not Before'
    end
    object lblHashAlgorithm: TLabel
      Left = 215
      Top = 26
      Width = 72
      Height = 13
      Caption = 'Hash Algorithm'
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
      Top = 212
      Width = 245
      Height = 28
      Action = actBuildJWS
      Images = imgListMain
      TabOrder = 16
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
      Top = 266
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
      Top = 306
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
      Top = 346
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
  end
  object grpConsumer: TGroupBox
    Left = 479
    Top = 8
    Width = 465
    Height = 377
    Caption = 'JWS Consumer '
    TabOrder = 2
    object lblEvaluationTime: TLabel
      Left = 209
      Top = 68
      Width = 98
      Height = 13
      Caption = 'Evaluation DateTime'
    end
    object btnConsumerBuild: TButton
      Left = 110
      Top = 297
      Width = 245
      Height = 28
      Action = actBuildJWTConsumer
      TabOrder = 0
    end
    object btnBuildJWTCustomConsumer: TButton
      Left = 110
      Top = 263
      Width = 245
      Height = 28
      Action = actBuildJWTCustomConsumer
      TabOrder = 1
    end
    object edtConsumerSecret: TLabeledEdit
      Left = 209
      Top = 41
      Width = 186
      Height = 21
      EditLabel.Width = 31
      EditLabel.Height = 13
      EditLabel.Caption = 'Secret'
      TabOrder = 2
      Text = 'mysecretkey256bitwide(32characters)'
    end
    object chkConsumerSecret: TCheckBox
      Left = 401
      Top = 44
      Width = 73
      Height = 17
      Caption = 'Include'
      Checked = True
      State = cbChecked
      TabOrder = 3
    end
    object chkConsumerSkipVerificationKey: TCheckBox
      Left = 209
      Top = 174
      Width = 193
      Height = 17
      Caption = 'Skip Verification Key Validation'
      TabOrder = 4
    end
    object chkConsumerSetDisableRequireSignature: TCheckBox
      Left = 209
      Top = 144
      Width = 149
      Height = 17
      Caption = 'Disable Require Signature'
      TabOrder = 5
    end
    object edtConsumerSubject: TLabeledEdit
      Left = 10
      Top = 84
      Width = 117
      Height = 21
      EditLabel.Width = 36
      EditLabel.Height = 13
      EditLabel.Caption = 'Subject'
      TabOrder = 6
    end
    object chkConsumerSubject: TCheckBox
      Left = 133
      Top = 86
      Width = 73
      Height = 17
      Caption = 'Include'
      TabOrder = 7
    end
    object edtConsumerAudience: TLabeledEdit
      Left = 10
      Top = 130
      Width = 117
      Height = 21
      EditLabel.Width = 44
      EditLabel.Height = 13
      EditLabel.Caption = 'Audience'
      TabOrder = 8
    end
    object chkConsumerAudience: TCheckBox
      Left = 133
      Top = 132
      Width = 73
      Height = 17
      Caption = 'Include'
      TabOrder = 9
    end
    object edtConsumerIssuer: TLabeledEdit
      Left = 10
      Top = 42
      Width = 117
      Height = 21
      EditLabel.Width = 30
      EditLabel.Height = 13
      EditLabel.Caption = 'Issuer'
      TabOrder = 10
      Text = 'delphi-jose-jwt'
    end
    object chkConsumerIssuer: TCheckBox
      Left = 133
      Top = 44
      Width = 73
      Height = 17
      Caption = 'Include'
      Checked = True
      State = cbChecked
      TabOrder = 11
    end
    object edtConsumerJWTId: TLabeledEdit
      Left = 10
      Top = 172
      Width = 117
      Height = 21
      EditLabel.Width = 34
      EditLabel.Height = 13
      EditLabel.Caption = 'JWT Id'
      TabOrder = 12
      Text = 'xyz123abc456'
    end
    object chkConsumerJWTId: TCheckBox
      Left = 133
      Top = 174
      Width = 73
      Height = 17
      Caption = 'Include'
      Checked = True
      State = cbChecked
      TabOrder = 13
    end
    object edtConsumerEvaluationDate: TDateTimePicker
      Left = 209
      Top = 84
      Width = 106
      Height = 21
      Date = 42207.710233020840000000
      Time = 42207.710233020840000000
      TabOrder = 14
    end
    object chkConsumerIssuedAt: TCheckBox
      Left = 209
      Top = 115
      Width = 69
      Height = 17
      Caption = 'Issued At'
      TabOrder = 15
    end
    object chkConsumerExpires: TCheckBox
      Left = 294
      Top = 115
      Width = 58
      Height = 17
      Caption = 'Expires'
      TabOrder = 16
    end
    object chkConsumerNotBefore: TCheckBox
      Left = 358
      Top = 115
      Width = 80
      Height = 17
      Caption = 'Not Before'
      TabOrder = 17
    end
    object edtSkewTime: TLabeledEdit
      Left = 10
      Top = 219
      Width = 175
      Height = 21
      EditLabel.Width = 100
      EditLabel.Height = 13
      EditLabel.Caption = 'Skew Time (seconds)'
      TabOrder = 18
      Text = '20'
    end
    object edtMaxFutureValidity: TLabeledEdit
      Left = 209
      Top = 219
      Width = 175
      Height = 21
      EditLabel.Width = 140
      EditLabel.Height = 13
      EditLabel.Caption = 'Max Future Validity (minutes)'
      TabOrder = 19
      Text = '30'
    end
    object edtConsumerEvaluationTime: TDateTimePicker
      Left = 321
      Top = 82
      Width = 74
      Height = 23
      Date = 42207.710233020840000000
      Time = 42207.710233020840000000
      Kind = dtkTime
      TabOrder = 20
    end
  end
  object actListMain: TActionList
    Images = imgListMain
    Left = 336
    Top = 352
    object actBuildJWS: TAction
      Caption = 'Build JWS'
      OnExecute = actBuildJWSExecute
    end
    object actBuildJWTConsumer: TAction
      Caption = 'Build Fixed Consumer'
      ImageIndex = 9
      OnExecute = actBuildJWTConsumerExecute
      OnUpdate = actBuildJWTConsumerUpdate
    end
    object actBuildJWTCustomConsumer: TAction
      Caption = 'Build Custom Consumer'
      ImageIndex = 14
      OnExecute = actBuildJWTCustomConsumerExecute
      OnUpdate = actBuildJWTCustomConsumerUpdate
    end
  end
  object imgListMain: TImageList
    ColorDepth = cd32Bit
    DrawingStyle = dsTransparent
    Height = 24
    Width = 24
    Left = 392
    Top = 352
  end
end
