object frmSimple: TfrmSimple
  Left = 0
  Top = 0
  Caption = 'frmSimple'
  ClientHeight = 488
  ClientWidth = 923
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  DesignSize = (
    923
    488)
  PixelsPerInch = 96
  TextHeight = 13
  object lbl1: TLabel
    Left = 157
    Top = 55
    Width = 91
    Height = 13
    Caption = 'JSON Visualization:'
  end
  object lbl2: TLabel
    Left = 8
    Top = 293
    Width = 107
    Height = 13
    Caption = 'Compact Visualization:'
  end
  object Label6: TLabel
    Left = 8
    Top = 8
    Width = 72
    Height = 13
    Caption = 'Hash Algorithm'
  end
  object btnBuild: TButton
    Left = 8
    Top = 135
    Width = 135
    Height = 25
    Caption = 'Build JWS (JWT && JWK)'
    TabOrder = 0
    OnClick = btnBuildClick
  end
  object btnTJOSEBuild: TButton
    Left = 8
    Top = 73
    Width = 135
    Height = 25
    Caption = 'Build JWS using TJOSE'
    TabOrder = 1
    OnClick = btnTJOSEBuildClick
  end
  object btnTJOSEVerify: TButton
    Left = 8
    Top = 104
    Width = 135
    Height = 25
    Caption = 'Verify JWS using TJOSE'
    TabOrder = 2
    OnClick = btnTJOSEVerifyClick
  end
  object btnTestClaims: TButton
    Left = 8
    Top = 182
    Width = 135
    Height = 25
    Caption = 'Test Date Claims'
    TabOrder = 3
    OnClick = btnTestClaimsClick
  end
  object memoJSON: TMemo
    Left = 157
    Top = 74
    Width = 758
    Height = 207
    Anchors = [akLeft, akTop, akRight]
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    TabOrder = 4
    ExplicitWidth = 662
  end
  object memoCompact: TMemo
    Left = 8
    Top = 312
    Width = 907
    Height = 168
    Anchors = [akLeft, akTop, akRight, akBottom]
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    TabOrder = 5
    ExplicitWidth = 810
    ExplicitHeight = 213
  end
  object cbbAlgorithm: TComboBox
    Left = 8
    Top = 26
    Width = 135
    Height = 21
    Style = csDropDownList
    ItemIndex = 0
    TabOrder = 6
    Text = 'HMAC SHA256'
    Items.Strings = (
      'HMAC SHA256'
      'HMAC SHA384'
      'HMAC SHA512')
  end
  object edtSecret: TLabeledEdit
    Left = 157
    Top = 26
    Width = 758
    Height = 21
    Anchors = [akLeft, akTop, akRight]
    EditLabel.Width = 72
    EditLabel.Height = 13
    EditLabel.Caption = 'Secret (256bit)'
    TabOrder = 7
    Text = 'mysecretkey256bitwide(32characters)'
    OnChange = edtSecretChange
    ExplicitWidth = 661
  end
end
