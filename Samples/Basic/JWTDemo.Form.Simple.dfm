object frmSimple: TfrmSimple
  Left = 0
  Top = 0
  Caption = 'frmSimple'
  ClientHeight = 518
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
    518)
  PixelsPerInch = 96
  TextHeight = 13
  object lblJSON: TLabel
    Left = 157
    Top = 55
    Width = 91
    Height = 13
    Caption = 'JSON Visualization:'
  end
  object lblCompact: TLabel
    Left = 8
    Top = 301
    Width = 107
    Height = 13
    Caption = 'Compact Visualization:'
  end
  object lblAlgorithm: TLabel
    Left = 8
    Top = 8
    Width = 72
    Height = 13
    Caption = 'Hash Algorithm'
  end
  object btnBuildClasses: TButton
    Left = 8
    Top = 104
    Width = 135
    Height = 25
    Caption = 'Build JWS using classes'
    TabOrder = 0
    OnClick = btnBuildClassesClick
  end
  object btnBuildTJOSE: TButton
    Left = 8
    Top = 73
    Width = 135
    Height = 25
    Caption = 'Build JWS using TJOSE'
    TabOrder = 1
    OnClick = btnBuildTJOSEClick
  end
  object btnVerifyTJOSE: TButton
    Left = 8
    Top = 152
    Width = 135
    Height = 25
    Caption = 'Verify JWS using TJOSE'
    TabOrder = 2
    OnClick = btnVerifyTJOSEClick
  end
  object btnTestClaims: TButton
    Left = 8
    Top = 264
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
    Height = 215
    Anchors = [akLeft, akTop, akRight]
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    TabOrder = 4
  end
  object memoCompact: TMemo
    Left = 8
    Top = 320
    Width = 907
    Height = 190
    Anchors = [akLeft, akTop, akRight, akBottom]
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    TabOrder = 5
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
  end
  object btnDeserializeTJOSE: TButton
    Left = 8
    Top = 215
    Width = 135
    Height = 25
    Caption = 'Deserialize using TJOSE'
    TabOrder = 8
    OnClick = btnDeserializeTJOSEClick
  end
  object btnVerifyClasses: TButton
    Left = 8
    Top = 183
    Width = 135
    Height = 25
    Caption = 'Verify JWS using classes'
    TabOrder = 9
    OnClick = btnVerifyClassesClick
  end
end
