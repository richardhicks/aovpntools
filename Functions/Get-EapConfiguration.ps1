<#

.SYNOPSIS
    Extract EAP configuration from existing Windows VPN connection.

.PARAMETER ConnectionName
    The name of the VPN connection to extract the EAP configuration from.

.PARAMETER xmlFilePath
    The full path and name of the file to export EAP configuration to.

.EXAMPLE
    Get-EapConfiguration -ConnectionName 'Test VPN Connection'

    Extracts the EAP configuration from a VPN connection named "Test VPN Connection". The file will be automatically saved as eapconfig.xml in the location where the script was executed from.

.EXAMPLE
    Get-EapConfiguration -ConnectionName 'Test VPN Connection' -AllUserConnection

    Extracts the EAP configuration from a VPN connection named "Test VPN Connection" that is configured in the "all users" context. The file will be automatically saved as eapconfig.xml in the location where the script was executed from.

.EXAMPLE
    Get-EapConfiguration -ConnectionName 'Test VPN Connection' -xmlFilePath 'C:\temp\eapconfig.xml'

    Extracts the EAP configuration from a VPN connection named "Test VPN Connection" and the file is saved to a custom location.

.DESCRIPTION
    Use this script to extract the EAP configuration from an existing VPN connection. The output XML can be copied and pasted in to ProfileXML for configuring Windows Always On VPN connections.

.LINK
    https://github.com/richardhicks/aovpntools/blob/main/Functions/Get-EapConfiguration.ps1

.LINK
    https://directaccess.richardhicks.com/

.NOTES
    Version:        1.4.4
    Creation Date:  May 27, 2019
    Last Updated:   June 6, 2022
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Web Site:       https://www.richardhicks.com/

#>

Function Get-EapConfiguration {

    [CmdletBinding()]

    Param (

        [Parameter(Mandatory, HelpMessage = "Enter the name of the VPN template connection.")]
        [Alias('Name')]
        [string]$ConnectionName,
        [string]$xmlFilePath = '.\eapconfig.xml',
        [switch]$AllUserConnection

    )

    # // Format XML
    Function Format-XML ([xml]$Xml, $indent = 3) {

        $StringWriter = New-Object System.IO.StringWriter
        $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
        $XmlWriter.Formatting = "Indented"
        $XmlWriter.Indentation = $Indent
        $Xml.WriteContentTo($XmlWriter)
        $XmlWriter.Flush()
        $StringWriter.Flush()
        Write-Output $StringWriter.ToString()

    } # // end function

    # // Validate VPN connection
    If ($AllUserConnection) {

        $VPN = Get-VpnConnection -Name $ConnectionName -AllUserConnection -ErrorAction SilentlyContinue
    }

    Else {

        $Vpn = Get-VpnConnection -Name $ConnectionName -ErrorAction SilentlyContinue

    }

    If ($null -eq $Vpn) {

        Write-Warning "The VPN connection ""$ConnectionName"" does not exist."
        Return

    }

    # // Create EAP configuration object
    Write-Verbose "Extracting EAP configuration from template connection $ConnectionName"
    $EapConfig = $Vpn.EapConfigXmlStream.InnerXml

    # // Validate EAP authentication is configured
    If ($Null -eq $EapConfig) {

        Write-Warning "The VPN connection ""$ConnectionName"" is not configured to use EAP authentication."
        Return

    }

    # // Remove existing EAP configuration file if it exists
    If (Test-Path $xmlFilePath) {

        Write-Verbose 'Old EAP configuration file found. Deleting...'
        Remove-Item $xmlFilePath

    }

    # // Convert text stream to XML format
    Write-Verbose 'Saving EAP configuration to file...'
    Format-XML $EapConfig | Out-File $xmlFilePath

    Write-Output "EAP configuration saved to $xmlFilePath."

}

# SIG # Begin signature block
# MIIhjgYJKoZIhvcNAQcCoIIhfzCCIXsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUCFhjUDW72/bGJK5JONBTSUpe
# 5Nugghs2MIIGrjCCBJagAwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0B
# AQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVk
# IFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKR
# N6mXUaHW0oPRnkyibaCwzIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZz
# lm34V6gCff1DtITaEfFzsbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1Oco
# LevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH
# 92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRA
# p8ByxbpOH7G1WE15/tePc5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+g
# GkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU
# 8lKVEStYdEAoq3NDzt9KoRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/
# FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwj
# jVj33GHek/45wPmyMKVM1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQ
# EgN9XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUae
# tdN2udIOa5kM0jO0zbECAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# HQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LS
# cV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
# BQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYy
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftw
# ig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalW
# zxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQm
# h2ySvZ180HAKfO+ovHVPulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScb
# qyQeJsG33irr9p6xeZmBo1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLaf
# zYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbD
# Qc1PtkCbISFA0LcTJM3cHXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0K
# XzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm
# 8heZWcpw8De/mADfIBZPJ/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9
# gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8a
# pIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBrAwggSY
# oAMCAQICEAitQLJg0pxMn17Nqb2TrtkwDQYJKoZIhvcNAQEMBQAwYjELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIx
# MDQyOTAwMDAwMFoXDTM2MDQyODIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0
# IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMTCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBANW0L0LQKK14t13VOVkbsYhC9TOM6z2Bl3DF
# u8SFJjCfpI5o2Fz16zQkB+FLT9N4Q/QX1x7a+dLVZxpSTw6hV/yImcGRzIEDPk1w
# JGSzjeIIfTR9TIBXEmtDmpnyxTsf8u/LR1oTpkyzASAl8xDTi7L7CPCK4J0JwGWn
# +piASTWHPVEZ6JAheEUuoZ8s4RjCGszF7pNJcEIyj/vG6hzzZWiRok1MghFIUmje
# EL0UV13oGBNlxX+yT4UsSKRWhDXW+S6cqgAV0Tf+GgaUwnzI6hsy5srC9KejAw50
# pa85tqtgEuPo1rn3MeHcreQYoNjBI0dHs6EPbqOrbZgGgxu3amct0r1EGpIQgY+w
# OwnXx5syWsL/amBUi0nBk+3htFzgb+sm+YzVsvk4EObqzpH1vtP7b5NhNFy8k0Uo
# gzYqZihfsHPOiyYlBrKD1Fz2FRlM7WLgXjPy6OjsCqewAyuRsjZ5vvetCB51pmXM
# u+NIUPN3kRr+21CiRshhWJj1fAIWPIMorTmG7NS3DVPQ+EfmdTCN7DCTdhSmW0td
# dGFNPxKRdt6/WMtyEClB8NXFbSZ2aBFBE1ia3CYrAfSJTVnbeM+BSj5AR1/JgVBz
# hRAjIVlgimRUwcwhGug4GXxmHM14OEUwmU//Y09Mu6oNCFNBfFg9R7P6tuyMMgkC
# zGw8DFYRAgMBAAGjggFZMIIBVTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQW
# BBRoN+Drtjv4XxGG+/5hewiIZfROQjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/
# 57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdwYI
# KwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9j
# cmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMBwGA1Ud
# IAQVMBMwBwYFZ4EMAQMwCAYGZ4EMAQQBMA0GCSqGSIb3DQEBDAUAA4ICAQA6I0Q9
# jQh27o+8OpnTVuACGqX4SDTzLLbmdGb3lHKxAMqvbDAnExKekESfS/2eo3wm1Te8
# Ol1IbZXVP0n0J7sWgUVQ/Zy9toXgdn43ccsi91qqkM/1k2rj6yDR1VB5iJqKisG2
# vaFIGH7c2IAaERkYzWGZgVb2yeN258TkG19D+D6U/3Y5PZ7Umc9K3SjrXyahlVhI
# 1Rr+1yc//ZDRdobdHLBgXPMNqO7giaG9OeE4Ttpuuzad++UhU1rDyulq8aI+20O4
# M8hPOBSSmfXdzlRt2V0CFB9AM3wD4pWywiF1c1LLRtjENByipUuNzW92NyyFPxrO
# JukYvpAHsEN/lYgggnDwzMrv/Sk1XB+JOFX3N4qLCaHLC+kxGv8uGVw5ceG+nKcK
# BtYmZ7eS5k5f3nqsSc8upHSSrds8pJyGH+PBVhsrI/+PteqIe3Br5qC6/To/RabE
# 6BaRUotBwEiES5ZNq0RA443wFSjO7fEYVgcqLxDEDAhkPDOPriiMPMuPiAsNvzv0
# zh57ju+168u38HcT5ucoP6wSrqUvImxB+YJcFWbMbA7KxYbD9iYzDAdLoNMHAmpq
# QDBISzSoUSC7rRuFCOJZDW3KBVAr6kocnqX9oKcfBnTn8tZSkP2vhUgh+Vc7tJwD
# 7YZF9LRhbr9o4iZghurIr6n+lB3nYxs6hlZ4TjCCBsYwggSuoAMCAQICEAp6Soie
# yZlCkAZjOE2Gl50wDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0
# IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yMjAzMjkwMDAwMDBa
# Fw0zMzAzMTQyMzU5NTlaMEwxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjEkMCIGA1UEAxMbRGlnaUNlcnQgVGltZXN0YW1wIDIwMjIgLSAyMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuSqWI6ZcvF/WSfAVghj0M+7M
# XGzj4CUu0jHkPECu+6vE43hdflw26vUljUOjges4Y/k8iGnePNIwUQ0xB7pGbumj
# S0joiUF/DbLW+YTxmD4LvwqEEnFsoWImAdPOw2z9rDt+3Cocqb0wxhbY2rzrsvGD
# 0Z/NCcW5QWpFQiNBWvhg02UsPn5evZan8Pyx9PQoz0J5HzvHkwdoaOVENFJfD1De
# 1FksRHTAMkcZW+KYLo/Qyj//xmfPPJOVToTpdhiYmREUxSsMoDPbTSSF6IKU4S8D
# 7n+FAsmG4dUYFLcERfPgOL2ivXpxmOwV5/0u7NKbAIqsHY07gGj+0FmYJs7g7a5/
# KC7CnuALS8gI0TK7g/ojPNn/0oy790Mj3+fDWgVifnAs5SuyPWPqyK6BIGtDich+
# X7Aa3Rm9n3RBCq+5jgnTdKEvsFR2wZBPlOyGYf/bES+SAzDOMLeLD11Es0MdI1DN
# kdcvnfv8zbHBp8QOxO9APhk6AtQxqWmgSfl14ZvoaORqDI/r5LEhe4ZnWH5/H+gr
# 5BSyFtaBocraMJBr7m91wLA2JrIIO/+9vn9sExjfxm2keUmti39hhwVo99Rw40KV
# 6J67m0uy4rZBPeevpxooya1hsKBBGBlO7UebYZXtPgthWuo+epiSUc0/yUTngIsp
# QnL3ebLdhOon7v59emsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNV
# HRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYG
# Z4EMAQQCMAsGCWCGSAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGog
# j57IbzAdBgNVHQ4EFgQUjWS3iSH+VlhEhGGn6m8cNo/drw0wWgYDVR0fBFMwUTBP
# oE2gS4ZJaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
# UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMw
# gYAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEF
# BQcwAoZMaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsF
# AAOCAgEADS0jdKbR9fjqS5k/AeT2DOSvFp3Zs4yXgimcQ28BLas4tXARv4QZiz9d
# 5YZPvpM63io5WjlO2IRZpbwbmKrobO/RSGkZOFvPiTkdcHDZTt8jImzV3/ZZy6HC
# 6kx2yqHcoSuWuJtVqRprfdH1AglPgtalc4jEmIDf7kmVt7PMxafuDuHvHjiKn+8R
# yTFKWLbfOHzL+lz35FO/bgp8ftfemNUpZYkPopzAZfQBImXH6l50pls1klB89Bem
# h2RPPkaJFmMga8vye9A140pwSKm25x1gvQQiFSVwBnKpRDtpRxHT7unHoD5PELkw
# NuTzqmkJqIt+ZKJllBH7bjLx9bs4rc3AkxHVMnhKSzcqTPNc3LaFwLtwMFV41pj+
# VG1/calIGnjdRncuG3rAM4r4SiiMEqhzzy350yPynhngDZQooOvbGlGglYKOKGuk
# zp123qlzqkhqWUOuX+r4DwZCnd8GaJb+KqB0W2Nm3mssuHiqTXBt8CzxBxV+NbTm
# tQyimaXXFWs1DoXW4CzM4AwkuHxSCx6ZfO/IyMWMWGmvqz3hz8x9Fa4Uv4px38qX
# sdhH6hyF4EVOEhwUKVjMb9N/y77BDkpvIJyu2XMyWQjnLZKhGhH+MpimXSuX4IvT
# nMxttQ2uR2M4RxdbbxPaahBuH0m3RFu0CAqHWlkEdhGhp3cCExwwggcCMIIE6qAD
# AgECAhABZnISBJVCuLLqeeLTB6xEMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQg
# VHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEw
# HhcNMjExMjAyMDAwMDAwWhcNMjQxMjIwMjM1OTU5WjCBhjELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1pc3Npb24gVmllam8xJDAi
# BgNVBAoTG1JpY2hhcmQgTS4gSGlja3MgQ29uc3VsdGluZzEkMCIGA1UEAxMbUmlj
# aGFyZCBNLiBIaWNrcyBDb25zdWx0aW5nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A
# MIIBigKCAYEA6svrVqBRBbazEkrmhtz7h05LEBIHp8fGlV19nY2gpBLnkDR8Mz/E
# 9i1cu0sdjieC4D4/WtI4/NeiR5idtBgtdek5eieRjPcn8g9Zpl89KIl8NNy1UlOW
# NV70jzzqZ2CYiP/P5YGZwPy8Lx5rIAOYTJM6EFDBvZNti7aRizE7lqVXBDNzyeHh
# fXYPBxaQV2It+sWqK0saTj0oNA2Iu9qSYaFQLFH45VpletKp7ded2FFJv2PKmYrz
# Ytax48xzUQq2rRC5BN2/n7771NDfJ0t8udRhUBqTEI5Z1qzMz4RUVfgmGPT+CaE5
# 5NyBnyY6/A2/7KSIsOYOcTgzQhO4jLmjTBZ2kZqLCOaqPbSmq/SutMEGHY1MU7xr
# WUEQinczjUzmbGGw7V87XI9sn8EcWX71PEvI2Gtr1TJfnT9betXDJnt21mukioLs
# UUpdlRmMbn23or/VHzE6Nv7Kzx+tA1sBdWdC3Mkzaw/Mm3X8Wc7ythtXGBcLmBag
# pMGCCUOk6OJZAgMBAAGjggIGMIICAjAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5h
# ewiIZfROQjAdBgNVHQ4EFgQUxF7do+eIG9wnEUVjckZ9MsbZ+4kwDgYDVR0PAQH/
# BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+G
# TWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVT
# aWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3Js
# NC5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQw
# OTZTSEEzODQyMDIxQ0ExLmNybDA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsG
# AQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwgZQGCCsGAQUFBwEB
# BIGHMIGEMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYI
# KwYBBQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAwGA1Ud
# EwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAEvHt/OKalRysHQdx4CXSOcgoayu
# FXWNwi/VFcFr2EK37Gq71G4AtdVcWNLu+whhYzfCVANBnbTa9vsk515rTM06exz0
# QuMwyg09mo+VxZ8rqOBHz33xZyCoTtw/+D/SQxiO8uQR0Oisfb1MUHPqDQ69FTNq
# IQF/RzC2zzUn5agHFULhby8wbjQfUt2FXCRlFULPzvp7/+JS4QAJnKXq5mYLvopW
# sdkbBn52Kq+ll8efrj1K4iMRhp3a0n2eRLetqKJjOqT335EapydB4AnphH2WMQBH
# Hroh5n/fv37dCCaYaqo9JlFnRIrHU7pHBBEpUGfyecFkcKFwsPiHXE1HqQJCPmMb
# vPdV9ZgtWmuaRD0EQW13JzDyoQdJxQZSXJhDDL+VSFS8SRNPtQFPisZa2IO58d1C
# vf5G8iK1RJHN/Qx413lj2JSS1o3wgNM3Q5ePFYXcQ0iPxjFYlRYPAaDx8t3olg/t
# VK8sSpYqFYF99IRqBNixhkyxAyVCk6uLBLgwE9egJg1AFoHEdAeabGgT2C0hOyz5
# 5PNoDZutZB67G+WN8kGtFYULBloRKHJJiFn42bvXfa0Jg1jZ41AAsMc5LUNlqLhI
# j/RFLinDH9l4Yb0ddD4wQVsIFDVlJgDPXA9E1Sn8VKrWE4I0sX4xXUFgjfuVfdcN
# k9Q+4sJJ1YHYGmwLMYIFwjCCBb4CAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# Q29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhABZnISBJVCuLLq
# eeLTB6xEMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkG
# CSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
# AYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRQW9YQ5e5avMIoTKo7N/BtLPvV9DANBgkq
# hkiG9w0BAQEFAASCAYC5xxT17S3TkJR8iE7qBJYGRZQcx3eKh0a7h3D4kk3JEGoF
# pWbcgTAOjktUEod2T/fzVvQ2hRTXVX0TWT6C/b1e5xdyoyiV/qI3CKcvavJX8inp
# KhE0onyWPtpFnKhE1tU27wZi3hvNVmxoQVJqKE5vCfsb+YaHmaAPBHt+h47+6Jfz
# 1Xal+Ye6rnt0ANx2+pUnxssnd1n/Wzuqq90S1Ripg5x4fGCcBSmXMkj0f80rVUkC
# AXLmfL3CA0uewNa4aZ12B2+3k3jMHrlvKcn78iTjrmg/9XnvI9k5p9hPwjTF/duh
# cUhEZhBHSXkP0dSVuRLVu1yPiy41YT/zzUnYBSePWSTMSdszZEUZ0HFk5I9DyiCL
# f1ojYA0D/DT4FbmGAoeNfCGogVqLerMC27dwtfZSXaIXWsHhVDaf3x/gbL+eYahE
# INqnXWEBCzPmd488B6j+MmPPiKvAQJM3lxgezE81kS9W5pxDHWIN61VclAIwOK5/
# livRgJtEnjG7YcoMIBKhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBj
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMT
# MkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5n
# IENBAhAKekqInsmZQpAGYzhNhpedMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcN
# AQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjIwNjA2MjIwMzM0WjAv
# BgkqhkiG9w0BCQQxIgQg3ivSlUN50t1ZTMFJJWMQvL+NKPXRIx4a2nNJWll7Bs8w
# DQYJKoZIhvcNAQEBBQAEggIAsGIhguSCPnMmAQr3AoXGVaeVEsL66ktipRzZuyeQ
# h5bxREedHAdmeH4LsFyoMttrSBrLSpv0G52DJhWf9Jnfhl1jwjuB51UlRZDjflWH
# z8raCJNEYsnu/gwHy8yt+zEjDnGql2sQkBGuN85W4zByqiW5ZfgP0WdplQdGVJgn
# 09H0BJ82mPO/mzHjhNpi2LvnQz2pKs0ck1PiM43NuNRSFHzolcnEbLX/u95bcGQb
# geac7+K5o7jIG6nWYAlpdJWfH70oZCFZPnXRVjTlqGboHgSr075u28jqQYjvAJ/R
# ElBbHkVUlq2aByVdzB85oMyh8tMiReuhmS2KCAxe1ehTjC13VsVAGHAHzemU6sGj
# qti/yxuRaRGwTm1A/tetgEhPuzcDJc7b/dl3+LGhPcFWMqMusblvpqqXIQd75jUW
# v36tAPfJpYF8r5MxjHWJTBxa/L0OilLNlOdU3B33IBnAty3bsAOUrB5WeWGSzlyk
# w35I6ygMnQ6PiWAOSGmh0958K1AGmVsFb6q/crpqQzcowTpw0oTKHZZfbvj11G0N
# tWB39HhFpNKp04oh0f3YRL0ZqvY0/b2FN/rGtGhSc2EFj0q1wcUNuBORLrLtKjwQ
# QGmfwgCuZe9iNDQ2jju8oR8bSo3l7moZicil55MtKxPybm9O8nVwlhLuid79dy9E
# ZmU=
# SIG # End signature block
