<#

.SYNOPSIS
    Configures the trusted root certification authority (CA) to be used for IKEv2 VPN connections on Windows Server Routing and Remote Access Service (RRAS) servers.

.PARAMETER Thumbprint
    Certificate thumbprint of the trusted root CA used for IKEv2 VPN connections.

.PARAMETER Eku
    Enhanced Key Usage (EKU) Object Identifier (OID) to be used for machine certificate EKU filtering.

.PARAMETER EnableCertificateAuthentication
    Enables machine certificate authentication for IKEv2 VPN connections.

.PARAMETER Clear
    Clears the currently configured root CA and machine certificate EKU filtering settings.

.PARAMETER Restart
    Restarts the RemoteAccess service.

.EXAMPLE
    Set-IKEv2VPNRootCertificate -Clear

    Running this command will clear the existing root CA and machine certificate EKU filtering settings.

.EXAMPLE
    Set-IKEv2VPNRootCertificate -Thumbprint '71899A67BF33AF31BEFDC071F8F733B183856332'

    Running this command will configure RRAS to use this CA as the exclusive trusted CA for all IKEv2 VPN connections.

.EXAMPLE
    Set-IKEv2VPNRootCertificate -Thumbprint '71899A67BF33AF31BEFDC071F8F733B183856332' -Eku '1.3.6.1.5.5.7.3.2'

    Running this command will configure RRAS to use this CA as the exclusive trusted CA for all IKEv2 VPN connections and accept only certificates with the 1.3.6.1.5.5.7.3.2 EKU.

.EXAMPLE
    Set-IKEv2VPNRootCertificate -Thumbprint '71899A67BF33AF31BEFDC071F8F733B183856332' -EnableCertificateAuthentication

    Running this command will configure RRAS to use this certification authority as the exclusive trusted CA for all IKEv2 VPN connections. Including the -EnableCertificateAuthentication switch will automatically add Certificate authentication to the list of accepted user authentication protocols (a prerequisite for setting root CA certificate).

.DESCRIPTION
    Use this script to configure the trusted root CA and machine certificate EKU filter settings for IKEv2 VPN connections.

.LINK
    https://github.com/richardhicks/aovpntools/blob/main/Functions/Set-IKEv2VpnRootCertificate.ps1

.LINK
    https://directaccess.richardhicks.com/

.NOTES
    Version:        1.4.5
    Creation Date:  August 2, 2019
    Last Updated:   July 7, 2022
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Web Site:       https://www.richardhicks.com/

#>

Function Set-IKEv2VpnRootCertificate {

    [CmdletBinding(SupportsShouldProcess)]

    Param (

        [string]$Thumbprint,
        [string]$Eku,
        [switch]$EnableCertificateAuthentication,
        [Alias('Reset')]
        [switch]$Clear,
        [switch]$Restart

    )

    # // Clear current root certificate configuration
    If ($Clear) {

        If ($PSCmdlet.ShouldProcess("$env:computername", 'Clear certificate configuration')) {

            Write-Verbose 'Clearing existing root certificate and EKU configuration...'
            Set-VpnAuthProtocol -RootCertificateNameToAccept $Null -CertificateEKUsToAccept $Null | Out-Null

        }

        If ($Restart) {

            Write-Verbose 'Restarting the RemoteAccess Service...'
            Restart-Service RemoteAccess -PassThru

        }

        ElseIf (-Not $Restart) {

            Write-Warning 'The RemoteAccess service must be restarted for these changes to take effect.'

        }

        Return

    }

    # // Get current user authentication protocol configuration
    $VpnAuthProtocol = (Get-VpnAuthProtocol | Select-Object -ExpandProperty UserAuthProtocolAccepted)

    # // Ensure that certificate authentication is enabled
    If ($VpnAuthProtocol -like '*certificate*') {

        Write-Verbose 'Certificate authentication is enabled.'

    }

    ElseIf (-Not $EnableCertificateAuthentication) {

        Write-Warning 'Certificate authentication not enabled. Use the -EnableCertificateAuthentication parameter to configure it.'
        Return

    }

    # // Assign root CA certificate
    $Thumbprint = $Thumbprint.Replace(' ', '')
    $RootCACert = (Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $Thumbprint } | Select-Object -First 1)

    # // Create user authentication protocol array
    $Protocols = @()
    $Protocols = { $Protocols }.Invoke()

    ForEach ($Protocol in $VpnAuthProtocol) {

        $Protocols.Add($Protocol)

    }

    # // Add the Certificate authentication protocol if required
    If ($EnableCertificateAuthentication) {

        $Protocols.Add('Certificate')

    }

    If ($PSCmdlet.ShouldProcess("$env:computername")) {

        Set-VpnAuthProtocol -UserAuthProtocolAccepted $Protocols -RootCertificateNameToAccept $RootCACert | Out-Null

        If ($Eku) {

            Write-Verbose "Using $Eku for the Machine Certificate EKU filter..."
            Set-VpnAuthProtocol -CertificateEKUsToAccept $Eku | Out-Null
            Write-Warning 'Ignore the Machine Certificate EKU filter is invalid warning. This is a bug.'

        }

    }

    # // Validate correct root CA certificate configured
    $ConfiguredThumbprint = (Get-VpnAuthProtocol | Select-Object -ExpandProperty RootCertificateNameToAccept).Thumbprint

    If ($ConfiguredThumbprint -ne $Thumbprint) {

        Write-Warning "Specified root CA certificate $Thumbprint does not match configured certificate $ConfiguredThumbprint. Check root CA certificate store for old certificates."

    }

    If ($Restart) {

        Write-Verbose 'Restarting the RemoteAccess service...'
        Restart-Service RemoteAccess -PassThru

    }

    Else {

        Write-Warning 'The RemoteAccess service must be restarted for these changes to take effect.'

    }

}

# SIG # Begin signature block
# MIInQwYJKoZIhvcNAQcCoIInNDCCJzACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUApYxpjRAfgP/vJMwyB1lMPjW
# 0oyggiDrMIIFsTCCBJmgAwIBAgIQASQK+x44C4oW8UtxnfTTwDANBgkqhkiG9w0B
# AQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMjIwNjA5MDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz
# 7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS
# 5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7
# bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfI
# SKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jH
# trHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14
# Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2
# h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt
# 6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPR
# iQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ER
# ElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4K
# Jpn15GkvmB0t9dmpsh3lGwIDAQABo4IBXjCCAVowDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaG
# NGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3
# DQEBDAUAA4IBAQCaFgKlAe+B+w20WLJ4ragjGdlzN9pgnlHXy/gvQLmjH3xATjM+
# kDzniQF1hehiex1W4HG63l7GN7x5XGIATfhJelFNBjLzxdIAKicg6okuFTngLD74
# dXwsgkFhNQ8j0O01ldKIlSlDy+CmWBB8U46fRckgNxTA7Rm6fnc50lSWx6YR3zQz
# 9nVSQkscnY2W1ZVsRxIUJF8mQfoaRr3esOWRRwOsGAjLy9tmiX8rnGW/vjdOvi3z
# nUrDzMxHXsiVla3Ry7sqBiD5P3LqNutFcpJ6KXsUAzz7TdZIcXoQEYoIdM1sGwRc
# 0oqVA3ZRUFPWLvdKRsOuECxxTLCHtic3RGBEMIIGrjCCBJagAwIBAgIQBzY3tyRU
# fNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UE
# ChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYD
# VQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcN
# MzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQs
# IEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEy
# NTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCwzIP5WvYRoUQVQl+k
# iPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFzsbPuK4CEiiIY3+va
# PcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RB
# idx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn
# 7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/tePc5OsLDnipUjW8LAx
# E6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB
# 3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9KoRxrOMUp88qqlnNC
# aJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWcZklS
# UPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM1+mYSlg+0wOI/rOP
# 015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXi
# YKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbECAwEAAaOCAV0wggFZ
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCP
# nshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQE
# AwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0
# cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
# cnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJ
# YIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULh
# sBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6hCAl
# NDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6q4XN
# Q1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVPulr3qRCyXen/KFSJ
# 8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmBo1aGqwpFyd/EjaDn
# mPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsd
# CEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3cHXg65J6t5TRxktcm
# a+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+
# 8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZPJ/tgZxahZrrdVcA6
# KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C+dAj
# fwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucT
# Dh3bNzgaoSv27dZ8/DCCBrAwggSYoAMCAQICEAitQLJg0pxMn17Nqb2TrtkwDQYJ
# KoZIhvcNAQEMBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IElu
# YzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQg
# VHJ1c3RlZCBSb290IEc0MB4XDTIxMDQyOTAwMDAwMFoXDTM2MDQyODIzNTk1OVow
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4
# NCAyMDIxIENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANW0L0LQ
# KK14t13VOVkbsYhC9TOM6z2Bl3DFu8SFJjCfpI5o2Fz16zQkB+FLT9N4Q/QX1x7a
# +dLVZxpSTw6hV/yImcGRzIEDPk1wJGSzjeIIfTR9TIBXEmtDmpnyxTsf8u/LR1oT
# pkyzASAl8xDTi7L7CPCK4J0JwGWn+piASTWHPVEZ6JAheEUuoZ8s4RjCGszF7pNJ
# cEIyj/vG6hzzZWiRok1MghFIUmjeEL0UV13oGBNlxX+yT4UsSKRWhDXW+S6cqgAV
# 0Tf+GgaUwnzI6hsy5srC9KejAw50pa85tqtgEuPo1rn3MeHcreQYoNjBI0dHs6EP
# bqOrbZgGgxu3amct0r1EGpIQgY+wOwnXx5syWsL/amBUi0nBk+3htFzgb+sm+YzV
# svk4EObqzpH1vtP7b5NhNFy8k0UogzYqZihfsHPOiyYlBrKD1Fz2FRlM7WLgXjPy
# 6OjsCqewAyuRsjZ5vvetCB51pmXMu+NIUPN3kRr+21CiRshhWJj1fAIWPIMorTmG
# 7NS3DVPQ+EfmdTCN7DCTdhSmW0tddGFNPxKRdt6/WMtyEClB8NXFbSZ2aBFBE1ia
# 3CYrAfSJTVnbeM+BSj5AR1/JgVBzhRAjIVlgimRUwcwhGug4GXxmHM14OEUwmU//
# Y09Mu6oNCFNBfFg9R7P6tuyMMgkCzGw8DFYRAgMBAAGjggFZMIIBVTASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBRoN+Drtjv4XxGG+/5hewiIZfROQjAfBgNV
# HSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYD
# VR0lBAwwCgYIKwYBBQUHAwMwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRSb290RzQuY3JsMBwGA1UdIAQVMBMwBwYFZ4EMAQMwCAYGZ4EMAQQBMA0G
# CSqGSIb3DQEBDAUAA4ICAQA6I0Q9jQh27o+8OpnTVuACGqX4SDTzLLbmdGb3lHKx
# AMqvbDAnExKekESfS/2eo3wm1Te8Ol1IbZXVP0n0J7sWgUVQ/Zy9toXgdn43ccsi
# 91qqkM/1k2rj6yDR1VB5iJqKisG2vaFIGH7c2IAaERkYzWGZgVb2yeN258TkG19D
# +D6U/3Y5PZ7Umc9K3SjrXyahlVhI1Rr+1yc//ZDRdobdHLBgXPMNqO7giaG9OeE4
# Ttpuuzad++UhU1rDyulq8aI+20O4M8hPOBSSmfXdzlRt2V0CFB9AM3wD4pWywiF1
# c1LLRtjENByipUuNzW92NyyFPxrOJukYvpAHsEN/lYgggnDwzMrv/Sk1XB+JOFX3
# N4qLCaHLC+kxGv8uGVw5ceG+nKcKBtYmZ7eS5k5f3nqsSc8upHSSrds8pJyGH+PB
# VhsrI/+PteqIe3Br5qC6/To/RabE6BaRUotBwEiES5ZNq0RA443wFSjO7fEYVgcq
# LxDEDAhkPDOPriiMPMuPiAsNvzv0zh57ju+168u38HcT5ucoP6wSrqUvImxB+YJc
# FWbMbA7KxYbD9iYzDAdLoNMHAmpqQDBISzSoUSC7rRuFCOJZDW3KBVAr6kocnqX9
# oKcfBnTn8tZSkP2vhUgh+Vc7tJwD7YZF9LRhbr9o4iZghurIr6n+lB3nYxs6hlZ4
# TjCCBsYwggSuoAMCAQICEAp6SoieyZlCkAZjOE2Gl50wDQYJKoZIhvcNAQELBQAw
# YzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQD
# EzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGlu
# ZyBDQTAeFw0yMjAzMjkwMDAwMDBaFw0zMzAzMTQyMzU5NTlaMEwxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEkMCIGA1UEAxMbRGlnaUNlcnQg
# VGltZXN0YW1wIDIwMjIgLSAyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEAuSqWI6ZcvF/WSfAVghj0M+7MXGzj4CUu0jHkPECu+6vE43hdflw26vUljUOj
# ges4Y/k8iGnePNIwUQ0xB7pGbumjS0joiUF/DbLW+YTxmD4LvwqEEnFsoWImAdPO
# w2z9rDt+3Cocqb0wxhbY2rzrsvGD0Z/NCcW5QWpFQiNBWvhg02UsPn5evZan8Pyx
# 9PQoz0J5HzvHkwdoaOVENFJfD1De1FksRHTAMkcZW+KYLo/Qyj//xmfPPJOVToTp
# dhiYmREUxSsMoDPbTSSF6IKU4S8D7n+FAsmG4dUYFLcERfPgOL2ivXpxmOwV5/0u
# 7NKbAIqsHY07gGj+0FmYJs7g7a5/KC7CnuALS8gI0TK7g/ojPNn/0oy790Mj3+fD
# WgVifnAs5SuyPWPqyK6BIGtDich+X7Aa3Rm9n3RBCq+5jgnTdKEvsFR2wZBPlOyG
# Yf/bES+SAzDOMLeLD11Es0MdI1DNkdcvnfv8zbHBp8QOxO9APhk6AtQxqWmgSfl1
# 4ZvoaORqDI/r5LEhe4ZnWH5/H+gr5BSyFtaBocraMJBr7m91wLA2JrIIO/+9vn9s
# Exjfxm2keUmti39hhwVo99Rw40KV6J67m0uy4rZBPeevpxooya1hsKBBGBlO7Ueb
# YZXtPgthWuo+epiSUc0/yUTngIspQnL3ebLdhOon7v59emsCAwEAAaOCAYswggGH
# MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsG
# AQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAfBgNVHSME
# GDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUjWS3iSH+VlhEhGGn
# 6m8cNo/drw0wWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NB
# LmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3Nw
# LmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2VydHMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGlu
# Z0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEADS0jdKbR9fjqS5k/AeT2DOSvFp3Z
# s4yXgimcQ28BLas4tXARv4QZiz9d5YZPvpM63io5WjlO2IRZpbwbmKrobO/RSGkZ
# OFvPiTkdcHDZTt8jImzV3/ZZy6HC6kx2yqHcoSuWuJtVqRprfdH1AglPgtalc4jE
# mIDf7kmVt7PMxafuDuHvHjiKn+8RyTFKWLbfOHzL+lz35FO/bgp8ftfemNUpZYkP
# opzAZfQBImXH6l50pls1klB89Bemh2RPPkaJFmMga8vye9A140pwSKm25x1gvQQi
# FSVwBnKpRDtpRxHT7unHoD5PELkwNuTzqmkJqIt+ZKJllBH7bjLx9bs4rc3AkxHV
# MnhKSzcqTPNc3LaFwLtwMFV41pj+VG1/calIGnjdRncuG3rAM4r4SiiMEqhzzy35
# 0yPynhngDZQooOvbGlGglYKOKGukzp123qlzqkhqWUOuX+r4DwZCnd8GaJb+KqB0
# W2Nm3mssuHiqTXBt8CzxBxV+NbTmtQyimaXXFWs1DoXW4CzM4AwkuHxSCx6ZfO/I
# yMWMWGmvqz3hz8x9Fa4Uv4px38qXsdhH6hyF4EVOEhwUKVjMb9N/y77BDkpvIJyu
# 2XMyWQjnLZKhGhH+MpimXSuX4IvTnMxttQ2uR2M4RxdbbxPaahBuH0m3RFu0CAqH
# WlkEdhGhp3cCExwwggcCMIIE6qADAgECAhABZnISBJVCuLLqeeLTB6xEMA0GCSqG
# SIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNB
# NDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjExMjAyMDAwMDAwWhcNMjQxMjIwMjM1
# OTU5WjCBhjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNV
# BAcTDU1pc3Npb24gVmllam8xJDAiBgNVBAoTG1JpY2hhcmQgTS4gSGlja3MgQ29u
# c3VsdGluZzEkMCIGA1UEAxMbUmljaGFyZCBNLiBIaWNrcyBDb25zdWx0aW5nMIIB
# ojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA6svrVqBRBbazEkrmhtz7h05L
# EBIHp8fGlV19nY2gpBLnkDR8Mz/E9i1cu0sdjieC4D4/WtI4/NeiR5idtBgtdek5
# eieRjPcn8g9Zpl89KIl8NNy1UlOWNV70jzzqZ2CYiP/P5YGZwPy8Lx5rIAOYTJM6
# EFDBvZNti7aRizE7lqVXBDNzyeHhfXYPBxaQV2It+sWqK0saTj0oNA2Iu9qSYaFQ
# LFH45VpletKp7ded2FFJv2PKmYrzYtax48xzUQq2rRC5BN2/n7771NDfJ0t8udRh
# UBqTEI5Z1qzMz4RUVfgmGPT+CaE55NyBnyY6/A2/7KSIsOYOcTgzQhO4jLmjTBZ2
# kZqLCOaqPbSmq/SutMEGHY1MU7xrWUEQinczjUzmbGGw7V87XI9sn8EcWX71PEvI
# 2Gtr1TJfnT9betXDJnt21mukioLsUUpdlRmMbn23or/VHzE6Nv7Kzx+tA1sBdWdC
# 3Mkzaw/Mm3X8Wc7ythtXGBcLmBagpMGCCUOk6OJZAgMBAAGjggIGMIICAjAfBgNV
# HSMEGDAWgBRoN+Drtjv4XxGG+/5hewiIZfROQjAdBgNVHQ4EFgQUxF7do+eIG9wn
# EUVjckZ9MsbZ+4kwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEu
# Y3JsMFOgUaBPhk1odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDA+BgNVHSAE
# NzA1MDMGBmeBDAEEATApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0
# LmNvbS9DUFMwgZQGCCsGAQUFBwEBBIGHMIGEMCQGCCsGAQUFBzABhhhodHRwOi8v
# b2NzcC5kaWdpY2VydC5jb20wXAYIKwYBBQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNI
# QTM4NDIwMjFDQTEuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AEvHt/OKalRysHQdx4CXSOcgoayuFXWNwi/VFcFr2EK37Gq71G4AtdVcWNLu+whh
# YzfCVANBnbTa9vsk515rTM06exz0QuMwyg09mo+VxZ8rqOBHz33xZyCoTtw/+D/S
# QxiO8uQR0Oisfb1MUHPqDQ69FTNqIQF/RzC2zzUn5agHFULhby8wbjQfUt2FXCRl
# FULPzvp7/+JS4QAJnKXq5mYLvopWsdkbBn52Kq+ll8efrj1K4iMRhp3a0n2eRLet
# qKJjOqT335EapydB4AnphH2WMQBHHroh5n/fv37dCCaYaqo9JlFnRIrHU7pHBBEp
# UGfyecFkcKFwsPiHXE1HqQJCPmMbvPdV9ZgtWmuaRD0EQW13JzDyoQdJxQZSXJhD
# DL+VSFS8SRNPtQFPisZa2IO58d1Cvf5G8iK1RJHN/Qx413lj2JSS1o3wgNM3Q5eP
# FYXcQ0iPxjFYlRYPAaDx8t3olg/tVK8sSpYqFYF99IRqBNixhkyxAyVCk6uLBLgw
# E9egJg1AFoHEdAeabGgT2C0hOyz55PNoDZutZB67G+WN8kGtFYULBloRKHJJiFn4
# 2bvXfa0Jg1jZ41AAsMc5LUNlqLhIj/RFLinDH9l4Yb0ddD4wQVsIFDVlJgDPXA9E
# 1Sn8VKrWE4I0sX4xXUFgjfuVfdcNk9Q+4sJJ1YHYGmwLMYIFwjCCBb4CAQEwfTBp
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMT
# OERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0
# IDIwMjEgQ0ExAhABZnISBJVCuLLqeeLTB6xEMAkGBSsOAwIaBQCgeDAYBgorBgEE
# AYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRIiWo/
# D67onkPHknSgGyIWB0ELoTANBgkqhkiG9w0BAQEFAASCAYCKugHE6BLBeP3aOMD9
# N2nv/vaXjbZoOA2r2EM6hnKh0EHwIcMkPMQG/es0vrCymH1C481+f7CekEwxBZOg
# kQipLPid8vkhjuPONPs49b7MGF5p0Wf46R7DyG6PG3mU1PnZ8jQfGnYYnEg83MRi
# SKo7a1c4cvZ/MP9BW0f8mdpMirlRbDJwqF0o+G5ZlLcFBcCS3A0PhLXKAR874O+R
# 6yizw0E6l/GA+JbSFJ/1JE7bzcLPH30I9yAKITZA5JvXrzlfMQEqiJaXvrs7etqR
# y+M/qw/K6+CfkfFq/u5bbjjtdzgF1PPx12ZCgEX4sPCpOnnwS6Zk22l1u8G3Nvrd
# /xvgPgBhhGk2QA3Tx7lCYO+oOyDUo0cxQl6F+H3Mc+bs7FjAcnF1Pym/L+yvLPOm
# dUhGKVsDxxG60n4U18PdWI3fyWecIyauPPQfQkRgfzpNKjb7HQ9nyZVa0a7oKlOC
# XROAb2hog+lY14Cw/ulrvX6xJTNwevhMnFXbb5xGmJe4ACuhggMgMIIDHAYJKoZI
# hvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5
# NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAKekqInsmZQpAGYzhNhpedMA0GCWCG
# SAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0B
# CQUxDxcNMjIwNzA3MTcxNDA1WjAvBgkqhkiG9w0BCQQxIgQg3aUPq4NXstaEqzXy
# EC0aS/Bg9Xcb4zL3lBY/w6orr2swDQYJKoZIhvcNAQEBBQAEggIAYaV0MWaejtVm
# zR+a6E5L0vxDS5U9gWQsqQBysnthv6pgbknhznJfi8WwrDOMxQq3yY5ScQM7Uu0y
# ds6hAhFZDEY0qJIGQhnIoCn3QSNnGSTTdDtbLgZv0ydGr3h1XD5pKhp3FPPT/j2t
# +Dk/d0VviYPUtqjMTqbuzxr/ijZfvQjN+9f5WmrYprZUhg2gDW0JyRKzj5bslR1v
# 6EUJrTnMfeImawSheQ22iuuhsUl5K7B/I6JFDFcdNH2x4Os+p9UNAuklqnA+eLVa
# NFp62Q2BdiAq71e/42txupXWZxRhJ9BXyf2a6+3J/sEPMdf5QY+9RRlP1iaYsu0r
# TgD5+qxLW9lXCmQglT/V8Ox50M3cSa/gm1aRygFKyWKgqw8jF/sGcFJ3GEAxRMVF
# iIMBdkRB9EXSU5E0PiGkfWG0Z+fZUeh+Zzp6T0DjJJGIPMVagh7sQXdmFeEdNBJu
# 8nsdOYzD6kgyBQ/rahQmBVS3Azj/OCQuzuFlF2s0vs5H96/G/YsOp9BHU7Lz8wTQ
# fQf5p1hsRtpqtnml7GUyq5FICbagKw2ezkfc2NApuKDrQy/T9bubZA/P+aMTzLR4
# nlmo/gUQTl4UXKsd5q4L5M/Zqi7ZCZEoPzFgfHDCiyrtdTO4XsV2hWW4FMSmbZl5
# UTIwW8HRDswqLca1wZCeOL8yVH8TVlU=
# SIG # End signature block
