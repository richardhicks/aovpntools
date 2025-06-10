<#

.SYNOPSIS
    Generate a Certificate Signing Request (CSR) for use with Windows Server Routing and Remote Access Service (RRAS) servers.

.PARAMETER Hostname
    The public hostname in fully qualified domain name (FQDN) format of the VPN server.

.PARAMETER AdditionalNames
    Additional public hostname(s) in fully qualified domain name (FQDN) format of the VPN server.

.PARAMETER EC
    This function generates a 2048-bit RSA key pair by default. Using this parameter will create a key pair using Elliptic Curve (EC) cryptography.

.PARAMETER Exportable
    Allows the private key of the certificate to be exported.

.PARAMETER InfOnly
    Creates the INF file only and does not generate the CSR.

.PARAMETER Online
    Submits the CSR to an online enterprise issuing CA.

.PARAMETER TemplateName
    The name of the certificate template to use for online requests.

.EXAMPLE
    New-CSR -Hostname vpn.example.net

    Generates a CSR with the public hostname vpn.example.net

.EXAMPLE
    New-CSR -Hostname vpn.example.net -AdditionalNames vpn2.example.net, vpn3.example.net

    Generates a CSR with the public hostname vpn.example.net and includes vpn2.example.net and vpn3.example.net in the Subject Alternative Names list.

.EXAMPLE
    New-CSR -Hostname vpn.example.net -EC

    Generates a CSR with the public hostname vpn.example.net using an EC key.

.EXAMPLE
    New-CSR -Hostname vpn.example.net -Exportable

    Generates a CSR with the public hostname vpn.example.net and allows the private key to be exported.

.EXAMPLE
    New-CSR -Hostname vpn.example.net -InfOnly

    Creates an INF file only.

.EXAMPLE
    New-CSR -Hostname vpn.example.net -Online -TemplateName VpnServers

    Generates a CSR with the public hostname vpn.example.net and submits the CSR to an online enterprise issuing CA using the certificate template named VpnServers. Use this option only if the certificate can be issued without CA manager approval.

.DESCRIPTION
    Automates the process of creating an INF file and generating a CSR on Windows Server RRAS servers. Also includes the option to submit the CSR to an online enterprise issuing CA for domain joined servers.

.LINK
    https://github.com/richardhicks/aovpntools/blob/main/Functions/New-Csr.ps1

.NOTES
    Version:        2.3.1
    Creation Date:  June 6, 2022
    Last Updated:   May 20, 2025
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

Function New-Csr {

    [CmdletBinding(SupportsShouldProcess)]

    Param (

        [Parameter(Mandatory, HelpMessage = 'Enter the public hostname of the VPN server')]
        [string]$Hostname,
        [string[]]$AdditionalNames,
        [switch]$EC,
        [switch]$Exportable,
        [switch]$InfOnly,
        [switch]$Online,
        [string]$TemplateName

    )

    # Define file locations
    $InfPath = ".\$env:computername.inf"
    $CsrPath = ".\$env:computername.csr"
    $CerPath = ".\$env:computername.cer"

    # Convert hostname to lower case
    $Hostname = $Hostname.ToLower()
    Write-Verbose "Subject name is $Hostname."

    # Identify wildcard certificate request
    If ($Hostname -Match '\*') {

        Write-Verbose 'Wildcard subject detected.'
        $Wildcard = $Hostname -Replace "^\*\.", ""

    }

    # Create INF file
    Write-Verbose 'Creating INF file...'
    $Inf = @()
    $Inf = { $Inf }.Invoke()

    # Build INF file
    $Inf.Add('[NewRequest]')
    $Inf.Add("Subject = ""CN=$Hostname""")

    If ($Wildcard) {

        $Inf.Add("FriendlyName = $Wildcard")

    }

    Else {

        $Inf.Add("FriendlyName = $Hostname")

    }

    # Define EC key parameters
    If ($EC) {

        Write-Verbose 'Generating CSR using 256-bit EC key...'
        $Inf.Add('KeyAlgorithm = ECDSA_P256')
        $Inf.Add('KeyLength = 256')

    }

    # Define RSA key parameters
    Else {

        Write-Verbose 'Generating CSR using 2048-bit RSA key...'
        $Inf.Add('KeyAlgorithm = RSA')
        $Inf.Add('KeyLength = 2048')

    }

    # Store the private key in the computer certificate store
    $Inf.Add('MachineKeySet = True')

    # Mark key exportable if required
    If ($Exportable) {

        Write-Verbose 'Private key will be marked exportable.'
        $Inf.Add('Exportable = True')

    }

    # Add subject alternative name(s)
    $Inf.Add('')
    $Inf.Add('[Extensions]')
    $Inf.Add('2.5.29.17 = "{text}"')
    $Inf.Add("_continue_ = ""dns=$Hostname&""")

    # Add wildcard hostname to subject alternative name list
    If ($Wildcard) {

        Write-Verbose "Adding $Wildcard to the Subject Alternative Name list..."
        $Inf.Add("_continue_ = ""dns=$Wildcard&""")

    }

    ElseIf ($AdditionalNames) {

        ForEach ($Name in $AdditionalNames) {

            # Add additional names to SAN list that do not match the primary subject name
            If ($Name -Ne $Hostname) {

                Write-Verbose "Adding $Name to the Subject Alternative Name list..."
                $Name = $Name.ToLower()
                $Inf.Add("_continue_ = ""dns=$Name&""")

            }

        }

    }

    # Specify Server Authentication EKU (will be overridden by template information when using the -Online switch)
    $Inf.Add('')
    $Inf.Add('[EnhancedKeyUsageExtension]')
    $Inf.Add('OID=1.3.6.1.5.5.7.3.1')

    # Create INF file
    Write-Verbose "Writing INF file to $InfPath..."
    $Inf | Out-File $InfPath

    If ($InfOnly) {

        Write-Output "INF file saved to $InfPath."
        Return

    }

    Else {

        # Create CSR
        Write-Verbose "Writing CSR file to $CsrPath..."
        [void](Invoke-Command -ScriptBlock { certreq.exe -new $InfPath $CsrPath })

        If (-Not ($Online)) {

            Write-Output "CSR file saved to $CsrPath."
            Return

        }

    }

    If ($Online) {

        # Submit CSR to online enterprise issuing CA
        Write-Verbose "Submitting CSR to issuing CA using $TemplateName certificate template..."
        Invoke-Command -ScriptBlock { certreq.exe -submit -attrib `"CertificateTemplate:$TemplateName`" $CsrPath $CerPath } | Out-Null

        If (Test-Path $CerPath) {

            # Import certificate
            Write-Verbose 'Certificate issued successfully. Importing certificate...'
            Import-Certificate -FilePath $CerPath -CertStoreLocation Cert:\LocalMachine\My | Out-Null

        }

        Else {

            Write-Warning 'The certificate was not issued automatically or failed. Check the issuing CA for details. The certificate may require approval from the CA manager before issuance.'

        }

    }

}

# SIG # Begin signature block
# MIIfnQYJKoZIhvcNAQcCoIIfjjCCH4oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBvd13ULHLrpHhF
# +b0qMqkJk8Apf+QYcbVX7w3Ggi5C6aCCGmIwggNZMIIC36ADAgECAhAPuKdAuRWN
# A1FDvFnZ8EApMAoGCCqGSM49BAMDMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xIDAeBgNVBAMT
# F0RpZ2lDZXJ0IEdsb2JhbCBSb290IEczMB4XDTIxMDQyOTAwMDAwMFoXDTM2MDQy
# ODIzNTk1OVowZDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTwwOgYDVQQDEzNEaWdpQ2VydCBHbG9iYWwgRzMgQ29kZSBTaWduaW5nIEVDQyBT
# SEEzODQgMjAyMSBDQTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAS7tKwnpUgNolNf
# jy6BPi9TdrgIlKKaqoqLmLWx8PwqFbu5s6UiL/1qwL3iVWhga5c0wWZTcSP8GtXK
# IA8CQKKjSlpGo5FTK5XyA+mrptOHdi/nZJ+eNVH8w2M1eHbk+HejggFXMIIBUzAS
# BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSbX7A2up0GrhknvcCgIsCLizh3
# 7TAfBgNVHSMEGDAWgBSz20ik+aHF2K42QcwRY2liKbxLxjAOBgNVHQ8BAf8EBAMC
# AYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdgYIKwYBBQUHAQEEajBoMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQAYIKwYBBQUHMAKGNGh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMy5jcnQw
# QgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0R2xvYmFsUm9vdEczLmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEE
# ATAKBggqhkjOPQQDAwNoADBlAjB4vUmVZXEB0EZXaGUOaKncNgjB7v3UjttAZT8N
# /5Ovwq5jhqN+y7SRWnjsBwNnB3wCMQDnnx/xB1usNMY4vLWlUM7m6jh+PnmQ5KRb
# qwIN6Af8VqZait2zULLd8vpmdJ7QFmMwggP+MIIDhKADAgECAhANSjTahpCPwBMs
# vIE3k68kMAoGCCqGSM49BAMDMGQxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE8MDoGA1UEAxMzRGlnaUNlcnQgR2xvYmFsIEczIENvZGUgU2ln
# bmluZyBFQ0MgU0hBMzg0IDIwMjEgQ0ExMB4XDTI0MTIwNjAwMDAwMFoXDTI3MTIy
# NDIzNTk1OVowgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYw
# FAYDVQQHEw1NaXNzaW9uIFZpZWpvMSQwIgYDVQQKExtSaWNoYXJkIE0uIEhpY2tz
# IENvbnN1bHRpbmcxJDAiBgNVBAMTG1JpY2hhcmQgTS4gSGlja3MgQ29uc3VsdGlu
# ZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFCbtcqpc7vGGM4hVM79U+7f0tKz
# o8BAGMJ/0E7JUwKJfyMJj9jsCNpp61+mBNdTwirEm/K0Vz02vak0Ftcb/3yjggHz
# MIIB7zAfBgNVHSMEGDAWgBSbX7A2up0GrhknvcCgIsCLizh37TAdBgNVHQ4EFgQU
# KIMkVkfISNUyQJ7bwvLm9sCIkxgwPgYDVR0gBDcwNTAzBgZngQwBBAEwKTAnBggr
# BgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA4GA1UdDwEB/wQE
# AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBqwYDVR0fBIGjMIGgME6gTKBKhkho
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxHM0NvZGVTaWdu
# aW5nRUNDU0hBMzg0MjAyMUNBMS5jcmwwTqBMoEqGSGh0dHA6Ly9jcmw0LmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbEczQ29kZVNpZ25pbmdFQ0NTSEEzODQyMDIx
# Q0ExLmNybDCBjgYIKwYBBQUHAQEEgYEwfzAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMFcGCCsGAQUFBzAChktodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRHbG9iYWxHM0NvZGVTaWduaW5nRUNDU0hBMzg0MjAy
# MUNBMS5jcnQwCQYDVR0TBAIwADAKBggqhkjOPQQDAwNoADBlAjBMOsBb80qx6E6S
# 2lnnHafuyY2paoDtPjcfddKaB1HKnAy7WLaEVc78xAC84iW3l6ECMQDhOPD5JHtw
# YxEH6DxVDle5pLKfuyQHiY1i0I9PrSn1plPUeZDTnYKmms1P66nBvCkwggWNMIIE
# daADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAe
# Fw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUw
# EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
# ITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC
# 4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWl
# fr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1j
# KS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dP
# pzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3
# pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJ
# pMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aa
# dMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXD
# j/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB
# 4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ
# 33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amy
# HeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC
# 0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823I
# DzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYD
# VR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcN
# AQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxpp
# VCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6
# mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPH
# h6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCN
# NWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg6
# 2fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwggauMIIElqADAgECAhAHNje3JFR8
# 2Ees/ShmKl5bMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0z
# NzAzMjIyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1
# NiBUaW1lU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQDGhjUGSbPBPXJJUVXHJQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI
# 82j6ffOciQt/nR+eDzMfUBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9
# xBd/qxkrPkLcZ47qUT3w1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ
# 3HxqV3rwN3mfXazL6IRktFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5Emfv
# DqVjbOSmxR3NNg1c1eYbqMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDET
# qVcplicu9Yemj052FVUmcJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHe
# IhTZgirHkr+g3uM+onP65x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jo
# n7ZGs506o9UD4L/wojzKQtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ
# 9FHzNklNiyDSLFc1eSuo80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/T
# Xkt2ElGTyYwMO1uKIqjBJgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJg
# o1gJASgADoRU7s7pXcheMBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkw
# EgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+e
# yG8wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQD
# AgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNy
# dDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglg
# hkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGw
# GC4QTRPPMFPOvxj7x1Bd4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0
# MWfNthKWb8RQTGIdDAiCqBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1D
# X+1gtqpPkWaeLJ7giqzl/Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw
# 1YpxdmXazPByoyP6wCeCRK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY
# +/umnXKvxMfBwWpx2cYTgAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0I
# SQ+UzTl63f8lY5knLD0/a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr
# 5Dhzq6YBT70/O3itTK37xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7y
# Rp11LB4nLCbbbxV7HhmLNriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDop
# hrCYoCvtlUG3OtUVmDG0YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/
# AAvkdgIm2fBldkKmKYcJRyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMO
# Hds3OBqhK/bt1nz8MIIGvDCCBKSgAwIBAgIQC65mvFq6f5WHxvnpBOMzBDANBgkq
# hkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIElu
# Yy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYg
# VGltZVN0YW1waW5nIENBMB4XDTI0MDkyNjAwMDAwMFoXDTM1MTEyNTIzNTk1OVow
# QjELMAkGA1UEBhMCVVMxETAPBgNVBAoTCERpZ2lDZXJ0MSAwHgYDVQQDExdEaWdp
# Q2VydCBUaW1lc3RhbXAgMjAyNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL5qc5/2lSGrljC6W23mWaO16P2RHxjEiDtqmeOlwf0KMCBDEr4IxHRGd7+L
# 660x5XltSVhhK64zi9CeC9B6lUdXM0s71EOcRe8+CEJp+3R2O8oo76EO7o5tLusl
# xdr9Qq82aKcpA9O//X6QE+AcaU/byaCagLD/GLoUb35SfWHh43rOH3bpLEx7pZ7a
# vVnpUVmPvkxT8c2a2yC0WMp8hMu60tZR0ChaV76Nhnj37DEYTX9ReNZ8hIOYe4jl
# 7/r419CvEYVIrH6sN00yx49boUuumF9i2T8UuKGn9966fR5X6kgXj3o5WHhHVO+N
# BikDO0mlUh902wS/Eeh8F/UFaRp1z5SnROHwSJ+QQRZ1fisD8UTVDSupWJNstVki
# qLq+ISTdEjJKGjVfIcsgA4l9cbk8Smlzddh4EfvFrpVNnes4c16Jidj5XiPVdsn5
# n10jxmGpxoMc6iPkoaDhi6JjHd5ibfdp5uzIXp4P0wXkgNs+CO/CacBqU0R4k+8h
# 6gYldp4FCMgrXdKWfM4N0u25OEAuEa3JyidxW48jwBqIJqImd93NRxvd1aepSeNe
# REXAu2xUDEW8aqzFQDYmr9ZONuc2MhTMizchNULpUEoA6Vva7b1XCB+1rxvbKmLq
# fY/M/SdV6mwWTyeVy5Z/JkvMFpnQy5wR14GJcv6dQ4aEKOX5AgMBAAGjggGLMIIB
# hzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggr
# BgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0j
# BBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYDVR0OBBYEFJ9XLAN3DigVkGal
# Y17uT5IfdqBbMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdD
# QS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBp
# bmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAD2tHh92mVvjOIQSR9lDkfYR25tO
# CB3RKE/P09x7gUsmXqt40ouRl3lj+8QioVYq3igpwrPvBmZdrlWBb0HvqT00nFSX
# gmUrDKNSQqGTdpjHsPy+LaalTW0qVjvUBhcHzBMutB6HzeledbDCzFzUy34VarPn
# vIWrqVogK0qM8gJhh/+qDEAIdO/KkYesLyTVOoJ4eTq7gj9UFAL1UruJKlTnCVaM
# 2UeUUW/8z3fvjxhN6hdT98Vr2FYlCS7Mbb4Hv5swO+aAXxWUm3WpByXtgVQxiBlT
# VYzqfLDbe9PpBKDBfk+rabTFDZXoUke7zPgtd7/fvWTlCs30VAGEsshJmLbJ6ZbQ
# /xll/HjO9JbNVekBv2Tgem+mLptR7yIrpaidRJXrI+UzB6vAlk/8a1u7cIqV0yef
# 4uaZFORNekUgQHTqddmsPCEIYQP7xGxZBIhdmm4bhYsVA6G2WgNFYagLDBzpmk91
# 04WQzYuVNsxyoVLObhx3RugaEGru+SojW4dHPoWrUhftNpFC5H7QEY7MhKRyrBe7
# ucykW7eaCuWBsBb4HOKRFVDcrZgdwaSIqMDiCLg4D+TPVgKx2EgEdeoHNHT9l3ZD
# BD+XgbF+23/zBjeCtxz+dL/9NWR6P2eZRi7zcEO1xwcdcqJsyz/JceENc2Sg8h3K
# eFUCS7tpFk7CrDqkMYIEkTCCBI0CAQEweDBkMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xPDA6BgNVBAMTM0RpZ2lDZXJ0IEdsb2JhbCBHMyBD
# b2RlIFNpZ25pbmcgRUNDIFNIQTM4NCAyMDIxIENBMQIQDUo02oaQj8ATLLyBN5Ov
# JDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkG
# CSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
# AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCArI1j9JApTSvnsWMZrDDuL5xOs5u46xEV3
# g96oEsJ7lDALBgcqhkjOPQIBBQAERzBFAiEApUCRLO+5bTMSlCO9cysutSKCYl+K
# wk+S0Ja3spF9kogCIFIpw6c+fRr4TXUblSg2bm2IzU1lNyghuJQxMCvEATjDoYID
# IDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVk
# IEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQC65mvFq6f5WHxvnp
# BOMzBDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEw
# HAYJKoZIhvcNAQkFMQ8XDTI1MDUyMDE5Mjc0NVowLwYJKoZIhvcNAQkEMSIEIJ+c
# PxRV6UzfPIC5XjUQZjdENbmTxH3vJPodDXfo2gzHMA0GCSqGSIb3DQEBAQUABIIC
# ADrc89eIUkjF/3bwpn0dUgKjEHO22w7YasLj35C63WC6GldN4VE8TdpWbpiJGB0B
# 73ybLZEW1IEQcD7vZeSM2guDVSPxOv03SYjPienAALeINJoZ9PRYXfN9pi+nwF6z
# /ee7CBmofun2pjBiH82gOTDMWzskd8WZRWZUtHV3nYKSNILRFH7yVQKy0mxgKdvQ
# 81VEOOKw52xKO8hOMOTzRMLPOfdGsw/VWGu6NHJjqOJsh8csGcLZRMPihhZl2ChL
# sJA/pUioAooOxckmCEWANeF6Y8oGtSjjLcCbbtcsJL1lYo4m/WMieeyRJQM/fTv3
# XlA2R6hmluLi7DVZDsa9QuCgEnK5ERPb/z1Y2XPodObp3YeK1L95xPrxG6HM2aec
# keYsGwwkvAjwUwV8ynKr5Jad9MZ7IEbjnIUZDTtE/KW84B/OFHV7EnKN7blu3ZEr
# RhOva7HVEHHY0JMPqRy1f2uj/TxRiyTRPNuY8k5fNw4POJv8Cj68nPxYgDxXOSXQ
# YDxFGz5ECYVRVD/+egZahhhoS+Ww0XnHmeocipQjUScmWdofUN+5kHCMRePyFKx6
# 4Jgty3bQcr2VHv3rbOw9djr4p8hkQTVQSSRlxEIylr4OObqpDIx+6fs3FPX89Yic
# RomNP1C+q+EAVgxsEzVs2b8nGdV5inyEmL9H+qm0r1xB
# SIG # End signature block
