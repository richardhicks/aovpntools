<#

.SYNOPSIS
    View and optionally save to a file the Transport Layer Security (TLS) certificate for a public website or service using HTTPS.

.PARAMETER Hostname
    The server name or Fully Qualified Domain Name (FQDN) of the target resource.

.PARAMETER Port
    The TCP port of the target resource. The default is 443.

.PARAMETER OutFile
    When this parameter is added the TLS certificate will be saved as a file in this location.

.EXAMPLE
    Get-TlsCertificate -Hostname 'www.richardhicks.com'

    Displays the TLS certificate for the website https://www.richardhicks.com/.

.EXAMPLE
    Get-TlsCertificate -Hostname 'www.richardhicks.com' -Port 8443

    Displays the TLS certificate for the website https://www.richardhicks.com/ listening on the nonstandard port 8443.

.EXAMPLE
    Get-TlsCertificate-Hostname 'www.richardhicks.com, www.richardhicks.net'

    Displays the TLS certificates for the websites https://www.richardhicks.com/ and https://www.richardhicks.net/.

.EXAMPLE
    Get-TlsCertificate -Hostname 'www.richardhicks.com' -OutFile .\tlscert.cer

    Displays the TLS certificate for the website https://www.richardhicks.com/ and saves the certificate to a file named .\tlscert.cer.

.DESCRIPTION
    This PowerShell script is helpful for troubleshooting TLS issues associated with public websites or other HTTPS services like TLS VPNs. Using this script, administrators can view and optionally save the certificate returned during the TLS handshake. Administrators can confirm certificate details and perform revocation checks, if necessary.

.INPUTS
    String[]]

    The Hostname parameter accepts a string array of public host names.

.OUTPUTS
    System.Management.Automation.PSCustomObject

    The output of this script is a custom object that contains the following properties:

    Subject            - The subject name of the certificate.
    Issuer             - The issuer name of the certificate.
    Thumbprint         - The thumbprint of the certificate.
    NotBefore          - The date and time the certificate is valid from.
    NotAfter           - The date and time the certificate expires.
    SerialNumber       - The serial number of the certificate.
    SignatureAlgorithm - The signature algorithm used by the certificate.
    PublicKeyAlgorithm - The public key algorithm used by the certificate.
    KeySize            - The size of the public key in bits.

    If the OutFile parameter is specified, the certificate will be saved to a file in PEM format.

.LINK
    https://github.com/richardhicks/aovpntools/blob/main/Functions/Get-TlsCertificate.ps1

.LINK
    https://directaccess.richardhicks.com/

.NOTES
    Version:        2.1
    Creation Date:  August 12, 2021
    Last Updated:   September 4, 2025
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

Function Get-TlsCertificate {

    [CmdletBinding()]

    Param (

        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]$Hostname,
        [int]$Port = 443,
        [string]$OutFile

    )

    Process {

        $FileIndex = 1

        ForEach ($Server in $Hostname) {

            # Initialize certificate object
            $Certificate = $Null

            # Create a TCP client object
            $TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient

            # Connect to the remote host
            Try {

                Write-Verbose "Connecting to $Server on port $Port..."
                Try {

                    $TcpClient.Connect($Server, $Port)

                }

                Catch {

                    Write-Warning "Failed to connect to $Server on port $Port."
                    Continue

                }

                # Create a TCP stream object
                $TcpStream = $TcpClient.GetStream()

                # Create an SSL stream object with a validation callback
                $Callback = {

                    Param($Source, $Cert, $Chain, [System.Net.Security.SslPolicyErrors]$Errors)
                    If ($Errors -ne [System.Net.Security.SslPolicyErrors]::None) {

                        Write-Verbose "Ignoring certificate validation errors: $Errors"

                    }

                    $True

                }

                $SslStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList @($TcpStream, $true, $Callback)

                # Retrieve the TLS certificate
                Try {

                    Write-Verbose 'Retrieving TLS certificate...'
                    $SslStream.AuthenticateAsClient($Server)
                    $Certificate = $SslStream.RemoteCertificate

                }

                Catch {

                    Write-Warning "Unable to retrieve TLS certificate from $Server."
                    Continue

                }

                Finally {

                    # Cleanup
                    $SslStream.Dispose()

                }

            }

            Finally {

                # Cleanup
                $TcpClient.Dispose()

            }

            # Output certificate properties as an object
            If ($Certificate) {

                If ($Certificate -IsNot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {

                    Write-Verbose 'Converting certificate to X509Certificate2 object...'
                    $Certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $Certificate

                }

                # Create custom object and populate with certificate properties
                $CertObject = [PSCustomObject]@{

                    Subject            = $Certificate.Subject
                    Issuer             = $Certificate.Issuer
                    Thumbprint         = $Certificate.Thumbprint
                    NotBefore          = $Certificate.NotBefore
                    NotAfter           = $Certificate.NotAfter
                    SerialNumber       = $Certificate.SerialNumber
                    SignatureAlgorithm = $Certificate.SignatureAlgorithm.FriendlyName
                    PublicKeyAlgorithm = $Certificate.PublicKey.Oid.FriendlyName
                    KeySize            = $Certificate.PublicKey.Key.KeySize

                }

                # Output certificate details
                $CertObject

                # Save certificate to file if OutFile is specified
                If ($OutFile) {

                    $CurrentOutFile = $OutFile

                    # If processing multiple host names, append an index to the file name
                    If ($Hostname.Count -gt 1) {

                        $FileExtension = [System.IO.Path]::GetExtension($OutFile)
                        $FileNameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($OutFile)
                        $Directory = [System.IO.Path]::GetDirectoryName($OutFile)

                        If (-Not [string]::IsNullOrWhiteSpace($Directory)) {

                            $CurrentOutFile = Join-Path $Directory "$FileNameWithoutExtension$FileIndex$FileExtension"

                        }

                        Else {

                            $CurrentOutFile = "$FileNameWithoutExtension$FileIndex$FileExtension"

                        }

                        $FileIndex++

                    }

                    Write-Verbose "Saving certificate to $CurrentOutFile..."
                    $CertOut = New-Object System.Text.StringBuilder
                    [void]($CertOut.AppendLine("-----BEGIN CERTIFICATE-----"))
                    [void]($CertOut.AppendLine([System.Convert]::ToBase64String($Certificate.RawData, 1)))
                    [void]($CertOut.AppendLine("-----END CERTIFICATE-----"))
                    [void]($CertOut.ToString() | Out-File $CurrentOutFile)

                }

            }

        }

    }

} # End function

# SIG # Begin signature block
# MIIf2QYJKoZIhvcNAQcCoIIfyjCCH8YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDxmbRK3jINV60y
# RksLgJHUKhWhSYp2BJ6ef42kGwCyF6CCGpkwggNZMIIC36ADAgECAhAPuKdAuRWN
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
# 2fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8h
# mS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0z
# ODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGP
# NRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1I
# pYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5A
# vftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDRe
# b6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBUR
# Jg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/ao
# fEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQ
# skBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJ
# lIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev
# +7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6B
# aaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IB
# XTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQ
# VvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEE
# AjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9
# vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwb
# SI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTL
# xLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD
# 8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVk
# o43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRa
# Ps+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8
# cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRz
# W6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KC
# LPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau
# 1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPS
# xyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0
# aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNl
# cnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1w
# aW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2
# MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAg
# UmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# ANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdw
# bHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9
# RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrU
# cCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iU
# SROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw
# 2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe4
# 6YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seA
# O+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSH
# lq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6
# EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDch
# Ic2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAM
# BgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNV
# HSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFt
# cGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3Rh
# bXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwB
# BAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezR
# CESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0
# k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFO
# tj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLW
# U0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2n
# HkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIF
# eRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqR
# hoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7
# roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47Cdx
# VRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/r
# ptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL
# 6vdCvHlshtjdNXOCIUjsarfNZzGCBJYwggSSAgEBMHgwZDELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTwwOgYDVQQDEzNEaWdpQ2VydCBHbG9i
# YWwgRzMgQ29kZSBTaWduaW5nIEVDQyBTSEEzODQgMjAyMSBDQTECEA1KNNqGkI/A
# Eyy8gTeTryQwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg0C1T/25zZsuSUfe2yBw/d4L9
# o+R2sgIYKVuzA0NWny4wCwYHKoZIzj0CAQUABEYwRAIgDlM2OmYez5k8DqnYECXu
# kXdskXahMEbauoHeiqt/LbgCICppzix5Fv/CzLIGPVL7eQ8jndPR8QleJ1rh2wzp
# 9dB+oYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBU
# cnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQ
# CoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1MDkwNDIzNDU1NlowLwYJKoZI
# hvcNAQkEMSIEIIK/LPsML6VYzFznPpywayvstO2F8bco4a2AprCvNw/+MA0GCSqG
# SIb3DQEBAQUABIICAGTI8ocEwpl+PbA+yz71Cnj9NxDALv0x4S89Ybja6OEAmNNK
# IvmJrD5cSwDgs7/pvKYBXq9DV+mXDS1s+giTgovTP2GkDNugV8p88IdKn0AWrsrA
# IN2tvafYmirLqZLJkC1WO0V4DESKjQf5MFregVyY13QBGWXAU5xa1+ao1d7wG2Zj
# nrJsswCi8kTCEEJGcnSsy4D1zEXd+OrRyLQCYv1GFo+C8xmvFZ10D/1RJfNjXnnd
# ymt6509K8+4u5rzNpSp5hAjY99y+k+qVjU3rgOxwQ2RXUiYNR3oG0nN7EIB3CGE9
# txrkrTIVvKo/BUGRRdN+F5SHt1gP3NjfOw0SfnKHZkHj/LgDH5aiQkYlrvYHG8xo
# jeN4CjHpzX6WyyDit4eVzclFR57faEbim/Rqd0dRTLIG1YYeGcrVTIXrTCN+otJx
# DUOh+2973AG6vs4DcTxdd9CV19mnLOUurfIxF9jCMVMCoOF6SfFq/3UxBlyCCSam
# nD9n6sjl5YrjZDfd8WEfkeAsI18OL8CjFR6Xx+Xx595yegmj6efEra3X93FahINC
# VuKYdYHceSsLqSy9sWINc+tv2W8Ru0lGJgPq60XU65w569bpQip0VcDQCTwQtZlr
# otGWUhnLxhr0P1Cg/c6zOxnqYcDZeRJS17F8fFw4BRF5N/kQfjn+WeLfbDLt
# SIG # End signature block
