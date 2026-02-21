<#

.SYNOPSIS
    View and optionally save to a file the Transport Layer Security (TLS) certificate for a website or service using HTTPS.

.PARAMETER Hostname
    The server name or Fully Qualified Domain Name (FQDN) of the target resource.

.PARAMETER Port
    The TCP port of the target resource. The default is 443.

.PARAMETER OutFile
    When specified, the TLS certificate will be saved to the current directory using the hostname as the filename with a .crt extension.

.EXAMPLE
    .\Get-TlsCertificate -Hostname 'www.richardhicks.com'

    Displays the TLS certificate for the website https://www.richardhicks.com/.

.EXAMPLE
    .\Get-TlsCertificate -Hostname 'www.richardhicks.com' -Port 8443

    Displays the TLS certificate for the website https://www.richardhicks.com/ listening on the nonstandard port 8443.

.EXAMPLE
    .\Get-TlsCertificate -Hostname 'www.richardhicks.com, www.richardhicks.net'

    Displays the TLS certificates for the websites https://www.richardhicks.com/ and https://www.richardhicks.net/.

.EXAMPLE
    .\Get-TlsCertificate -Hostname 'www.richardhicks.com' -OutFile

    Displays the TLS certificate for the website https://www.richardhicks.com/ and saves the certificate to a file named www.richardhicks.com.crt in the current directory.

.DESCRIPTION
    This PowerShell script is helpful for troubleshooting TLS issues associated with public websites or other HTTPS services like TLS VPNs. Using this script, administrators can view and optionally save the certificate returned during the TLS handshake. Administrators can confirm certificate details and perform revocation checks, if necessary.

.INPUTS
    String[]]

    The Hostname parameter accepts a string array of public host names.

.OUTPUTS
    System.Management.Automation.PSCustomObject

    The output of this script is a custom object that contains the following properties:

    Subject                 - The subject name of the certificate.
    Issuer                  - The issuer name of the certificate.
    SerialNumber            - The serial number of the certificate.
    Thumbprint              - The thumbprint of the certificate.
    Issued                  - The date and time the certificate is valid from.
    Expires                 - The date and time the certificate expires.
    AlternativeNames        - The subject alternative names (SANs) of the certificate.
    EnhancedKeyUsage        - The enhanced key usage (EKU) values of the certificate.
    PublicKeyAlgorithm      - The public key algorithm used by the certificate.
    KeySize                 - The size of the public key in bits.
    SignatureAlgorithm      - The signature algorithm used by the certificate.

    If the OutFile parameter is specified, the certificate will be saved to a file in PEM format.

.LINK
    https://github.com/richardhicks/aovpntools/blob/main/Functions/Get-TlsCertificate.ps1

.LINK
    https://directaccess.richardhicks.com/

.NOTES
    Version:        2.4.0
    Creation Date:  August 12, 2021
    Last Updated:   February 21, 2026
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
        [switch]$OutFile

    )

    Process {

        ForEach ($Server in $Hostname) {

            # Test connectivity before proceeding
            If (-not (Test-NetConnection -ComputerName $Server -Port $Port -InformationLevel Quiet)) {

                Write-Warning "Unable to connect to $Server on port $Port."
                Continue

            }

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

                # Determine key size based on algorithm type
                $KeySize = $null

                # Try to get key size directly (works for RSA)
                If ($Certificate.PublicKey.Key -and $Certificate.PublicKey.Key.KeySize) {

                    $KeySize = $Certificate.PublicKey.Key.KeySize

                }

                # For EC certificates, need alternative approach
                ElseIf ($Certificate.PublicKey.Oid.FriendlyName -eq 'ECC' -or $Certificate.PublicKey.Oid.Value -eq '1.2.840.10045.2.1') {

                    # Try to get from encoded parameters OID
                    If ($Certificate.PublicKey.EncodedParameters -and $Certificate.PublicKey.EncodedParameters.Oid) {

                        $Oid = $Certificate.PublicKey.EncodedParameters.Oid
                        Switch ($Oid.Value) {

                            '1.2.840.10045.3.1.7' { $KeySize = 256 }  # secp256r1 (P-256)
                            '1.3.132.0.34' { $KeySize = 384 }         # secp384r1 (P-384)
                            '1.3.132.0.35' { $KeySize = 521 }         # secp521r1 (P-521)

                            Default {

                                # Try to infer from friendly name
                                If ($Oid.FriendlyName -match '256') { $KeySize = 256 }
                                ElseIf ($Oid.FriendlyName -match '384') { $KeySize = 384 }
                                ElseIf ($Oid.FriendlyName -match '521') { $KeySize = 521 }

                            }

                        }

                    }

                    # If still null, try to determine from the public key data length
                    If (-not $KeySize -and $Certificate.PublicKey.EncodedKeyValue) {

                        $KeyLength = $Certificate.PublicKey.EncodedKeyValue.RawData.Length
                        # EC public keys in uncompressed format: 0x04 + X + Y coordinates
                        Switch ($KeyLength) {

                            65 { $KeySize = 256 }   # P-256: 1 + 32 + 32
                            97 { $KeySize = 384 }   # P-384: 1 + 48 + 48
                            133 { $KeySize = 521 }  # P-521: 1 + 66 + 66
                            # ASN.1 encoded versions (with header bytes)
                            { $_ -in 67, 68, 69 } { $KeySize = 256 }
                            { $_ -in 99, 100, 101 } { $KeySize = 384 }
                            { $_ -in 135, 136, 137 } { $KeySize = 521 }

                        }

                    }

                }

                # Extract Subject Alternative Names (SANs) from the certificate
                $SubjectAlternativeNames = @()
                $SanExtension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }

                If ($SanExtension) {

                    Write-Verbose 'Extracting Subject Alternative Names...'
                    $SanString = $SanExtension.Format($true)

                    # Parse the formatted SAN string to extract individual entries
                    ForEach ($Line in $SanString -split "`n") {

                        $Line = $Line.Trim()

                        If ($Line -match '^DNS Name=(.+)$') {

                            $SubjectAlternativeNames += $Matches[1].Trim()

                        }

                        ElseIf ($Line -match '^IP Address=(.+)$') {

                            $SubjectAlternativeNames += $Matches[1].Trim()

                        }

                        ElseIf ($Line -match '^RFC822 Name=(.+)$') {

                            $SubjectAlternativeNames += $Matches[1].Trim()

                        }

                        ElseIf ($Line -match '^URL=(.+)$') {

                            $SubjectAlternativeNames += $Matches[1].Trim()

                        }

                    }

                }

                # Extract Enhanced Key Usage (EKU) from the certificate
                $EnhancedKeyUsage = @()
                $EkuExtension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }

                If ($EkuExtension) {

                    Write-Verbose 'Extracting Enhanced Key Usage...'
                    $EkuExtensionTyped = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$EkuExtension

                    ForEach ($Eku in $EkuExtensionTyped.EnhancedKeyUsages) {

                        If ($Eku.FriendlyName) {

                            $EnhancedKeyUsage += $Eku.FriendlyName

                        }

                        Else {

                            $EnhancedKeyUsage += $Eku.Value

                        }

                    }

                }

                # Create custom object and populate with certificate properties
                $CertObject = [PSCustomObject]@{

                    Subject            = $Certificate.Subject
                    Issuer             = $Certificate.Issuer
                    SerialNumber       = $Certificate.SerialNumber
                    Thumbprint         = $Certificate.Thumbprint
                    Issued             = $Certificate.NotBefore
                    Expires            = $Certificate.NotAfter
                    AlternativeNames   = $SubjectAlternativeNames
                    EnhancedKeyUsage   = $EnhancedKeyUsage
                    PublicKeyAlgorithm = $Certificate.PublicKey.Oid.FriendlyName
                    KeySize            = $KeySize
                    SignatureAlgorithm = $Certificate.SignatureAlgorithm.FriendlyName

                }

                # Output certificate details
                $CertObject

                # Save certificate to file if OutFile is specified
                If ($OutFile) {

                    $CurrentOutFile = "$Server.crt"
                    Write-Verbose "Saving certificate to $CurrentOutFile..."
                    $CertOut = New-Object System.Text.StringBuilder
                    [void]($CertOut.AppendLine("-----BEGIN CERTIFICATE-----"))
                    [void]($CertOut.AppendLine([System.Convert]::ToBase64String($Certificate.RawData, 1)))
                    [void]($CertOut.AppendLine("-----END CERTIFICATE-----"))
                    [void]($CertOut.ToString() | Out-File $CurrentOutFile -Encoding ascii -Force)
                    Write-Output "Certificate saved to $((Resolve-Path $CurrentOutFile).Path)."

                }

            }

        }

    }

}

# SIG # Begin signature block
# MIIf2wYJKoZIhvcNAQcCoIIfzDCCH8gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAzZtPuk8VHTV9d
# zYl2YUh97pRxmZwwRpNJqt3wuKzEoKCCGpkwggNZMIIC36ADAgECAhAPuKdAuRWN
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
# 6vdCvHlshtjdNXOCIUjsarfNZzGCBJgwggSUAgEBMHgwZDELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTwwOgYDVQQDEzNEaWdpQ2VydCBHbG9i
# YWwgRzMgQ29kZSBTaWduaW5nIEVDQyBTSEEzODQgMjAyMSBDQTECEA1KNNqGkI/A
# Eyy8gTeTryQwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg2jobCTHg8cRBvUX4pOWHLNJY
# 70p8Rjp/BPLBFXdmW/4wCwYHKoZIzj0CAQUABEgwRgIhAPXMKK2KC3nnC69DlwbV
# D+xjea0pZ3nHKSxn7v35AyqFAiEA8C3Bi8oiJ4MN6gos490bwUdKzJzMNlXtzOA3
# PXUxD9WhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# AhAKgO8YS43xBYLRxHanlXRoMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwMjIxMjIzOTAwWjAvBgkq
# hkiG9w0BCQQxIgQg+xl0Mt0QlmkxlFkb5Vd/2c+BvA0YAhQCXDSZmpAGDoowDQYJ
# KoZIhvcNAQEBBQAEggIAgykmxURrHUixs9Ci9J8TUO0fFeQ7FXiiJ98TGjnb186H
# lrxAhn+iPMLgOjiPoP9kdvSmN7n8Nux2n9iMdRnNLMx9xBryUlDpTcUIvW3QKdx3
# RsNv+/VNB9Op14pa+LgPTIRTaQ+oCdHvCdTcnngY85GIhqdPwkeIjpXijXAt/aL3
# h1shajWzc3FVx1qAevpFn5UhQqj4Spit9OjT19OVWMfpASYDIl2nkDmsdLe5mgMn
# lOuKS+/DkgAIh51zEKWmSxNwPq8SZvZMNzddwi99G9L/sIQssQnimtM7lSMDBCeC
# yMJs2rgi3hoTxVnitFkhvTcYWAxM/X5R2gMkF/TRc2h2meu+VHWXrD+X4e/X9I4f
# VOyED4etws1aVBTJYkNONx+eDeucgYFXmUt97hyazlK6a+SuqfQeqkDkwRWGKdkC
# MiBvYjK0jTJ0aRyPVt3Iq/hRyfaraqPfm4PthI8kX2wcTNwxZcQRmirBXQe7h6LT
# cann1Njd7GjC2du6iY+Cr0xgpvRmCqaWB3Gsy0vEmmlf6yYQmE8IsYk4IpMosuBP
# /jkfU/GoDxtDBpEX3hzeQ4P83qlginDD47jNt10Js0m38iYCE/0yrG4AY3qDectV
# xpwJOt5LHnCPwCxLxFMpC7BVYUcbwlc4iv0xyo2CRnZMxFsvUnGn3I43spwPi+0=
# SIG # End signature block
