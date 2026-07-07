<#

.SYNOPSIS
    Retrieve and display the TLS certificate used by the VPN server for SSTP.

.DESCRIPTION
    This script retrieves the TLS certificate used by the VPN server for SSTP connections using the Get-RemoteAccess cmdlet.
    It extracts key details from the certificate and displays them in a structured format. Optionally, it can save the
    certificate to a specified file in DER format.

.PARAMETER OutFile
    Specifies the path to the output file where the certificate will be saved in binary (DER) format. If not specified, the certificate will not be saved to a file.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    [PSCustomObject] containing the details of the TLS certificate.

.EXAMPLE
    Get-VpnServerTlsCertificate

    Retrieves and displays the TLS certificate details used by the VPN server for SSTP connections.

.EXAMPLE
    Get-VpnServerTlsCertificate -OutFile 'C:\Temp\VpnServerCert.cer'

    Retrieves the TLS certificate details and saves the certificate to the specified file in binary (DER) format.

.LINK
    https://github.com/richardhicks/aovpntools/blob/main/Functions/Get-VpnServerTlsCertificate.ps1

.LINK
    https://directaccess.richardhicks.com/2025/09/16/always-on-vpn-rras-and-powershell-7/

.LINK
    https://directaccess.richardhicks.com/

.NOTES
    Version:        1.1
    Creation Date:  September 15, 2025
    Last Updated:   June 14, 2026
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

Function Get-VpnServerTlsCertificate {

    [CmdletBinding()]

    Param (

        [Parameter()]
        [switch]$OutFile,
        [string]$FilePath = "$env:TEMP\$env:COMPUTERNAME.cer"

    )

    Try {

        # Call Get-RemoteAccess once and store the result
        $GRAOutput = Get-RemoteAccess

        # Check PowerShell version
        If ($PSVersionTable.PSVersion.Major -ge 7) {

            # PowerShell 7: Convert byte array to X509Certificate2
            $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($GRAOutput.SslCertificate)

        }

        Else {

            # PowerShell 5.x: SslCertificate should return a certificate object directly
            $Certificate = $GRAOutput.SslCertificate
            If (-not $Certificate -or $Certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {

                Throw 'Unable to retrieve a valid X509Certificate2 object from Get-RemoteAccess.'

            }

        }

        # Determine key size based on algorithm type
        $KeySize = $Null

        # Try to get key size directly (works for RSA)
        If ($Certificate.PublicKey.Key -and $Certificate.PublicKey.Key.KeySize) {

            $KeySize = $Certificate.PublicKey.Key.KeySize

        }

        # For EC certificates, need alternative approach
        ElseIf ($Certificate.PublicKey.Oid.FriendlyName -eq 'ECC' -or $Certificate.PublicKey.Oid.Value -eq '1.2.840.10045.2.1') {

            # Try to get from encoded parameters OID
            If ($Certificate.PublicKey.EncodedParameters -and $Certificate.PublicKey.EncodedParameters.Oid) {

                $CurveOid = $Certificate.PublicKey.EncodedParameters.Oid
                Switch ($CurveOid.Value) {

                    '1.2.840.10045.3.1.7' { $KeySize = 256 }  # secp256r1 (P-256)
                    '1.3.132.0.34'        { $KeySize = 384 }  # secp384r1 (P-384)
                    '1.3.132.0.35'        { $KeySize = 521 }  # secp521r1 (P-521)

                    Default {

                        If ($CurveOid.FriendlyName -match '256')      { $KeySize = 256 }
                        ElseIf ($CurveOid.FriendlyName -match '384')  { $KeySize = 384 }
                        ElseIf ($CurveOid.FriendlyName -match '521')  { $KeySize = 521 }

                    }

                }

            }

            # Fall back to key value byte length if OID lookup did not resolve
            If (-not $KeySize -and $Certificate.PublicKey.EncodedKeyValue) {

                Switch ($Certificate.PublicKey.EncodedKeyValue.RawData.Length) {

                    65  { $KeySize = 256 }  # P-256: 0x04 + 32 + 32
                    97  { $KeySize = 384 }  # P-384: 0x04 + 48 + 48
                    133 { $KeySize = 521 }  # P-521: 0x04 + 66 + 66

                }

            }

        }

        # Compute SHA256 thumbprint
        $Sha256 = [System.Security.Cryptography.SHA256]::Create()
        $Sha256Hash = ($Sha256.ComputeHash($Certificate.RawData) | ForEach-Object { $_.ToString('X2') }) -join ''
        $Sha256.Dispose()

        # Prepare output object
        $CertificateDetails = [PSCustomObject]@{

            Subject            = $Certificate.Subject
            Issuer             = $Certificate.Issuer
            SerialNumber       = $Certificate.SerialNumber
            Thumbprint         = $Certificate.Thumbprint
            SHA256Thumbprint   = $Sha256Hash
            Issued             = $Certificate.NotBefore
            Expires            = $Certificate.NotAfter
            PublicKeyAlgorithm = $Certificate.PublicKey.Oid.FriendlyName
            KeySize            = $KeySize
            SignatureAlgorithm = $Certificate.SignatureAlgorithm.FriendlyName

        }

        # Output certificate details
        $CertificateDetails

        # Save to file if OutFile is specified
        If ($OutFile) {

            # Resolve parent directory; default to current dir if none provided
            $Directory = Split-Path -Path $FilePath -Parent
            If ([string]::IsNullOrWhiteSpace($Directory)) {

                $Directory = (Get-Location).Path
                $FilePath = Join-Path -Path $Directory -ChildPath (Split-Path -Leaf $FilePath)

            }

            # Ensure parent directory exists (create if missing)
            If (-not (Test-Path -LiteralPath $Directory)) {

                New-Item -ItemType Directory -Path $Directory -Force | Out-Null

            }

            # Export cert as DER (.cer) and write raw bytes (works PS 5.1 and 7+)
            $Bytes = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            [System.IO.File]::WriteAllBytes($FilePath, $Bytes)

            Write-Output "Certificate saved to $FilePath."

        }

    }

    Catch {

        Write-Error "Failed to retrieve or process the VPN server TLS certificate: $_"

    }

}

# SIG # Begin signature block
# MIIk7AYJKoZIhvcNAQcCoIIk3TCCJNkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAutrA0YVAcQ/9J
# 3FYqfVzzRlvemDsB7zkRPyrq35PCnqCCH6YwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggW0MIIDnKADAgECAhAOxitIKuZQm69NGxw+uiH/MA0GCSqG
# SIb3DQEBDAUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNB
# NDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjYwNTE2MDAwMDAwWhcNMjcwODE3MjM1
# OTU5WjCBhjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNV
# BAcTDU1pc3Npb24gVmllam8xJDAiBgNVBAoTG1JpY2hhcmQgTS4gSGlja3MgQ29u
# c3VsdGluZzEkMCIGA1UEAxMbUmljaGFyZCBNLiBIaWNrcyBDb25zdWx0aW5nMFkw
# EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOooTPiege6mCA4AriPO+Xh3mymiiZ+3k
# kn31uJifB2ojzzfY7VkAVKhgj+rcVBnofnj2b8OhvAJ4YaQ2Iwuc6aOCAgMwggH/
# MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBQJvGhl
# Ahwi6UKROatrFKBmPLmd5TA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsGAQUF
# BwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/BAQDAgeA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5n
# UlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEz
# ODQyMDIxQ0ExLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0
# MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkqhkiG9w0BAQwFAAOC
# AgEAbaKnnRcJAMHjuWSc2PG/QhJ0jj4hQVwJIbddYDJNxPmD0cxuuorSiR9gX2nl
# ajqNI9N7Kl+FB3oheRTGh/wp4JgZMpCq0qS0zGJ/N6Js+HmVtbkFaPyYxJMXbIWq
# p9zKkoXtSXkpR6nGZnzYkn3EBcRlu4R6hIJHzM/C2PUztH/Hd4fGIryyD69iHvKx
# zotYdlHHY6+X1ACaQnuCz3TLxs3/CDKhPUXesKcISnXHmm4uCwyVdtGyl7wPuZVk
# +rfCIOeWn+XG5J7L8xwhXCPSJ5fKJ5m8/H5cICLR0I7hI4SUiybE1nG5CZ1hKhbW
# abSfNer1dHH/vSYi80YGXCej/88vZeCGQ9/rrjugsg0yN7WCPqNKjEMTYGWkrt37
# lp4cJqULS+alUbL6x1HBdoBStDE2CFmPivL7cCCtnudqCA6b3XB416/FlRo8t4Lw
# Dc2ty+RDKirWM84Zj3ANTVs5fi43rxClBQwngGdqi5TjriKHGTkEKYRIFTViy6Ie
# JDIboOkCFJU5vM7Curvh4rQnw+aM4CyjwnDwnzwcKQVZC3Iy1T4h/FvmpSgu5ouM
# wjdzaR3cSh4OPDRrfBl1YIOoZEOHcshCaHDC46t8+UyAf70BMlrB7Nj84ORTuKTi
# IlU062VzGeREc1KHJqp/S3/NtArpVUVQEgibRxQ99KJCOV8wggawMIIEmKADAgEC
# AhAIrUCyYNKcTJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0Mjkw
# MDAwMDBaFw0zNjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2Rl
# IFNpZ25pbmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYw
# n6SOaNhc9es0JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43i
# CH00fUyAVxJrQ5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1
# hz1RGeiQIXhFLqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd
# 6BgTZcV/sk+FLEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObar
# YBLj6Na59zHh3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18eb
# MlrC/2pgVItJwZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYo
# X7BzzosmJQayg9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDz
# d5Ea/ttQokbIYViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8S
# kXbev1jLchApQfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZ
# YIpkVMHMIRroOBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxW
# EQIDAQABo4IBWTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg
# 67Y7+F8Rhvv+YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTAT
# MAcGBWeBDAEDMAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6P
# vDqZ01bgAhql+Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V
# 1T9J9Ce7FoFFUP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+
# 3NiAGhEZGM1hmYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcn
# P/2Q0XaG3RywYFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgU
# kpn13c5UbdldAhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6Q
# B7BDf5WIIIJw8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3
# kuZOX956rEnPLqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKL
# QcBIhEuWTatEQOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47v
# tevLt/B3E+bnKD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0
# qFEgu60bhQjiWQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0
# YW6/aOImYIbqyK+p/pQd52MbOoZWeE4wgga0MIIEnKADAgECAhANx6xXBf8hmS5A
# QyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMT
# GERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAx
# MTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcy
# bEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzT
# qpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftB
# dsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3
# mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6z
# MUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS
# 5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBB
# BnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqL
# XvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7ps
# NOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeE
# WvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCC
# AVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv
# 1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/
# BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggr
# BgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVo
# dHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0
# LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjAL
# BglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvI
# tTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/m
# S83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgX
# f9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liy
# rukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+
# Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2
# ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipD
# oq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6Ax
# nJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAl
# Z66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1
# MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZs
# q8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDAN
# BgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQs
# IEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5n
# IFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkw
# MzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVz
# cG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBG
# rC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwB
# SOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/
# 4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3
# K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROU
# INDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3
# w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46Yce
# NA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d
# 2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8x
# ymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+
# AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2b
# Qhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNV
# HRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSME
# GDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0l
# AQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGlu
# Z1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBp
# bmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIw
# CwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESe
# Y0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FU
# FqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7Y
# MTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0zi
# TN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/
# QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlq
# AcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3
# Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roan
# cJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/
# ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7
# IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdC
# vHlshtjdNXOCIUjsarfNZzGCBJwwggSYAgEBMH0waTELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVk
# IEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQDsYrSCrm
# UJuvTRscProh/zANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKAC
# gAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsx
# DjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCkgezfQshPE6ycFTas0at/
# aemaedd5/CzRFxCG+W+xMzALBgcqhkjOPQIBBQAERzBFAiAJFAaVI4kom+YcAede
# Ywy6BezIzWPU+y2wDR4vAxRwDgIhAI+Me3hOIHhZyy3Ana/TGQIdzPSZY0S65Km6
# M+RUrFDyoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENB
# MQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJ
# AzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDYxNDE5MDM0OFowLwYJ
# KoZIhvcNAQkEMSIEICoXKCA7NKF5b8qGY8DkkFnEa4GQT/28zGWWs9Z2uIVPMA0G
# CSqGSIb3DQEBAQUABIICABxCUyZVKwHBXA2SK4lBzdqhPtF2sGW208V6qKqM7bPj
# jcpJ06FJm16bYd4ITjzj/UI/VRJMPR8qD2vgtLAgxIEea7BLAKDpRZdezMFkF1Rj
# u4dmjlj3cW6yO2wFSwtUZCB61XZy9ytllhzUbHkugoSx6s1G8dXIhIZmxnBEkOVi
# DyGfuk6c4iMVDoOuBYNFzvQhJaRZm3dJymuROH1O6cmga6rdSSnGWfTqCd1jvjbH
# zdV4+yis+muJYpSFcV/Rgp/23j/2R1BurMIfePzeQ/o+2H5TWT+Wo/sZ+WrnLa+8
# 9AqZuGEn0WIM3CpU6RYPAb+s0Q6tZogLaKkWxVfMsplfiq9KeYm5DLBKW4htUPIK
# xq2Km0yHDiHJWgQmfAVo2IVcKaY90W+qsX+qXVM/C8F/whzmv5RUGOCOMFLuCgZT
# 7vSiGjE2xcjUVn6S2TMA63MxbNWDRKajjn7v9IkYtcDUqGAA1fgPa9AtRQdhq7Rs
# DG7q9n88ilpll0r2aEwg8HzoanyrM+E5VZIZp0w75N8Z6vjfFknhCsUmWIAVgS8k
# iqzkkN/9zLwVY23khk5i5ISdWf3cch70LUeCwMeNVjqfpbD9VgEC9MOFxeh1DIP3
# 4dChrYFflLRpW1leqsgfatXMLqHapHENjuhHXpVn+pzXOilyCzqTctJTlUgEo2Tl
# SIG # End signature block
