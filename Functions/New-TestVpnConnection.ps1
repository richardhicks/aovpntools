<#

.SYNOPSIS
    Create a test VPN connection for validating Always On VPN infrastructure.

.PARAMETER ConnectionName
    Defines the name of the test VPN connection.

.PARAMETER ServerAddress
    The public hostname in fully qualified domain name (FQDN) format of the VPN server.

.PARAMETER VpnProtocol
    The VPN protocol to be used for the test VPN connection.

.PARAMETER DnsSuffix
    Defines the DNS suffix to be used for the test VPN connection.

.PARAMETER SplitTunnel
    Configures split tunneling for the test VPN connection.

.PARAMETER Routes
    Defines IPv4 networks to be routed over the test VPN connection when split tunneling is enabled.

.PARAMETER NpsServers
    Defines NPS servers trusted for authentication with the test VPN connection.

.PARAMETER RootCaThumbprint
    The thumbprint of the enterprise root CA server certificate.

.PARAMETER EkuName
    The name of the custom application policy assigned to the user authentication certificate (optional).

.PARAMETER EkuOID
    The Object Identifier (OID) of the custom application policy assigned to the user authentication certificate (optional).

.PARAMETER Connect
    Initiates the test VPN connection.

.EXAMPLE
    New-TestVpnConnection -ConnectionName 'Always On VPN Test' -ServerAddress test.example.net -VpnProtocol SSTP -DnsSuffix corp.example.net -SplitTunnel -Routes 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 -NpsServers nps1.corp.example.net, nps2.corp.example.net -RootCaThumbprint CDD4EEAE6000AC7F40C3802C171E30148030C072

    Creates a new test VPN connection.

    Note: This command requires many parameters. Using Show-Command New-TestVpnConnection displays a GUI to input required parameters.

.DESCRIPTION
    Administrators should configure a test VPN connection to validate Always On VPN infrastructure before proceeding with broad client configuration deployment. This function creates a test VPN connection for validating connection establishment, authentication, routing, and single sign-on.

.LINK
    https://github.com/richardhicks/aovpntools/blob/main/Functions/New-TestVpnConnection.ps1

.LINK
    https://directaccess.richardhicks.com/

.NOTES
    Version:        1.3
    Creation Date:  July 11, 2022
    Last Updated:   March 5, 2025
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

Function New-TestVpnConnection {

    [CmdletBinding(SupportsShouldProcess)]

    Param (

        [Parameter(Mandatory, HelpMessage = 'Enter a name for the VPN connection.')]
        [string]$ConnectionName,
        [Parameter(Mandatory, HelpMessage = "Enter the VPN server's public hostname in FQDN format.")]
        [string]$ServerAddress,
        [Parameter(Mandatory, HelpMessage = 'Specify a VPN protocol for the connection - IKEv2 or SSTP.')]
        [ValidateSet('IKEv2', 'SSTP')]
        [string]$VpnProtocol,
        [Parameter(Mandatory, HelpMessage = 'Enter a DNS suffix for the VPN connection.')]
        [string]$DnsSuffix,
        [switch]$SplitTunnel,
        [string[]]$Routes,
        [Parameter(Mandatory, HelpMessage = 'Enter the names of NPS servers trusted for this VPN connection.')]
        [string[]]$NpsServers,
        [Parameter(Mandatory, HelpMessage = "Enter the thumbprint of the root CA server's certificate.")]
        [ValidatePattern('^[0-9A-Fa-f]{40}$')]
        [string]$RootCaThumbprint,
        [string]$EkuName,
        [string]$EkuOID,
        [switch]$Connect

    )

    # Check if VPN connection already exists
    $Vpn = Get-VpnConnection -Name $ConnectionName -ErrorAction SilentlyContinue

    If ($Vpn) {

        Write-Warning "The VPN connection ""$ConnectionName"" already exists."
        Return

    }

    # Convert NPS servers array to semi-colon separated string
    $NpsServers = [System.String]::Join(";", $NpsServers)

    # Select XML template
    If ($EkuOID) {

        $EapConfig = "<EapHostConfig xmlns=`"http://www.microsoft.com/provisioning/EapHostConfig`"><EapMethod><Type xmlns=`"http://www.microsoft.com/provisioning/EapCommon`">25</Type><VendorId xmlns=`"http://www.microsoft.com/provisioning/EapCommon`">0</VendorId><VendorType xmlns=`"http://www.microsoft.com/provisioning/EapCommon`">0</VendorType><AuthorId xmlns=`"http://www.microsoft.com/provisioning/EapCommon`">0</AuthorId></EapMethod><Config xmlns=`"http://www.microsoft.com/provisioning/EapHostConfig`"><Eap xmlns=`"http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1`"><Type>25</Type><EapType xmlns=`"http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1`"><ServerValidation><DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation><ServerNames>$NpsServers</ServerNames><TrustedRootCA>$RootCAThumbprint</TrustedRootCA></ServerValidation><FastReconnect>false</FastReconnect><InnerEapOptional>false</InnerEapOptional><Eap xmlns=`"http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1`"><Type>13</Type><EapType xmlns=`"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1`"><CredentialsSource><CertificateStore><SimpleCertSelection>true</SimpleCertSelection></CertificateStore></CredentialsSource><ServerValidation><DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation><ServerNames>$NpsServers</ServerNames><TrustedRootCA>$RootCAThumbprint</TrustedRootCA></ServerValidation><DifferentUsername>false</DifferentUsername><PerformServerValidation xmlns=`"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2`">true</PerformServerValidation><AcceptServerName xmlns=`"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2`">true</AcceptServerName><TLSExtensions xmlns=`"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2`"><FilteringInfo xmlns=`"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV3`"><CAHashList Enabled=`"true`"><IssuerHash>$RootCAThumbprint</IssuerHash><IssuerHash>$RootCAThumbprint</IssuerHash></CAHashList><EKUMapping><EKUMap><EKUName>$EkuName</EKUName><EKUOID>$EkuOID</EKUOID></EKUMap></EKUMapping><ClientAuthEKUList Enabled=`"true`"><EKUMapInList><EKUName>$EkuName</EKUName></EKUMapInList></ClientAuthEKUList></FilteringInfo></TLSExtensions></EapType></Eap><EnableQuarantineChecks>false</EnableQuarantineChecks><RequireCryptoBinding>true</RequireCryptoBinding><PeapExtensions><PerformServerValidation xmlns=`"http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2`">true</PerformServerValidation><AcceptServerName xmlns=`"http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2`">true</AcceptServerName></PeapExtensions></EapType></Eap></Config></EapHostConfig>"

    }

    Else {

        $EapConfig = "<EapHostConfig xmlns=`"http://www.microsoft.com/provisioning/EapHostConfig`"><EapMethod><Type xmlns=`"http://www.microsoft.com/provisioning/EapCommon`">25</Type><VendorId xmlns=`"http://www.microsoft.com/provisioning/EapCommon`">0</VendorId><VendorType xmlns=`"http://www.microsoft.com/provisioning/EapCommon`">0</VendorType><AuthorId xmlns=`"http://www.microsoft.com/provisioning/EapCommon`">0</AuthorId></EapMethod><Config xmlns=`"http://www.microsoft.com/provisioning/EapHostConfig`"><Eap xmlns=`"http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1`"><Type>25</Type><EapType xmlns=`"http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1`"><ServerValidation><DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation><ServerNames>$NpsServers</ServerNames><TrustedRootCA>$RootCaThumbprint</TrustedRootCA></ServerValidation><FastReconnect>false</FastReconnect><InnerEapOptional>false</InnerEapOptional><Eap xmlns=`"http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1`"><Type>13</Type><EapType xmlns=`"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1`"><CredentialsSource><CertificateStore><SimpleCertSelection>true</SimpleCertSelection></CertificateStore></CredentialsSource><ServerValidation><DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation><ServerNames>$NpsServers</ServerNames><TrustedRootCA>$RootCaThumbprint</TrustedRootCA></ServerValidation><DifferentUsername>false</DifferentUsername><PerformServerValidation xmlns=`"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2`">true</PerformServerValidation><AcceptServerName xmlns=`"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2`">true</AcceptServerName><TLSExtensions xmlns=`"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2`"><FilteringInfo xmlns=`"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV3`"><CAHashList Enabled=`"true`"><IssuerHash>$RootCaThumbprint</IssuerHash></CAHashList><ClientAuthEKUList Enabled=`"true`" /></FilteringInfo></TLSExtensions></EapType></Eap><EnableQuarantineChecks>false</EnableQuarantineChecks><RequireCryptoBinding>true</RequireCryptoBinding><PeapExtensions><PerformServerValidation xmlns=`"http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2`">true</PerformServerValidation><AcceptServerName xmlns=`"http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2`">true</AcceptServerName></PeapExtensions></EapType></Eap></Config></EapHostConfig>"

    }

    # Define VPN connection parameters
    $Parameters = @{

        ConnectionName       = $ConnectionName
        ServerAddress        = $ServerAddress
        TunnelType           = 'IKEv2'
        DnsSuffix            = $DnsSuffix
        AuthenticationMethod = 'EAP'
        EapConfigXmlStream   = $EapConfig

    }

    If ($PsCmdlet.ShouldProcess($ConnectionName, 'Create test VPN connection')) {

        # Create VPN connection
        Write-Verbose "Creating VPN connection $ConnectionName..."
        Add-VpnConnection @Parameters

        # Enable split tunneling and define routes
        If ($SplitTunnel) {

            Write-Verbose 'Enabling split tunneling...'
            Set-VpnConnection -Name $ConnectionName -SplitTunneling $True

            ForEach ($Route in $Routes) {

                Write-Verbose "Adding route to $Route..."
                Add-VpnConnectionRoute -ConnectionName $ConnectionName -DestinationPrefix $Route

            }

        }

        # Define IPsec policy
        $Parameters = @{

            AuthenticationTransformConstants = 'GCMAES128'
            CipherTransformConstants         = 'GCMAES128'
            DHGroup                          = 'Group14'
            EncryptionMethod                 = 'GCMAES128'
            IntegrityCheckMethod             = 'SHA256'
            PFSgroup                         = 'ECP256'

        }

        Write-Verbose 'Updating IKEv2 IPsec security policy...'
        [PSCustomObject]$Parameters | Set-VpnConnectionIPsecConfiguration -ConnectionName $ConnectionName -Force

        # Enable SSTP if required
        If ($VpnProtocol -eq 'SSTP') {

            Set-VpnConnection -Name $ConnectionName -TunnelType 'SSTP' -Force

        }

        If ($Connect) {

            Write-Verbose "Launching VPN connection $ConnectionName..."
            Invoke-Command -ScriptBlock { rasdial.exe $ConnectionName }

        }

    }

}

# SIG # Begin signature block
# MIIfnQYJKoZIhvcNAQcCoIIfjjCCH4oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDbu1mZzcr5YcD2
# 9czS9FHSTaoVn9uqpION6IjaC6TtPaCCGmIwggNZMIIC36ADAgECAhAPuKdAuRWN
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
# AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDYYqTYhgoKPYj5EFSahaj2DsGkNtiN3oGW
# UK3PvC6N9jALBgcqhkjOPQIBBQAERzBFAiAyGUrjotpY6rGEmQ6P2vzZoGeDOBhX
# rp3Y8D+VpFKyZAIhAKdcOHm36eLBGK33sXZQMkM98lQS4w606scS2DqQtmWaoYID
# IDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVk
# IEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQC65mvFq6f5WHxvnp
# BOMzBDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEw
# HAYJKoZIhvcNAQkFMQ8XDTI1MDMwNjAyMDczNFowLwYJKoZIhvcNAQkEMSIEIFe3
# bTby9mKscOqSHRotr4QCH0QQ6AfOwg8qDjskfzhpMA0GCSqGSIb3DQEBAQUABIIC
# AFLkU1WHMQJlTRNEhkpRMvQvg8EYVNf7YCkRluLO+GuIETBu2QvzUy+synJ4VYtU
# 7DPLbNfvMxfjIfMtxj0velyuYVxnJ0pctWM+80M8rckx4tMFJjjcD2laScS0RFPz
# 0thw90yT+E902uDHeS2EQirIK3QhTJnVsvd1+Q0qjd+2LC5iqjj3Ogvo/MMYktu+
# hqSGWclU/BmaX6AZnZbyAWyEUYIpTviFl2dTzX3KNeENmVZl3UlpM5JmJWVoaBP2
# J8EExCLJ8JErLgCKyJbYvZ5/My83i77Yti5lIQkUiHfN4EFZ7Q7NfpX9l61ZbSHm
# GDClIxHnbWNvpL7uu/77aTzjQmXrDtPsoYmYjaZv7qdr8r4VajMitkCRDpEp+zqk
# /mWjYQe1CHI5O4cygrwTSJ6Euzw52ttZG59lWU/kerS2fV0EZpA0+TIiixOx8I9D
# MKWAwiOcMaaiUux7rN3m86SuPsfy9oy3RUbNXwIcXC93D4QuXQry7PfFhwBQR7TD
# HzAHE4PMs5o2oxk5g4HSQ5C/1OgrT7ojBDZe1uHNgbXpesYLXmQt/W4GLffWFn92
# SRbC1+GBl9hOKcp/e/FjQY2cVKgZx526kZnja/ULeepSVl9nQbDbO3Q/5D8CCgwn
# proKcGWv/h647zfdcV1TTOGmhLvBHd45ObhSxnbW3Rvl
# SIG # End signature block
