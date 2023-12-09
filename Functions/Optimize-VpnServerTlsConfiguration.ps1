<#

.SYNOPSIS
    Optimizes TLS configuration for SSTP VPN connections.

.PARAMETER Security
    TLS cipher suites optimized for security. AES-256 ciphers are included.

.EXAMPLE
    Optimize-VpnTlsConfiguration

    Running this command will optimize TLS configuration for performance. Cipher suites using AES-256 are not included in this configuration.

.EXAMPLE
    Optimize-VpnTlsConfiguration -Security

    Running this command will optimize TLS configuration for security. Cipher suites using AES-256 are included and preferred over AES-128 ciphers.

.DESCRIPTION
    Use this script to optimize TLS configuration to improve security and performance for SSTP VPN connections. TLS cipher suites are configured and optimized and deprecated TLS protocols are disabled.

.LINK
    https://github.com/richardhicks/aovpntools/blob/main/Functions/Optimize-VpnServerTlsConfiguration.ps1

.LINK
    https://directaccess.richardhicks.com/

.NOTES
    Version:        2.0
    Creation Date:  October 24, 2019
    Last Updated:   December 7, 2023
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

Function Optimize-VpnServerTlsConfiguration {

    [CmdletBinding()]

    Param (

        [switch]$Security

    )

    # // Determine OS version
    $OSVersion = (Get-CimInstance 'Win32_OperatingSystem').Version
    Write-Verbose "Operating system version is $OSVersion."

    # Find the Windows Server OS version
    Switch -Regex ($OsVersion) {

        # Windows Server 2012/R2
        '^6.*' {

            Write-Verbose 'Detected Windows Server 2012 or 2012R2.'
            $Ciphers = 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256';
            $CiphersSecure = 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256'

        }

        # Windows Server 2016
        '14393|17134' {

            Write-Verbose 'Detected Windows Server 2016 or SAC release.'
            $Ciphers = 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256';
            $CiphersSecure = 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'

        }

        # Windows Server 2019/2022
        '20348|18363|18362|17763' {

            Write-Verbose 'Detected Windows Server 2019, 2022, or SAC release.'
            $Ciphers = 'TLS_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256';
            $CiphersSecure = 'TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'

        }

        # Default
        Default { $Unknown = $True }

    }

    If ($Unknown) {

        Write-Warning 'Error identifying operating system version.'
        Return

    }

    # Set cipher suite order
    If ($Security) {

        Write-Verbose 'Using security optimized TLS configuration.'
        $CipherSuiteOrder = $CiphersSecure

    }

    Else {

        Write-Verbose 'Using performance optimized TLS configuration.'
        $CipherSuiteOrder = $Ciphers

    }

    # Use transaction for registry updates
    Write-Verbose 'Starting registry transaction...'
    Start-Transaction

    # // Define registry parameters
    $Parameters = @{

        Path           = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\'
        Name           = 'Functions'
        PropertyType   = 'String'
        Value          = $CipherSuiteOrder
        UseTransaction = $True

    }

    # // Update registry settings
    Write-Verbose 'Updating TLS cipher suite configuration...'
    New-ItemProperty @Parameters -Force | Out-Null

    # // Disable SSL 3.0
    Write-Verbose 'Disabling SSL 3.0...'

    # // Create registry key
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server\' -Force | Out-Null

    # // Define registry parameters
    $Parameters = @{

        Path           = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server\'
        Name           = 'Enabled'
        PropertyType   = 'DWORD'
        Value          = '0'
        UseTransaction = $True

    }

    # // Update registry settings
    New-ItemProperty @Parameters -Force | Out-Null

    # // Disable TLS 1.0
    Write-Verbose 'Disabling TLS 1.0...'

    # // Create registry key
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\' -Force | Out-Null

    # // Define registry parameters
    $Parameters = @{

        Path           = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\'
        Name           = 'Enabled'
        PropertyType   = 'DWORD'
        Value          = '0'
        UseTransaction = $True

    }

    # // Update registry settings
    New-ItemProperty @Parameters -Force | Out-Null

    # // Disable TLS 1.1
    Write-Verbose 'Disabling TLS 1.1...'

    # // Create registry key
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\' -Force | Out-Null

    # // Define registry parameters
    $Parameters = @{

        Path           = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\'
        Name           = 'Enabled'
        PropertyType   = 'DWORD'
        Value          = '0'
        UseTransaction = $True

    }

    # // Update registry settings
    New-ItemProperty @Parameters -Force | Out-Null

    # Complete transaction
    Write-Verbose 'Committing registry transaction...'
    Complete-Transaction

    Write-Warning 'The server must be restarted for these changes to take effect. After restart, validate TLS configuration at https://ssllabs.com/ssltest/.'

}

# SIG # Begin signature block
# MIInGwYJKoZIhvcNAQcCoIInDDCCJwgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUOP4Qq+kZguDPSq7RsSzMycbU
# 4u2ggiDDMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
# AQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQsw
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
# Jpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAC
# hjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRV
# HSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyh
# hyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO
# 0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo
# 8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++h
# UD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5x
# aiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGrjCCBJag
# AwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIw
# MzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQg
# UlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCw
# zIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFz
# sbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ
# 7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7
# QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/teP
# c5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCY
# OjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9K
# oRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6
# dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM
# 1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbC
# dLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbEC
# AwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1N
# hS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9P
# MA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcB
# AQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggr
# BgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7Zv
# mKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI
# 2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/ty
# dBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVP
# ulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmB
# o1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc
# 6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3c
# HXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0d
# KNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZP
# J/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLe
# Mt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDy
# Divl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBrAwggSYoAMCAQICEAitQLJg0pxM
# n17Nqb2TrtkwDQYJKoZIhvcNAQEMBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UE
# AxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIxMDQyOTAwMDAwMFoXDTM2
# MDQyODIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBS
# U0E0MDk2IFNIQTM4NCAyMDIxIENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBANW0L0LQKK14t13VOVkbsYhC9TOM6z2Bl3DFu8SFJjCfpI5o2Fz16zQk
# B+FLT9N4Q/QX1x7a+dLVZxpSTw6hV/yImcGRzIEDPk1wJGSzjeIIfTR9TIBXEmtD
# mpnyxTsf8u/LR1oTpkyzASAl8xDTi7L7CPCK4J0JwGWn+piASTWHPVEZ6JAheEUu
# oZ8s4RjCGszF7pNJcEIyj/vG6hzzZWiRok1MghFIUmjeEL0UV13oGBNlxX+yT4Us
# SKRWhDXW+S6cqgAV0Tf+GgaUwnzI6hsy5srC9KejAw50pa85tqtgEuPo1rn3MeHc
# reQYoNjBI0dHs6EPbqOrbZgGgxu3amct0r1EGpIQgY+wOwnXx5syWsL/amBUi0nB
# k+3htFzgb+sm+YzVsvk4EObqzpH1vtP7b5NhNFy8k0UogzYqZihfsHPOiyYlBrKD
# 1Fz2FRlM7WLgXjPy6OjsCqewAyuRsjZ5vvetCB51pmXMu+NIUPN3kRr+21CiRshh
# WJj1fAIWPIMorTmG7NS3DVPQ+EfmdTCN7DCTdhSmW0tddGFNPxKRdt6/WMtyEClB
# 8NXFbSZ2aBFBE1ia3CYrAfSJTVnbeM+BSj5AR1/JgVBzhRAjIVlgimRUwcwhGug4
# GXxmHM14OEUwmU//Y09Mu6oNCFNBfFg9R7P6tuyMMgkCzGw8DFYRAgMBAAGjggFZ
# MIIBVTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRoN+Drtjv4XxGG+/5h
# ewiIZfROQjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8B
# Af8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdwYIKwYBBQUHAQEEazBpMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKG
# NWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290
# RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMBwGA1UdIAQVMBMwBwYFZ4EMAQMw
# CAYGZ4EMAQQBMA0GCSqGSIb3DQEBDAUAA4ICAQA6I0Q9jQh27o+8OpnTVuACGqX4
# SDTzLLbmdGb3lHKxAMqvbDAnExKekESfS/2eo3wm1Te8Ol1IbZXVP0n0J7sWgUVQ
# /Zy9toXgdn43ccsi91qqkM/1k2rj6yDR1VB5iJqKisG2vaFIGH7c2IAaERkYzWGZ
# gVb2yeN258TkG19D+D6U/3Y5PZ7Umc9K3SjrXyahlVhI1Rr+1yc//ZDRdobdHLBg
# XPMNqO7giaG9OeE4Ttpuuzad++UhU1rDyulq8aI+20O4M8hPOBSSmfXdzlRt2V0C
# FB9AM3wD4pWywiF1c1LLRtjENByipUuNzW92NyyFPxrOJukYvpAHsEN/lYgggnDw
# zMrv/Sk1XB+JOFX3N4qLCaHLC+kxGv8uGVw5ceG+nKcKBtYmZ7eS5k5f3nqsSc8u
# pHSSrds8pJyGH+PBVhsrI/+PteqIe3Br5qC6/To/RabE6BaRUotBwEiES5ZNq0RA
# 443wFSjO7fEYVgcqLxDEDAhkPDOPriiMPMuPiAsNvzv0zh57ju+168u38HcT5uco
# P6wSrqUvImxB+YJcFWbMbA7KxYbD9iYzDAdLoNMHAmpqQDBISzSoUSC7rRuFCOJZ
# DW3KBVAr6kocnqX9oKcfBnTn8tZSkP2vhUgh+Vc7tJwD7YZF9LRhbr9o4iZghurI
# r6n+lB3nYxs6hlZ4TjCCBsIwggSqoAMCAQICEAVEr/OUnQg5pr/bP1/lYRYwDQYJ
# KoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQTAeFw0yMzA3MTQwMDAwMDBaFw0zNDEwMTMyMzU5NTla
# MEgxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEgMB4GA1UE
# AxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjMwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQCjU0WHHYOOW6w+VLMj4M+f1+XS512hDgncL0ijl3o7Kpxn3GIV
# WMGpkxGnzaqyat0QKYoeYmNp01icNXG/OpfrlFCPHCDqx5o7L5Zm42nnaf5bw9Yr
# IBzBl5S0pVCB8s/LB6YwaMqDQtr8fwkklKSCGtpqutg7yl3eGRiF+0XqDWFsnf5x
# XsQGmjzwxS55DxtmUuPI1j5f2kPThPXQx/ZILV5FdZZ1/t0QoRuDwbjmUpW1R9d4
# KTlr4HhZl+NEK0rVlc7vCBfqgmRN/yPjyobutKQhZHDr1eWg2mOzLukF7qr2JPUd
# vJscsrdf3/Dudn0xmWVHVZ1KJC+sK5e+n+T9e3M+Mu5SNPvUu+vUoCw0m+PebmQZ
# BzcBkQ8ctVHNqkxmg4hoYru8QRt4GW3k2Q/gWEH72LEs4VGvtK0VBhTqYggT02ke
# fGRNnQ/fztFejKqrUBXJs8q818Q7aESjpTtC/XN97t0K/3k0EH6mXApYTAA+hWl1
# x4Nk1nXNjxJ2VqUk+tfEayG66B80mC866msBsPf7Kobse1I4qZgJoXGybHGvPrhv
# ltXhEBP+YUcKjP7wtsfVx95sJPC/QoLKoHE9nJKTBLRpcCcNT7e1NtHJXwikcKPs
# CvERLmTgyyIryvEoEyFJUX4GZtM7vvrrkTjYUQfKlLfiUKHzOtOKg8tAewIDAQAB
# o4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSltu8T
# 5+/N0GSh1VapZTGj3tXjSTBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0
# YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGlt
# ZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCBGtbeoKm1mBe8cI1P
# ijxonNgl/8ss5M3qXSKS7IwiAqm4z4Co2efjxe0mgopxLxjdTrbebNfhYJwr7e09
# SI64a7p8Xb3CYTdoSXej65CqEtcnhfOOHpLawkA4n13IoC4leCWdKgV6hCmYtld5
# j9smViuw86e9NwzYmHZPVrlSwradOKmB521BXIxp0bkrxMZ7z5z6eOKTGnaiaXXT
# UOREEr4gDZ6pRND45Ul3CFohxbTPmJUaVLq5vMFpGbrPFvKDNzRusEEm3d5al08z
# jdSNd311RaGlWCZqA0Xe2VC1UIyvVr1MxeFGxSjTredDAHDezJieGYkD6tSRN+9N
# UvPJYCHEVkft2hFLjDLDiOZY4rbbPvlfsELWj+MXkdGqwFXjhr+sJyxB0JozSqg2
# 1Llyln6XeThIX8rC3D0y33XWNmdaifj2p8flTzU8AL2+nCpseQHc2kTmOt44Owde
# OVj0fHMxVaCAEcsUDH6uvP6k63llqmjWIso765qCNVcoFstp8jKastLYOrixRoZr
# uhf9xHdsFWyuq69zOuhJRrfVf8y2OMDY7Bz1tqG4QyzfTkx9HmhwwHcK1ALgXGC7
# KP845VJa1qwXIiNO9OzTF/tQa/8Hdx9xl0RBybhG02wyfFgvZ0dl5Rtztpn5aywG
# Ru9BHvDwX+Db2a2QgESvgBBBijCCBwIwggTqoAMCAQICEAFmchIElUK4sup54tMH
# rEQwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2ln
# bmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMTAeFw0yMTEyMDIwMDAwMDBaFw0y
# NDEyMjAyMzU5NTlaMIGGMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5p
# YTEWMBQGA1UEBxMNTWlzc2lvbiBWaWVqbzEkMCIGA1UEChMbUmljaGFyZCBNLiBI
# aWNrcyBDb25zdWx0aW5nMSQwIgYDVQQDExtSaWNoYXJkIE0uIEhpY2tzIENvbnN1
# bHRpbmcwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDqy+tWoFEFtrMS
# SuaG3PuHTksQEgenx8aVXX2djaCkEueQNHwzP8T2LVy7Sx2OJ4LgPj9a0jj816JH
# mJ20GC116Tl6J5GM9yfyD1mmXz0oiXw03LVSU5Y1XvSPPOpnYJiI/8/lgZnA/Lwv
# HmsgA5hMkzoQUMG9k22LtpGLMTuWpVcEM3PJ4eF9dg8HFpBXYi36xaorSxpOPSg0
# DYi72pJhoVAsUfjlWmV60qnt153YUUm/Y8qZivNi1rHjzHNRCratELkE3b+fvvvU
# 0N8nS3y51GFQGpMQjlnWrMzPhFRV+CYY9P4JoTnk3IGfJjr8Db/spIiw5g5xODNC
# E7iMuaNMFnaRmosI5qo9tKar9K60wQYdjUxTvGtZQRCKdzONTOZsYbDtXztcj2yf
# wRxZfvU8S8jYa2vVMl+dP1t61cMme3bWa6SKguxRSl2VGYxufbeiv9UfMTo2/srP
# H60DWwF1Z0LcyTNrD8ybdfxZzvK2G1cYFwuYFqCkwYIJQ6To4lkCAwEAAaOCAgYw
# ggICMB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBTE
# Xt2j54gb3CcRRWNyRn0yxtn7iTAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYI
# KwYBBQUHAwMwgbUGA1UdHwSBrTCBqjBToFGgT4ZNaHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0
# MjAyMUNBMS5jcmwwU6BRoE+GTWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3Js
# MD4GA1UdIAQ3MDUwMwYGZ4EMAQQBMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cu
# ZGlnaWNlcnQuY29tL0NQUzCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGG
# GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2Nh
# Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdS
# U0E0MDk2U0hBMzg0MjAyMUNBMS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0B
# AQsFAAOCAgEAS8e384pqVHKwdB3HgJdI5yChrK4VdY3CL9UVwWvYQrfsarvUbgC1
# 1VxY0u77CGFjN8JUA0GdtNr2+yTnXmtMzTp7HPRC4zDKDT2aj5XFnyuo4EfPffFn
# IKhO3D/4P9JDGI7y5BHQ6Kx9vUxQc+oNDr0VM2ohAX9HMLbPNSflqAcVQuFvLzBu
# NB9S3YVcJGUVQs/O+nv/4lLhAAmcpermZgu+ilax2RsGfnYqr6WXx5+uPUriIxGG
# ndrSfZ5Et62oomM6pPffkRqnJ0HgCemEfZYxAEceuiHmf9+/ft0IJphqqj0mUWdE
# isdTukcEESlQZ/J5wWRwoXCw+IdcTUepAkI+Yxu891X1mC1aa5pEPQRBbXcnMPKh
# B0nFBlJcmEMMv5VIVLxJE0+1AU+KxlrYg7nx3UK9/kbyIrVEkc39DHjXeWPYlJLW
# jfCA0zdDl48VhdxDSI/GMViVFg8BoPHy3eiWD+1UryxKlioVgX30hGoE2LGGTLED
# JUKTq4sEuDAT16AmDUAWgcR0B5psaBPYLSE7LPnk82gNm61kHrsb5Y3yQa0VhQsG
# WhEockmIWfjZu9d9rQmDWNnjUACwxzktQ2WouEiP9EUuKcMf2XhhvR10PjBBWwgU
# NWUmAM9cD0TVKfxUqtYTgjSxfjFdQWCN+5V91w2T1D7iwknVgdgabAsxggXCMIIF
# vgIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFB
# MD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5
# NiBTSEEzODQgMjAyMSBDQTECEAFmchIElUK4sup54tMHrEQwCQYFKw4DAhoFAKB4
# MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkE
# MRYEFKA624Qso3X3mbOC+s3PstIOJ5wtMA0GCSqGSIb3DQEBAQUABIIBgIh+WZ3V
# dPtc5AbtEzZpvSjlLxKIPzatuWXK6tnVMqrawRa9681p2s2J8y2FRPqovqXSTKls
# jbhjZgKQklLJlvbQCGZAYmMtAbJG5mqg9slf5IvvsPlO/rpdi9uNKCzh2SCuk8JB
# pj0D5qvCD94uRkxWCRRuN2UIxRyFX1oWCo0BJ46kc/k122zxbQGp0zmrYYmj+YZV
# 2MoaOwDPGMGkS8ldI1UvPfkJSWfoOerkzMtuEznA+U1JdLj88W0KG8e+YKivEf/Z
# KV9JNkcmtpo4yZwzh7HsZcbclz22RVQ6GO786/GWaAfks1/iWbNnOM6IxzlXGonR
# J6wPLGGt/i9aFl5+KdgVYUWXv8ojTosa3WM5KIJSItJByJyjiMre0W+xaMdpGc2Y
# BTa6KKQRtxzXm4PlQ6NVsJvb+GmqovypMGSdIHRubuhT2DsZFL5IJmro+k+bveLA
# Jw1vs82P2HQieoB/5c84QcrchtTdwjn3hfK0SKZwH7fCTks0GlJ/adPZy6GCAyAw
# ggMcBgkqhkiG9w0BCQYxggMNMIIDCQIBATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBH
# NCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/l
# YRYwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
# CSqGSIb3DQEJBTEPFw0yMzEyMDgwMDAwMjZaMC8GCSqGSIb3DQEJBDEiBCCQ53SH
# eSnFjH46SS62E+QunAoqbRkRfH3eTBxnQ1arETANBgkqhkiG9w0BAQEFAASCAgCa
# 9WRsIjypZ8S0sLVcKtjmtvyte6Af6nZMSyDM1LfSQEsG8vVKDD/0h7YqndvGFWUV
# Cxx2a3o+noFKE4nHeRpd9AnFPi4NICLcm3AoaqZOTsKXggNWYTLeRJILcnjNyKpi
# wS2aHO1oj75hIxteWVxPQwv61o2sG/En8brNziCx+MXTjmrTxr3QJmbu4AUp+/9K
# g6EajJKKewOYcbVoli1ErUhHXUZqJR2rX5Y2ENvZk0D5rPeyMOCaLL1AWfMzvkDO
# uw65yhXz5MruyFkOTir/KMDR+JSJ7uoKsKJqmLneexLh2tLJmHho2auoKumBSbZ6
# LP+QcYBwxXzPHtE97MrlZs7Iv/C06GFM5YFmMBTzgf/i9HGGPaFgv85nl48iAKLd
# vO7j4OXOyWjoAlZR1eF3/HdqU3wkGZoW92ZhYIGk3rgiiD+CNoXvhG4nPmWmapdx
# sAOJmmlLFw0CQ2R4hUqex7DJYW/CirOT45GYGV0VvzpMUXSImpedVjPwgxwEqRLb
# KluNxl1+p7LLs20n4uySH8ZLJm2jmc35HK6NNxiJZ0geQ2+jhpmboLqPOXbZFL8y
# BkKpNC8JEbuOoRP0uxZ7QedcOcEH5EEDEuusT1XAbf/IQSZS796f51mVMNSCTfEx
# /LiAehvkeET10pGTNvNXVCAfT8D/Hdc50QUoT1H6Dg==
# SIG # End signature block
