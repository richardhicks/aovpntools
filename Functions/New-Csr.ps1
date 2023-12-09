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
    Version:        2.2.1
    Creation Date:  June 6, 2022
    Last Updated:   December 9, 2023
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

    $Hostname = $Hostname.ToLower()
    Write-Verbose "Subject name is $Hostname."

    If ($Hostname -Match '\*') {

        Write-Verbose 'Wildcard subject detected.'
        $Wildcard = $Hostname -Replace "^\*\.", ""

    }

    # Create INF file
    Write-Verbose 'Creating INF file...'
    $Inf = @()
    $Inf = { $Inf }.Invoke()

    $Inf.Add('[NewRequest]')
    $Inf.Add("Subject = ""CN=$Hostname""")

    If ($Wildcard) {

        $Inf.Add("FriendlyName = $Wildcard")

    }

    Else {

        $Inf.Add("FriendlyName = $Hostname")

    }

    If ($EC) {

        Write-Verbose 'Generating CSR using 256-bit EC key...'
        $Inf.Add('KeyAlgorithm = ECDSA_P256')
        $Inf.Add('KeyLength = 256')

    }

    Else {

        Write-Verbose 'Generating CSR using 2048-bit RSA key...'
        $Inf.Add('KeyAlgorithm = RSA')
        $Inf.Add('KeyLength = 2048')

    }

    $Inf.Add('MachineKeySet = True')

    If ($Exportable) {

        Write-Verbose 'Private key will be marked exportable.'
        $Inf.Add('Exportable = True')

    }

    $Inf.Add('')
    $Inf.Add('[Extensions]')
    $Inf.Add('2.5.29.17 = "{text}"')
    $Inf.Add("_continue_ = ""dns=$Hostname&""")

    If ($Wildcard) {

        Write-Verbose "Adding $Wildcard to the Subject Alternative Name list..."
        $Inf.Add("_continue_ = ""dns=$Wildcard&""")

    }

    ElseIf ($AdditionalNames) {

        ForEach ($Name in $AdditionalNames) {

            Write-Verbose "Adding $Name to the Subject Alternative Name list..."
            $Name = $Name.ToLower()
            $Inf.Add("_continue_ = ""dns=$Name&""")

        }

    }

    Write-Verbose "Writing INF file to $InfPath..."
    $Inf | Out-File $InfPath

    If (-Not $InfOnly) {

        # Create CSR
        Write-Verbose "Writing CSR file to $CsrPath..."
        Invoke-Command -ScriptBlock { certreq.exe -new $InfPath $CsrPath } | Out-Null

    }

    If ($Online) {

        # Submit CSR to online enterprise issuing CA
        Write-Verbose "Submitting CSR to issuing CA using $TemplateName certificate template..."
        Invoke-Command -ScriptBlock { certreq.exe -submit -attrib `"CertificateTemplate:$TemplateName`" $CsrPath $CerPath } | Out-Null

        # Import certificate
        Write-Verbose 'Importing certificate...'
        Import-Certificate -FilePath $CerPath -CertStoreLocation Cert:\LocalMachine\My | Out-Null

    }

}

# SIG # Begin signature block
# MIInGwYJKoZIhvcNAQcCoIInDDCCJwgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUdeiimtdcQIxfr264Mlw6L/Sw
# +9aggiDDMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
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
# MRYEFGnGPKNtn8TM87rtbGwjuggILwnwMA0GCSqGSIb3DQEBAQUABIIBgNXyRz7p
# q9J/iOOPEekG5I/Y24kBF3B0AHUqNDBC1M2dTSOITgvpL/M5QvsTNFAwHk6kCJj5
# YhEo5yJZkVtK0gw8OwD7SQxn4rvaXlMUdeS3cpO4bxD+pmR/BwrTGbN+op4BHxZW
# QTfoyHnkwNuavk9l7aXQG4sGHTG/Q/YUEzFa6aENDFiH7ZXwgQwp9cd4BL/i7vz6
# 0TJKkBmiWbuV2NbfK1bh7oO7Yy7Uq2Hg10vXcYFcJJkCo+VL7HWS4ssqVUURm8JI
# wcWI+6ks1203LcVroNcQHMDwUKXm/GtfCaBIXsrGQ2Ijc4U6zJ6hn/tm45K1vuIa
# bmW566456Z765vm6n1IaDayBcEGOX+UF+eagOoWYW+mRpJmIUYhNyoc900qcytfT
# 5k8bPhUMHti7jNkWx6KlqcusA/NVXBEWNXQdYdyfLqjpu9HH0ltVHRmgspgKfKL9
# uovHb/hri0/cnMDKDXFKYKGkhO6ly0wbj7e6kb5K6XCdQS8qBWSZMSVo1aGCAyAw
# ggMcBgkqhkiG9w0BCQYxggMNMIIDCQIBATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBH
# NCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/l
# YRYwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
# CSqGSIb3DQEJBTEPFw0yMzEyMDkxOTMyMThaMC8GCSqGSIb3DQEJBDEiBCAPde1X
# 4v6ykjq/1Ce/NSYQdA4Im9fbhxekHWrilavLzDANBgkqhkiG9w0BAQEFAASCAgAB
# 1/5Acw6hjYGoNVz1fRcNLeDQTsVLYgemwkOnFmQEWHTLxU5m0BMqWGTs55zQOXKp
# y/cxBr47jgTcc7pYS2xvY1uIm3UjxKk5dEnAIIdrcbR0BQ1I6ZfS4WU06ElXZEn2
# mR/PcpAgMMzCoA97PSXtOP9NOLG+aay3x7XG6ojo2Wqt58FREW7CWWygZ4sSh3i5
# tUOZ88wqmboMJAGXu83RF203a6K0rxHGaOBWQG+7IBeoNxtX+58DdukwD11FS937
# RjLpYWCUdZx9Jbl7Q/0d8E77FBaFb0Tb3XMclPQS1t3E3c+t05Pvl796xKwFr4Px
# J8sIVS2T71kxJtkmThCyMCKUwuDlaphml+rQCAv+TrCiU8+CvxrtCHSQ9PVNt0Xr
# OiFaRmJsw9Aef8jQyG80DtpuuFF47YMUEK6nlHB5aHTk7xj07zDeu/l91f1rxo8+
# WjgH+vkErkE2DmcY1K2tjBWB2QVhs1rq+LMIajmj1YMU3Zrzc89+XiHOE5AGEB+7
# 6w06kihAIEkGtwAw8LlQSlgENDr/kPrCeVpQursDdp45vgFaWzknpS5gTz54wuwz
# GOyHlWoQlA0eq7umYN+hWtlD0t+da86a0k8gcesCdU53m6AD2MISz/gf0dm2uDvf
# 5R+b/4J8umVk5CuOmfGuDMYK3iGgXSYwF+BWz2bPhQ==
# SIG # End signature block
