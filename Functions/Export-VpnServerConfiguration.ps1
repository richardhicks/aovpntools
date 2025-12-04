<#

.SYNOPSIS
    Export Windows Server Routing and Remote Access Service (RRAS) configuration to a text file.

.PARAMETER Path
    The path for the RRAS configuration export file. The files are placed in the current directory by default.

.EXAMPLE
    Export-VPNServerConfiguration -Path C:\Backup

.DESCRIPTION
    This function will export the Windows Server RRAS configuration and IKEv2 settings to text files.

.LINK
    https://github.com/richardhicks/aovpntools/blob/main/Functions/Export-VpnServerConfiguration.ps1

.LINK
    https://directaccess.richardhicks.com/

.NOTES
    Version:        2.1.3
    Creation Date:  January 8, 2020
    Last Updated:   November 26, 2025
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

Function Export-VpnServerConfiguration {

    [CmdletBinding()]

    Param (

        [string]$Path = '.\'

    )

    If (-Not (Test-Path -Path $Path)) {

        # Create folder if it doesn't exist
        Write-Verbose "$Path doesn't exist. Creating it..."
        New-Item -ItemType Directory -Path $Path | Out-Null

    }

    # Define file locations
    $Hostname = $env:computername.ToLower()
    $FilePath = Join-Path $Path -ChildPath "${Hostname}_rasconfig.txt"
    $Ikev2Configuration = Join-Path $Path -ChildPath "${Hostname}_ikev2config.reg"

    # Check for existing RRAS configuration backup file. Delete if it exists
    Write-Verbose 'Checking for existing RRAS configuration backup file...'
    If (Test-Path $FilePath) {

        Write-Verbose 'Deleting existing RRAS configuration backup file...'
        Remove-Item $FilePath

    }

    If (Test-Path $Ikev2Configuration) {

        Write-Verbose 'Deleting existing IKEv2 configuration backup file...'
        Remove-Item $Ikev2Configuration

    }

    # Export RRAS configuration to text file
    Write-Verbose "Exporting VPN server configuration..."
    Invoke-Command -ScriptBlock { netsh.exe ras dump | Out-File $FilePath.ToLower() -Encoding ASCII }
    Write-Output "Exported RRAS configuration to $FilePath."

    # Export IKEv2 configuration to text file
    Write-Verbose 'Exporting IKEv2 settings...'
    Invoke-Command -ScriptBlock { reg.exe export HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\IKEV2\ $Ikev2Configuration | Out-Null }
    Write-Output "Exported IKEv2 settings to $Ikev2Configuration."

    # Remind administrator about missing NPS shared secret and TLS certificate binding for SSTP
    Write-Warning 'The RRAS configuration backup does NOT include RADIUS shared secrets or SSTP certificate binding information. Those must be configured manually after import.'
    Write-Verbose "RRAS configuration saved to $FilePath and $Ikev2Configuration."

}

# SIG # Begin signature block
# MIIftAYJKoZIhvcNAQcCoIIfpTCCH6ECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUseXofxLzH7PKPNLWQro89cZM
# FwWgghqZMIIDWTCCAt+gAwIBAgIQD7inQLkVjQNRQ7xZ2fBAKTAKBggqhkjOPQQD
# AzBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQL
# ExB3d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9v
# dCBHMzAeFw0yMTA0MjkwMDAwMDBaFw0zNjA0MjgyMzU5NTlaMGQxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE8MDoGA1UEAxMzRGlnaUNlcnQg
# R2xvYmFsIEczIENvZGUgU2lnbmluZyBFQ0MgU0hBMzg0IDIwMjEgQ0ExMHYwEAYH
# KoZIzj0CAQYFK4EEACIDYgAEu7SsJ6VIDaJTX48ugT4vU3a4CJSimqqKi5i1sfD8
# KhW7ubOlIi/9asC94lVoYGuXNMFmU3Ej/BrVyiAPAkCio0paRqORUyuV8gPpq6bT
# h3Yv52SfnjVR/MNjNXh25Ph3o4IBVzCCAVMwEgYDVR0TAQH/BAgwBgEB/wIBADAd
# BgNVHQ4EFgQUm1+wNrqdBq4ZJ73AoCLAi4s4d+0wHwYDVR0jBBgwFoAUs9tIpPmh
# xdiuNkHMEWNpYim8S8YwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUF
# BwMDMHYGCCsGAQUFBwEBBGowaDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMEAGCCsGAQUFBzAChjRodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRHbG9iYWxSb290RzMuY3J0MEIGA1UdHwQ7MDkwN6A1oDOGMWh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMy5jcmww
# HAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwCgYIKoZIzj0EAwMDaAAwZQIw
# eL1JlWVxAdBGV2hlDmip3DYIwe791I7bQGU/Df+Tr8KuY4ajfsu0kVp47AcDZwd8
# AjEA558f8QdbrDTGOLy1pVDO5uo4fj55kOSkW6sCDegH/FamWords1Cy3fL6ZnSe
# 0BZjMIID/jCCA4SgAwIBAgIQDUo02oaQj8ATLLyBN5OvJDAKBggqhkjOPQQDAzBk
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xPDA6BgNVBAMT
# M0RpZ2lDZXJ0IEdsb2JhbCBHMyBDb2RlIFNpZ25pbmcgRUNDIFNIQTM4NCAyMDIx
# IENBMTAeFw0yNDEyMDYwMDAwMDBaFw0yNzEyMjQyMzU5NTlaMIGGMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNTWlzc2lvbiBWaWVq
# bzEkMCIGA1UEChMbUmljaGFyZCBNLiBIaWNrcyBDb25zdWx0aW5nMSQwIgYDVQQD
# ExtSaWNoYXJkIE0uIEhpY2tzIENvbnN1bHRpbmcwWTATBgcqhkjOPQIBBggqhkjO
# PQMBBwNCAARQm7XKqXO7xhjOIVTO/VPu39LSs6PAQBjCf9BOyVMCiX8jCY/Y7Aja
# aetfpgTXU8IqxJvytFc9Nr2pNBbXG/98o4IB8zCCAe8wHwYDVR0jBBgwFoAUm1+w
# NrqdBq4ZJ73AoCLAi4s4d+0wHQYDVR0OBBYEFCiDJFZHyEjVMkCe28Ly5vbAiJMY
# MD4GA1UdIAQ3MDUwMwYGZ4EMAQQBMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cu
# ZGlnaWNlcnQuY29tL0NQUzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwgasGA1UdHwSBozCBoDBOoEygSoZIaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0R2xvYmFsRzNDb2RlU2lnbmluZ0VDQ1NIQTM4NDIwMjFDQTEu
# Y3JsME6gTKBKhkhodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9i
# YWxHM0NvZGVTaWduaW5nRUNDU0hBMzg0MjAyMUNBMS5jcmwwgY4GCCsGAQUFBwEB
# BIGBMH8wJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBXBggr
# BgEFBQcwAoZLaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xv
# YmFsRzNDb2RlU2lnbmluZ0VDQ1NIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQCMAAw
# CgYIKoZIzj0EAwMDaAAwZQIwTDrAW/NKsehOktpZ5x2n7smNqWqA7T43H3XSmgdR
# ypwMu1i2hFXO/MQAvOIlt5ehAjEA4Tjw+SR7cGMRB+g8VQ5XuaSyn7skB4mNYtCP
# T60p9aZT1HmQ052CpprNT+upwbwpMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21Di
# CEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtE
# aWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzEx
# MTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/
# 5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xuk
# OBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpz
# MpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7Fsa
# vOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qT
# XtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRz
# Km6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRc
# Ro9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADk
# RSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMY
# RJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4m
# rLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C
# 1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYD
# VR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkG
# CCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmww
# EQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+g
# o3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0
# /4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnL
# nU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU9
# 6LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ
# 9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9X
# ql4o4rmUMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkqhkiG9w0B
# AQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVk
# IFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUg
# Q0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+PEbA
# HKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8
# I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Ma
# l5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIBHYJBYgzW
# Ijk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IB
# ZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN20VRS3hpL
# gIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDnki7CcoKC
# z6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV
# /FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8
# M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1Nq
# zJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlY
# zyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaA
# FOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAK
# BggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4
# oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJv
# b3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqG
# SIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wG
# c/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F
# 448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/axFSgoR8
# n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYfctSLANEB
# fHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4MXRJDMdT
# SlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i697cvaiIo2
# p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy
# +GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm
# 4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSabnf7+Pu0V
# rFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7
# Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2T7m3XDCC
# Bu0wggTVoAMCAQICEAqA7xhLjfEFgtHEdqeVdGgwDQYJKoZIhvcNAQELBQAwaTEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhE
# aWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAy
# MDI1IENBMTAeFw0yNTA2MDQwMDAwMDBaFw0zNjA5MDMyMzU5NTlaMGMxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNl
# cnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI1IDEwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDQRqwtEsae0OquYFazK1e6b1H/
# hnAKAd/KN8wZQjBjMqiZ3xTWcfsLwOvRxUwXcGx8AUjni6bz52fGTfr6PHRNv6T7
# zsf1Y/E3IU8kgNkeECqVQ+3bzWYesFtkepErvUSbf+EIYLkrLKd6qJnuzK8Vcn0D
# vbDMemQFoxQ2Dsw4vEjoT1FpS54dNApZfKY61HAldytxNM89PZXUP/5wWWURK+If
# xiOg8W9lKMqzdIo7VA1R0V3Zp3DjjANwqAf4lEkTlCDQ0/fKJLKLkzGBTpx6EYev
# vOi7XOc4zyh1uSqgr6UnbksIcFJqLbkIXIPbcNmA98Oskkkrvt6lPAw/p4oDSRZr
# eiwB7x9ykrjS6GS3NR39iTTFS+ENTqW8m6THuOmHHjQNC3zbJ6nJ6SXiLSvw4Smz
# 8U07hqF+8CTXaETkVWz0dVVZw7knh1WZXOLHgDvundrAtuvz0D3T+dYaNcwafsVC
# GZKUhQPL1naFKBy1p6llN3QgshRta6Eq4B40h5avMcpi54wm0i2ePZD5pPIssosz
# QyF4//3DoK2O65Uck5Wggn8O2klETsJ7u8xEehGifgJYi+6I03UuT1j7FnrqVrOz
# aQoVJOeeStPeldYRNMmSF3voIgMFtNGh86w3ISHNm0IaadCKCkUe2LnwJKa8TIlw
# CUNVwppwn4D3/Pt5pwIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNVHQ4E
# FgQU5Dv88jHt/f3X85FxYxlQQ89hjOgwHwYDVR0jBBgwFoAU729TSunkBnx6yuKQ
# VvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMI
# MIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAy
# NUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIw
# MjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkq
# hkiG9w0BAQsFAAOCAgEAZSqt8RwnBLmuYEHs0QhEnmNAciH45PYiT9s1i6UKtW+F
# ERp8FgXRGQ/YAavXzWjZhY+hIfP2JkQ38U+wtJPBVBajYfrbIYG+Dui4I4PCvHpQ
# uPqFgqp1PzC/ZRX4pvP/ciZmUnthfAEP1HShTrY+2DE5qjzvZs7JIIgt0GCFD9kt
# x0LxxtRQ7vllKluHWiKk6FxRPyUPxAAYH2Vy1lNM4kzekd8oEARzFAWgeW3az2xe
# jEWLNN4eKGxDJ8WDl/FQUSntbjZ80FU3i54tpx5F/0Kr15zW/mJAxZMVBrTE2oi0
# fcI8VMbtoRAmaaslNXdCG1+lqvP4FbrQ6IwSBXkZagHLhFU9HCrG/syTRLLhAezu
# /3Lr00GrJzPQFnCEH1Y58678IgmfORBPC1JKkYaEt2OdDh4GmO0/5cHelAK2/gTl
# QJINqDr6JfwyYHXSd+V08X1JUPvB4ILfJdmL+66Gp3CSBXG6IwXMZUXBhtCyIaeh
# r0XkBoDIGMUG1dUtwq1qmcwbdUfcSYCn+OwncVUXf53VJUNOaMWMts0VlRYxe5nK
# +At+DI96HAlXHAL5SlfYxJ7La54i71McVWRP66bW+yERNpbJCjyCYG2j+bdpxo/1
# Cy4uPcU3AWVPGrbn5PhDBf3Froguzzhk++ami+r3Qrx5bIbY3TVzgiFI7Gq3zWcx
# ggSFMIIEgQIBATB4MGQxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjE8MDoGA1UEAxMzRGlnaUNlcnQgR2xvYmFsIEczIENvZGUgU2lnbmluZyBF
# Q0MgU0hBMzg0IDIwMjEgQ0ExAhANSjTahpCPwBMsvIE3k68kMAkGBSsOAwIaBQCg
# eDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEE
# AYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJ
# BDEWBBQ7LgeMtcICBdeZrxMVPIV+FMEVajALBgcqhkjOPQIBBQAERjBEAiBcFYkt
# KVwf1kU+2bv9ViSsVz+EgMj2imPiqYQmqNu+lQIgU4SEpto9NxH/J7J8b6ORrgUA
# ctvhB1RApnH69mYebomhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBp
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMT
# OERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2
# IDIwMjUgQ0ExAhAKgO8YS43xBYLRxHanlXRoMA0GCWCGSAFlAwQCAQUAoGkwGAYJ
# KoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUxMTI2MTky
# NTA3WjAvBgkqhkiG9w0BCQQxIgQg1RguXCkiyfrTHCm11gETVm+0sxyORBqaoSIe
# XKsIQC8wDQYJKoZIhvcNAQEBBQAEggIALR4yjIqxOuxNPGbdCvBPHsRZJWRd+Pit
# FKTgGFUq9BxwGdL8VbaoYm1ytPr/L+kg7gcMTLKZ2PUtT73mHxLO0QU92go5AmkY
# fyjij/qbiNm/jweSdHnmyI5JNn7QT0JpbqNUFPWF7wamz0Qvr5t26bBD6P7mppWq
# eZhT6RvrkUj+RTjSyHjcMd6eOBzzqoq/OsOGbR76H1xxY1o25zQJt45GIj4TSTN1
# tSsLgsgR/yisL2MYPuA4a8GMBIwhzRrhvKeCWGSyUmz3h6cCY9KgvyAUJdMArGxy
# Y6MyVpuwoWLUYCx6xbIK4Z4fjpLTuCyx8ewPKXC0HLRUC11AQfCZJWSEk4IePXT/
# MfJ2JtuODt2C82hZqkyWbyKA/C+Ls/bSmW5gU/73SowVMlCDGikdfi5/+dYcwDS4
# dvM7arZbx/JxSDPDJFH9gVOh3AfrXC/nK+LyePvZ/y3VfQrO91A7XIwjIEpNNkp1
# RUpfNs6iv068azkwe88KNMofUAuETHe8jvOuWLmlnyIk30m7HipSBOAcIDohSIdo
# ZBTgPwy6pfjkXBHmmj6L9n2a7J5Ks7/FrXnc5EWBw0HMqBKowcDgsLQJe/TCAl4o
# Z3PJv4gqOcmOMXR1XB89MAAUvd8/XKWbZx2aHmf0dwLGvOeyV4DXy24Ja+N5LGEe
# BWk8uBKlMvY=
# SIG # End signature block
