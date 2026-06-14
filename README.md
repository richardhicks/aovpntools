# AOVPNTools

[![PowerShell Gallery](https://img.shields.io/badge/PowerShell%20Gallery-AOVPNTools-blue)](https://www.powershellgallery.com/packages/AOVPNTools) [![License](https://img.shields.io/badge/License-MIT-green)](https://github.com/richardhicks/aovpntools/blob/main/LICENSE) [![Version](https://img.shields.io/badge/Version-1.9.14-brightgreen)](https://github.com/richardhicks/aovpntools)

PowerShell module for configuring, optimizing, and troubleshooting Windows Server Routing and Remote Access Service (RRAS) for Always On VPN.

## Description

AOVPNTools is a collection of PowerShell functions designed to simplify the deployment, configuration, optimization, and troubleshooting of Microsoft Always On VPN. It provides tools for installing and configuring RRAS and NPS servers, managing VPN and TLS certificates, creating and removing VPN client connections, hardening IKEv2 and SSTP security settings, and more.

## Installation

### PowerShell Gallery

```
Install-Module -Name AOVPNTools -Scope CurrentUser
```

### Manual Installation

1. Download the module files from the [GitHub repository](https://github.com/richardhicks/aovpntools).
2. Copy the `AOVPNTools` folder to a PowerShell module directory (e.g., `$env:USERPROFILE\Documents\PowerShell\Modules\`).
3. Import the module:

```
Import-Module -Name AOVPNTools
```

## Functions

| Function                               | Description                                                                                                  |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `Clear-AutoTriggerDisabledProfile`     | Remove an Always On VPN profile from the AutoTriggerDisabledProfilesList                                      |
| `Enable-Ikev2CrlCheck`                 | Enable Certificate Revocation List (CRL) checking for IKEv2 VPN connections on RRAS servers                   |
| `Enable-SstpOffload`                   | Enable TLS offloading for SSTP VPN connections on RRAS servers                                                |
| `Enable-VpnServerIKEv2Fragmentation`   | Enable IKEv2 fragmentation support on Windows Server 1803 and later operating systems                        |
| `Export-VpnServerConfiguration`        | Export RRAS configuration to a text file                                                                     |
| `Get-EapConfiguration`                 | Extract EAP configuration from an existing Windows VPN connection                                             |
| `Get-PublicIpAddress`                  | Identify a client's public IP address                                                                        |
| `Get-RadiusSharedSecret`               | Enumerate RADIUS clients and extract their shared secrets from an NPS configuration export file               |
| `Get-SstpOffload`                      | Enumerate TLS offload settings for SSTP VPN connections on RRAS servers                                       |
| `Get-TlsCertificate`                   | View and optionally save the TLS certificate for an HTTPS website or service                                  |
| `Get-VpnClientMdmNodeCache`            | Retrieve VPN profile information from the Windows MDM node cache                                              |
| `Get-VpnClientProfileXml`              | Extract ProfileXML from an existing VPN connection                                                           |
| `Get-VpnServerTlsCertificate`          | Retrieve and display the TLS certificate used by the VPN server for SSTP                                      |
| `Import-VpnServerConfiguration`        | Import RRAS configuration from a text file                                                                   |
| `Install-NpsServer`                    | Install a baseline configuration for Windows Server Network Policy and Access Services (NPAS) servers          |
| `Install-VpnServer`                    | Install a baseline configuration for Windows Server RRAS servers                                              |
| `Install-VpnServerTlsCertificate`      | Assign a TLS certificate to the SSTP listener on RRAS servers                                                 |
| `New-AovpnConnection`                  | Create an Always On VPN user or device tunnel connection                                                      |
| `New-Csr`                              | Generate a Certificate Signing Request (CSR) for use with RRAS servers                                        |
| `New-TestVpnConnection`                | Create a test VPN connection for validating Always On VPN infrastructure                                      |
| `Optimize-VpnServerTlsConfiguration`   | Optimize TLS configuration for SSTP VPN connections                                                          |
| `Remove-AovpnConnection`               | Remove an Always On VPN profile and associated registry artifacts from Windows 10/11 clients                 |
| `Remove-VpnServerDuplicateConnection`  | Remove duplicate VPN connections on RRAS servers                                                              |
| `Remove-VpnServerStaleConnection`      | Remove stale VPN connections on an RRAS server                                                                |
| `Set-Ikev2VpnLoadBalancingConfiguration` | Increase concurrent IPsec connections from the same source IP and update IKEv2 idle timeout and network outage defaults |
| `Set-Ikev2VpnRootCertificate`          | Configure the trusted root certification authority (CA) for IKEv2 VPN connections on RRAS servers             |
| `Set-Ikev2VpnSecurityBaseline`         | Configure baseline IPsec security settings on RRAS servers                                                    |
| `Set-VpnServerPortConfiguration`       | Configure SSTP and IKEv2 VPN ports on an RRAS server                                                          |

## Requirements

- Windows Server with the Routing and Remote Access Service (RRAS) role installed (for VPN server functions).
- Windows Server with the Network Policy and Access Services (NPAS) role installed (for NPS/RADIUS functions).
- Windows 10/11 (for VPN client functions).
- Administrative privileges (for functions that modify server configuration or services).

## Author

**Richard M. Hicks** - [Richard M. Hicks Consulting, Inc.](https://www.richardhicks.com/)

- Website: <https://www.richardhicks.com/>
- GitHub: <https://github.com/richardhicks/aovpntools>
- X: [@richardhicks](https://x.com/richardhicks)

## License

This project is licensed under the [MIT License](https://github.com/richardhicks/aovpntools/blob/main/LICENSE).

## Copyright

© 2022-2026 Richard M. Hicks Consulting, Inc. All rights reserved.
