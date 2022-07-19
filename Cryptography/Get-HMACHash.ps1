<#
.NOTES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Function: Get-HMACHash
Module: N/A - Standalone Function
Author:	Martin Cooper (@mc1903)
Date: 19-07-2022
GitHub Repo: https://github.com/mc1903/Functions
Version: 1.0.0
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.SYNOPSIS
Will return the HMAC (Hash-based Message Authentication Code) Hash of the plain text message using the shared secret key in both Base64 and Hex.

.DESCRIPTION
Supports HMAC-MD5/SHA1/SHA256/SHA384/SHA512

.PARAMETER message
The plain text message contents

.PARAMETER secret
The shared secret key

.PARAMETER algorithm
The algorithm to use 

.EXAMPLE
Get-HMACHash -message "this is a test" -secret "this is a key" -algorithm SHA256

Will return:

    Algorithm : SHA256
    HashB64   : N2QlRcskbAzqng/Zm5k3z6pkDTBqa8q0Zsx8cPPI1dA=
    HashHex   : 37642545CB246C0CEA9E0FD99B9937CFAA640D306A6BCAB466CC7C70F3C8D5D0

#>

Function Get-HMACHash {

    [CmdletBinding(
        PositionalBinding = $true
    )]

    Param (
        [Parameter(
            Position = 0,
            Mandatory = $true
        )]
        [ValidateNotNullOrEmpty()]
        [String] $message,

        [Parameter(
            Position = 1,
            Mandatory = $true
         )]
        [ValidateNotNullOrEmpty()]
        [String] $secret,

        [Parameter(
            Position = 2,
            Mandatory = $true
        )]
        [ValidateSet("MD5","SHA1","SHA256","SHA384","SHA512")]
        [String] $algorithm
    )

    $hmac = Switch ($algorithm) {
        "MD5" { New-Object System.Security.Cryptography.HMACMD5; Break }
        "SHA1" { New-Object System.Security.Cryptography.HMACSHA1; Break }
        "SHA256" { New-Object System.Security.Cryptography.HMACSHA256; Break }
        "SHA384" { New-Object System.Security.Cryptography.HMACSHA384; Break }
        "SHA512" { New-Object System.Security.Cryptography.HMACSHA512; Break }
    }

    $hmac.key = [Text.Encoding]::UTF8.GetBytes($secret)
    $signature = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($message))

    $hashB64 = [Convert]::ToBase64String($signature)
    $hashHex = [BitConverter]::ToString($signature).Replace('-','').ToUpper()

    $result = [PSCustomObject]@{
        Algorithm = [string]($algorithm)
        HashB64 = [string]($hashB64)
        HashHex = [string]($hashHex)
        }
   
    Return $result
}

<#

#Testing

Clear-Host
Remove-Variable * -ErrorAction SilentlyContinue

$algos = "MD5","SHA1","SHA256","SHA384","SHA512"

$knownhashes = [Ordered]@{
"MD5"=@{"B64"="Ia3EUg3AU1WNutfZ0VOOSQ==";"Hex"="21ADC4520DC053558DBAD7D9D1538E49"};
"SHA1"=@{"B64"="FWZky3vay5I0/GKafy/FmJxrvYw=";"Hex"="156664CB7BDACB9234FC629A7F2FC5989C6BBD8C"};
"SHA256"=@{"B64"="N2QlRcskbAzqng/Zm5k3z6pkDTBqa8q0Zsx8cPPI1dA=";"Hex"="37642545CB246C0CEA9E0FD99B9937CFAA640D306A6BCAB466CC7C70F3C8D5D0"};
"SHA384"=@{"B64"="R8gwP7XxamCLOJuWygRCMxeTAxcHIS/h6HXqu8N0gs4he+fHKU9pamZKnMmXGuLD";"Hex"="47C8303FB5F16A608B389B96CA0442331793031707212FE1E875EABBC37482CE217BE7C7294F696A664A9CC9971AE2C3"};
"SHA512"=@{"B64"="dR++AXStnCcqRCbLixSVEt/FXP1HtlALj/xHtbVnVFaAshzO0kvjcGcq219wHLxSnzXU+9AMQ06rDopHURcIDQ==";"Hex"="751FBE0174AD9C272A4426CB8B149512DFC55CFD47B6500B8FFC47B5B567545680B21CCED24BE370672ADB5F701CBC529F35D4FBD00C434EAB0E8A475117080D"}
}

$message = "this is a test" 
$secret = "this is a key"

Foreach ($algo in $algos) {

    $t = Get-HMACHash -message $message -secret $secret -algorithm $algo

    Write-Output "HMAC-$($algo) Base64 Matches: $($t.HashB64.Equals($knownhashes.$algo.B64))"
    Write-Output "HMAC-$($algo) Hex Matches: $($t.HashHex.Equals($knownhashes.$algo.Hex))`n"

}

#>