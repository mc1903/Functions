<#
.NOTES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Function: Get-Epoch
Module: N/A - Standalone Function
Author:	Martin Cooper (@mc1903)
Date: 19-07-2022
GitHub Repo: https://github.com/mc1903/Functions
Version: 1.0.0
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.SYNOPSIS
Returns current time as an Epoch Timestamp (aka Unix or POSIX Time)

.DESCRIPTION
Returns current time as an Epoch Timestamp in either seconds (10 digits - default), milliseconds (13 digits) or microseconds (16 digits) 

.PARAMETER siTimeUnit
Use 'Seconds', 'Milliseconds', 'Microseconds'

.EXAMPLE
Get-Epoch -siTimeUnit Milliseconds

#>

Function Get-Epoch {

    [CmdletBinding(
        PositionalBinding = $true
    )]

    Param (
        [Parameter(
            Position = 0,
            Mandatory = $false
        )]
        [ValidateSet("Seconds","Milliseconds","Microseconds")]
        [String] $siTimeUnit = "Seconds"
    )

    If ($siTimeUnit -eq "Microseconds") {
        $x = 1000000
    }
    ElseIf ($siTimeUnit -eq "Milliseconds") {
        $x = 1000
    }
    Else {
        $x = 1
    }
    
    $epoch = [int64][Math]::Floor((Get-Date (Get-Date).ToUniversalTime() -UFormat %s)) * $x
    Return $epoch

}
