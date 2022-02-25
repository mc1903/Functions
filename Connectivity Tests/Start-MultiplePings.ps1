<#
.NOTES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Module: N/A - Standalone Function
Function: Start-MultiplePings
Author:	Martin Cooper (@mc1903)
Date: 25-02-2022
GitHub Repo: https://github.com/mc1903/Functions
Version: 1.0.1
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.SYNOPSIS
Pings a list of servers.

.DESCRIPTION
Pings a list of servers, displays the results on a single page & loops until stopped.

.PARAMETER ServerList
Required. The 'serverList' and 'ServerCSV' parameters are mutually exclusive.
This is a double-quote enclosed comma seperated list of IPs/Hostnames/FQDNs - e.g. "8.8.8.8,Server1,Server2.domain.tld"
Duplicate values are ignored.

.PARAMETER ServerCSV
Required. The 'serverList' and 'ServerCSV' parameters are mutually exclusive.
This is the full path to a .csv file containing a comma seperated list of IPs/Hostnames/FQDNs - e.g. "8.8.8.8,Server1,Server2.domain.tld".
CSV List should be privided WITHOUT a header.
Duplicate values are ignored.

.PARAMETER reloadCSV
Optional.
Switch. If $true the ServerCSV file will be reloaded before the next loop. Allows servers to be added/removed by editing/saving the CSV during runtime.

.PARAMETER waittime
Optional. If not provided, there will be a 15 second wait between running each round of Pings.

.EXAMPLE
Start-MultiplePings -ServerList "MC-ADDC-V-101,MC-ADDC-V-102,MC-ADDC-V-103" -waittime 10

.EXAMPLE
Start-MultiplePings -ServerCSV "P:\Start-MultiplePings\pinglist.csv" -reloadCSV -waittime 5
#>

Function Start-MultiplePings {

    [CmdletBinding(
        PositionalBinding = $false,
        SupportsShouldProcess = $false
    )]
    
    Param (
        [Parameter(
            Position = 0,
            ParameterSetName="List",
            Mandatory = $true
        )]
        [ValidateNotNullOrEmpty()]
        [String] $ServerList,
    
        [Parameter(
            Position = 0,
            ParameterSetName="CSV",
            Mandatory = $true
        )]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]$ServerCSV,

        [Parameter(
            Position = 1,
            ParameterSetName="CSV",
            Mandatory = $false
        )]
        [Switch] $reloadCSV,
    
        [Parameter(
            Position = 2,
            Mandatory = $false
        )]
        [ValidateRange(1,3600)]
        [Int] $waittime = 15
    
    )
    
    
    #Private Functions
    #

    $InitScriptblock = {
    
        Function Test-PING {
    
            [CmdletBinding(
                PositionalBinding = $true
            )]
    
            Param (
                [Parameter(
                    Position = 0,
                    Mandatory = $true
                )]
                [ValidateNotNullOrEmpty()]
                [String] $hostname,
    
                [Parameter(
                    Position = 1,
                    Mandatory = $false
                )]
                [ValidateRange(1,65500)]
                [Int] $packetbytes = 32,
    
                [Parameter(
                    Position = 2,
                    Mandatory = $false
                )]
                [Int] $timeout = 100,
    
                [Parameter(
                    Position = 3,
                    Mandatory = $false
                )]
                [ValidateRange(1,256)]
                [Int] $maxTtl = 32,
    
                [Parameter(
                    Position = 4,
                    Mandatory = $false
                )]
                [Switch] $dontFragment = $false
    
            )
    
            $icmpPing = New-Object system.Net.NetworkInformation.Ping
            $icmpOptions = New-Object System.Net.NetworkInformation.PingOptions
            $icmpOptions.Ttl = $maxTtl
            $icmpOptions.DontFragment = $dontFragment
            $icmpDataBuffer = New-Object byte[] $packetbytes
            $lastChecked = (Get-Date).ToString("HH:mm:ss.fff")
            $icmpPingResult = $icmpPing.Send($hostname,$timeout,$icmpDataBuffer,$icmpOptions)
    
            If (!$($icmpPingResult.Address) -and !$($icmpPingResult.Status)) {
                $icmpPingResultStatus = "TimedOut"
                $icmpPingResultRoundtripTime = 0
            }
            Else {
                $icmpPingResultStatus = $($icmpPingResult.Status)
                $icmpPingResultRoundtripTime = $($icmpPingResult.RoundtripTime)
            }
    
            $result = [PSCustomObject]@{
                LastChecked = [string]$($lastChecked)
                ServerName = [string]$($hostname)
                IPAddress = [string]$($icmpPingResult.Address)
                Status = [string]$($icmpPingResultStatus) 
                RTT_ms = [string]$($icmpPingResultRoundtripTime) 
                TTL = [string]$($icmpPingResult.Options.Ttl)
                Buffer_bytes = [string]$($packetbytes)
                DontFragment = [boolean]$($dontFragment)
                Timeout_ms = [string]$($timeout)
            }
    
            $icmpPing.Dispose()
            Return $result
        }
    
    }
    
    $MainScriptblock = {
        Param($a,$b,$c,$d,$e)
        Test-PING -hostname $a -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }

    #Main Script
    #
    
    If ($ServerList) {
        
        $servers = $ServerList.split(",") | Sort-object -Unique
    }
    
    If ($ServerCSV) {
        
        If(-Not ($($ServerCSV.FullName) | Test-Path) ){
            Throw "The file $($ServerCSV.FullName) was NOT found"
        }
        
        If(-Not ($($ServerCSV.FullName) | Test-Path -PathType Leaf) ){
            Throw "Folder paths are NOT allowed. Please specify the path to a .csv or .txt file"
        }
        
        If($($ServerCSV.FullName) -notmatch "(\.csv|\.txt)" ){
            Throw "The file specified MUST be either a .csv or .txt"
        }
        
        $serversCSV = Import-Csv -LiteralPath $($ServerCSV.FullName) -Header Name | Select-object -Unique Name
        $servers = $($serversCSV.Name) | Sort-object
    
    }
    
    $sessionID = ( -join ((0x30..0x39) + (0x41..0x5A) + (0x61..0x7A) | Get-Random -Count 6 | ForEach-Object {[char]$_}) )
    $results = $null
    
    Clear-Host
    
    While ($true) {
        
        $lastrun = (Get-Date).ToString("HH:mm:ss")
        $writeProgressCount = 0
        
        ForEach ($server in $servers) {
        
            $writeProgressCount++
        
            Write-Progress -Activity "Processing Server $($writeProgressCount) of $($servers.count)" -CurrentOperation $($server.ToUpper()) -PercentComplete (($writeProgressCount / $($servers.count)) * 100) | Out-Default
        
            While (@(Get-Job -state Running).count -ge 10) {
                Start-Sleep -Milliseconds 50
            }
            
            Start-Job -Name "$($sessionID)-PING-$($server)" -InitializationScript $InitScriptblock -ScriptBlock $MainScriptblock -ArgumentList $server | Out-Null
        }
        
        Write-Progress -Completed -Activity " "
        
        Clear-Host
        
        Write-Output "`n`n`n`n`n`n`nLast Run: $lastrun"

        $results = Get-Job | Where-Object {$_.Name -like "$($sessionID)*"} | Wait-Job | Receive-Job | Select-Object LastChecked, ServerName, IPAddress, Status, RTT_ms, TTL
        $results | Format-Table -AutoSize
        
        $goodPings = $results | Where-Object {$_.Status -eq "Success"}
        $badPings = $results | Where-Object {$_.Status -ne "Success"}
        
        Get-Job | Remove-Job | Where-Object {$_.Name -like "$($sessionID)*"} -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        
        Write-Output "Total: $($results.count) | Good: $($goodPings.count) | Bad: $($badPings.count)`n"
        Write-Output "Next Run in $($waittime) Seconds. Use CTRL+C to Exit"
        
        Start-Sleep -Seconds $waittime

        If ($reloadCSV -eq $true) {

            $serversCSV = Import-Csv -LiteralPath $($ServerCSV.FullName) -Header Name | Select-object -Unique Name
            $servers = $($serversCSV.Name) | Sort-object

        }
    
    }
 
}

