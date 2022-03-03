<#
.NOTES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Module: N/A - Standalone Function
Function: Get-VMHardDisks
Author:	Martin Cooper (@mc1903)
Date: 01-03-2022
GitHub Repo: https://github.com/mc1903/Functions
Version: 1.0.3
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.SYNOPSIS
Gets some basic details for all HDD's attached to a VM.

.DESCRIPTION
Gets some basic details for all HDD's attached to a VM. Works for multiple VM's and across multiple vCenter Servers. 

.PARAMETER vmList
Required. The '-vmList' and '-vmCSV' parameters are mutually exclusive.
This is a double-quote enclosed comma seperated list of Virtual Machine Inventory Names - e.g. "VM1,VM2".
Duplicate values are ignored.

.PARAMETER vmCSV
Required. The '-vmList' and '-vmCSV' parameters are mutually exclusive.
This is the full path to a .csv file containing a comma seperated list of Virtual Machine Inventory Names - e.g. "VM1,VM2".
CSV List should be privided WITHOUT a header.
Duplicate values are ignored.

.PARAMETER vCenterServerList
Required.
This is a double-quote enclosed comma seperated list of vCenter Server Hostnames/FQDNs - e.g. "vcenter1,vcenter2.domain.tld".
Duplicate values are ignored.

.PARAMETER vCenterCred
Optional. If not provided, the user will be prompted at runtime to supply the Credentials to authenticate to each vCenter Server.
If the credential is a vCenter Server SSO account (usually user@vsphere.local) pre-validation is skipped.
If the credential is a Windows AD Domain account, the credentials will be pre-validated against the AD Domain before being used on each vCenter Server connection request. This is to help prevent account lockouts if the password is incorrectly typed.
Provide as a PSCredential object

.PARAMETER exportCSV
Optional.
Switch. If $true the results will be saved to .csv file in the userprofile\Downloads directory.
The exported file will be named VMHardDisks_Export_dd-MMM-yyyy_HH-mm-ss.csv

.PARAMETER suppressProgress
Optional.
Switch. If $true the progress bar will be suppressed.

#>


Function Get-VMHardDisks {

[CmdletBinding(
    PositionalBinding = $false,
    SupportsShouldProcess = $false
)]

Param (
    [Parameter(
        ParameterSetName="vmList",
        Mandatory = $true
    )]
    [ValidateNotNullOrEmpty()]
    [String] $vmList,

    [Parameter(
        ParameterSetName="vmCSV",
        Mandatory = $true
    )]
    [ValidateNotNullOrEmpty()]
    [System.IO.FileInfo]$vmCSV,

    [Parameter(
        Mandatory = $false
    )]
    [ValidateNotNullOrEmpty()]
    [String] $vCenterServerList,

    [Parameter(
        Mandatory = $false
    )]
    [ValidateNotNullOrEmpty()]
    [System.Management.Automation.PSCredential] $vCenterCred,

    [Parameter(
        Mandatory = $false
    )]
    [Switch] $exportCSV,

    [Parameter(
        Mandatory = $false
    )]
    [Switch] $suppresProgress

)

#Functions
Function Test-WinCredential {
  <#
  .SYNOPSIS
    Validates Windows user credentials.

  .DESCRIPTION
    Validates a [pscredential] instance representing user-account credentials
    against the current user's logon domain or local machine.

  .PARAMETER Credential
    The [pscredential] instance to validate, typically obtained with
    Get-Credential.

    The .UserName value may be:
       * a mere username: e.g, "jdoe"
       * prefixed with a NETBIOS domain name (NTLM format): e.g., "us\jdoe"
       * in UPN format: e.g., "jdoe@us.example.org"

    IMPORTANT: 
     * If the logon domain is the current machine, validation happens against
       the local user database.
     * IRRESPECTIVE OF THE DOMAIN NAME SPECIFIED, VALIDATION IS 
       ONLY EVER PERFORMED AGAINST THE CURRENT USER'S LOGON DOMAIN.
    * If an NTLM-format username is specified, the NETBIOS domain prefix, if
      specified, must match the NETBIOS logon domain as reflected in 
      $env:USERDOMAIN
    * If a UPN-format username is specified, its domain suffix should match
      $env:USERDNSDOMAIN, although if it doesn't, only a warning is issued
      and an attempt to validate against the logon domain is still attempted,
      so as to support UPNs whose domain suffix differs from the logon DNS
      name. To avoid the warning, use the NTLM-format username with the
      NETBIOS domain prefix, or omit the domain part altogether.
    * If the credentials are valid in principle, but using them with the 
      target account is in effect not possible - such as due to the account
      being disabled or having expired - a warning to that effect is issued
      and $False is returned.
    * The SecureString instance containing the decrypted password in the input
      credentials is decrypted *in local memory*, though it is again encrypted
      *in transit* when querying Active Directory.

  .PARAMETER Local
    Use this switch to validate perform validation against the local machine's
    user database rather than against the current logon domain.
    
    If you're not currently logged on to a domain, use of this switch is
    optional.
    Conversely, however, the only way to validate against a domain
    is to be logged on to it.

  .OUTPUTS
      A Boolean indicating whether the credentials were successfully validated.

  .NOTES
      Gratefully adapted from https://gallery.technet.microsoft.com/scriptcenter/Test-Credential-dda902c6,
      via https://stackoverflow.com/q/10802850/45375; WinAPI solution for local-account validation inspired
      by https://stackoverflow.com/a/15644447/45375

.EXAMPLE
Test-WinCredential -Credential jdoe
True

Prompts for the password for user "jdoe" and validates it against the current
logon domain (which may be the local machine). 'True' ($True) as the output 
indicates successful validation.

.EXAMPLE
Test-WinCredential us\jdoe

Prompts for the password for user "us\jdoe" and validates it against 
the current logon domain, whose NETBIOS name (as reflected in $env:USERDOMAIN)
must match.

.EXAMPLE
Test-WinCredential jdoe@us.example.org

Prompts for the password for user "jdoe@us.example.org" and validates it against 
the current logon domain, whose DNS name (as reflected in $env:USERDNSDOMAIN)
is expected to match; if not, a warning is issued, but validation is still
attempted.

.EXAMPLE
Test-WinCredential Administrator -Local

Prompts for the password of the machine-local administrator account and 
validates it against the local user database.
#>
  [CmdletBinding(PositionalBinding = $False)]
  param(
    [Parameter(Position = 0)]
    [System.Management.Automation.CredentialAttribute()]
    [pscredential] $Credential = (Get-Credential '')
    ,
    [switch] $Local
  )
    
  $ErrorActionPreference = 'Stop'; Set-StrictMode -Version 1
  if ($env:OS -ne 'Windows_NT') { Throw "This command runs on WINDOWS ONLY." }

  # Note: Not necessary in PowerShell Core.
  Add-Type -AssemblyName System.DirectoryServices.AccountManagement

  $logonDomain = $env:USERDOMAIN # NETBIOS domain name or local machine name.
  $username = $Credential.UserName
  $isUpn = $Credential.UserName -match '@'
  $specifiedDomain = '' # A domain contained $Credential.UserName, if any, extracted below.
  # See if we're logged on to an actual domain or just to the local machine...
  $loggedOnToDomain = $env:COMPUTERNAME -ne $env:USERDOMAIN

  # ... and set the validation context accordingly.
  $contextType = (
    [System.DirectoryServices.AccountManagement.ContextType]::Machine, # !! LOCAL account - not actually used; see below.
    [System.DirectoryServices.AccountManagement.ContextType]::Domain # AD DS
  )[$loggedOnToDomain -and -not $Local]

  # Extract the domain-name portion, if any, from the username.
  # Recognizes formats NTLM (domain\username) and UPN (username@dns.domain)
  if ($Credential.UserName -match '^[^\\]+(?=\\)|(?<=@).+$') {
    $specifiedDomain = $Matches[0]
    # Note: We must pass a mere username to .ValidateCredentials below.
    #       .GetNetworkCredential().UserName conveniently strips the NTLM-style
    #       domain prefix, but we must strip the UPN-style suffix manually.
    $username = $Credential.GetNetworkCredential().UserName -replace '@.+$'
  }
  
  # If a domain name was specified, validate it.
  if ($specifiedDomain) {
    if ($Local -and $specifiedDomain -ne $env:COMPUTERNAME) { Throw "You've requested validation of machine-local credentials with -Local, so your username must not have a domain component that differs from the local machine name." }
    elseif (-not $isUpn -and $specifiedDomain -ne $logonDomain) { Throw "Specified NETBIOS domain prefix ($specifiedDomain) does not match the logon domain ($logonDomain)." }
    elseif ($isUpn -and -not $loggedOnToDomain) { Throw "You've specified a UPN, but you're not logged on to a domain: $($Credential.UserName)" }
    elseif ($isUpn -and $specifiedDomain -ne $env:USERDNSDOMAIN) { 
      Write-Warning @"
You've specified a UPN, but its domain-name part ($specifiedDomain) does not match the logon DNS domain name ($env:USERDNSDOMAIN).
Proceeding on the assumption that the UPN still refers to an account in the logon domain.
To avoid this warning, use the NTLM username form ($env:USERDOMAIN\$username), 
or omit the domain part altogether ($username).
"@ 
    }
  }
  
  Write-Verbose ("Validating: " + (@{ 
        username    = $username
        domain      = $logonDomain
        contextType = $contextType
      } | Out-String))

  if ($Local -or -not $loggedOnToDomain) { # LOCAL account
    # !! System.DirectoryServices.AccountManagement.PrincipalContext with non-domain-joined machines with context 'Machine' doesn't work
    # !! reliably - can result in the following exceptoin:
    # !!   Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed. Disconnect all previous
    # !!   connections to the server or shared resource and try again.
    # Therefore, we use the WinAPI's LogonUser function instead, which requires compiling a helper type on demand.
    (Add-Type -PassThru -TypeDefinition @'
      using System;
      using System.Runtime.InteropServices;

      namespace net.same2u.util {
        public class WinCredentialHelper {

          [DllImport("advapi32.dll", SetLastError=true)]
          private static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

          [DllImport("kernel32.dll", SetLastError=true)]
          private static extern bool CloseHandle(IntPtr hObject);
          
          // Validates the specified credentials (username and password) agains the account database of the specified domain,
          // which defaults to the current domain or, for non-domain-joined machines, the local machine.
          // Note: Strictly speaking, the ability to log on locally, at the time of the call is tested;
          //       especially in domain environments, incidental restrictions such as time of day or what workstations a user may log on to
          //       could prevent logon, even if the credentials are valid in principle.
          //       See the error codes at https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--1300-1699-, starting with 1326 (ERROR_LOGON_FAILURE).
          public static bool Validate(string username, string password, string domain = "") {
            IntPtr hToken = IntPtr.Zero;
            if (domain == String.Empty) domain = System.Environment.GetEnvironmentVariable("USERDOMAIN");
            // Note: * On a machine not connected to a domain, the domain parameter is seemingly IGNORED.
            //       * In a domain environment:
            //           * to explicitly target only the local user-account database, pass "." for `domain`.
            //           * if you pass null for `domain`, `username` must be in UPN format (user@domain.com)
            bool ok = LogonUser(username, domain, password, 3 /*LOGON32_LOGON_NETWORK*/, 0 /*LOGON32_PROVIDER_DEFAULT*/, out hToken);
            // int lastErr = Marshal.GetLastWin32Error(); Console.WriteLine(lastErr);
            if (hToken != IntPtr.Zero) CloseHandle(hToken);
            return ok;
          }
        }
      }
'@)::Validate($username, $Credential.GetNetworkCredential().password)
    
  }
  else { # DOMAIN == AD DS account.
    # Note: While .GetNetworkCredential().password retrieves the *plain-text* password *locally*, the *connection
    #       to AD* (in the case of [System.DirectoryServices.AccountManagement.ContextType]::Domain) is
    #       encrypted, because "When the context options are not specified by the application, 
    #         the Account Management API uses the following combination of options:
    #           ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing
    #       " - https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.accountmanagement.contextoptions
    $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext $contextType, $logonDomain
    try {
      $principalContext.ValidateCredentials($username, $Credential.GetNetworkCredential().password)
    }
    catch {
      # An exception occurring in .ValidateCredentials() often suggests that the credentials were valid in principle,
      # but there's a problem with the *account*, such as it being disabled or
      # the password having expired; we return $False in that case, but issue a *warning*
      # with the cause of the problem.
      # !! However, it can also indicate the inability to connect to the server.
      # Note: The underlying exception message is wrapped as follows, so we must extract it:
      #          Exception calling "ValidateCredentials" with "2" argument(s): "<msg>"<newline>
      Write-Warning ($_.exception.message -replace '\r?\n' -split '"' -ne '')[-1]
      $False  # Output $False, given that *in effect* the credentials do not work.
    }
    finally {
      $principalContext.Dispose()
    }
  
  }

}

Function Get-VMDisk {
[CmdletBinding()]
    param( 
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, Position=0, HelpMessage = "VMs to process")]
        [ValidateNotNullorEmpty()]
          [VMware.VimAutomation.ViCore.Impl.V1.Inventory.InventoryItemImpl[]] $myVMs
    )
Process {
        $View = @()
        foreach ($myVM in $myVMs){
            $VMDKs = $myVM | Get-HardDisk
            foreach ($VMDK in $VMDKs) {
                if ($null -ne $VMDK){
                    [int]$CapacityGB = $VMDK.CapacityKB/1024/1024
                    $Report = [PSCustomObject] @{
                            VMName = $myVM.name 
                            PowerState = $myVM.PowerState
                            HDDName = $VMDK.Name
                            Datastore = $VMDK.FileName.Split(']')[0].TrimStart('[')
                            VMDK = $VMDK.FileName.Split(']')[1].TrimStart('[')
                            StorageFormat = $VMDK.StorageFormat
                            CapacityGB = $CapacityGB
                            Controller = $VMDK.ExtensionData.ControllerKey -1000
                            Unit = $VMDK.ExtensionData.UnitNumber
                        }
                        $View += $Report
                    }   
                }
            }
    $View | Sort-Object VMname, Controller, Unit
    }
}

#Main Code Starts

Clear-Host

If ($vmList) {
    $vms = $vmList.split(",") | Sort-object -Unique
}
        
If ($vmCSV) {
    
    If(-Not ($($vmCSV.FullName) | Test-Path) ){
        Throw "The file $($vmCSV.FullName) was NOT found"
    }
    
    If(-Not ($($vmCSV.FullName) | Test-Path -PathType Leaf) ){
        Throw "Folder paths are NOT allowed. Please specify the path to a .csv or .txt file"
    }
    
    If($($vmCSV.FullName) -notmatch "(\.csv|\.txt)" ){
        Throw "The file specified MUST be either a .csv or .txt"
    }
    
    $vmsCSV = Import-Csv -LiteralPath $($vmCSV.FullName) -Header Name | Select-object -Unique Name
    $vms = $($vmsCSV.Name) | Sort-object
}

If ($vCenterServerList) {
    $vCenterServers = $vCenterServerList.split(",") | Sort-object -Unique
}
           
If (!$vCenterCred) {
    $vCenterCred = Get-Credential -Message 'Please enter your vCenter Server credentials'
}

If ($($vCenterCred.UserName.Split("@")[1] -like 'vsphere.local')) {
    Write-Verbose "Unable to pre-validate vCenter Server SSO credentials. Skipping"
}
Else {
    $TestvCenterDomainCred = Test-WinCredential -Credential $vCenterCred
    If ($TestvCenterDomainCred  -eq $false) {
        Throw "FAILED to pre-validate the Windows Domain credentials. Exiting."
    }
    Else {
        Write-Verbose "Successfully pre-validated the Windows Domain credentials."
    }
}

$result = ForEach ($vCenterServer in $vCenterServers) {
    
    $objvCenter = Connect-VIServer $vCenterServer -Credential $vCenterCred -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    
    If (!$objvCenter) {
        Throw "Failed to connect to vCenter Server: $($vCenterServer) - Please check your credentials and vCenter permissions. Exiting."
    }
    Else {
        Write-Verbose "Successfully connected to vCenter Server: $($vCenterServer)"
    }    

    $objvcvms = Get-VM -Server $objvCenter -Name $vms -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    $writeProgressCount = 0

        ForEach ($objvcvm in $objvcvms) {

            $writeProgressCount++

            If (!$suppresProgress) {
                Write-Progress -Activity "vCenter Server $($vCenterServer). Processing VM $($writeProgressCount) of $($objvcvms.count)" -CurrentOperation $($objvcvm.name.ToUpper()) -PercentComplete (($writeProgressCount / $($objvcvms.count)) * 100) | Out-Default
            }

            $objvmhdds = Get-VM -Name $objvcvm -Server $objvCenter | Get-VMdisk

            ForEach ($objvmhdd in $objvmhdds) {

                $objLastChecked = (Get-Date).ToString("dd-MMM-yyyy HH:mm:ss")

                    [PSCustomobject]@{
                        LastChecked = [string]$($objLastChecked)
                        VMName = [string]$($objvcvm.name).ToUpper()
                        HDDName = [string]$($objvmhdd.HDDName)
                        Datastore = [string]$($objvmhdd.Datastore)
                        VMDK = [string]$($objvmhdd.VMDK)
                        StorageFormat = [string]$($objvmhdd.StorageFormat)
                        CapacityGB = [string]$($objvmhdd.CapacityGB)
                        Controller = [int]$($objvmhdd.Controller)
                        Unit = [int]$($objvmhdd.Unit)
                        vCenterServer = [string]$($vCenterServer)
                    }                

                }

            }

    Disconnect-VIServer -Server $objvCenter -Force -Confirm:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
}

Remove-Variable -Name vCenterCred -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    
If ($exportCSV) {
    $csvdate = Get-Date
    $csvfile = "$env:USERPROFILE\Downloads\VMHardDisks_Export_$($csvdate.ToString('dd-MMM-yyyy_HH-mm-ss')).csv"
    $result | Sort-Object vCenterServer,VMName,Controller,Unit | Export-Csv -path $csvfile -NoTypeInformation
    Write-Output "`nExported to .csv file: $csvfile" | Out-Default
}

Return $result | Sort-Object vCenterServer,VMName,Controller,Unit
}

