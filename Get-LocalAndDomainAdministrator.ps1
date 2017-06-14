Function Get-LocalAdministrator {
    
    <#
        .Synopsis   
        Gets members of the local Administrators group on local or remote computer.

        .Description
        The Get-LocalAdministrator function gets all members of the local Administrators group. 
        The returned members can be either UserAccount entities or Group entities.
        For Group entities further quering is required to get all users part of that group.
        It uses Wsman protocol for hosts with that capability and Dcom otherwise.

        .Parameter ComputerName
        A comma delimited list of computers.

        .Parameter FilePath
        Import computers from the specified file. Make sure the file contains a single computer per line.

        .Parameter Credential
        Credential to use for retrieving services, used by the New-CimSession cmdlet.

        .Example

        PS C:\> Get-LocalAdministrator -ComputerName Client7sp1-06, ClientXPsp3-07 -Credential (Get-Credential) | Format-Table -AutoSize 

        PSComputerName Account       Domain        
        -------------- -------       ------        
        Client7sp1-06  Administrator CLIENT7SP1-06 
        Client7sp1-06  cnlocal       ZOOVASH       
        Client7sp1-06  Domain Admins ZOOVASH       
        Client7sp1-06  cn7admin      ZOOVASH       
        ClientXPsp3-07 Administrator CLIENTXPSP3-07
        ClientXPsp3-07 Domain Admins ZOOVASH       
        ClientXPsp3-07 cnlocal       ZOOVASH     

        .Example

        PS C:\> Get-LocalAdministrator -FilePath .\computers.txt -Credential (Get-Credential) | Format-Table -AutoSize

        PSComputerName Account           Domain        
        -------------- -------           ------        
        dc             Administrator     ZOOVASH       
        dc             Enterprise Admins ZOOVASH       
        dc             Domain Admins     ZOOVASH       
        dc             cnadmin           ZOOVASH       
        client10e-01   Administrator     CLIENT10E-01  
        client10e-01   cnlocal           ZOOVASH       
        client10e-01   Domain Admins     ZOOVASH       
        helpdesk-02    Administrator     HELPDESK-02   
        helpdesk-02    Domain Admins     ZOOVASH       
        helpdesk-02    cnlocal           ZOOVASH       
        client7-05     Administrator     CLIENT7-05    
        client7-05     cnlocal           ZOOVASH       
        client7-05     Domain Admins     ZOOVASH       
        clientxpsp3-07 Administrator     CLIENTXPSP3-07
        clientxpsp3-07 Domain Admins     ZOOVASH       
        clientxpsp3-07 cnlocal           ZOOVASH       
        client7sp1-06  Administrator     CLIENT7SP1-06 
        client7sp1-06  cnlocal           ZOOVASH       
        client7sp1-06  Domain Admins     ZOOVASH       
        client7sp1-06  cn7admin          ZOOVASH      

    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ParameterSetName = 'ByName')]
        [string[]]$ComputerName,

        [Parameter(Mandatory, ParameterSetName = 'ByFile')]
        [ValidateScript( { Test-Path -Path $_ })]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [pscredential]$Credential
    )

    Begin {
        if ( -not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) ) {
            Write-Error -Message "[-] Please run as administrator..." -ErrorAction Stop
        }
        Switch ($PSCmdlet.ParameterSetName) {
            'ByName' { $Assets = $ComputerName }
            'ByFile' { $Assets = Get-Content -Path $FilePath }
        }
    }
	
    Process {
        foreach ($Computer in $Assets) {

            try {
                $productVersion = (Test-WSMan -ComputerName $Computer -ErrorAction SilentlyContinue ).ProductVersion 
				
                if ($productVersion -like '*Stack: 3.0*') {
                    $cimProtocol = 'Wsman'
                    Write-Verbose "[!] Using Wsman protocol for $Computer"
                }
                else {
                    Write-Verbose "[!] Using Dcom protocol for $Computer"
                    $cimProtocol = 'Dcom'
                }
            } catch {
                Write-Verbose "[!] Using Dcom protocol for $Computer"
                $cimProtocol = 'Dcom'
            }

            try {
                $cimSessionOption = New-CimSessionOption -Protocol $cimProtocol
                $cimSession = New-CimSession -ComputerName $Computer -Credential $Credential -SessionOption $cimSessionOption -ErrorAction Stop

                $groupUserAdministrators = Get-CimInstance -CimSession $cimSession -ClassName Win32_GroupUser |
                    Where-Object { $_.GroupComponent.Name -eq 'Administrators' }
                
                $groupUserAdministrators | 
                    Select-Object PScomputerName, 
                @{Name = 'Account'; Expression = {$_.PartComponent.Name}},
                @{Name = 'Domain'; Expression = {$_.PartComponent.Domain}}
                
                Remove-CimSession $cimSession

            } catch {
                Write-Error -Message "[-] Something went wrong, please assure $Computer is online and reachable and you have administrator rights..."
            }
        } 

    }

    End {
    }
}

Function Get-DomainAdmin {
    <#
        .SYNOPSIS
        Gets all domain admins user accounts.

        .DESCRIPTION
        Gets all domain admins user accounts. Local computer needs to be domain joined.

        .EXAMPLE

        PS C:\> Get-DomainAdmins

        Name             Caption                                    AccountType                               SID                                       Domain                                   
        ----             -------                                    -----------                               ---                                       ------                                   
        Administrator    ZOOVASH\Administrator                      512                                       S-1-5-21-650147352-1135740473-26879744... ZOOVASH                                  
        cnadmin          ZOOVASH\cnadmin                            512                                       S-1-5-21-650147352-1135740473-26879744... ZOOVASH                                  
        cnhelp           ZOOVASH\cnhelp                             512                                       S-1-5-21-650147352-1135740473-26879744... ZOOVASH                                  

    #>

    if ( $env:USERDOMAIN -eq $env:COMPUTERNAME ) {
        Write-Error -Message '[-] Local computer is not in a domain' -ErrorAction Stop
    }

    $query = "Associators of {Win32_Group.Name='Domain Admins',Domain='$win32GroupDomain'} Where ResultClass=Win32_UserAccount"
  
    Get-CimInstance -Query $query

}