Function Get-PotentiallyMisconfiguredService {

    <#
		.Synopsis
		Gets potentially misconfigured services on local or remote computer.

		.Description
		The Get-PotentiallyMisconfiguredService function gets all Services (running or stopped) and checks for potentially misconfigured services.
		A potentially misconfigured service is one that has the Path outside of WinDir, ProgramFiles or starts under the context of a different user than Local System, Network Service.
		Further investigation is required to confirm the misconfiguration status. 
		It uses Wsman protocol for hosts with that capability and Dcom otherwise.

		.Parameter ComputerName
		A comma delimited list of computers.

		.Parameter FilePath
		Import computers from the specified file. Make sure the file contains a single computer per line.

		.Parameter Credential
		Credential to use for retrieving services, used by the New-CimSession cmdlet.

		.Example

		PS C:\> Get-PotentiallyMisconfiguredServices -ComputerName Client10E-01, ClientXPsp3-07 -Credential (Get-Credential) | Format-Table PSComputerName, PathName, StartName, Name -AutoSize
		cmdlet Get-Credential at command pipeline position 1
		Supply values for the following parameters:

		PSComputerName PathName                                                     StartName   Name                         
		-------------- --------                                                     ---------   ----                         
		Client10E-01   C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      CDPUserSvc_21c65a            
		Client10E-01   C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      MessagingService_21c65a      
		Client10E-01   C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      OneSyncSvc_21c65a            
		Client10E-01   C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      PimIndexMaintenanceSvc_21c65a
		Client10E-01   C:\Windows\System32\svchost.exe -k UnistackSvcGroup                      UnistoreSvc_21c65a           
		Client10E-01   C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      UserDataSvc_21c65a           
		Client10E-01   C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      WpnUserService_21c65a        
		ClientXPsp3-07 C:\Documents and Settings\cnlocal\Desktop\StopMeIfYouCan.exe LocalSystem StopMe                       

		.Example

		PS C:\> Get-PotentiallyMisconfiguredServices -FilePath .\computers.txt -Credential (Get-Credential) | Format-Table PSComputerName, PathName, StartName, Name -AutoSize
		cmdlet Get-Credential at command pipeline position 1
		Supply values for the following parameters:

		PSComputerName PathName                                                     StartName   Name                         
		-------------- --------                                                     ---------   ----                         
		dc             C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      CDPUserSvc_4f7fa             
		dc             C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      OneSyncSvc_4f7fa             
		dc             C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      PimIndexMaintenanceSvc_4f7fa 
		dc             C:\Windows\System32\svchost.exe -k UnistackSvcGroup                      UnistoreSvc_4f7fa            
		dc             C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      UserDataSvc_4f7fa            
		dc             C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      WpnUserService_4f7fa         
		client10e-01   C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      CDPUserSvc_21c65a            
		client10e-01   C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      MessagingService_21c65a      
		client10e-01   C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      OneSyncSvc_21c65a            
		client10e-01   C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      PimIndexMaintenanceSvc_21c65a
		client10e-01   C:\Windows\System32\svchost.exe -k UnistackSvcGroup                      UnistoreSvc_21c65a           
		client10e-01   C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      UserDataSvc_21c65a           
		client10e-01   C:\Windows\system32\svchost.exe -k UnistackSvcGroup                      WpnUserService_21c65a        
		client7-05     C:\Users\cnlocal\Desktop\StopMeIfYouCan.exe                  LocalSystem StopMe                       
		client7sp1-06  C:\Users\cnuser\Desktop\StopMeIfYouCan.exe                   LocalSystem StopMe                       
		clientxpsp3-07 C:\Documents and Settings\cnlocal\Desktop\StopMeIfYouCan.exe LocalSystem StopMe 

		.Outputs
		System.ServiceProcess.ServiceController
		This cmdlet returns objects that represent the services on the computer.

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

                $services = Get-CimInstance -ClassName Win32_Service -CimSession $cimSession

                $potentiallyVulnerableServices = $services | Where-Object {
                    (
                        $_.PathName -notlike "*$env:windir*" -and 
                        $_.PathName -notlike "*$env:ProgramFiles*" -and 
                        $_.PathName -notlike "*${env:ProgramFiles(x86)}*"
                    ) -or 
                    (
                        $_.StartName -notlike "*local*" -and 
                        $_.StartName -notlike "*networkservice*"

                    )
                }

                $potentiallyVulnerableServices

                Remove-CimSession $cimSession
            } catch {
                Write-Error -Message "[-] Something went wrong, please assure $Computer is online and reachable and you have administrator rights..."
            }
        } 

    }

    End {
    }
}
