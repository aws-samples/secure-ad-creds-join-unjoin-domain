param (
    [string]$ad_secret,
    [string]$ad_username,
    [string]$ad_domain_name,
	[string]$instance_hostname

	
)
$ErrorActionPreference = 'Stop'

try{
        # Parse the response and convert the Secret String JSON into an object
        $username = $ad_domain_name.ToUpper() + "\" + $ad_username

        $password = $ad_secret | ConvertTo-SecureString -AsPlainText -Force

        $credential = New-Object System.Management.Automation.PSCredential($username, $password)
        echo "fetching machine name to be removed from the domain"
        $MachineName = Get-ADComputer -filter "Name -eq '$instance_hostname'" -Credential $credential -Server $ad_domain_name -AuthType 0 | Select-Object Name | foreach { $_.Name }
        
		echo "Removing $MachineName computer from the AD domain"
		Remove-ADComputer -Identity $MachineName -Credential $credential -Server $ad_domain_name -Confirm:$false
		echo "Domain unjoin completed successfully for COMPUTER_NAME = $MachineName"
        
}
catch [Exception]{
    Write-Host $_.Exception.ToString()
    Write-Host 'Command execution failed.'
    $host.SetShouldExit(1)
	
}
