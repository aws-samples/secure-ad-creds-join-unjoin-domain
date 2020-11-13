#!/bin/pwsh

param (
    [string]$ad_secret,
    [string]$ad_username,
    [string]$ad_domain_name,
	[string]$privateip,
	[string]$instance_username,
	[string]$instance_password
	#[string]$comp_name
	
)


try{
       $rdp_password = $instance_password | ConvertTo-SecureString -AsPlainText -Force

        # Create a System.Management.Automation.PSCredential object
       $rdp_credential = New-Object System.Management.Automation.PSCredential($instance_username, $rdp_password)

       #$ad_password = $ad_secret | ConvertTo-SecureString -AsPlainText -Force
	   echo "invoking remote command on $privateip "
	   
       $command = Invoke-Command -ComputerName $privateip -FilePath  'C:\\scripts\\adjoin.ps1' -Credential $rdp_credential -Authentication Negotiate  -ArgumentList $ad_secret,$ad_username,$ad_domain_name
	   echo "last command status is : $?"
}
catch [Exception]{
    Write-Host $_.Exception.ToString()
    Write-Host 'Command execution failed.'
    $host.SetShouldExit(1)
	
}
