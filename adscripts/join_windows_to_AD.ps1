#!/bin/pwsh

param (
    [string]$secrets_manager_secret_id,
	[string]$privateip,
	[string]$instance_username,
	[string]$instance_password,
    [string]$instance_id
	
)

echo "starting script"	
$LOG_DIR =  "C:\ad-join-unjoin-solution\adlog"
$SCRIPT_DIR = "C:\ad-join-unjoin-solution\adscripts"
$CONFIG_DIR = "C:\ad-join-unjoin-solution\config"
$REGION = (Invoke-WebRequest -UseBasicParsing -Uri http://169.254.169.254/latest/dynamic/instance-identity/document | ConvertFrom-Json | Select region).region
$SECRETENDPOINT = get-content  $CONFIG_DIR\\sqsworker.conf | convertfrom-Json | select SECRETMANAGERENDPOINT | foreach { $_.SECRETMANAGERENDPOINT }

try{

$secretvaluejson = Get-SECSecretValue -region $REGION -EndpointUrl $SECRETENDPOINT -SecretId $secrets_manager_secret_id
$secretvalue = $secretvaluejson.SecretString | ConvertFrom-Json
$ad_domain_name = $secretvalue.domain_name
$username = $secretvalue.domain_user
$ad_secret = $secretvalue.domain_password | ConvertTo-SecureString -AsPlainText -Force
$directory_ou = $secretvalue.directory_ou
$DNSIPS=([System.Net.DNS]::GetHostAddresses(${ad_domain_name})|Where-Object {$_.AddressFamily -eq "InterNetwork"}) | select-object IPAddressToString | foreach { $_.IPAddressToString }
$dns_IP1 = $DNSIPS[0]
$dns_IP2 = $DNSIPS[1]   
$rdp_password = $instance_password | ConvertTo-SecureString -AsPlainText -Force

# Create a System.Management.Automation.PSCredential object
$rdp_credential = New-Object System.Management.Automation.PSCredential($instance_username, $rdp_password)

echo "invoking remote command on $privateip" | Out-File "${LOG_DIR}\${instance_id}_log.log" -Encoding ASCII  -Append

$command = (Invoke-Command -ComputerName $privateip -FilePath  $SCRIPT_DIR\\win_adjoin.ps1 -Credential $rdp_credential -Authentication Negotiate  -ArgumentList $ad_secret,$username,$ad_domain_name,$dns_IP1,$dns_IP2,$directory_ou)  *>&1 | Out-File "${LOG_DIR}\${instance_id}_log.log" -Encoding ASCII  -Append
}

catch [System.Management.Automation.RuntimeException]{
    Write-Host $_.Exception.ToString()
    write-host $_.Exception.ToString()
    $host.SetShouldExit(1)
	
}
