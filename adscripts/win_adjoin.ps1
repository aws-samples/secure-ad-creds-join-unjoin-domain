$secret=$args[0]
$user_name=$args[1]
$domain_name=$args[2]
$dns_IP1=$args[3]
$dns_IP2=$args[4]
$directory_ou=$args[5]

$ErrorActionPreference = 'Stop'

try{

# Parse the response and convert the Secret String JSON into an object
$username = $domain_name.ToUpper() + "\" + $user_name

$credential = New-Object System.Management.Automation.PSCredential($username, $secret)
# Get the Instance ID from the metadata store, if you want to use this as  computer name during domain registration.
#$instanceID = invoke-restmethod -uri http://169.254.169.254/latest/meta-data/instance-id

# Set up the IPv4 address of the AD DNS server as the first DNS server on this machine. Uncomment the below 4 lines if your VPC is not using the AD DNS servers by default.

#$networkAdapter = Get-WmiObject Win32_NetworkAdapter -Filter "AdapterType = 'Ethernet 802.3'"
#$networkAdapterName = ($networkAdapter | Select-Object -First 1).NetConnectionID
#netsh.exe interface ipv4 add dnsservers name="$networkAdapterName" address=$dns_IP1 index=1
#netsh.exe interface ipv4 add dnsservers name="$networkAdapterName" address=$dns_IP2 index=2

echo "adding computer to domain" 
$COMPUTER_NAME = hostname
if ([bool]$directory_ou)
{
Add-Computer -ComputerName $COMPUTER_NAME -DomainName $domain_name -OUPath $directory_ou  -Credential $credential
if (!$?)
	{
	 echo  "COMPUTER_NAME = $COMPUTER_NAME domain failed to join domain for some reason"
	}

	else
	{
	echo "Domain join SUCCESS for COMPUTER_NAME = $COMPUTER_NAME , proceeding with reboot"
	Restart-Computer -Force
	}
}	
else
{
Add-Computer -ComputerName $COMPUTER_NAME -DomainName $domain_name -Credential $credential
if (!$?)
	{
	 echo  "COMPUTER_NAME = $COMPUTER_NAME domain failed to join domain for some reason"
	}

	else
	{
	echo "Domain join SUCCESS for COMPUTER_NAME = $COMPUTER_NAME , proceeding with reboot"
	Restart-Computer -Force
	}
}     
}

catch [Exception]{
    Write-Host $_.Exception.ToString()
    Write-Host 'Command execution failed.'
    $host.SetShouldExit(1)
	
}
