$secret=$args[0]
$username=$args[1]
$domain_name=$args[2]

$ErrorActionPreference = 'Stop'

try{

        # Parse the response and convert the Secret String JSON into an object
        $username = $domain_name.ToUpper() + "\" + $username

        $password = $secret | ConvertTo-SecureString -AsPlainText -Force

        $credential = New-Object System.Management.Automation.PSCredential($username, $password)

        # Get the Instance ID from the metadata store, we will use this as our computer name during domain registration.
        $instanceID = invoke-restmethod -uri http://169.254.169.254/latest/meta-data/instance-id

        $COMPUTER_NAME = hostname
        Add-Computer -ComputerName $COMPUTER_NAME -DomainName $domain_name -Credential $credential -Force -Restart
		if (!$?)
			{
			 echo  "COMPUTER_NAME = $COMPUTER_NAME domain failed to join domain for some reason"
			}

			else
			{
			echo "Domain join SUCCESS for COMPUTER_NAME = $COMPUTER_NAME , proceeding with reboot"
			}
      
}
catch [Exception]{
    Write-Host $_.Exception.ToString()
    Write-Host 'Command execution failed.'
    $host.SetShouldExit(1)
	
}
