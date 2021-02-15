### Define parameters
$CONFIG_DIR = "C:\ad-join-unjoin-solution\config"
$LOG_DIR =  "C:\ad-join-unjoin-solution\adlog"
$WORKING_DIR= "C:\ad-join-unjoin-solution\adscripts"
$USERDATALOG =  $LOG_DIR + "\userdata.log"
$SOFTWAREPATH = $env:USERPROFILE + "\Downloads"
$REGION = (Invoke-WebRequest -UseBasicParsing -Uri http://169.254.169.254/latest/dynamic/instance-identity/document | ConvertFrom-Json | Select region).region
$S3BUCKET = get-content  $CONFIG_DIR\\sqsworker.conf | convertfrom-Json | select S3BUCKETNAME | foreach { $_.S3BUCKETNAME }
$S3PREFIX = get-content  $CONFIG_DIR\\sqsworker.conf | convertfrom-Json | select S3PREFIX | foreach { $_.S3PREFIX }
$EC2ENDPOINT = get-content  $CONFIG_DIR\\sqsworker.conf | convertfrom-Json | select EC2ENDPOINT | foreach { $_.EC2ENDPOINT }
$SSH_SECRET = get-content  $CONFIG_DIR\\sqsworker.conf | convertfrom-Json | select SSHSECRETKEY | foreach { $_.SSHSECRETKEY }
$logendpoint = get-content  $CONFIG_DIR\\sqsworker.conf | convertfrom-Json | select LOGSENDPOINT | foreach { $_.LOGSENDPOINT }
$secretendpoint = get-content  $CONFIG_DIR\\sqsworker.conf | convertfrom-Json | select SECRETMANAGERENDPOINT | foreach { $_.SECRETMANAGERENDPOINT }
$env:Path += ";C:\\Program Files\\Amazon\\AWSCLIV2\\"
$env:Path += ";C:\\Program Files\\Git\\"
$env:Path += ";C:\\Program Files\\"

Function LogWrite {
    param(
        [Parameter(Mandatory=$true)][String]$logstring
    )    
    ((Get-Date).ToString() + " - " + $logstring ) | Out-File $USERDATALOG -Encoding ASCII  -Append 
}

function install_awscli
{
$awscli = Get-ChildItem  $SOFTWAREPATH -recurse | where {$_.name -like "*CLI*"} | select name | foreach { $_.Name }

if ($awscli)
{

 if ((Get-Command aws -ErrorAction SilentlyContinue) -eq $null) {
	LogWrite  "installing aws cli" 
	$command = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12"
	Invoke-Expression $command
	$arguments = "/i `"$SOFTWAREPATH\$awscli`" /quiet"
	Start-Process msiexec.exe -ArgumentList $arguments -Wait
	setx /M PATH "$Env:PATH;C:\\Program Files\\Amazon\\AWSCLIV2\\"
	LogWrite  "AWSCLI installation completed" 
}

else
{ LogWrite  "AWS CLI is already installed." }

}
else

{LogWrite "AWSclI msi or exe not found in the source S3 bucket. Check the bucket and make sure the executables are uploaded in the software folder."}
}

function install_git
{
$gitexe= Get-ChildItem  $SOFTWAREPATH -recurse | where {$_.name -like "*Git*"} | select name | foreach { $_.Name }
if ($gitexe)
{

 if ((Get-Command git -ErrorAction SilentlyContinue) -eq $null) {
	LogWrite  "installing git client and git bash" 
	$command = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12"
	Invoke-Expression $command
	cd $SOFTWAREPATH
	$arguments = ".\"  + $gitexe
	& $arguments /VERYSILENT /NORESTART /SUPPRESSMSGBOXES
	setx /M PATH "$Env:PATH;C:\\Program Files\\Git\\"
	LogWrite  "Git installation completed" 
}

else
{ LogWrite  "Git is already installed." }

}
else

{LogWrite "Git msi or exe not found in the source S3 bucket. Check the bucket and make sure the executables are uploaded in the software folder."}
}

function install_jq
{
$jqexe= Get-ChildItem  $SOFTWAREPATH -recurse | where {$_.name -like "*jq*"} | select name | foreach { $_.Name }
if ($jqexe)
{

 if ((Get-Command jq -ErrorAction SilentlyContinue) -eq $null) {
	LogWrite  "installing jq" 
	cp "$SOFTWAREPATH\$jqexe" "C:\\Program Files\\jq.exe" -Force
	setx /M PATH "$Env:PATH;C:\\Program Files\\"
	cp "C:\\Program Files\\jq.exe" "C:\Program Files\Git\usr\bin\" -Force
	LogWrite  "jq installation completed" 
}

else
{ LogWrite  "jq  is already installed." }

}
else

{LogWrite "jq msi or exe not found in the source S3 bucket. Check the bucket and make sure the executables are uploaded in the software folder."}


}

function restart_cwagent
{
cp  $CONFIG_DIR\\amazon-cloudwatch-agent.json 'C:\\programdata\\Amazon\\AmazonCloudWatchAgent\\' -Force
(get-content 'C:\\programdata\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent.json' ) -replace "vpce-XXXX", $logendpoint | set-content 'C:\\programdata\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent.json'
& $Env:ProgramFiles\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1 -m ec2 -a stop
& $Env:ProgramFiles\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1 -m ec2 -a start
}

function  install_cloudwatch
{

$check_cw_agent_if_installed = get-service -Name AmazonCloudWatchAgent | select status | foreach { $_.Status }
if ( $check_cw_agent_if_installed -eq 'Running')
{
 restart_cwagent
 LogWrite "Cloudwatch Service is running"
}
elseif ( $check_cw_agent_if_installed -eq 'Stopped')
{
 LogWrite "Cloudwatch Service is stopped..starting service"
 start-service -Name AmazonCloudWatchAgent
 restart_cwagent
}
else
{
LogWrite "Installing Cloudwatch agent..."
Invoke-WebRequest -Uri https://s3.amazonaws.com/amazoncloudwatch-agent/windows/amd64/latest/amazon-cloudwatch-agent.msi -OutFile $env:USERPROFILE\\Downloads\\amazon-cloudwatch-agent.msi -UseBasicParsing
$arguments = "/i `"$env:USERPROFILE\\Downloads\\amazon-cloudwatch-agent.msi`" /quiet"
Start-Process msiexec.exe -ArgumentList $arguments -Wait
cp  $CONFIG_DIR\\amazon-cloudwatch-agent.json 'C:\\programdata\\Amazon\\AmazonCloudWatchAgent\\' -Force
(get-content 'C:\\programdata\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent.json' ) -replace "vpce-XXXX", $logendpoint | set-content 'C:\\programdata\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent.json'
& $Env:ProgramFiles\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1 -a fetch-config -m ec2 -c file:'C:\\Programdata\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent.json' -s
& $Env:ProgramFiles\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1 -m ec2 -a stop
(Get-Content 'C:\\Programdata\\Amazon\\AmazonCloudWatchAgent\\log-config.json') -replace 'us-east-1', $REGION | Set-Content 'C:\\Programdata\\Amazon\\AmazonCloudWatchAgent\\log-config.json'
& $Env:ProgramFiles\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1 -m ec2 -a start
LogWrite "Cloudwatch successfully installed"
}

}

function set_variables_config
{
LogWrite "Setting variables value for scripts"
setx /M PATH "$Env:PATH;C:\\Program Files\\Amazon\\AWSCLIV2\\" | Out-Null
setx /M PATH "$Env:PATH;C:\\Program Files\\Git\\" | Out-Null
setx /M PATH "$Env:PATH;C:\\Program Files\\" | Out-Null
LogWrite "variable values substituted successfully"
}

function schedule_worker_task
{
LogWrite "Scheduling sqs worker task"
Set-Item WSMan:\localhost\Client\TrustedHosts -Force -Value *
##Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -RemoteAddress $WORKERIP
restart-service -Name 'winrm'
$checktaskstatus = Get-ScheduledTask -TaskName "SqsWorkerTask"  | Select-Object State | foreach { $_.State}
if ($checktaskstatus -eq 'Running')
{
LogWrite "SQS worker task already scheduled"
return 0
}
$action = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument  $WORKING_DIR\refresh_scripts.ps1
$STPrin = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType "S4U" -RunLevel Highest
$trigger = @(
    $(Get-CimClass "MSFT_TaskRegistrationTrigger" -Namespace "Root/Microsoft/Windows/TaskScheduler"),
    $(New-ScheduledTaskTrigger -AtStartup), $(New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) ))
$Schedule = New-ScheduledTaskSettingsSet -Hidden:$True
$task = New-ScheduledTask -Action $action  -Trigger $trigger  -Description "This is my description" -Settings $Schedule
Register-ScheduledTask -TaskName "SqsWorkerTask" -Action $action -Trigger $trigger -Settings $Schedule -Principal $STPrin  -Force

LogWrite "sqs worker task configured successfully"

}
function install_packages_from_internet
{
 if ((Get-Command choco -ErrorAction SilentlyContinue) -eq $null) {
        LogWrite  "installing choco" 
		Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        choco feature enable -n=allowGlobalConfirmation -y
		LogWrite  "choco installation completed" 
}
choco feature enable -n=allowGlobalConfirmation -y
choco install jq awscli git
}

function sync_s3_objects
{
aws s3 sync  s3://$S3BUCKET/$S3PREFIX $WORKING_DIR --region $REGION --exclude "userdata.ps1" --only-show-errors --no-progress
aws s3 sync  s3://$S3BUCKET/config $CONFIG_DIR --region $REGION --exclude "*sqsworker.conf*" --only-show-errors --no-progress
}

function get_ssh_key
{
aws secretsmanager get-secret-value --endpoint-url $secretendpoint --region $REGION --secret-id $SSH_SECRET | jq -r "(.SecretString)" > $CONFIG_DIR/sshkey.pem 2>&1 | out-null
$check_bash_process = Get-Process -Name bash 2>&1 | out-null
  if ($?)
  {
   Stop-Process -Name bash 2>&1 | out-null
  }
git-bash.exe 'dos2unix $CONFIG_DIR\\sqsworker.conf'  

}

function create_vpc_endpoints {
LogWrite "Creating VPC endpoints"
$metadata = 'http://169.254.169.254/latest/meta-data/network/interfaces/macs' 
$Interface = Invoke-WebRequest -Uri  $metadata// | Select-Object Content | foreach { $_.Content } 
$subnetid = Invoke-WebRequest -Uri  $metadata//$Interface//subnet-id | Select-Object Content | foreach { $_.Content } 
$vpcid = Invoke-WebRequest -Uri  $metadata//$Interface//vpc-id | Select-Object Content | foreach { $_.Content } 
$routetableId = Get-EC2RouteTable -region $REGION -EndpointUrl $EC2ENDPOINT -Filter @{ Name='association.subnet-id'; Value=$subnetid } | Select-Object RouteTableId  | foreach { $_.RouteTableId } 
$service = "dynamodb"
$checkendpoint = Get-EC2VpcEndpoint -region $REGION -EndpointUrl $EC2ENDPOINT  -Filter @{ Name='vpc-id'; Value=$vpcid } ,@{Name="service-name";Value="com.amazonaws.$REGION.$service" } | Select-Object ServiceName
$vpcendpoint = Get-EC2VpcEndpoint -region $REGION -EndpointUrl $EC2ENDPOINT  -Filter @{ Name='vpc-id'; Value=$vpcid } ,@{Name="service-name";Value="com.amazonaws.$REGION.$service" } | Select-Object VpcEndpointId | foreach {  $_.VpcEndpointId }

if ($checkendpoint -eq $null)
  { 
  LogWrite "creating $service VPC endpoint"
  New-EC2VpcEndpoint  -region $REGION -EndpointUrl $EC2ENDPOINT -ServiceName com.amazonaws.$REGION.$service -VpcId $vpcid  -RouteTableId $routetableid
  }
else
  {
   $checkroutetable = Get-EC2VpcEndpoint -region $REGION -EndpointUrl $EC2ENDPOINT -Filter @{Name="service-name";Values="com.amazonaws.$REGION.$service"}  | select-object RouteTableIds | foreach {  $_.RouteTableIds } | Select-String $routetableid
   if ( $checkroutetable -eq $null)
	 {
	 Edit-EC2VpcEndpoint -region $REGION -EndpointUrl $EC2ENDPOINT -VpcEndpointId $vpcendpoint -AddRouteTableId $routetableid
	 }
   else { LogWrite "no action required for $service" }
   }
}

### Script entry point ### 

LogWrite "User data script execution starting at $(date)"

$ErrorActionPreference = 'Continue'
Import-Module AWSPowerShell
Install-WindowsFeature RSAT-ADDS
set_variables_config

## Check instance internet connectivity
Test-Connection -ComputerName aws.amazon.com -Count 1 2>&1 | out-null
if ($? )
 {
  LogWrite "Instance has outbound internet access. Will install packages from internet"
  install_packages_from_internet
  get_ssh_key
  sync_s3_objects
 }

else
{
LogWrite "Instance has no internet access. Will install packages from S3"
if ((Get-Command aws -ErrorAction SilentlyContinue) -eq $null)
	{
     Copy-S3Object -BucketName $S3BUCKET -KeyPrefix softwares  -Localfolder $env:USERPROFILE\Downloads\
	 Copy-S3Object -BucketName $S3BUCKET -KeyPrefix /  -Localfolder $env:USERPROFILE\Downloads\
	} 
else
    {
	  aws s3 sync s3://$S3BUCKET/ $env:USERPROFILE\Downloads\ --region $REGION --exclude "*" --include "*.exe*" --include "*.msi*"  --only-show-errors --no-progress 2>&1
	}
install_awscli
install_git
install_jq
create_vpc_endpoints
get_ssh_key
sync_s3_objects
}
install_cloudwatch
schedule_worker_task

LogWrite "User data script execution completed at $(date)"
LogWrite "Printing errors during script execution: $Error"
$host.SetShouldExit(1)