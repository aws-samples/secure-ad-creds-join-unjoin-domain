##################################################
######## Define parameters #######################
##################################################
$LOG_DIR =  "C:\ad-join-unjoin-solution\adlog"
$TEMP_DIR =  "C:\ad-join-unjoin-solution\adtemp"
$WORKING_DIR= "C:\ad-join-unjoin-solution\adscripts"
$CONFIG_DIR = "C:\ad-join-unjoin-solution\config"
$S3BUCKETNAME = get-content  $CONFIG_DIR\\sqsworker.conf | convertfrom-Json | select S3BUCKETNAME | foreach { $_.S3BUCKETNAME }
$S3PREFIX = get-content  $CONFIG_DIR\\sqsworker.conf | convertfrom-Json | select S3PREFIX | foreach { $_.S3PREFIX }
$SOFTWAREPATH = $env:USERPROFILE + "\Downloads"
$DDBTABLE = get-content  $CONFIG_DIR\\sqsworker.conf | convertfrom-Json | select DDBTABLE | foreach { $_.DDBTABLE }
$secrets_manager_secret_id = get-content  $CONFIG_DIR\\sqsworker.conf | convertfrom-Json | select ADSECRETKEY | foreach { $_.ADSECRETKEY }
$REGION = (Invoke-WebRequest -UseBasicParsing -Uri http://169.254.169.254/latest/dynamic/instance-identity/document | ConvertFrom-Json | Select region).region
$SECRETENDPOINT = get-content  $CONFIG_DIR\\sqsworker.conf | convertfrom-Json | select SECRETMANAGERENDPOINT | foreach { $_.SECRETMANAGERENDPOINT }
$EC2_ENDPOINT_URL = get-content  $CONFIG_DIR\\sqsworker.conf | convertfrom-Json | select EC2ENDPOINT | foreach { $_.EC2ENDPOINT }
$logendpoint = get-content  $CONFIG_DIR\\sqsworker.conf | convertfrom-Json | select LOGSENDPOINT | foreach { $_.LOGSENDPOINT }
$SCRIPTLOG =  $LOG_DIR + "\refresh_script.log"
$env:Path += ";C:\\Program Files\\Git\\"
$env:Path += ";C:\\Program Files\\Amazon\\AWSCLIV2\\"

$ErrorActionPreference = 'Continue'
Function LogWrite {
    param([Parameter(Mandatory=$true)][String]$logstring)    
    ((Get-Date).ToString() + " - " + $logstring ) | Out-File $SCRIPTLOG -Encoding ASCII  -Append 
}

function sync_s3_scripts {
$checks3_script_change = aws s3 sync s3://${S3BUCKETNAME}/${S3PREFIX} $WORKING_DIR --exclude "*sqsworker.sh*" --dryrun
  if ($checks3_script_change)
  {
   LogWrite "change found for AD scripts"
   aws s3 sync  s3://$S3BUCKETNAME/$S3PREFIX $WORKING_DIR --only-show-errors --no-progress 2>&1 | out-null
  }
   
$checks3_worker_Script_change = aws s3 sync s3://$S3BUCKETNAME/config $CONFIG_DIR --exclude "*" --include "*sqsworker.sh*" --dryrun
  if ($checks3_worker_Script_change)
  {
   LogWrite "change found for AD sqs worker script"
   stop-process -Name 'bash' -Force 2>&1 | out-null
   aws s3 sync  s3://$S3BUCKETNAME/$S3PREFIX $WORKING_DIR --only-show-errors --no-progress 2>&1 | out-null
   git-bash.exe $WORKING_DIR\sqsworker.sh
  }
  

$checks3_config_update = aws s3 sync  s3://${S3BUCKETNAME}/config $CONFIG_DIR --dryrun
 if ($checks3_config_update)
  {
   LogWrite "change found for config files"
   aws s3 sync  s3://$S3BUCKETNAME/config --exclude "*sqsworker.conf*" --only-show-errors --no-progress
   cp  $CONFIG_DIR\\amazon-cloudwatch-agent.json 'C:\\programdata\\Amazon\\AmazonCloudWatchAgent\\' -Force
   (get-content 'C:\\programdata\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent.json' ) -replace "vpce-XXXX", $logendpoint | set-content 'C:\\programdata\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent.json'
   & $Env:ProgramFiles\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1 -m ec2 -a stop
   & $Env:ProgramFiles\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1 -m ec2 -a start
  }

$check_bash_process = Get-Process -Name bash 2>&1 | out-null
  if (!$?)
  {
    git-bash.exe $WORKING_DIR\sqsworker.sh
  }
   
}

function sync_dynamodb_with_AD_computers  {
$computers = ''
LogWrite "Sync Dynamodb with AD computer objects: Script execution started at $(date)"

function set_variables ([string]$hostname, [string]$IPv4, [string]$instanceid, [string]$whencreated)
{
$param1 = @"
{\"INSTANCEID\": {\"S\": \"$instanceid\"}}
"@

$param2 = @"
{\"PRIVATEIP\": {\"S\": \"$IPv4\"} , \"HOSTNAME\": {\"S\": \"$hostname\"} , \"INSTANCEID\": {\"S\": \"$instanceid\"} , \"WHENCREATED\": {\"S\": \"$whencreated\"} }
"@
$host_in_ddb = aws dynamodb get-item --table-name $DDBTABLE --key $param1 --attributes-to-get "INSTANCEID" --region $REGION | jq -r '.Item.INSTANCEID.S' *>&1
   if ($host_in_ddb -eq $null)
   {
    echo "adding enrty in table"
    aws dynamodb put-item --table-name $DDBTABLE --item $param2 --region $REGION
   }
   else
   {
   echo "nothing to add"
   }
}

$last_update_time = aws dynamodb get-item --table-name $DDBTABLE --key '{\"INSTANCEID\": {\"S\": \"DONOTDELETEME\"}}' --attributes-to-get "WHENCREATED" --region $REGION | jq -r '.Item.WHENCREATED.S' *>&1
if ($last_update_time -eq $null)
{
 $start_date = $(date)
 $computers = Get-ADComputer -Filter 'whenCreated -le $start_date' -Properties whencreated , IPv4Address | Select Name , IPv4Address, whencreated
}
else
{
 $start_date = $last_update_time
 $computers = Get-ADComputer -Filter 'whenCreated -gt $start_date' -Properties whencreated , IPv4Address | Select Name , IPv4Address, whenCreated
}

$secretvaluejson = Get-SECSecretValue -region $REGION -EndpointUrl $SECRETENDPOINT -SecretId $secrets_manager_secret_id
$secretvalue = $secretvaluejson.SecretString | ConvertFrom-Json
$ad_secret = $secretvalue.domain_password | ConvertTo-SecureString -AsPlainText -Force
$ad_domain_name = $secretvalue.domain_name
$username = $secretvalue.domain_user
$ad_username = $ad_domain_name.ToUpper() + "\" + $username
$credential = New-Object System.Management.Automation.PSCredential($ad_username, $ad_secret)

Get-ADComputer -Filter 'whenCreated -le $start_date' -Properties IPv4Address -Credential $credential -Server $ad_domain_name -AuthType 0 | Select Name , IPv4Address , whenCreated | foreach {
$hostname = $_.Name ; $IPv4 =  $_.IPv4Address ; $whencreatd = $_.whenCreated ;
$instanceid = ''
$instanceid = aws ec2 describe-instances --region $REGION --endpoint-url $EC2_ENDPOINT_URL --filter Name=private-ip-address,Values=$IPv4 --query 'Reservations[].Instances[].InstanceId' --output text

if ($hostname -or $IPv4)
  {
   set_variables "$hostname" "$IPv4" "$instanceid" "$whencreatd"
  }
}

$param2 = @"
{\"WHENCREATED\": {\"S\": \"$(date)\"}, \"INSTANCEID\": {\"S\": \"DONOTDELETEME\"}}
"@
aws dynamodb put-item --table-name $DDBTABLE --item $param2 --region $REGION
LogWrite "Sync Dynamodb with AD computer objects: Script execution completed at $(date)"

}

function cleanup_tempfile_logs {
#rm $LOG_DIR\\i-* -Force 2>&1 | out-null
}

try {
LogWrite "refresh started at $(date)"
sync_s3_scripts
sync_dynamodb_with_AD_computers
LogWrite "refresh completed at $(date)"
cleanup_tempfile_logs
exit 0
}

catch [Exception]{
    Write-Host $_.Exception.ToString()
    Write-Host 'Command execution failed.'
}
finally {
LogWrite $Error
$host.SetShouldExit(1)
}
