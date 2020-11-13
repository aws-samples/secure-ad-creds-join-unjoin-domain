#$action = New-ScheduledTaskAction -Execute 'C:\Users\Admin\Desktop\customami.bat'
Set-Item WSMan:\localhost\Client\TrustedHosts -Force -Value *
restart-service -Name 'winrm'
$check_cw_agent_if_installed = get-service -Name AmazonCloudWatchAgent | select status | foreach { $_.Status }
if ( $check_cw_agent_if_installed -eq 'Running')
{
 echo "Service is running"
}
elseif ( $check_cw_agent_if_installed -eq 'Stopped')
{
 echo "Service is stopped"
 start-service -Name AmazonCloudWatchAgent
}
else
{
Invoke-WebRequest -Uri https://s3.amazonaws.com/amazoncloudwatch-agent/windows/amd64/latest/amazon-cloudwatch-agent.msi -OutFile C:\\amazon-cloudwatch-agent.msi -UseBasicParsing
#Invoke-Item $env:USERPROFILE\\Downloads\\amazon-cloudwatch-agent.msi -Confirm:$False
Invoke-Item C:\\amazon-cloudwatch-agent.msi -Confirm:$False
sleep 3
cd 'C:\\Program Files\\Amazon\\AmazonCloudWatchAgent'
.\amazon-cloudwatch-agent-ctl.ps1 -a fetch-config -m ec2 -c file:'C:\\Programdata\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent.json' -s
}
#Stop-ScheduledTask -TaskName "WorkerTask"
#$action = New-ScheduledTaskAction -Execute "C:\\ProgramData\\chocolatey\\bin\\Cygwin.exe" -Argument "C:\scripts\sqsworker.sh"
$action = New-ScheduledTaskAction -Execute "C:\\Program Files\\Git\\git-bash.exe" -Argument "C:\scripts\sqsworker.sh"
#$action = New-ScheduledTaskAction –Execute "powershell.exe -windowstyle hidden"  -Argument  "C:\Users\Admin\Desktop\customami.bat" -windowstyle hidden
#$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount
$STPrin = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
$trigger = @(
    $(Get-CimClass "MSFT_TaskRegistrationTrigger" -Namespace "Root/Microsoft/Windows/TaskScheduler"),
    $(New-ScheduledTaskTrigger -AtStartup))
#$trigger = New-ScheduledTaskTrigger -AtStartup
#$trigger = Get-CimClass "MSFT_TaskRegistrationTrigger" -Namespace "Root/Microsoft/Windows/TaskScheduler"
$S = New-ScheduledTaskSettingsSet -Hidden:$True
$task = New-ScheduledTask -Action $action  -Trigger $trigger  -Description "This is my description" -Settings $S
Register-ScheduledTask -TaskName "WorkerTask" -Action $action -Trigger $trigger -Settings $S -Principal $STPrin  -Force
Start-ScheduledTask -TaskName "WorkerTask"
rm C:\\cleanup.ps1 -Force 2>&1 | out-null
