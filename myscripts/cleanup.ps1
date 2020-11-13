#powershell.exe

try{

rm  C:\\scripts\\*.bak* -Force
rm C:\\cfn\\*.bak* -Force
rm C:\\scripts\\*.bak* -Force
stop-process -Name 'bash' -Force 2>&1 | out-null
rm C:\\scripts\\* -Exclude 'sqsworker.conf' -Force

}

catch [Exception]{
    Write-Host $_.Exception.ToString()
    Write-Host 'Command execution failed.'
    $host.SetShouldExit(1)
	
}