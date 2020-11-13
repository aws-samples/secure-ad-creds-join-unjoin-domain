#!/bin/bash
logger='/c/log/script_log.log'
#INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
REGION=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq .region -r)
SQSQUEUE=%SQSQUEUE%
DEADLETTERQUEUE=%DEADLETTERQUEUE%
DDBTABLE=%DDBTABLE%
INSTANCEID=''
PRIVATEIP=''
WORKDIR='/c/scripts'
SSHKEYUSED=%SSHKEYUSED%
SSHKEYNAME=%SSHKEYNAME%				   
# name of the scret in secret manager that stores Instance and AD crdenials
secrets_manager_secret_id="myadcredV1"

function fetch_ad_credential()
    {
        echo "$0: Fetching AD credentials from Secrets Manager" >> $logger
		#instance_id="$1"
		ad_secret=$(aws secretsmanager get-secret-value --secret-id $secrets_manager_secret_id --query SecretString --output text | jq -r '"\(.domain_password)"' 2>/dev/null)
        ad_username=$( aws secretsmanager get-secret-value --secret-id $secrets_manager_secret_id --query SecretString --output text | jq -r '"\(.domain_user)"' 2>/dev/null)
		ad_domain_name=$(aws secretsmanager get-secret-value --secret-id $secrets_manager_secret_id --query SecretString --output text | jq -r '"\(.domain_name)"' 2>/dev/null)
		directory_ou=$(aws secretsmanager get-secret-value --secret-id $secrets_manager_secret_id --query SecretString --output text | jq -r '"\(.directory_ou)"' 2>/dev/null)
		#instance_username=$(aws secretsmanager get-secret-value --secret-id $secrets_manager_secret_id --query SecretString --output text | jq -r '"\(.instance_user)"' 2>/dev/null)
		if [[ "$ad_secret" == 'null' || "$ad_username" == 'null' || "$ad_domain_name" == 'null' ]] ;then
		   echo "$0: Failed: cannot fetch credentials from Secrets Manager" >> $logger
           return 1
		fi   
    }
	
function delete_sqs_message()
    {
        echo "$0: Running: aws sqs --output=json delete-message --queue-url $SQSQUEUE" >> $logger
		aws sqs --output=json delete-message --queue-url $SQSQUEUE --receipt-handle $RECEIPT
		if [ $? -eq 0 ];then
		   echo "$0: message deletion completed" >> $logger
		   return 0
		else
		   echo "$0: message deletion failed" >> $logger
		   return 1
		fi 
		
    }

function get_instance_details()
  {
  INSTANCEID=$(echo "$BODY" | jq -r '.instanceId')
  PRIVATEIP=$(echo "$BODY" | jq -r '.privateIp')
  INSTANCESTATE=$(echo "$BODY" | jq -r '.instance_state')
  PLATFORM=$(aws ec2 describe-instances --instance-id $INSTANCEID --query 'Reservations[*].Instances[*].[Platform]' --region $REGION --output text)
  if [ $? -eq 0 ];then
	 return 0   
  else
     return 1
  fi   
  }

function send_msg_to_dead_letter_queue()
 {
   echo "$0: Got a message to send to DLQ" >> $logger
   aws sqs send-message --queue-url $DEADLETTERQUEUE --region $REGION --message-body "`cat /c/temp/msg.json | jq`" 
        if [ $? -eq 0 ];then
		    echo "$0: message sent to dead letter queue: $DEADLETTERQUEUE" >> $logger
		    return 0
		else
		    echo "$0: message move to dead letter queue failed" >> $logger
		    return 1
		fi 
 }


function unjoin_domain()
{	
  echo "$0: Instance $INSTANCEID is being terminated, will proceed with Instance deregistration from the AD" >> $logger
  #privateIp=$PRIVATEIP
  comp_name=$(aws dynamodb get-item --table-name $DDBTABLE --key '{"instanceid": {"S": "'"$INSTANCEID"'"}}' --attributes-to-get "hostname" | jq -r '.Item.hostname.S' 2>/dev/null)
  if [[ "$comp_name" == '' ]]; then
     echo "$0: Could not fetch hostname from DDB table" >> $logger
	 return 1
  else
      echo "$0: Host $comp_name will be removed from the AD Domain" >> $logger
	  fetch_ad_credential
	  if [ $? -eq 0 ]; then
		#response=$($WORKDIR/remove_comp_from_domain.ps1 $ad_secret $ad_username $ad_domain_name $privateIp $ad_tools_instance_ip )
		# call unjoin function from here
		echo "$0: Executing command to remove $comp_name from the domain" >> $logger
		response=$(powershell.exe $WORKDIR/adunjoin.ps1 "'$ad_secret'" "'$ad_username'" "'$ad_domain_name'" "'$comp_name'" )
		echo "$0: $response" >> $logger
		echo "$0: Deleting entry from DDB table" >> $logger
		aws dynamodb delete-item --table-name $DDBTABLE --key '{"instanceid": {"S": "'"$INSTANCEID"'"}}'
		return 0
	  else
		echo "$0: Failed to remove instance from the domain: $response" >> $logger
		return 1
	  fi
  fi	  
}

function update_ddb_table()
{
#aws dynamodb get-item --table-name instanceid_hostname_mapping --key '{"instanceid": {"S": "Mimi"}}' --attributes-to-get "hostname" | jq -r '.Item.hostname.S'
#aws dynamodb put-item --table-name instanceid_hostname_mapping --item '{"instanceid": {"S": "test"},"hostname": {"S": "test2"}, "privateIp": {"S": "test2"}}'
#aws dynamodb delete-item --table-name instanceid_hostname_mapping --key '{"instanceid": {"S": "Mimi"}}'
echo "$0: adding $1 , $2 to DDB table" >> $logger
aws dynamodb put-item --table-name $DDBTABLE --item '{"instanceid": {"S": "'"$INSTANCEID"'"},"hostname": {"S": "'"$1"'"},"privateIp": {"S": "'"$2"'"}}'
}

function verify_instance_ad_status()
{
 comp_name=$(aws dynamodb get-item --table-name $DDBTABLE --key '{"instanceid": {"S": "'"$INSTANCEID"'"}}' --attributes-to-get "hostname" | jq -r '.Item.hostname.S' 2>/dev/null)
 if [[ "$comp_name" == '' ]]; then
     echo "$0: A new Instance wants to join the AD Domain " >> $logger
	 return 0
 else
     return 1
 fi 
}

function join_windows_to_domain()
{
 #RANDOM_COMPUTER_NAME=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 6 | head -n 1)
 #comp_name=$(echo EC2AMAZ-$RANDOM_COMPUTER_NAME)
 instance_user=$(cat $WORKDIR/OS_User_Mapping.json | jq -r '.WINDOWS')
 fetch_ad_credential
  if [ $? -eq 0 ];then
	  #privateIp=$PRIVATEIP
		if [ $SSHKEYUSED == 'false' ]; then
	     instance_password=$(aws secretsmanager get-secret-value --secret-id $secrets_manager_secret_id --query SecretString --output text | jq -r '"\(.instance_password)"' 2>/dev/null)
	    else
		  MAX_RETRIES=5
		  for i in $(seq 1 $MAX_RETRIES)
			do
			instance_password=$(aws ec2 get-password-data --instance-id  $INSTANCEID --priv-launch-key $WORKDIR/$SSHKEYNAME | jq -r '.PasswordData' 2>/dev/null)
			if [[ -z "$instance_password" ]]; then
			  echo "$0: Retrying retrieving instance password...." >> $logger
			  sleep 25
			else
			  break
			fi																					   
		  done
		 
	    fi	  	   
	  if [[ -z "$instance_password" ]]; then
		 echo "$0: Could not fetch instance password using get-password-data" >> $logger
		 return 1
	  fi	 
	  echo "$0: starting power shell script on remote machine to add instance $comp_name to domain" >> $logger
	  response=$(powershell.exe $WORKDIR/join_windows_to_AD.ps1 "'$ad_secret'" "'$ad_username'" "'$ad_domain_name'" "'$PRIVATEIP'" "'$instance_user'" "'$instance_password'")
	  if echo "$response" | grep -q "Command execution failed"; then
		 if echo "$response" | grep -q "because it is already in that domain"; then
		   echo "$0: Powershell script failed because the host is already part of domain: $response" >> $logger
		   comp_name=$(echo $response | sed 's/.*Cannot add computer \(.*\)to domain.*/\1/' | tr -d [\'])
		   echo "$0: host details = $comp_name" >> $logger
		   update_ddb_table $comp_name $PRIVATEIP
		   return 0
		 elif echo "$response" | grep -q "Access is denied"; then
		   echo "$0: Powershell script failed because of access denied. Check WSMan setting on remote host : $response " >> $logger
		   return 1
		 else
           echo "$0: Powershell script failed: $response " >> $logger
           return 1		   
		 fi	   
	  elif echo "$response" | grep -q "Domain join SUCCESS"; then
	     echo "$0: SUCCESS*** powershell script execution completed on remote windows server: $response" >> $logger
		 #comp_name=$(echo "$response" | sed -nr '/COMPUTER_NAME =/ s/.*COMPUTER_NAME =([^"]+).*/\1/p')
		 #comp_name=$(echo $response | sed -nr '/computer / s/.*computer ([^"]+).*/\1/p' | tr -d [.])
		 comp_name=$(echo $response | sed 's/.*COMPUTER_NAME = \(.*\) , proceeding.*/\1/' | tr -d [\'])
		 update_ddb_table $comp_name $PRIVATEIP 
		 return 0
	  else
	     #echo $response >> /c/temp/logs.txt
         echo "$0: Powershell script failed on remote windows server due to some errors: $response" >> $logger
         return 1		 
	  fi	 
	  sleep 5			  
  else		  
	  return 1
  fi
}

function getosuser()
{
OPERATING_SYSTEM=$(aws ec2 describe-instances --instance-id $INSTANCEID --query 'Reservations[].Instances[].[Tags[?Key==`Operating_System`].Value | [0]]' --output text 2>/dev/null)
if [ "$OPERATING_SYSTEM" == 'AMAZON_LINUX' ]; then
 instance_user=$(cat $WORKDIR/OS_User_Mapping.json | jq -r '.AMAZON_LINUX')
elif [ "$OPERATING_SYSTEM" == 'FEDORA' ]; then
 instance_user=$(cat $WORKDIR/OS_User_Mapping.json | jq -r '.FEDORA')
elif [ "$OPERATING_SYSTEM" == 'RHEL' ]; then
 instance_user=$(cat $WORKDIR/OS_User_Mapping.json | jq -r '.RHEL')
elif [ "$OPERATING_SYSTEM" == 'CENTOS' ]; then
 instance_user=$(cat $WORKDIR/OS_User_Mapping.json | jq -r '.CENTOS')
elif [ "$OPERATING_SYSTEM" == 'UBUNTU' ]; then
 instance_user=$(cat $WORKDIR/OS_User_Mapping.json | jq -r '.UBUNTU')
elif [ "$OPERATING_SYSTEM" == 'DEBIAN' ]; then
 instance_user=$(cat $WORKDIR/OS_User_Mapping.json | jq -r '.DEBIAN')
elif [ "$OPERATING_SYSTEM" == 'SUSE' ]; then
 instance_user=$(cat $WORKDIR/OS_User_Mapping.json | jq -r '.SUSE') 
elif [ "$OPERATING_SYSTEM" == 'WINDOWS' ]; then
 instance_user=$(cat $WORKDIR/OS_User_Mapping.json | jq -r '.WINDOWS')
 else
 instance_user=$(cat $WORKDIR/OS_User_Mapping.json | jq -r '.DEFAULT')
fi
if [[ "$instance_user" == 'None'  ]]; then
     echo "$0: Could not find instance_user name. Check the OS_User_Mapping.json file in the S3 bucket and also make sure the Instance is tagged with appropriate Operating_System tag name/value pair" >> $logger
	 return 1
fi 
}


function join_linux_to_domain()
{
 RANDOM_COMPUTER_NAME=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 6 | head -n 1)
 comp_name=$(echo EC2AMAZ-$RANDOM_COMPUTER_NAME | tr 'a-z' 'A-Z')
 getosuser
 fetch_ad_credential
  if [ $? -eq 0 ];then
	  #privateip=$PRIVATEIP
	  IPAddresses=($(dig $ad_domain_name A | grep $ad_domain_name | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | awk '{print $5}'))
	  dns_server1=${IPAddresses[0]}
	  dns_server2=${IPAddresses[1]}
	  echo "$0: starting Linux script to add instance $INSTANCEID to domain" >> $logger
	  echo "$0: DNS Server IPs are:  $dns_server1, $dns_server2" >> $logger
		  if [ $SSHKEYUSED == 'false' ]; then
		    # plink -v youruser@yourhost.com -pw yourpw "some linux command"
			echo "You have not provided an SSH key pair to allow the worker Instance run the domain join scripts on remote Liux compueter"
			return 1
		  else
		  MAX_RETRIES=3
		  for i in $(seq 1 $MAX_RETRIES)
			do
			response=$(ssh -i $WORKDIR/$SSHKEYNAME $instance_user@$PRIVATEIP -o StrictHostKeyChecking=no 'bash -s' < $WORKDIR/join_linux_to_AD.sh "$ad_username" "$ad_secret" "$ad_domain_name" "$dns_server1" "$dns_server2" "$comp_name" "$directory_ou" )
			sleep 15
		  done
		  fi
	  echo "$0: Bash script execution competed on remote Linux server" >> $logger
		 if echo "$response" | grep -q "realm join successful"; then
		   echo "$0: Instance added to the domain: $response" >> $logger
		   #comp_name=$(echo "$response" | sed -nr '/COMPUTER_NAME =/ s/.*COMPUTER_NAME =([^"]+).*/\1/p')
		   update_ddb_table $comp_name $PRIVATEIP
		   return 0
		 elif  echo "$response" | grep -q "Already joined to this domain"; then
		   echo "$0: Instance already joined to the domain: $response" >> $logger
		   #comp_name=$(echo "$response" | sed -nr '/COMPUTER_NAME =/ s/.*COMPUTER_NAME =([^"]+).*/\1/p')
		   update_ddb_table $comp_name $PRIVATEIP
		   return 0
		 else 
		   echo "$0: Failed: realm join failed: $response" >> $logger
		   return 1
		 fi
	  #sleep 5
	  #delete_sqs_message
  else		  
	  return 1
  fi

}


function join_domain()
   {	  
	  if [[ "$PRIVATEIP" == 'null' || "$INSTANCEID" == 'null' ]]; then
		   echo "$0: Skipping message - no instance found. Deleting message from queue" >> $logger
		   return 0		   
	  else
		   if [ "$PLATFORM" == 'windows' ]; then
			  echo "$0: Found a new windows machine to be added in Active Directory. Details: INSTANCEID=$INSTANCEID, PRIVATEIP=$PRIVATEIP, INSTANCESTATE=$INSTANCESTATE" >> $logger
			  join_windows_to_domain
              if [ $? -eq 0 ];then
                  return 0
              else
                  return 1
              fi				  
		   elif [ "$PLATFORM" == 'None' ]; then
		      join_linux_to_domain
              if [ $? -eq 0 ];then
                  return 0
              else
                  return 1
              fi			  
		   else
		     echo "$0: Unable to get Instance OS, trying Linux join, please check logs" >> $logger
		     join_linux_to_domain
		     if [ $? -eq 0 ];then
                   return 0
             else
                   return 1
             fi		   
		   fi 
     fi
}

while sleep 5; do
  #echo "reading message from sqs $SQSQUEUE "									
  JSON=$(aws sqs --output=json get-queue-attributes --queue-url $SQSQUEUE --attribute-names ApproximateNumberOfMessages)
  MESSAGES=$(echo "$JSON" | jq -r '.Attributes.ApproximateNumberOfMessages')
   
  if [ $MESSAGES -eq 0 ]; then

    continue

  fi

  JSON=$(aws sqs --output=json receive-message --queue-url $SQSQUEUE)
  RECEIPT=$(echo "$JSON" | jq -r '.Messages[] | .ReceiptHandle')
  BODY=$(echo "$JSON" | jq -r '.Messages[] | .Body')

  if [ -z "$RECEIPT" ]; then
    echo "$0: Empty receipt. Something went wrong." >> $logger
    continue

  fi

  echo "$0: Found $MESSAGES messages in $SQSQUEUE ." >> $logger
  echo $BODY > /c/temp/msg.json
  get_instance_details
  if [ $? -eq 0 ]; then
	    if [ "$INSTANCESTATE" == 'terminated' ]; then
		   unjoin_domain
		   if [ $? -eq 0 ]; then
		      delete_sqs_message
		   else
              send_msg_to_dead_letter_queue
			  delete_sqs_message
		   fi
        elif [ "$INSTANCESTATE" == 'running' ]; then
           verify_instance_ad_status
		   if [ $? -eq 0 ]; then
			  join_domain
			  if [ $? -eq 0 ]; then
			   delete_sqs_message
			  else
			   send_msg_to_dead_letter_queue
			   delete_sqs_message
			  fi
		   else
		      echo "$0: Instance is already part of the AD Domain" >> $logger
			  delete_sqs_message
		   fi			 
		else   
          echo "$0: Instance state should be running or terminated. Please verify." >> $logger
       fi			
	else
		echo "$0: **Failed to get Instance details" >> $logger
		echo "$0: Sending message to dead letter queue for debug purpose" >> $logger
		send_msg_to_dead_letter_queue
		delete_sqs_message
  fi
	

done