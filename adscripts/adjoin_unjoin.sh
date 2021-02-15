#!/bin/bash

#########################################
## Defining parameters ##################
#########################################
INSTANCEID=$1
PRIVATEIP=$2
INSTANCESTATE=$3
RECEIPT=$4
REGION=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq .region -r)
CONFIGDIR="/c/ad-join-unjoin-solution/config"
LOGLOCATION="/c/ad-join-unjoin-solution/adlog"
WORKDIR="/c/ad-join-unjoin-solution/adscripts"
TEMPDIR="/c/ad-join-unjoin-solution/adtemp"
SQSQUEUE=$(cat $CONFIGDIR/sqsworker.conf | jq -r '.SQSQUEUE')
DEADLETTERQUEUE=$(cat $CONFIGDIR/sqsworker.conf | jq -r '.DEADLETTERQUEUE')
DDBTABLE=$(cat $CONFIGDIR/sqsworker.conf | jq -r '.DDBTABLE')
EC2_ENDPOINT_URL=$(cat ${CONFIGDIR}/sqsworker.conf | jq -r '.EC2ENDPOINT')
SQS_ENDPOINT_URL=$(cat ${CONFIGDIR}/sqsworker.conf | jq -r '.SQSENDPOINT')
SECRET_ENDPOINT_URL=$(cat ${CONFIGDIR}/sqsworker.conf | jq -r '.SECRETMANAGERENDPOINT')
export PATH="C:\\Program Files\\Amazon\\AWSCLIV2\\":$PATH
logger=${LOGLOCATION}/${INSTANCEID}_log.log
unjoin_logger=${LOGLOCATION}/${INSTANCEID}_unjoin.log

# name of the scret in secret manager that stores Instance and AD crdenials
SECRETID=$(cat $CONFIGDIR/sqsworker.conf | jq -r '.ADSECRETKEY')

##Check if SSH Key is available
if [ $(ls -la $CONFIGDIR | grep sshkey.pem | wc -l) -gt 0 ]; then 
 SSHKEYUSED='true'
 SSHKEYNAME=${CONFIGDIR}/sshkey.pem
else
  SSHKEYUSED='false'
fi

##################################################
## Remove temp files #############################
##################################################
cleanup() { 
ssh-keygen -R $PRIVATEIP
rm -f ~/.ssh/*.old
}

trap cleanup EXIT

#############################################################
## Fetch AD Credentials from Secrets Manager        #########
#############################################################
function fetch_ad_credential()
    {
        echo "join-unjoin: Fetching AD credentials from Secrets Manager" >> $logger
		ad_secret=$(aws secretsmanager get-secret-value --region $REGION --endpoint-url $SECRET_ENDPOINT_URL --secret-id $SECRETID --query SecretString --output text | jq -r '"\(.domain_password)"' 2>/dev/null)
        ad_username=$( aws secretsmanager get-secret-value --region $REGION --endpoint-url $SECRET_ENDPOINT_URL --secret-id $SECRETID --query SecretString --output text | jq -r '"\(.domain_user)"' 2>/dev/null)
		ad_domain_name=$(aws secretsmanager get-secret-value --region $REGION --endpoint-url $SECRET_ENDPOINT_URL --secret-id $SECRETID --query SecretString --output text | jq -r '"\(.domain_name)"' 2>/dev/null)
		directory_ou=$(aws secretsmanager get-secret-value --region $REGION --endpoint-url $SECRET_ENDPOINT_URL --secret-id $SECRETID --query SecretString --output text | jq -r '"\(.directory_ou)"' 2>/dev/null)
		var=$(nslookup $ad_domain_name | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
		DNSIPS=($var)
		dns_server1=${DNSIPS[1]}
        dns_server2=${DNSIPS[2]}
		#dns_server1=$(aws secretsmanager get-secret-value --secret-id $SECRETID --query SecretString --output text | jq -r '"\(.dnsIP1)"' 2>/dev/null)
		#dns_server2=$(aws secretsmanager get-secret-value --secret-id $secrets_manager_secret_id --query SecretString --output text | jq -r '"\(.dnsIP2)"' 2>/dev/null)
		if [[ "$ad_secret" == 'null' || "$ad_username" == 'null' || "$ad_domain_name" == 'null' ]] ;then
		   echo "join-unjoin: Failed: cannot fetch credentials from Secrets Manager" >> $logger
           return 1
		fi   
    }


#############################################################
## Delete processed message from SQS queue          #########
#############################################################
function delete_sqs_message()
    {
        echo "join-unjoin: Deleting message form SQS queue: $SQSQUEUE" >> $logger
		aws sqs --output=json delete-message --endpoint-url $SQS_ENDPOINT_URL --queue-url $SQSQUEUE --receipt-handle $RECEIPT --region $REGION 
		if [ $? -eq 0 ];then
		   echo "join-unjoin: message deletion completed" >> $logger
		   rm -f ${TEMPDIR}/${INSTANCEID}_msg.json
		   return 0
		else
		   echo "join-unjoin: message deletion failed" >> $logger
		   return 1
		fi 
		
    }

#############################################################
## Get Instance Operating System from Instance tag  #########
#############################################################
function get_instance_details()
  {
  PLATFORM=$(aws ec2 describe-instances --endpoint-url $EC2_ENDPOINT_URL --instance-id $INSTANCEID --query 'Reservations[*].Instances[*].[Platform]' --region $REGION --output text)
  if [ $? -eq 0 ];then
	 return 0   
  else
     return 1
  fi   
  }

#############################################################
## Send unprocessed message to Dead Letter SQS Queue     ####
#############################################################
function send_msg_to_dead_letter_queue()
 {
   echo "join-unjoin: Got a message to send to DLQ" >> $logger
   aws sqs send-message --endpoint-url $SQS_ENDPOINT_URL --queue-url $DEADLETTERQUEUE --region $REGION --message-body "`cat ${TEMPDIR}/${INSTANCEID}_msg.json | jq .`" 
        if [ $? -eq 0 ];then
		    echo "$0: message sent to dead letter queue: $DEADLETTERQUEUE" >> $logger
			rm -f ${TEMPDIR}/${INSTANCEID}_msg.json
		    return 0
		else
		    echo "$0: message move to dead letter queue failed" >> $logger
		    return 1
		fi 
 }

#############################################################
## Remove computer from AD Domain upon Instance termination #
#############################################################
function unjoin_domain()
{	
  echo "join-unjoin: Instance $INSTANCEID is being terminated, will proceed with Instance deregistration from the AD" >> $unjoin_logger
  comp_name=$(aws dynamodb get-item --table-name $DDBTABLE --key '{"INSTANCEID": {"S": "'"$INSTANCEID"'"}}' --attributes-to-get "HOSTNAME" | jq -r '.Item.HOSTNAME.S' 2>/dev/null)
  if [[ "$comp_name" == '' ]]; then
     echo "join-unjoin: Could not fetch hostname from DDB table" >> $unjoin_logger
	 return 1
  else
      echo "join-unjoin: Host $comp_name will be removed from the AD Domain" >> $unjoin_logger
	  fetch_ad_credential
	  if [ $? -eq 0 ]; then
		# call unjoin function from here
		echo "join-unjoin: Executing command to remove $comp_name from the domain" >> $unjoin_logger
		response=$(powershell.exe $WORKDIR/adunjoin.ps1 "'$ad_secret'" "'$ad_username'" "'$ad_domain_name'" "'$comp_name'" )
		if grep -q "Command execution failed" $logger; then
			 echo "join-unjoin: Failed to remove instance from the domain: $response" >> $unjoin_logger
			 return 1
		else
		    echo "join-unjoin: Deleting entry from DDB table" >> $unjoin_logger
		    aws dynamodb delete-item --region $REGION --table-name $DDBTABLE --key '{"INSTANCEID": {"S": "'"$INSTANCEID"'"}}'
            return 0		
		fi 
	  else
		echo "join-unjoin: Failed to fetch AD credential from Secrets Manager: $response" >> $unjoin_logger
		return 1
	  fi
  fi	  
}

#######################################################
## Add entry to DynamoDB after successful domain join #
#######################################################
function update_ddb_table()
{
echo "join-unjoin: adding $1 , $2 to DDB table" >> $logger
aws dynamodb put-item --region $REGION --table-name $DDBTABLE --item '{"INSTANCEID": {"S": "'"$INSTANCEID"'"},"HOSTNAME": {"S": "'"$1"'"},"PRIVATEIP": {"S": "'"$2"'"}}'
}

function verify_instance_ad_status()
{
 comp_name=$(aws dynamodb get-item --region $REGION --table-name $DDBTABLE --key '{"INSTANCEID": {"S": "'"$INSTANCEID"'"}}' --attributes-to-get "HOSTNAME" | jq -r '.Item.HOSTNAME.S' 2>/dev/null)
 if [[ "$comp_name" == '' ]]; then
     echo "join-unjoin: A new Instance wants to join the AD Domain " >> $logger
	 return 0
 else
     return 1
 fi 
}

##################################################
#########        Windows Domain Join      ########
##################################################
function join_windows_to_domain()
{
 instance_user=$(cat $CONFIGDIR/OS_User_Mapping.json | jq -r '.WINDOWS')
  if [ $? -eq 0 ];then
		if [ $SSHKEYUSED == 'false' ]; then
	     instance_password=$(aws secretsmanager --region $REGION  get-secret-value --endpoint-url $SECRET_ENDPOINT_URL --secret-id $SECRETID --query SecretString --output text | jq -r '"\(.instance_password)"' 2>/dev/null)
	    else
		  MAX_RETRIES=5
		  for i in $(seq 1 $MAX_RETRIES)
			do
			instance_password=$(aws ec2 get-password-data --region $REGION --endpoint-url $EC2_ENDPOINT_URL --instance-id  $INSTANCEID --priv-launch-key $SSHKEYNAME | jq -r '.PasswordData' 2>/dev/null)
			if [[ -z "$instance_password" ]]; then
			  echo "join-unjoin: Retrying retrieving instance password...." >> $logger
			  sleep 45
			else
			  echo "join-unjoin: Instance password fetched successfully" >> $logger
			  break
			fi																					   
		  done
		 
	    fi	  	   
	  if [[ -z "$instance_password" ]]; then
		 echo "join-unjoin: Could not fetch instance password using get-password-data" >> $logger
		 return 1
	  fi	 
	  echo "join-unjoin: starting power shell script on remote machine to add instance $INSTANCEID to domain" >> $logger
	  response=$(powershell.exe $WORKDIR/join_windows_to_AD.ps1  "'$SECRETID'" "'$PRIVATEIP'" "'$instance_user'" "'$instance_password'" "'$INSTANCEID'")
	  if  grep -q "Command execution failed" $logger; then
		 if grep -q "already in that domain" $logger; then
		   echo "join-unjoin: Powershell script failed because the host is already part of domain" >> $logger
		   var=$(grep -w "Cannot add computer" $logger)
		   comp_name=$(echo $var | sed 's/.*Cannot add computer \(.*\)to domain.*/\1/' | tr -d [\'])
		   echo "join-unjoin: host details = $comp_name" >> $logger
		   update_ddb_table $comp_name $PRIVATEIP
		   return 0
		 elif grep -q "Access is denied" $logger; then
		   echo "join-unjoin: Powershell script failed because of access denied. Check WSMan setting on remote host" >> $logger
		   return 1
		 else
           echo "$0: Powershell script failed" >> $logger
           return 1		   
		 fi	   
	  elif cat $logger | grep -q "Domain join SUCCESS"; then
	     echo "join-unjoin: SUCCESS*** powershell script execution completed on remote windows server" >> $logger
		 comp_name=$(echo $response | sed 's/.*COMPUTER_NAME = \(.*\) , proceeding.*/\1/' | tr -d [\'])
		 update_ddb_table $comp_name $PRIVATEIP 
		 return 0
	  else
         echo "join-unjoin: Powershell script failed on remote windows server due to some errors" >> $logger
         return 1		 
	  fi	 			  
  else		  
	  return 1
  fi
}

##################################################
## Get instance username for SSH login ###########
##################################################
function getosuser()
{
OPERATING_SYSTEM=$(aws ec2 describe-instances --region $REGION --endpoint-url $EC2_ENDPOINT_URL --instance-id $INSTANCEID --query 'Reservations[].Instances[].[Tags[?Key==`Operating_System`].Value | [0]]' --output text 2>/dev/null)
if [ "$OPERATING_SYSTEM" == 'AMAZON_LINUX' ]; then
 instance_user=$(cat $CONFIGDIR/OS_User_Mapping.json | jq -r '.AMAZON_LINUX')
elif [ "$OPERATING_SYSTEM" == 'FEDORA' ]; then
 instance_user=$(cat $CONFIGDIR/OS_User_Mapping.json | jq -r '.FEDORA')
elif [ "$OPERATING_SYSTEM" == 'RHEL' ]; then
 instance_user=$(cat $CONFIGDIR/OS_User_Mapping.json | jq -r '.RHEL')
elif [ "$OPERATING_SYSTEM" == 'CENTOS' ]; then
 instance_user=$(cat $CONFIGDIR/OS_User_Mapping.json | jq -r '.CENTOS')
elif [ "$OPERATING_SYSTEM" == 'UBUNTU' ]; then
 instance_user=$(cat $CONFIGDIR/OS_User_Mapping.json | jq -r '.UBUNTU')
elif [ "$OPERATING_SYSTEM" == 'DEBIAN' ]; then
 instance_user=$(cat $CONFIGDIR/OS_User_Mapping.json | jq -r '.DEBIAN')
elif [ "$OPERATING_SYSTEM" == 'SUSE' ]; then
 instance_user=$(cat $CONFIGDIR/OS_User_Mapping.json | jq -r '.SUSE') 
elif [ "$OPERATING_SYSTEM" == 'WINDOWS' ]; then
 instance_user=$(cat $CONFIGDIR/OS_User_Mapping.json | jq -r '.WINDOWS')
 else
 instance_user=$(cat $CONFIGDIR/OS_User_Mapping.json | jq -r '.DEFAULT')
fi
if [[ "$instance_user" == 'None'  ]]; then
     echo "join-unjoin: Could not find instance_user name. Check the OS_User_Mapping.json file in the S3 bucket and also make sure the Instance is tagged with appropriate Operating_System tag name/value pair" >> $logger
	 return 1
fi 
}

##################################################
## Encrypt domain credential with openssl ########
##################################################
function encrypt_cred
{
randompass=$(date +%s | sha256sum | base64 | head -c 20)
echo $ad_secret | openssl enc -aes-256-cbc -md md5 -out /tmp/${INSTANCEID}_temp -salt -k $randompass
echo $ad_secret | openssl enc -aes-256-cbc -md md5 -pbkdf2 -out /tmp/${INSTANCEID}_temppbk -salt -k $randompass
ssh-keyscan -H $PRIVATEIP >> ~/.ssh/known_hosts
scp /tmp/${INSTANCEID}_temp* ec2-user@$PRIVATEIP:/tmp/
}

##################################################
## Check instance SSH connectivity on port 22  ###
##################################################
function check_ssh_connection()
{
	echo "Checking SSH connectivity for $PRIVATEIP" >> $logger
	MAX_RETRIES=8
	for i in $(seq 1 $MAX_RETRIES)
	do
		if (exec 1<>/dev/tcp/${PRIVATEIP}/22) 2> /dev/null; then
		  return 0
		fi
	sleep 30	
	done
	return 1
}

##################################################
## LINUX domain join                            ##
##################################################
function join_linux_to_domain()
{
 # Naming conventions in Active Directory
 # https://support.microsoft.com/en-us/help/909264/naming-conventions-in-active-directory-for-computers-domains-sites-and
 RANDOM_COMPUTER_NAME=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 6 | head -n 1)
 comp_name=$(echo EC2AMAZ-$RANDOM_COMPUTER_NAME | tr 'a-z' 'A-Z')
 getosuser
 fetch_ad_credential
 if [ $? -eq 0 ];then
	if [ $SSHKEYUSED == 'false' ]; then
		# plink -v youruser@yourhost.com -pw yourpw "some linux command"
		echo "You have not provided an SSH key pair to allow the worker Instance run the domain join scripts on remote Liux compueter" >> $logger
		return 1
	else
	  check_ssh_connection
	  if [ $? -eq 0 ];then 
		encrypt_cred
		echo "join-unjoin: starting Linux script to add instance $INSTANCEID to AD domain" >> $logger  
		response=$(ssh $instance_user@$PRIVATEIP 'bash -s' < $WORKDIR/join_linux_to_AD.sh "$ad_username" "$randompass" "$ad_domain_name" "$dns_server1" "$dns_server2" "$comp_name" "$directory_ou" )
		echo "join-unjoin: Bash script execution completed on remote Linux server" >> $logger
		if  echo "$response" | grep -q "realm join successful"; then
			echo "join-unjoin: Instance added to the domain: $response" >> $logger
			update_ddb_table $comp_name $PRIVATEIP
			return 0
		elif  echo "$response" | grep -q "Already joined to this domain"; then
			echo "join-unjoin: Instance already joined to the domain: $response" >> $logger
			comp_name=$(echo "$response" | sed -nr '/COMPUTER_NAME =/ s/.*COMPUTER_NAME =([^"]+).*/\1/p')
			update_ddb_table $comp_name $PRIVATEIP
			return 0
		elif  echo "$response" | grep -q "instance already part of an AD domain"; then
			echo "join-unjoin: Instance already joined to the domain: $response" >> $logger
			comp_name=$(echo "$response" | sed -nr '/COMPUTER_NAME =/ s/.*COMPUTER_NAME =([^"]+).*/\1/p')
			update_ddb_table $comp_name $PRIVATEIP
			return 0  
		else 
			echo "join-unjoin: Failed: realm join failed: $response" >> $logger
			return 1
		fi
	  else
		echo "join-unjoin: SSH connection (port 22) test to instance $INSTANCEID failed" >> $logger
		return 1
	  fi
	fi
		
 else		  
	return 1
 fi
}

##################################################
## Main Domain Join function #####################
##################################################
function join_domain()
   {	  
	  if [[ "$PRIVATEIP" == 'null' || "$INSTANCEID" == 'null' ]]; then
		   echo "join-unjoin: Skipping message - no instance found. Deleting message from queue" >> $logger
		   return 0		   
	  else
		   if [ "$PLATFORM" == 'windows' ]; then
			  echo "join-unjoin: Found a new windows machine to be added in Active Directory. Details: INSTANCEID=$INSTANCEID, PRIVATEIP=$PRIVATEIP, INSTANCESTATE=$INSTANCESTATE" >> $logger
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
		     echo "join-unjoin: Unable to get Instance OS, trying Linux join, please check logs" >> $logger
		     join_linux_to_domain
		     if [ $? -eq 0 ];then
                   return 0
             else
                   return 1
             fi		   
		   fi 
     fi
}


##################################################
## Main entry point ##############################
##################################################

export PATH="C:\\Program Files\\Amazon\\AWSCLIV2\\":$PATH

JSON_STRING=$( jq -n \
                  --arg bn "$INSTANCEID" \
                  --arg on "$PRIVATEIP" \
                  --arg tl "$INSTANCESTATE" \
                  '{instanceId: $bn, privateIp: $on, instance_state: $tl}' )

  echo $JSON_STRING > ${TEMPDIR}/${INSTANCEID}_msg.json
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
		      echo "join-unjoin: Instance is already part of the AD Domain" >> $logger
			  delete_sqs_message
		   fi			 
		else   
          echo "join-unjoin: Instance state should be running or terminated. Please verify." >> $logger
       fi			
	else
		echo "join-unjoin: **Failed to get Instance details" >> $logger
		echo "join-unjoin: Sending message to dead letter queue for debug purpose" >> $logger
		send_msg_to_dead_letter_queue
		delete_sqs_message
  fi