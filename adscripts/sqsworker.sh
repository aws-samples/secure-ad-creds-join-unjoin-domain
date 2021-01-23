#!/bin/bash

########################################
## Defining parameters  ################
########################################
REGION=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq .region -r)
CONFIGDIR="/c/ad-join-unjoin-solution/config"
LOGLOCATION="/c/ad-join-unjoin-solution/adlog"
WORKDIR="/c/ad-join-unjoin-solution/adscripts"
dos2unix ${CONFIGDIR}/sqsworker.conf >/dev/null
S3BUCKETNAME=$(cat ${CONFIGDIR}/sqsworker.conf | jq -r '.S3BUCKETNAME')
S3PREFIX=$(cat ${CONFIGDIR}/sqsworker.conf | jq -r '.S3PREFIX')
SQSQUEUE=$(cat ${CONFIGDIR}/sqsworker.conf | jq -r '.SQSQUEUE')
SSH_SECRET=$(cat ${CONFIGDIR}/sqsworker.conf | jq -r '.SSHSECRETKEY')
SQS_ENDPOINT_URL=$(cat ${CONFIGDIR}/sqsworker.conf | jq -r '.SQSENDPOINT')
SECRET_ENDPOINT_URL=$(cat ${CONFIGDIR}/sqsworker.conf | jq -r '.SECRETMANAGERENDPOINT')
logger=${LOGLOCATION}/sqsworker_log.log
export PATH="C:\\Program Files\\Amazon\\AWSCLIV2\\":$PATH

############################################
## Fetching SSH key from Secrets Manager  ##
############################################
aws secretsmanager get-secret-value --region $REGION --endpoint-url $SECRET_ENDPOINT_URL --secret-id $SSH_SECRET | jq -r "(.SecretString)" > $CONFIGDIR/sshkey.pem 2>/dev/null
chmod 400 *.pem 2>/dev/null
if [ ! -d ~/.ssh ] 
then
    mkdir -p ~/.ssh
fi
echo "IdentityFile $CONFIGDIR/sshkey.pem" > ~/.ssh/config
echo "sqsworker: Starting sqs worker script at `date` " >> $logger

###########################################
## Reading message from SQSQUEUE   ########
########################################### 
while sleep 5; do
JSON=$(aws sqs --output=json get-queue-attributes --queue-url $SQSQUEUE --attribute-names ApproximateNumberOfMessages --endpoint-url $SQS_ENDPOINT_URL --region $REGION )
MESSAGES=$(echo "$JSON" | jq -r '.Attributes.ApproximateNumberOfMessages')
   
if [ $MESSAGES -eq 0 ]; then
  continue
fi

JSON=$(aws sqs --output=json receive-message --queue-url $SQSQUEUE --max-number-of-messages 1 --visibility-timeout 360 --endpoint-url $SQS_ENDPOINT_URL --region $REGION   )
RECEIPT=$(echo "$JSON" | jq -r '.Messages[] | .ReceiptHandle')
BODY=$(echo "$JSON" | jq -r '.Messages[] | .Body')

if [ -z "$RECEIPT" ]; then
  #echo "sqsworker: Empty receipt. Something went wrong." >> $logger
  continue

fi
  
echo "sqsworker: New Message found" >> $logger

  INSTANCEID=$(echo "$BODY" | jq -r '.instanceId')
  PRIVATEIP=$(echo "$BODY" | jq -r '.privateIp')
  INSTANCESTATE=$(echo "$BODY" | jq -r '.instance_state')
  response=$(nohup ${WORKDIR}\\adjoin_unjoin.sh $INSTANCEID $PRIVATEIP $INSTANCESTATE $RECEIPT) &  

done