#!/bin/bash

INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
WORKING_DIR=/c/scripts
REGION=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq .region -r)
CLOUDWATCHLOGSGROUP=$(cat $WORKING_DIR/sqsworker.conf | jq -r '.CLOUDWATCHLOGSGROUP')
SQSQUEUE=$(cat $WORKING_DIR/sqsworker.conf | jq -r '.SQSQUEUE')
DEADLETTERQUEUE=$(cat $WORKING_DIR/sqsworker.conf | jq -r '.DLSQSQUEUE')
DDBTABLE=$(cat $WORKING_DIR/sqsworker.conf | jq -r '.DDBTABLE')
S3BUCKETNAME=$(cat $WORKING_DIR/sqsworker.conf | jq -r '.S3BUCKETNAME')
S3PREFIX=$(cat $WORKING_DIR/sqsworker.conf | jq -r '.S3PREFIX')
SSHKEYNAME=$(cat $WORKING_DIR/sqsworker.conf | jq -r '.SSHKEYNAME')
aws configure set default.region $REGION
aws s3 cp s3://$S3BUCKETNAME/amazon-cloudwatch-agent.json  $WORKING_DIR 2>/dev/null
aws s3 cp s3://$S3BUCKETNAME/OS_User_Mapping.json  $WORKING_DIR 2>/dev/null
aws s3 cp s3://$S3BUCKETNAME/$SSHKEYNAME  $WORKING_DIR 2>/dev/null
cp -avf $WORKING_DIR/amazon-cloudwatch-agent.json /c/programdata/Amazon/AmazonCloudWatchAgent/
chmod +x $WORKING_DIR/*.sh
# check if a pem file exists for SSH/RPD access
var=$(ls -la $WORKING_DIR | grep .pem | wc -l)
if [ $var -gt 0 ]; then 
 chmod 400 $WORKING_DIR/*.pem
 SSHKEYUSED=true
 sed -i "s|%SSHKEYUSED%|$SSHKEYUSED|g" $WORKING_DIR/sqsworker.sh
else
  SSHKEYUSED=false
  sed -i "s|%SSHKEYUSED%|$SSHKEYUSED|g" $WORKING_DIR/sqsworker.sh
fi 
chmod +x $WORKING_DIR/*.ps1
sed -i "s|us-east-1|$REGION|g" /c/programdata/Amazon/AmazonCloudWatchAgent/log-config.json
echo $CLOUDWATCHLOGSGROUP >> /tmp/userdatalog.txt
echo $SQSQUEUE >> /tmp/userdatalog.txt
#sed -i "s|%CLOUDWATCHLOGSGROUP%|$CLOUDWATCHLOGSGROUP|g" /etc/awslogs/awslogs.conf
sed -i "s|%SQSQUEUE%|$SQSQUEUE|g" $WORKING_DIR/sqsworker.sh
sed -i "s|%DEADLETTERQUEUE%|$DEADLETTERQUEUE|g" $WORKING_DIR/sqsworker.sh
sed -i "s|%DDBTABLE%|$DDBTABLE|g" $WORKING_DIR/sqsworker.sh
sed -i "s|%SSHKEYNAME%|$SSHKEYNAME|g" $WORKING_DIR/sqsworker.sh
powershell.exe  $WORKING_DIR/schedule_task.ps1
