#*** A sample Lambda function that posts Instance status, InstandID and private IPv address to an SQS queue ***.

#!/usr/bin/python
# -*- coding: utf-8 -*-
import boto3
import os
import json
import logging
from botocore.exceptions import ClientError
from datetime import datetime
import sys


# Set the log format

logger = logging.getLogger()
for h in logger.handlers:
    logger.removeHandler(h)

h = logging.StreamHandler(sys.stdout)
FORMAT = ' [%(levelname)s]/%(asctime)s/%(name)s - %(message)s'
h.setFormatter(logging.Formatter(FORMAT))
logger.addHandler(h)
logger.setLevel(logging.INFO)

INSTANCE_AD_TAG = os.getenv("INSTANCE_AD_TAG")
INSTANCE_TAG_VALUE = os.getenv("INSTANCE_TAG_VALUE")

def lambda_handler(event, context):
  print(event)
  try:
     ec2_client = boto3.client('ec2')
     instance_id = event['detail']['instance-id']
     instance_state = event['detail']['state']
     print(instance_id)
     print(instance_state)   
     var = ec2_client.describe_instances(Filters=[{'Name': 'tag:JoinAD','Values': [INSTANCE_TAG_VALUE]}, {'Name': 'instance-id','Values': [instance_id]}]).get('Reservations', '')
     testcount = sum([[i for i in r['Instances']] for r in var], [])

     if format(len(testcount)) == '1':
	     if instance_state == 'terminated':
	        privateIP = 'none'
	     else:
	        privateIP = var[0]['Instances'][0]['PrivateIpAddress']
	        print(privateIP)
	     data = {}
	     data['instanceId'] = instance_id
	     data['privateIp'] = privateIP
	     data['instance_state'] = instance_state
	     json_data = json.dumps(data)
	     print(json_data)
	     QUEUE_NAME = os.getenv("QUEUE_NAME")
	     SQS = boto3.client("sqs")
	     q = SQS.get_queue_url(QueueName=QUEUE_NAME).get('QueueUrl')
	     print(q)
	     resp = SQS.send_message(QueueUrl=q, MessageBody=json_data)
     else:
            print('no result, check request parameters')
  except botocore.exceptions.ClientError as e:
		       log("Error sending message to the SQS queue {}".format(e.response['Error'])) 				
def log(error):
    print('{}Z {}'.format(datetime.utcnow().isoformat(), error))				