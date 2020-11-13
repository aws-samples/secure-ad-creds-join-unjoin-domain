#*** A sample Lambda function that updtaes the IAM policy and S3 bucket policy created in the soution to restrict unauthorized access ***.

import boto3, json
import botocore
import os
from datetime import datetime

ec2_client = boto3.client('ec2')
asg_client = boto3.client('autoscaling')
secret_client = boto3.client('secretsmanager')
iam = boto3.client('iam')
s3 = boto3.client('s3')

# Environment variables fetched from the Cloudformation Stack

ROLE_NAME = os.getenv("IAM_EC2_ROLE")
POLICY_NAME = os.getenv("IAM_POLICY")
AD_SECRET = os.getenv("SECRET_NAME")
BUCKET_NAME = os.getenv("S3_BUCKET")
MANAGED_POLICY_ARN = os.getenv("MANAGED_POLICY_ARN")


def lambda_handler(event, context):
        message = event['Records'][0]['Sns']['Message']
        json_message = json.loads(message)
        Lifecycle_Transition = json_message['Event']
        if Lifecycle_Transition == "autoscaling:EC2_INSTANCE_LAUNCH":
            instance_id = json_message['EC2InstanceId']
            print(instance_id)
            update_iam_policy = update_iam_inline_policy(instance_id)
            update_secret_manager = update_secret_manager_policy(instance_id)
            update_bucket_policy = update_s3_bucket_policy(BUCKET_NAME,instance_id)
            update_iam_managed_policy = update_managed_policy(MANAGED_POLICY_ARN,instance_id)
            if update_iam_managed_policy:
                print("SUCCESS")
            else:
                print("something failed: FAILURE")
       
        
def update_iam_inline_policy(instance_id):
    try:
        response = iam.get_role_policy(RoleName=ROLE_NAME,
                PolicyName=POLICY_NAME)
        policy_document = response['PolicyDocument']
        inst_user_id = policy_document['Statement'][0]['Condition'
                ]['StringNotLike']['aws:userid'][0]
        split_string = inst_user_id.split(':')
        instance_id_old = split_string[1]
        # convert dictionary object into string to replace the instance id
        result = json.dumps(policy_document)
        temp_policy_doc = result.replace(instance_id_old, instance_id)
        #print(temp_policy_doc)
        updated_policy = json.dumps(temp_policy_doc)
        response = iam.put_role_policy(RoleName=ROLE_NAME,
                PolicyName=POLICY_NAME,
                PolicyDocument=temp_policy_doc)
        print(response)
    except botocore.exceptions.ClientError as e:
        log("Error updating the inline policy {}: {}".format(instance_id, e.response['Error'])) 

def update_secret_manager_policy(instance_id):
  try:
    response = secret_client.get_resource_policy(SecretId=AD_SECRET)
    policy_document = response['ResourcePolicy']
    #print(policy_document)
    json_ver = json.loads(policy_document)
    inst_user_id = json_ver['Statement'][0]['Condition']['StringNotLike']['aws:userid'][0]
    split_string = inst_user_id.split(':')
    instance_id_old = split_string[1]
    result = json.dumps(json_ver)
    temp_policy_doc = result.replace(instance_id_old, instance_id)
    #print(temp_policy_doc)
    updated_policy = temp_policy_doc
    response = secret_client.put_resource_policy(SecretId=AD_SECRET,ResourcePolicy=temp_policy_doc)
    print(response)
  except  botocore.exceptions.ClientError as e:
        log("Error updating the secret manager policy {}: {}".format(instance_id, e.response['Error']))	
	
def update_s3_bucket_policy(bucket_name,instance_id):
  try:
    response = s3.get_bucket_policy(Bucket=bucket_name)
    policy_document = response['Policy']
    json_ver = json.loads(policy_document)
    inst_user_id = json_ver['Statement'][0]['Condition']['StringNotLike']['aws:userid'][0]
    split_string = inst_user_id.split(':')
    instance_id_old = split_string[1]
    # convert dictionary object into string to replace the instance id
    result = json.dumps(json_ver) 
    temp_policy_doc = result.replace(instance_id_old, instance_id)
    updated_policy = temp_policy_doc
    response = s3.put_bucket_policy(Bucket=bucket_name,Policy=updated_policy)
    print(response)
  except  botocore.exceptions.ClientError as e:
        log("Error updating S3 bucket policy {}: {}".format(instance_id, e.response['Error']))	

def update_managed_policy(policy_arn,instance_id):
  var4 = None
  try:
    response = iam.get_policy(PolicyArn=policy_arn)
    policy_detail = response['Policy']
    policy_version = policy_detail['DefaultVersionId']
    response2 = iam.get_policy_version(PolicyArn=policy_arn,VersionId=policy_version)
    policy_body = response2['PolicyVersion']['Document']
    inst_user_id = policy_body['Statement'][0]['Resource'][1]
    split_string = inst_user_id.split(':instance/')
    instance_id_old = split_string[1]
    result = json.dumps(policy_body) 
    temp_policy_doc = result.replace(instance_id_old, instance_id)
    #print(temp_policy_doc)
    response = iam.create_policy_version(PolicyArn=policy_arn,PolicyDocument=temp_policy_doc,SetAsDefault= True)
    response = iam.delete_policy_version(PolicyArn= policy_arn,VersionId=policy_version)
    #print(response)	
    var4 = response['ResponseMetadata']['HTTPStatusCode']	
  except botocore.exceptions.ClientError as e:
        log("Error updating IAM managed policy {}: {}".format(instance_id, e.response['Error']))
  return var4	

def log(error):
    print('{}Z {}'.format(datetime.utcnow().isoformat(), error))
	