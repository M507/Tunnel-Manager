import boto3
from config import *


def create_instance():
    # public_ip_address = create_instance()
    ec2_client = boto3.resource('ec2', region_name="us-east-2")
    instances = ec2_client.create_instances(
        ImageId=IMAGEID,
        InstanceType='t2.micro',
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[SECURITYGROUPID],
        SubnetId=SUBNETID,
        KeyName=SSHKEYNAME
    )

    instances[0].wait_until_running()
    public_ip_address = ""
    while len(public_ip_address) <= 0:
        time.sleep(30)
        instances[0].reload()
        public_ip_address = instances[0].public_ip_address
        print(public_ip_address)
    return public_ip_address



