import boto3
from config import *
from common import *

def getec2():
    ec2_client = boto3.resource('ec2', region_name="us-east-2", aws_access_key_id=ACCESS_KEY,
         aws_secret_access_key= SECRET_KEY)
    return ec2_client

def create_aws_network_settings(config_data_tmp):
    ec2_client = getec2()
    # create VPC
    vpc = ec2_client.create_vpc(CidrBlock='192.168.0.0/16')
    # we can assign a name to vpc, or any resource, by using tag
    vpc.create_tags(Tags=[{"Key": "Name", "Value": "Tunnel-Manager_vpc"}])
    vpc.wait_until_available()
    print(vpc.id)
    config_data_tmp['aws']['vpc'] = vpc.id

    # create then attach internet gateway
    ig = ec2_client.create_internet_gateway()
    vpc.attach_internet_gateway(InternetGatewayId=ig.id)
    print(ig.id)
    config_data_tmp['aws']['igw'] = ig.id


    # create a route table and a public route
    route_table = vpc.create_route_table()
    route = route_table.create_route(
        DestinationCidrBlock='0.0.0.0/0',
        GatewayId=ig.id
    )
    print(route_table.id)
    config_data_tmp['aws']['rtb'] = route_table.id


    # create subnet
    subnet = ec2_client.create_subnet(CidrBlock='192.168.1.0/24', VpcId=vpc.id)
    print(subnet.id)
    config_data_tmp['aws']['subnet'] = subnet.id

    # associate the route table with the subnet
    route_table.associate_with_subnet(SubnetId=subnet.id)

    # Create sec group
    sec_group = ec2_client.create_security_group(
        GroupName='Tunnel-Manager slice_0', Description='Tunnel-Manager slice_0 sec group', VpcId=vpc.id)
    sec_group.authorize_ingress(
        CidrIp='0.0.0.0/0',
        IpProtocol='tcp',
        FromPort=22,
        ToPort=22
    )
    sec_group.authorize_ingress(
        CidrIp='0.0.0.0/0',
        IpProtocol='tcp',
        FromPort=80,
        ToPort=80
    )
    sec_group.authorize_ingress(
        CidrIp='0.0.0.0/0',
        IpProtocol='tcp',
        FromPort=443,
        ToPort=443
    )
    print(sec_group.id)
    config_data_tmp['aws']['sg'] = sec_group.id
    overwrite_vars(config_data_tmp)


"""
This function terminates ec2 instances using the instance id
"""
def terminate_instance(id_tmp):
    try:
        ec2_client = getec2()
        ec2_client.instances.filter(InstanceIds = [id_tmp]).terminate()
        return 1
    except Exception as e:
        print("Error: terminate_instance()")
        print(str(e))
        return 0

def create_instance(config_data_tmp):
    ec2_client = getec2()

    # Create instance
    instances = ec2_client.create_instances(
        ImageId=IMAGEID, InstanceType='t2.micro', MaxCount=1, MinCount=1, KeyName=SSHKEYNAME,
        NetworkInterfaces=[{'SubnetId': config_data_tmp['aws']['subnet'], 'DeviceIndex': 0, 'AssociatePublicIpAddress': True, 'Groups': [config_data_tmp['aws']['sg']]}])
    instances[0].wait_until_running()
    
    public_ip_address = ""
    while len(public_ip_address) <= 0:
        time.sleep(30)
        instances[0].reload()
        public_ip_address = instances[0].public_ip_address
        print(public_ip_address)
    return [str(public_ip_address),str(instances[0].id)]


if __name__ == "__main__":
   print("Executed directly")
   #terminate_instance("i-029aca95ed91f23dc")
   pass
   #public_ip_address = create_instance()
   #print("public_ip_address: "+str(public_ip_address))


