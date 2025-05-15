from lambda_mcp.lambda_mcp import LambdaMCPServer
from datetime import datetime, UTC
import random
import boto3
import os
import json
import ipaddress, botocore
# Get session table name from environment variable
session_table = os.environ.get('MCP_SESSION_TABLE', 'mcp_sessions')

# Create the MCP server instance
mcp_server = LambdaMCPServer(name="mcp-lambda-server", version="1.0.0", session_table=session_table)

@mcp_server.tool()
def get_time() -> str:
    """Get the current UTC date and time."""
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")

@mcp_server.tool()
def get_weather(city: str) -> str:
    """Get the current weather for a city.
    
    Args:
        city: Name of the city to get weather for
        
    Returns:
        A string describing the weather
    """
    temp = random.randint(15, 35)
    return f"The temperature in {city} is {temp}°C"

@mcp_server.tool()
def count_s3_buckets() -> int:
    """Count the number of S3 buckets."""
    s3 = boto3.client('s3')
    response = s3.list_buckets()
    return len(response['Buckets'])

@mcp_server.tool()
def create_vpc() -> dict:
    """
    Create a VPC with 2 public + 2 private subnets across us-east-1a and us-east-1b.
    """

    ec2 = boto3.client("ec2", region_name="us-east-1")
    out = {}

    cidr_block = "10.0.0.0/16"
    name_tag = "mcp-server"
    az_list = ["us-east-1a", "us-east-1b"]

    # 0) 기존 VPC 확인
    existing = ec2.describe_vpcs(Filters=[
        {"Name": "tag:Name", "Values": [f"{name_tag}-vpc"]}
    ])["Vpcs"]

    if existing:
        vpc_id = existing[0]["VpcId"]
        print(f"[INFO] Existing VPC found: {vpc_id}")
        out["VpcId"] = vpc_id
        return out  # 이미 있다면 더 이상 진행 안 함

    # 1) VPC
    vpc_id = ec2.create_vpc(CidrBlock=cidr_block)["Vpc"]["VpcId"]
    out["VpcId"] = vpc_id
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    ec2.create_tags(Resources=[vpc_id],
                    Tags=[{"Key": "Name", "Value": f"{name_tag}-vpc"}])

    # 2) IGW
    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    out["InternetGatewayId"] = igw_id
    ec2.attach_internet_gateway(VpcId=vpc_id, InternetGatewayId=igw_id)

    main_rt_id = ec2.describe_route_tables(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "association.main", "Values": ["true"]}
        ]
    )["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=main_rt_id,
                     DestinationCidrBlock="0.0.0.0/0",
                     GatewayId=igw_id)

    # 3) Subnets
    subnet_blocks = list(ipaddress.ip_network(cidr_block).subnets(new_prefix=20))
    if len(subnet_blocks) < 4:
        raise Exception("Not enough subnet blocks in CIDR.")

    out["PublicSubnets"] = []
    out["PrivateSubnets"] = []
    nat_gateways = []

    for i, az in enumerate(az_list):
        # Public
        cidr_pub = str(subnet_blocks[i * 2])
        pub_subnet = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=cidr_pub, AvailabilityZone=az,
            TagSpecifications=[{
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": f"{name_tag}-pub-{az}"}]
            }]
        )["Subnet"]
        pub_id = pub_subnet["SubnetId"]
        out["PublicSubnets"].append(pub_id)
        ec2.modify_subnet_attribute(SubnetId=pub_id,
                                    MapPublicIpOnLaunch={"Value": True})

        # NAT Gateway
        eip = ec2.allocate_address(Domain="vpc")["AllocationId"]
        nat = ec2.create_nat_gateway(
            SubnetId=pub_id, AllocationId=eip,
            TagSpecifications=[{
                "ResourceType": "natgateway",
                "Tags": [{"Key": "Name", "Value": f"{name_tag}-nat-{az}"}]
            }]
        )["NatGateway"]
        nat_id = nat["NatGatewayId"]
        nat_gateways.append(nat_id)

        waiter = ec2.get_waiter("nat_gateway_available")
        print(f"Waiting for NAT Gateway {nat_id} in {az}...")
        waiter.wait(NatGatewayIds=[nat_id])
        print(f"NAT Gateway {nat_id} is now available.")

        # Private
        cidr_pri = str(subnet_blocks[i * 2 + 1])
        pri_subnet = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=cidr_pri, AvailabilityZone=az,
            TagSpecifications=[{
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": f"{name_tag}-pri-{az}"}]
            }]
        )["Subnet"]
        pri_id = pri_subnet["SubnetId"]
        out["PrivateSubnets"].append(pri_id)

        rt_priv = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
        ec2.associate_route_table(RouteTableId=rt_priv, SubnetId=pri_id)
        ec2.create_route(RouteTableId=rt_priv,
                         DestinationCidrBlock="0.0.0.0/0",
                         NatGatewayId=nat_id)

    return out

def ensure_eks_access_entries(eks, iam, cluster_name):
    access_entries = eks.list_access_entries(clusterName=cluster_name)["accessEntries"]

    # 1) EKSNodeRole 등록
    try:
        node_role_arn = iam.get_role(RoleName="EKSNodeRole")["Role"]["Arn"]
        if not any(e["principalArn"] == node_role_arn for e in access_entries):
            print(f"[INFO] Creating Access Entry for Node Role: {node_role_arn}")
            eks.create_access_entry(
                clusterName=cluster_name,
                principalArn=node_role_arn,
                type="EC2_LINUX",
                username="system:node:{{EC2PrivateDNSName}}",
                groups=["system:nodes"]
            )
        else:
            print("[INFO] EKSNodeRole already registered.")
    except Exception as e:
        print(f"[WARN] Could not create node role access entry: {e}")

    # 2) 현재 사용 중인 실행 역할 (예: Lambda 역할) 등록
    try:
        sts = boto3.client("sts")
        caller_arn = sts.get_caller_identity()["Arn"]
        if not any(e["principalArn"] == caller_arn for e in access_entries):
            print(f"[INFO] Creating Access Entry for Admin Caller: {caller_arn}")
            eks.create_access_entry(
                clusterName=cluster_name,
                principalArn=caller_arn,
                type="STANDARD",
                accessPolicies=[{
                    "policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
                }]
            )
        else:
            print("[INFO] Admin caller already registered.")
    except Exception as e:
        print(f"[WARN] Could not create admin access entry: {e}")

@mcp_server.tool()
def create_eks_cluster(
    cluster_name: str
) -> dict:
    """
    Create an Amazon EKS cluster named 'my-cluster' using a VPC tagged with Name='mcp-server-vpc'.
    Automatically creates the IAM service role 'EKSServiceRole' if not exists.
    """
    eks = boto3.client("eks")
    ec2 = boto3.client("ec2")
    iam = boto3.client("iam")
    sts = boto3.client("sts")

    version = "1.32"
    endpoint_public = True
    endpoint_private = True
    public_cidrs = ["0.0.0.0/0"]

    # 0) 기존 EKS Cluster 존재 여부 확인
    cluster_name = "my-cluster"
    existing_clusters = eks.list_clusters()["clusters"]

    if cluster_name in existing_clusters:
        print(f"[INFO] EKS cluster '{cluster_name}' already exists. Skipping creation.")
        return  # 이미 있다면 더 이상 진행 안 함

    # 1) EKS Cluster IAM Role 확인 또는 생성
    control_role_name = "EKSServiceRole"
    try:
        control_role_arn = iam.get_role(RoleName=control_role_name)["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        print(f"[INFO] Creating control plane IAM role: {control_role_name}")
        control_role = iam.create_role(
            RoleName=control_role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "eks.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            }),
            Description="IAM role for EKS control plane"
        )
        control_role_arn = control_role["Role"]["Arn"]
        iam.attach_role_policy(RoleName=control_role_name,
                               PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    # 2) Node IAM Role 확인 또는 생성
    node_role_name = "EKSNodeRole"
    try:
        node_role_arn = iam.get_role(RoleName=node_role_name)["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        print(f"[INFO] Creating node IAM role: {node_role_name}")
        node_role = iam.create_role(
            RoleName=node_role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            }),
            Description="IAM role for EKS worker nodes"
        )
        node_role_arn = node_role["Role"]["Arn"]
        for policy in [
            "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
            "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
            "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
        ]:
            iam.attach_role_policy(RoleName=node_role_name, PolicyArn=policy)

    # Name 태그가 "mcp-server-vpc"인 VPC 찾기
    vpcs = ec2.describe_vpcs(
        Filters=[{
            "Name": "tag:Name",
            "Values": ["mcp-server-vpc"]
        }]
    )["Vpcs"]

    if not vpcs:
        raise Exception('No VPC found with tag Name="mcp-server-vpc".')
    vpc_id = vpcs[0]["VpcId"]
    print("VPC 찾기 완료", vpc_id)

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets]
    print("Subnet 찾기 완료", subnet_ids)

    if len(subnet_ids) < 2:
        raise Exception("At least two subnets are required to create an EKS cluster.")

    sgs = ec2.describe_security_groups(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "group-name", "Values": ["default"]}
    ])
    if not sgs["SecurityGroups"]:
        raise Exception("No security group found in the specified VPC.")
    sg_id = sgs["SecurityGroups"][0]["GroupId"]
    print("SG 찾기 완료", sg_id)

    print("EKS Cluster 생성 시작")
    response = eks.create_cluster(
        name=cluster_name,
        version=version,
        roleArn=control_role_name,
        resourcesVpcConfig={
            "subnetIds": subnet_ids,
            "securityGroupIds": [sg_id],
            "endpointPublicAccess": endpoint_public,
            "endpointPrivateAccess": endpoint_private,
            "publicAccessCidrs": public_cidrs
        },
        accessConfig={
            "authenticationMode": "API"
        }
    )
    print("EKS Cluster 생성 완료")

    # 클러스터 활성화 대기
    waiter = eks.get_waiter("cluster_active")
    print("[INFO] Waiting for EKS cluster to become ACTIVE...")
    waiter.wait(name=cluster_name)
    print("[INFO] EKS cluster is ACTIVE.")

    # Add-ons 설치 (버전 명시)
    addon_versions = {
        "vpc-cni": "v1.19.2-eksbuild.1",
        "coredns": "v1.11.4-eksbuild.2",
        "kube-proxy": "v1.32.0-eksbuild.2",
        "eks-pod-identity-agent": "v1.3.4-eksbuild.1"
    }

    for addon, version_str in addon_versions.items():
        try:
            print(f"[INFO] Installing addon: {addon} ({version_str})")
            eks.create_addon(
                clusterName=cluster_name,
                addonName=addon,
                addonVersion=version_str,
                resolveConflicts="OVERWRITE"
            )
        except eks.exceptions.ResourceInUseException:
            print(f"[WARN] Addon '{addon}' already exists. Skipping.")
        except Exception as e:
            print(f"[ERROR] Failed to install addon '{addon}': {e}")
    
    # 6) Access Entry 등록 함수
    def ensure_eks_access_entries():
        access_entries = eks.list_access_entries(clusterName=cluster_name)["accessEntries"]
        # node role
        if not any(e["principalArn"] == node_role_arn for e in access_entries):
            eks.create_access_entry(
                clusterName=cluster_name,
                principalArn=node_role_arn,
                type="EC2_LINUX",
                username="system:node:{{EC2PrivateDNSName}}",
                groups=["system:nodes"]
            )
            print("[INFO] EKSNodeRole registered to access entries.")
        # current caller (admin)
        caller_arn = sts.get_caller_identity()["Arn"]
        if not any(e["principalArn"] == caller_arn for e in access_entries):
            eks.create_access_entry(
                clusterName=cluster_name,
                principalArn=caller_arn,
                type="STANDARD",
                accessPolicies=[{
                    "policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
                }]
            )
            print("[INFO] Admin caller registered to access entries.")

    ensure_eks_access_entries()

    return {"ClusterArn": response["cluster"]["arn"]}

@mcp_server.tool()
def create_eks_nodegroup() -> dict:
    """
    Create a managed node group in the specified EKS cluster using private subnets only.
    Automatically creates the EKSNodeRole IAM role if it doesn't exist.
    """

    eks = boto3.client("eks")
    ec2 = boto3.client("ec2")
    iam = boto3.client("iam")

    cluster_name = "my-cluster"
    nodegroup_name = "my-ng"
    desired_size = 1
    min_size = 1
    max_size = 1
    instance_type = "t3.medium"
    role_name = "EKSNodeRole"

    # 1) 기존 IAM 역할 ARN 가져오기
    try:
        node_role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
        print(f"[INFO] Using existing IAM role: {role_name}")
    except iam.exceptions.NoSuchEntityException:
        raise Exception(f"IAM role '{role_name}' not found. Please create the EKS cluster first.")

    # 2) 클러스터 VPC에서 private subnet 찾기
    cluster = eks.describe_cluster(name=cluster_name)["cluster"]
    vpc_id = cluster["resourcesVpcConfig"]["vpcId"]

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    private_subnets = [
        s["SubnetId"]
        for s in subnets
        if any(tag["Key"] == "Name" and "-pri-" in tag["Value"] for tag in s.get("Tags", []))
    ]

    if len(private_subnets) < 1:
        raise Exception("No private subnets found in the VPC. Make sure they are tagged with '-pri-' in the Name.")

    # 3) NodeGroup 생성
    print(f"[INFO] Creating node group: {nodegroup_name}")
    response = eks.create_nodegroup(
        clusterName=cluster_name,
        nodegroupName=nodegroup_name,
        scalingConfig={
            "minSize": min_size,
            "maxSize": max_size,
            "desiredSize": desired_size
        },
        subnets=private_subnets,
        instanceTypes=[instance_type],
        nodeRole=node_role_arn,
        amiType="AL2023_x86_64",
        diskSize=20,
        capacityType="ON_DEMAND"
    )

    print(f"[INFO] Node group '{nodegroup_name}' creation initiated.")
    return {"NodeGroupArn": response["nodegroup"]["nodegroupArn"]}

def lambda_handler(event, context):
    """AWS Lambda handler function."""
    return mcp_server.handle_request(event, context) 