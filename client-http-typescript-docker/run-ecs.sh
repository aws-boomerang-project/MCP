#!/bin/bash

# Exit on any error
set -e

echo "🚀 Deploying MCP Client to ECS..."

# Config files
CONFIG_FILE=".mcp-config"
API_TOKEN_FILE=".mcp-api-token"
HASH_FILE=".docker-build-hash"
ECR_REPO_NAME="mcp-client"
ECS_CLUSTER_NAME="mcp-cluster"
ECS_SERVICE_NAME="mcp-client-service"
ECS_TASK_FAMILY="mcp-client-task"

# Function to read MCP URL from config file
get_saved_mcp_url() {
    if [ -f "$CONFIG_FILE" ]; then
        cat "$CONFIG_FILE"
    fi
}

# Function to read MCP API Key from config file
get_saved_api_token() {
    if [ -f "$API_TOKEN_FILE" ]; then
        cat "$API_TOKEN_FILE"
    fi
}

# Function to calculate hash of Dockerfile and source code
calculate_build_hash() {
    find ./client -type f \( -name "Dockerfile" -o -path "*/src/*" \) -exec sha256sum {} \; | sort | sha256sum | cut -d' ' -f1
}

# Get saved values directly without prompting
MCP_URL=$(get_saved_mcp_url)
MCP_TOKEN=$(get_saved_api_token)

# Verify values exist
if [ -z "$MCP_URL" ]; then
    echo "Error: MCP URL not found in config file"
    exit 1
fi

if [ -z "$MCP_TOKEN" ]; then
    echo "Error: API token not found in config file"
    exit 1
fi

# Continue with your ECS deployment using $MCP_URL and $MCP_TOKEN
# These values can be passed as environment variables to your task definition

echo "Using MCP URL: $MCP_URL"
echo "Using saved API token"

# Save the values
echo "$MCP_URL" > "$CONFIG_FILE"
echo "$MCP_TOKEN" > "$API_TOKEN_FILE"

# Verify AWS access
echo "📦 Verifying AWS credentials..."
CURRENT_ROLE=$(aws sts get-caller-identity --query 'Arn' --output text)
if [ $? -ne 0 ]; then
    echo "❌ Failed to get AWS credentials. Please check your AWS configuration."
    exit 1
fi
echo "🔑 Using AWS Role: $CURRENT_ROLE"

# Get AWS region
AWS_REGION=$(aws configure get region)
if [ -z "$AWS_REGION" ]; then
    AWS_REGION="us-east-1"
    echo "⚠️  No AWS region found in config, defaulting to $AWS_REGION"
else
    echo "✅ Using region: $AWS_REGION"
fi

# Get AWS account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Calculate current hash
CURRENT_HASH=$(calculate_build_hash)
STORED_HASH=""
if [ -f "$HASH_FILE" ]; then
    STORED_HASH=$(cat "$HASH_FILE")
fi

# Create ECR repository if it doesn't exist
echo "🔄 Setting up ECR repository..."
aws ecr describe-repositories --repository-names ${ECR_REPO_NAME} 2>/dev/null || \
    aws ecr create-repository --repository-name ${ECR_REPO_NAME}

# Get ECR login token
echo "🔑 Logging into ECR..."
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Build and push if changes detected

echo "🏗️  Changes detected, rebuilding and pushing the client container..."
    
# Build the image
docker build --platform linux/amd64 -t ${ECR_REPO_NAME} ./client

# Tag the image
docker tag ${ECR_REPO_NAME}:latest ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_NAME}:latest

# Push to ECR
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_NAME}:latest

echo "$CURRENT_HASH" > "$HASH_FILE"

# Create ECS service-linked role if it doesn't exist
echo "🔄 Creating ECS service-linked role..."
aws iam create-service-linked-role --aws-service-name ecs.amazonaws.com 2>/dev/null || true
echo "✅ ECS service-linked role is ready"

# Wait a few seconds for role propagation
# sleep 5

# Create ECS cluster if it doesn't exist
echo "🔄 Creating ECS cluster..."
aws ecs create-cluster \
    --cluster-name ${ECS_CLUSTER_NAME} \
    --capacity-providers FARGATE \
    --default-capacity-provider-strategy capacityProvider=FARGATE,weight=1 \
    --settings name=containerInsights,value=enabled


echo "🔄 Checking VPC..."
VPC_ID=$(aws ec2 describe-vpcs --query 'Vpcs[0].VpcId' --output text)
VPC_CIDR=$(aws ec2 describe-vpcs --vpc-ids $VPC_ID --query 'Vpcs[0].CidrBlock' --output text)

echo "✅ Using VPC: $VPC_ID with CIDR: $VPC_CIDR"


# Security Group Management
echo "🔄 Setting up security groups..."
# Check if security group exists
SECURITY_GROUP=$(aws ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=group-name,Values=mcp-client-sg" \
    --query 'SecurityGroups[0].GroupId' \
    --output text)

if [ "$SECURITY_GROUP" == "None" ] || [ -z "$SECURITY_GROUP" ]; then
    echo "🆕 Creating security group..."
    SECURITY_GROUP=$(aws ec2 create-security-group \
        --group-name mcp-client-sg \
        --description "Security group for MCP client" \
        --vpc-id $VPC_ID \
        --query 'GroupId' \
        --output text)
    
    # Add inbound rules
    echo "Adding inbound rules..."
    aws ec2 authorize-security-group-ingress \
        --group-id $SECURITY_GROUP \
        --protocol tcp \
        --port 80 \
        --cidr 0.0.0.0/0
    
    aws ec2 authorize-security-group-ingress \
        --group-id $SECURITY_GROUP \
        --protocol tcp \
        --port 3000 \
        --cidr 0.0.0.0/0
fi

echo "✅ Using security group: $SECURITY_GROUP"

# Create policy
cat << EOF > bedrock-policy.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "bedrock:InvokeModel",
                "bedrock:InvokeModelWithResponseStream"
            ],
            "Resource": "*"
        }
    ]
}
EOF


# Check and create ECS Task Execution Role
echo "🔄 Checking ECS Task Execution Role..."
TASK_EXECUTION_ROLE_NAME="ecsTaskExecutionRole"

# Check if role exists
ROLE_EXISTS=$(aws iam get-role --role-name $TASK_EXECUTION_ROLE_NAME 2>/dev/null || echo "false")

if [ "$ROLE_EXISTS" == "false" ]; then
    echo "🆕 Creating ECS Task Execution Role..."
    
    # Create trust policy document
    cat << EOF > trust-policy.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ecs-tasks.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF

    # Create the role
    aws iam create-role \
        --role-name $TASK_EXECUTION_ROLE_NAME \
        --assume-role-policy-document file://trust-policy.json

    # Attach required policies
    aws iam attach-role-policy \
        --role-name $TASK_EXECUTION_ROLE_NAME \
        --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

    # Add additional permissions for ECR and CloudWatch
    cat << EOF > task-execution-policy.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
EOF

    aws iam put-role-policy \
        --role-name $TASK_EXECUTION_ROLE_NAME \
        --policy-name ecsTaskExecutionPolicy \
        --policy-document file://task-execution-policy.json

    # Wait for role to propagate
    echo "⏳ Waiting for role to propagate..."
    sleep 10
fi

echo "✅ ECS Task Execution Role is ready"

# Checking if role exists
ROLE_EXISTS=$(aws iam get-role --role-name ecsTaskRole --query 'Role.RoleName' --output text 2>/dev/null || true)
if [ -n "$ROLE_EXISTS" ]; then
    echo "🔄 Updating existing ECS task role..."
    aws iam update-assume-role-policy \
        --role-name ecsTaskRole \
        --policy-document '{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ecs-tasks.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }'
else
    echo "🆕 Creating new ECS task role..."
    # Create or update the role
    aws iam create-role \
        --role-name ecsTaskRole \
        --assume-role-policy-document '{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ecs-tasks.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }'
fi

# Attach the policy
aws iam put-role-policy \
    --role-name ecsTaskRole \
    --policy-name bedrock-access \
    --policy-document file://bedrock-policy.json

# Create task definition
echo "📝 Creating ECS task definition..."
cat << EOF > task-definition.json
{
    "family": "${ECS_TASK_FAMILY}",
    "networkMode": "awsvpc",
    "requiresCompatibilities": ["FARGATE"],
    "cpu": "256",
    "memory": "512",
    "runtimePlatform": {
        "cpuArchitecture": "X86_64",
        "operatingSystemFamily": "LINUX"
    },
    "executionRoleArn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/ecsTaskExecutionRole",
    "taskRoleArn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/ecsTaskRole",
    "containerDefinitions": [
        {
            "name": "mcp-client",
            "portMappings": [
                {
                    "containerPort": 3000,
                    "protocol": "tcp",
                    "hostPort": 3000
                }
            ],
            "image": "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_NAME}:latest",
            "essential": true,
            "environment": [
                {
                    "name": "NODE_ENV",
                    "value": "production"
                },
                {
                    "name": "MCP_URL",
                    "value": "${MCP_URL}"
                },
                {
                    "name": "MCP_TOKEN",
                    "value": "${MCP_TOKEN}"
                },
                {
                    "name": "AWS_REGION",
                    "value": "${AWS_REGION}"
                }
            ],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": "/ecs/${ECS_TASK_FAMILY}",
                    "awslogs-region": "${AWS_REGION}",
                    "awslogs-stream-prefix": "ecs"
                }
            }
        }
    ]
}
EOF

# Register task definition
echo "🔄 Registering task definition..."
TASK_DEFINITION_ARN=$(aws ecs register-task-definition \
    --cli-input-json file://task-definition.json \
    --query 'taskDefinition.taskDefinitionArn' \
    --output text)

# Create CloudWatch log group
echo "🔄 Creating CloudWatch log group..."
aws logs create-log-group --log-group-name /ecs/${ECS_TASK_FAMILY} 2>/dev/null || true

# Get VPC ID and CIDR block
echo "🔄 Checking VPC..."
VPC_ID=$(aws ec2 describe-vpcs --query 'Vpcs[0].VpcId' --output text)
VPC_CIDR=$(aws ec2 describe-vpcs --vpc-ids $VPC_ID --query 'Vpcs[0].CidrBlock' --output text)

echo "✅ Using VPC: $VPC_ID with CIDR: $VPC_CIDR"

# Function to calculate subnet CIDR blocks based on VPC CIDR
calculate_subnet_cidrs() {
    local vpc_cidr=$1
    local vpc_prefix=${vpc_cidr%/*}
    local vpc_bits=${vpc_cidr#*/}
    
    # Extract first three octets of VPC CIDR
    local base_prefix=$(echo $vpc_prefix | cut -d. -f1-3)
    
    # Calculate two different subnet CIDRs
    echo "${base_prefix}.0/26"
    echo "${base_prefix}.64/26"
}

# Get subnet CIDRs
echo "🔄 Calculating subnet CIDRs..."
SUBNET_CIDRS=($(calculate_subnet_cidrs "$VPC_CIDR"))
SUBNET1_CIDR=${SUBNET_CIDRS[0]}
SUBNET2_CIDR=${SUBNET_CIDRS[1]}

echo "Calculated subnet CIDRs:"
echo "Subnet 1: $SUBNET1_CIDR"
echo "Subnet 2: $SUBNET2_CIDR"

# Get available availability zones
echo "🔄 Getting availability zones..."
AVAILABILITY_ZONES=$(aws ec2 describe-availability-zones \
    --query 'AvailabilityZones[?State==`available`].ZoneName' \
    --output text)

# Convert to array
AZ_ARRAY=($AVAILABILITY_ZONES)

# Create public subnets with calculated CIDRs
echo "🆕 Creating public subnets..."
SUBNET1=$(aws ec2 create-subnet \
    --vpc-id $VPC_ID \
    --cidr-block $SUBNET1_CIDR \
    --availability-zone ${AZ_ARRAY[0]} \
    --query 'Subnet.SubnetId' \
    --output text) || {
        echo "❌ Failed to create first subnet. Checking existing subnets..."
        EXISTING_SUBNETS=$(aws ec2 describe-subnets \
            --filters "Name=vpc-id,Values=$VPC_ID" \
            --query 'Subnets[].SubnetId' \
            --output text)
        if [ ! -z "$EXISTING_SUBNETS" ]; then
            SUBNET_ARRAY=($EXISTING_SUBNETS)
            SUBNET1=${SUBNET_ARRAY[0]}
            echo "✅ Using existing subnet: $SUBNET1"
        else
            echo "❌ No existing subnets found"
            exit 1
        fi
    }

SUBNET2=$(aws ec2 create-subnet \
    --vpc-id $VPC_ID \
    --cidr-block $SUBNET2_CIDR \
    --availability-zone ${AZ_ARRAY[1]} \
    --query 'Subnet.SubnetId' \
    --output text) || {
        echo "❌ Failed to create second subnet. Checking existing subnets..."
        EXISTING_SUBNETS=$(aws ec2 describe-subnets \
            --filters "Name=vpc-id,Values=$VPC_ID" \
            --query 'Subnets[].SubnetId' \
            --output text)
        SUBNET_ARRAY=($EXISTING_SUBNETS)
        if [ ${#SUBNET_ARRAY[@]} -gt 1 ]; then
            SUBNET2=${SUBNET_ARRAY[1]}
            echo "✅ Using existing subnet: $SUBNET2"
        else
            echo "❌ Not enough existing subnets found"
            exit 1
        fi
    }

echo "✅ Using subnets: $SUBNET1 and $SUBNET2"

# Create and attach internet gateway if it doesn't exist
echo "🌐 Checking Internet Gateway..."
IGW_ID=$(aws ec2 describe-internet-gateways \
    --filters "Name=attachment.vpc-id,Values=$VPC_ID" \
    --query 'InternetGateways[0].InternetGatewayId' \
    --output text)

if [ -z "$IGW_ID" ] || [ "$IGW_ID" == "None" ]; then
    echo "🆕 Creating Internet Gateway..."
    IGW_ID=$(aws ec2 create-internet-gateway --query 'InternetGateway.InternetGatewayId' --output text)
    aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway-id $IGW_ID
fi

# Create route table if it doesn't exist
echo "🛣️ Creating route table..."
ROUTE_TABLE_ID=$(aws ec2 describe-route-tables \
    --filters "Name=vpc-id,Values=$VPC_ID" \
    --query 'RouteTables[0].RouteTableId' \
    --output text)

if [ -z "$ROUTE_TABLE_ID" ] || [ "$ROUTE_TABLE_ID" == "None" ]; then
    ROUTE_TABLE_ID=$(aws ec2 create-route-table --vpc-id $VPC_ID --query 'RouteTable.RouteTableId' --output text)
fi

# Add internet route
aws ec2 create-route \
    --route-table-id $ROUTE_TABLE_ID \
    --destination-cidr-block 0.0.0.0/0 \
    --gateway-id $IGW_ID 2>/dev/null || true

# Associate subnets with route table
aws ec2 associate-route-table --subnet-id $SUBNET1 --route-table-id $ROUTE_TABLE_ID 2>/dev/null || true
aws ec2 associate-route-table --subnet-id $SUBNET2 --route-table-id $ROUTE_TABLE_ID 2>/dev/null || true

# Enable auto-assign public IP
aws ec2 modify-subnet-attribute --subnet-id $SUBNET1 --map-public-ip-on-launch
aws ec2 modify-subnet-attribute --subnet-id $SUBNET2 --map-public-ip-on-launch

echo "✅ Network configuration complete"


# Create ALB with verified security group
echo "🆕 Creating Application Load Balancer..."
ALB_ARN=$(aws elbv2 create-load-balancer \
    --name mcp-client-alb \
    --subnets $SUBNET1 $SUBNET2 \
    --security-groups $SECURITY_GROUP \
    --scheme internet-facing \
    --query 'LoadBalancers[0].LoadBalancerArn' \
    --output text)

if [ $? -ne 0 ]; then
    echo "❌ Failed to create ALB. Checking if it already exists..."
    ALB_ARN=$(aws elbv2 describe-load-balancers \
        --names mcp-client-alb \
        --query 'LoadBalancers[0].LoadBalancerArn' \
        --output text 2>/dev/null || echo "")
    
    if [ -z "$ALB_ARN" ]; then
        echo "❌ Could not create or find ALB"
        exit 1
    else
        echo "✅ Using existing ALB: $ALB_ARN"
    fi
fi

echo "🔄 Checking if target group exists..."
TG_ARN=$(aws elbv2 describe-target-groups --names mcp-client-tg --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null || true)

if [ -z "$TG_ARN" ]; then
    echo "🆕 Creating target group..."
    TG_ARN=$(aws elbv2 create-target-group \
        --name mcp-client-tg \
        --protocol HTTP \
        --port 3000 \
        --vpc-id $VPC_ID \
        --target-type ip \
        --health-check-path /health \
        --health-check-interval-seconds 30 \
        --query 'TargetGroups[0].TargetGroupArn' \
        --output text)

    echo "🔄 Creating listener..."
    aws elbv2 create-listener \
        --load-balancer-arn ${ALB_ARN} \
        --protocol HTTP \
        --port 80 \
        --default-actions Type=forward,TargetGroupArn=${TG_ARN}
fi

# Check and update security group rules
echo "🔄 Checking and updating security group rules..."

# Function to check if rule exists
check_rule_exists() {
    local group_id=$1
    local port=$2
    
    aws ec2 describe-security-groups \
        --group-ids ${group_id} \
        --query "SecurityGroups[].IpPermissions[?FromPort==${port}]" \
        --output text | grep -q "${port}"
    
    return $?
}

# Add port 80 rule, ignore if it exists
echo "Ensuring port 80 ingress rule exists..."
aws ec2 authorize-security-group-ingress \
    --group-id ${SECURITY_GROUP} \
    --protocol tcp \
    --port 80 \
    --cidr 0.0.0.0/0 2>/dev/null || \
    echo "✅ Port 80 ingress rule already exists"

# Add port 3000 rule, ignore if it exists
echo "Ensuring port 3000 ingress rule exists..."
aws ec2 authorize-security-group-ingress \
    --group-id ${SECURITY_GROUP} \
    --protocol tcp \
    --port 3000 \
    --source-group ${SECURITY_GROUP} 2>/dev/null || \
    echo "✅ Port 3000 ingress rule already exists"

# Create or update ECS service
echo "🔄 Checking if service exists..."
if aws ecs describe-services --cluster ${ECS_CLUSTER_NAME} --services ${ECS_SERVICE_NAME} --query 'services[?status!=`INACTIVE`]' --output text 2>/dev/null | grep -q "${ECS_SERVICE_NAME}"; then
    echo "🔄 Updating existing ECS service..."
    aws ecs update-service \
        --cluster ${ECS_CLUSTER_NAME} \
        --service ${ECS_SERVICE_NAME} \
        --task-definition ${TASK_DEFINITION_ARN} \
        --force-new-deployment \
        --network-configuration "awsvpcConfiguration={subnets=[$SUBNET1,$SUBNET2],securityGroups=[${SECURITY_GROUP}],assignPublicIp=ENABLED}" \
        --load-balancers "targetGroupArn=${TG_ARN},containerName=mcp-client,containerPort=3000"
else
    echo "🆕 Creating new ECS service..."
    aws ecs create-service \
        --cluster ${ECS_CLUSTER_NAME} \
        --service-name ${ECS_SERVICE_NAME} \
        --task-definition ${TASK_DEFINITION_ARN} \
        --desired-count 1 \
        --launch-type FARGATE \
        --network-configuration "awsvpcConfiguration={subnets=[$SUBNET1,$SUBNET2],securityGroups=[${SECURITY_GROUP}],assignPublicIp=ENABLED}" \
        --load-balancers "targetGroupArn=${TG_ARN},containerName=mcp-client,containerPort=3000"
fi

# Get and display the ALB DNS name
ALB_DNS=$(aws elbv2 describe-load-balancers --names mcp-client-alb --query 'LoadBalancers[0].DNSName' --output text)
echo "✅ Application Load Balancer DNS: ${ALB_DNS}"
echo "🌐 You can access your application at: http://${ALB_DNS}"

echo "✅ Deployment complete! Your application is now running on ECS."
echo "📊 Monitor your application in the ECS console:"
echo "https://${AWS_REGION}.console.aws.amazon.com/ecs/home?region=${AWS_REGION}#/clusters/${ECS_CLUSTER_NAME}/services/${ECS_SERVICE_NAME}"


echo "🔄 Waiting for service to stabilize..."
aws ecs wait services-stable \
    --cluster ${ECS_CLUSTER_NAME} \
    --services ${ECS_SERVICE_NAME}

if [ $? -eq 0 ]; then
    echo "✅ Service has stabilized successfully!"
else
    echo "⚠️ Service may not have stabilized. Please check the ECS console for details."
fi