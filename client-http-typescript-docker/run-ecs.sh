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
# else
#     echo "✅ No changes detected, using existing container"
# fi

# Create ECS cluster if it doesn't exist
echo "🔄 Creating ECS cluster..."
aws ecs create-cluster \
    --cluster-name ${ECS_CLUSTER_NAME} \
    --capacity-providers FARGATE \
    --default-capacity-provider-strategy capacityProvider=FARGATE,weight=1 \
    --settings name=containerInsights,value=enabled

# Get security group
echo "🔄 Getting security group..."
SECURITY_GROUP=$(aws ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=vpc-053ec2ab2af382b97" \
    --query 'SecurityGroups[?GroupName==`default`].GroupId' \
    --output text)

if [ -z "$SECURITY_GROUP" ]; then
    echo "⚠️ No security group found, using default security group..."
    SECURITY_GROUP=$(aws ec2 describe-security-groups \
        --query 'SecurityGroups[?GroupName==`default`].GroupId' \
        --output text | head -n 1)
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

# Create ALB and target group if they don't exist
echo "🔄 Checking if ALB exists..."
ALB_ARN=$(aws elbv2 describe-load-balancers --names mcp-client-alb --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || true)

if [ -z "$ALB_ARN" ]; then
    echo "🆕 Creating Application Load Balancer..."
    ALB_ARN=$(aws elbv2 create-load-balancer \
        --name mcp-client-alb \
        --subnets subnet-096220ee118b0809f subnet-083f09cf1cdd6ea69 \
        --security-groups ${SECURITY_GROUP} \
        --scheme internet-facing \
        --query 'LoadBalancers[0].LoadBalancerArn' \
        --output text)
fi

echo "🔄 Checking if target group exists..."
TG_ARN=$(aws elbv2 describe-target-groups --names mcp-client-tg --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null || true)

if [ -z "$TG_ARN" ]; then
    echo "🆕 Creating target group..."
    TG_ARN=$(aws elbv2 create-target-group \
        --name mcp-client-tg \
        --protocol HTTP \
        --port 3000 \
        --vpc-id vpc-053ec2ab2af382b97 \
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
        --network-configuration "awsvpcConfiguration={subnets=[subnet-096220ee118b0809f,subnet-083f09cf1cdd6ea69],securityGroups=[${SECURITY_GROUP}],assignPublicIp=ENABLED}" \
        --load-balancers "targetGroupArn=${TG_ARN},containerName=mcp-client,containerPort=3000"
else
    echo "🆕 Creating new ECS service..."
    aws ecs create-service \
        --cluster ${ECS_CLUSTER_NAME} \
        --service-name ${ECS_SERVICE_NAME} \
        --task-definition ${TASK_DEFINITION_ARN} \
        --desired-count 1 \
        --launch-type FARGATE \
        --network-configuration "awsvpcConfiguration={subnets=[subnet-096220ee118b0809f,subnet-083f09cf1cdd6ea69],securityGroups=[${SECURITY_GROUP}],assignPublicIp=ENABLED}" \
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