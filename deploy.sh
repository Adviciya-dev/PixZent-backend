#!/bin/bash

# PixZent Backend - AWS Lambda Deployment Script
# Usage: ./deploy.sh [dev|staging|prod]

set -e

STAGE=${1:-prod}
STACK_NAME="pixzent-backend-${STAGE}"
REGION=${AWS_REGION:-us-east-1}

echo "=========================================="
echo "PixZent Backend - AWS Lambda Deployment"
echo "=========================================="
echo "Stage: ${STAGE}"
echo "Stack: ${STACK_NAME}"
echo "Region: ${REGION}"
echo ""

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "Error: AWS CLI is not installed. Please install it first."
    exit 1
fi

# Check if SAM CLI is installed
if ! command -v sam &> /dev/null; then
    echo "Error: AWS SAM CLI is not installed. Please install it first."
    echo "Run: pip install aws-sam-cli"
    exit 1
fi

# Check for required environment variables
if [ -z "$MONGO_URL" ]; then
    echo "Error: MONGO_URL environment variable is required"
    echo "Example: export MONGO_URL='mongodb+srv://user:pass@cluster.mongodb.net'"
    exit 1
fi

if [ -z "$JWT_SECRET_KEY" ]; then
    echo "Warning: JWT_SECRET_KEY not set. Generating a random one..."
    JWT_SECRET_KEY=$(openssl rand -base64 32)
fi

if [ -z "$ADMIN_PASSWORD" ]; then
    echo "Warning: ADMIN_PASSWORD not set. Using default (change in production!)"
    ADMIN_PASSWORD="uaepixzent@#2026@$"
fi

# Create a deployment package directory
echo "Creating deployment package..."
rm -rf .aws-sam
mkdir -p .aws-sam/build

# Copy source files
cp server.py .aws-sam/build/
cp requirements-lambda.txt .aws-sam/build/requirements.txt

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements-lambda.txt -t .aws-sam/build/ --upgrade --quiet

# Build with SAM
echo "Building with SAM..."
sam build --use-container

# Deploy
echo "Deploying to AWS..."
sam deploy \
    --stack-name ${STACK_NAME} \
    --region ${REGION} \
    --capabilities CAPABILITY_IAM \
    --parameter-overrides \
        Stage=${STAGE} \
        MongoURL="${MONGO_URL}" \
        DBName="${DB_NAME:-pixzent}" \
        JWTSecretKey="${JWT_SECRET_KEY}" \
        AdminEmail="${ADMIN_EMAIL:-dmb@pixzent.com}" \
        AdminPassword="${ADMIN_PASSWORD}" \
    --no-confirm-changeset \
    --no-fail-on-empty-changeset

# Get the API URL
echo ""
echo "=========================================="
echo "Deployment Complete!"
echo "=========================================="
API_URL=$(aws cloudformation describe-stacks \
    --stack-name ${STACK_NAME} \
    --region ${REGION} \
    --query 'Stacks[0].Outputs[?OutputKey==`ApiUrl`].OutputValue' \
    --output text)

echo "API URL: ${API_URL}"
echo ""
echo "Test your API:"
echo "  curl ${API_URL}/api/health"
echo ""
