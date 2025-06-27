#!/bin/bash

# Batch create AWS security checks to expand CSPM coverage

# Create new service directories
mkdir -p /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/sqs
mkdir -p /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/elasticache
mkdir -p /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/ecs
mkdir -p /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/eks
mkdir -p /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/efs
mkdir -p /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/elb
mkdir -p /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/route53
mkdir -p /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/config
mkdir -p /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/cloudformation
mkdir -p /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/guardduty
mkdir -p /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/securityhub
mkdir -p /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/apigateway
mkdir -p /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/cloudwatch
mkdir -p /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/redshift
mkdir -p /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/workspaces

# Create __init__.py files
touch /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/sqs/__init__.py
touch /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/elasticache/__init__.py
touch /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/ecs/__init__.py
touch /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/eks/__init__.py
touch /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/efs/__init__.py
touch /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/elb/__init__.py
touch /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/route53/__init__.py
touch /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/config/__init__.py
touch /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/cloudformation/__init__.py
touch /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/guardduty/__init__.py
touch /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/securityhub/__init__.py
touch /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/apigateway/__init__.py
touch /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/cloudwatch/__init__.py
touch /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/redshift/__init__.py
touch /Users/fab/GitHub/wildbox/open-security-cspm/app/checks/aws/workspaces/__init__.py

echo "Created AWS service directories and __init__.py files"
