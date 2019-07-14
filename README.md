# AWS Services Last Accessed Analysis
This solution uses [AWS's Access Advisor's API](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_access-advisor.html) to produce a report showing which services an AWS security principal (User, Group, Role) has accessed.  The resulting data is then transformed and delivered to the [Azure Monitor's HTTP Data Collector API](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/data-collector-api).  

## What problem does this solve?
An effective way to mitigate risk is abide by least privilege and limit a human or non-human to only the permissions required.  These required permissions may change over time and new permissions may be required.  Often old permissions are not removed resulting in access creep.  Additionally, when starting to the journey to the cloud, organizations often provide overly permissive permissions because roles and responsibilities are not yet clear.

AWS's Access Advisor API enables organizations to report on what AWS services a security principal has used when when the service was last used.  This information can be analyzed to identify permissions to services that may no longer be required.  Azure Monitor provides a powerful and simple to use tool to both take in the data and analyze it.

## Requirements

### Python Runtime and Modules
* [Python 3.6](https://www.python.org/downloads/release/python-360/)
* [AWS Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html?id=docs_gateway)
** Boto3 - 1.9.188
** Bootcore - 1.12.188

### AWS Permissions Requirement
* IAM:ListUsers
* IAM:ListGroups
* IAM:ListRoles
* IAM:GenerateServiceLastAccessedDetails
* IAM:GetServiceLastAccessedDetails

## Setup
Ensure the appropriate version of Boto3 and Botocore are installed. A sample parameters file is provided with the repository.

python service_last_accessed.py --parameterfile parameters.json [--logfile]

