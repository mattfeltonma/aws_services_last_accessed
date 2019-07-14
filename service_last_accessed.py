import boto3
import json
import time
import logging
import sys
import os
import hmac
import base64
import hashlib
import requests

from argparse import ArgumentParser
from datetime import datetime

# Reusable function to create a logging mechanism
def create_logger(logfile=None):
        
    # Create a logging handler that will write to stdout and optionally to a log file
    stdout_handler = logging.StreamHandler(sys.stdout)
    try:
        if logfile != None:
            file_handler = logging.FileHandler(filename=logfile)
            handlers = [file_handler, stdout_handler]
        else:
            handlers = [stdout_handler]
    except Exception as e:
        handlers = [stdout_handler]
        print("Log file could not be created. Error: {}".format(e))

    # Configure logging mechanism
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers = handlers
    )
    
# Convert timestamp to one more compatible with Azure Monitor
def transform_datetime(awsdatetime):
    transf_time = awsdatetime.strftime("%Y-%m-%dT%H:%M:%S")
    return transf_time

# Query for a list of IAM user, group, and roles
def query_aws_principal():
    
    # Initialize an empty list to store security principals
    aws_security_principals = []
    
    # Query for Users, Roles, and Groups with pagination
    client = boto3.client('iam')
    paginator = client.get_paginator('list_users')
    response_iterator = paginator.paginate()
    for page in response_iterator:
        for user in page['Users']:
            aws_security_principals.append(user['Arn'])

    paginator = client.get_paginator('list_roles')
    response_iterator = paginator.paginate()
    for page in response_iterator:
        for role in page['Roles']:
            aws_security_principals.append(role['Arn'])
        
    paginator = client.get_paginator('list_groups')
    response_iterator = paginator.paginate()
    for page in response_iterator:
        for group in page['Groups']:
            aws_security_principals.append(group['Arn'])
    
    return aws_security_principals

# Generate and process last accessed report
def query_last_accessed(principal):

    try:    
        principal_services_accessed = []
        logging.info('Processing ' + principal + '...')
            
        # Generate last accessed report for principal
        client = boto3.client('iam')
        response = client.generate_service_last_accessed_details(
            Arn = principal
        )
        job_id = response['JobId']
    
        # Retrieve the report and loop until it's complete
        status = None
        while status != 'COMPLETED':
            response = client.get_service_last_accessed_details(
                JobId = job_id
            )
            status = response['JobStatus']
            if status == 'COMPLETED':
                logging.info('Report successfull generated for ' + principal)
            else:
                time.sleep(5)
            
        services_last_accessed = response['ServicesLastAccessed']
        for service in services_last_accessed:
            service['Principal'] = principal
            if 'LastAuthenticated' in service:
                service['LastAuthenticated'] = transform_datetime(service['LastAuthenticated'])
            principal_services_accessed.append(service)
        
        # Handle paged results
        while 'Marker' in response:
            logging.info('Services Last Accessed results are paged.  Getting paged results...')
            response = client.get_service_last_accessed_details(
                JobId = job_id,
                Marker = response['Marker']
            )
            services_last_accessed = response['ServicesLastAccessed']
            for service in services_last_accessed:
                service['Principal'] = principal
                if 'LastAuthenticated' in service:
                    service['LastAuthenticated'] = transform_datetime(service['LastAuthenticated'])
                principal_services_accessed.append(service)
            time.sleep(5)
        
        return principal_services_accessed
    except:
        logging.error('Unable to retrieve record for ' + principal + 'Error: ',exc_info=True)

# Function which builts signature to sign requests to Azure Monitor API
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization

# Function which posts data to Azure Monitor API  
def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        logging.info("Accepted")
    else:
        logging.error("Data was not posted to API.  Response code: {}".format(response.status_code))

# Function to export logs
def main():

    # Initialize empty list
    principals = []
    
    # Create logging mechanism
    create_logger()
    
    try:
        
        # Initialize variables
        services_accessed_records = []
        
        # Process arguments
        parser = ArgumentParser()
        parser.add_argument('--parameterfile', type=str, help='JSON file with parameters')
        parser.add_argument('--logfile', type=str, default=None, help='Specify an optional log file')
        args = parser.parse_args()

        with open(args.parameterfile) as json_data:
            config = json.load(json_data)
        
        # Set the maximum size of the log to 20MB because Azure Monitor API has 30MB limit per request
        maxLogSize = 20000000
        
        # Query for list of IAM User, Role, and Group principals and return ARN
        principals = query_aws_principal()
        
        # Create a report for principal and process the data
        for principal in principals:
            principal_access = query_last_accessed(principal=principal)
            if (sys.getsizeof(services_accessed_records) + sys.getsizeof(principal_access)) > maxLogSize:
                json_data = json.dumps(services_accessed_records)
                print(json_data)
                post_data(
                    customer_id = config['WorkspaceId'],
                    shared_key = config['WorkspaceKey'],
                    body = json_data,
                    log_type = config['LogName']
                )
                services_accessed_records = []
            else:
                services_accessed_records.extend(principal_access)
        json_data = json.dumps(services_accessed_records)
        post_data(
            customer_id = config['WorkspaceId'],
            shared_key = config['WorkspaceKey'],
            body = json_data,
            log_type = config['LogName']
        )
        print(json_data)
            
    except Exception as e:
        logging.error('Execution error',exc_info=True)    


if __name__ == "__main__":

    main()
    
