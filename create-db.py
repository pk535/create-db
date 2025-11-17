import json
import os
import sys
import boto3
import string
import secrets
import mysql.connector
from time import sleep
from datetime import datetime

environment = sys.argv[1]
namespace = sys.argv[2]
user_service_name = sys.argv[3]
region = sys.argv[4]
db_port = sys.argv[5]
adminDBSecretName = sys.argv[6]
update_db_user = sys.argv[7]

#Set AWS account ids for environments
env_to_account_mapping = {
    "prod": "<aws_account_id>",
    "stage": "<aws_account_id>",
    "qa": "<aws_account_id>",
    "dev": "<aws_account_id>",
    "sbx": "<aws_account_id>", 
}
gitlab_user = os.getenv("GITLAB_USER_EMAIL")
authorized_users = [
    "<authorized_user_email>",
    "<authorized_user_email>",
    "<authorized_user_email>",
    "<authorized_user_email>"
]
#Check if the environment is entered correct and provided
if not environment:
    print(f"\nEnvironment name must be provided.")
    exit()
if environment not in ["dev", "qa"]:
    if environment in ["sbx", "stage", "prod"]:
        if gitlab_user not in authorized_users:
            print(f"Hello, {gitlab_user} !")
            print(f"You are not authorized to run job in the '{environment}' environment.")
            print(f"Please check if the provided Environment name is correct.")
            exit()

try:
    print(f"Hello, {gitlab_user} !")
    print(f"INFO: Executing the script on environment '{environment}'.")
    print(f"INFO: Assuming the role for '{environment}'.")
    #formulate the role ARN
    ROLE_ARN = f"arn:aws:iam::{env_to_account_mapping[environment]}:role/<project>-{environment}-tf-role"
    role_session_name = "AssumedRoleSession"
    #Create boto client for sts to assume the role
    sts_client = boto3.client('sts', region_name=region)
    response = sts_client.assume_role(RoleArn=ROLE_ARN, RoleSessionName=role_session_name)
    #use the session library to store the creds for current session
    session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                        aws_session_token=response['Credentials']['SessionToken'])
except Exception as e:
    print(f"ERROR: An error occurred while assuming the session for environment: {environment}: {e}")
    exit(1)

if 'Credentials' in response:
    print(f"SUCCESS: Assumed the role for environment '{environment}'")
    #Define the characters for the password
    characters = string.ascii_letters + string.digits + string.punctuation
    #Generate a random password with the specified length
    password = ''.join(secrets.choice(characters) for _ in range(12))

    #Check if json file exists 
    try:
        if not os.path.isfile("configs/dbAndSecrets.json"):
            print("ERROR: JSON file not found.")
            exit()
        #Read the JSON file and parse it
        with open("configs/dbAndSecrets.json", "r") as json_file:
            data = json.load(json_file)
        print("SUCCESS: JSON file found. Printing....")
        #Print the JSON file
        print(json.dumps(data, indent=2))
        #Process services
        services = data.get("services", [])
        #Loop through json file to find given service name
        for service in services:
            service_name = service.get("serviceName")
            #Check if the current service matches the user input
            if service_name == user_service_name:
                service_description = service.get("description")
                db_required = service['dbRequired']
                print(f"SUCCESS: Service Found....")
                print(f"Name: {service_name}")
                print(f"Description: {service_description}")
                print(f"DB Required: {db_required}")
                break  #No need to continue searching for services once found     
        else:
            print(f"ERROR: The Service Name {user_service_name} is not found in Json file")
            print(f"INFO: Plese verify the Input or Json file, exiting....!")
            exit()
    except Exception as e:
        print(f"ERROR: error while checking the Json file. {e}")
        exit(1)

    #Retrieve the secret values from AWS Secrets Manager for admin DB secret
    try:
        print(f"INFO: Searching for DB host info....")
        secret_name = adminDBSecretName
        #Create secret manager client
        client = session.client('secretsmanager', region_name=region)
        response = client.get_secret_value(SecretId=secret_name)
        secret_values = json.loads(response['SecretString'])
        #Extract admin username and password
        db_host_admin_user = secret_values.get('username')
        db_host_admin_password = secret_values.get('password')
        print(f"user:{db_host_admin_user}")
        print(f"pass:{db_host_admin_password}")
        #Describe the RDS Aurora cluster and extract the DB endpoint
        cluster_search_name = f"<project>-{environment}-rds-cluster-{region}"
        rds_client = session.client('rds', region_name=region)
        cluster_info = rds_client.describe_db_clusters(DBClusterIdentifier=cluster_search_name)
        db_host_endpoint = cluster_info['DBClusters'][0]['Endpoint']
        print(f"endpoint:{db_host_endpoint}")
        #If RDS host endpoint is not found then exit
        if db_host_endpoint is None:
            print(f"ERROR: DB host info retrieval failed. Exiting....")
            exit(1)
        else:
            print(f"SUCCESS: DB host info retrieved. Proceeding....")
    except Exception as e:
        print(f"ERROR: Error while Searching DB host info: {e}")
    
    # #Check the connection to DB
    # try:
    #     connection = mysql.connector.connect(
    #         host=db_host_endpoint,
    #         user=db_host_admin_user,
    #         password=db_host_admin_password,
    #         port=db_port
    #     )
    #     cursor = connection.cursor()
    #     print(f"MySQL connection: OK")
    #     cursor.close()
    #     connection.close()
    # except mysql.connector.Error as err:
    #     print(f"MySQL connection: FAILED - {db_host_endpoint} - {err}")
    #     exit(1)
    # Try to connect to RDS MySQL instance
    try:
        conn = mysql.connector.connect(
            host=db_host_endpoint,
            user=db_host_admin_user,
            password=db_host_admin_password,
            port=db_port
        )
        if conn.is_connected():
            print("OK: Connection to RDS MySQL instance successful!")
            conn.close()
        else:
            print("FAILED: Connection failed to RDS MySQL instance!")
    except mysql.connector.Error as e:
        print(f"Error: {e}")
        
    #Set naming conventions for services
    SECRET_NAME = f"{environment}-{namespace}-{service_name}"
    NEW_DB_NAME = f"{namespace}-{service_name}-db"
    NEW_USR_NAME = f"{namespace}-{service_name}-usr"
    DB_PASSWORD = password

    if service_name == "governance-service":
        NEW_DB_NAME = f"{namespace}-gov-db"
        NEW_USR_NAME = f"{namespace}-gov-usr"

    if service_name == "account-service":
        NEW_DB_NAME = f"{namespace}-acct-db"
        NEW_USR_NAME = f"{namespace}-acct-usr"

    if db_required == "yes" :
        if update_db_user == "no":  
            print(f"=====================================================================================================")
            print(f"INFO: Starting DB and its credential creation process for {service_name}")
            print(f"INFO: Will also be storing credentials in AWS Secrets Manager for {service_name}")
            print("")
            sleep(1)
            try:
                connection = mysql.connector.connect(
                    host=db_host_endpoint,
                    user=db_host_admin_user,
                    password=db_host_admin_password,
                    port=db_port
                )
                cursor = connection.cursor()

                #Check if the database already exists
                cursor.execute(f"SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '{NEW_DB_NAME}'")
                existing_db = cursor.fetchone()
                #Check if DB already exists
                if existing_db:
                    print(f"WARNING: Database '{NEW_DB_NAME}' already exists for {service_name}. Won't do anything")
                    print(f"INFO: If you want to update user credentials for DB '{NEW_DB_NAME}', run the Job with parameter 'UPDATE_DB_USER' = 'yes'.")
                    print(f"=====================================================================================================")
                else:
                    try:
                        if service_name == "keycloak":
                            cursor.execute(f"CREATE DATABASE `{NEW_DB_NAME}` CHARACTER SET utf8 COLLATE utf8_general_ci;")
                        else:  
                            cursor.execute(f"CREATE DATABASE `{NEW_DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;")

                        cursor.execute(f"GRANT ALL PRIVILEGES ON `{NEW_DB_NAME}`.* TO '{NEW_USR_NAME}'@'%';")
                        cursor.execute(f"ALTER USER '{NEW_USR_NAME}'@'%' IDENTIFIED BY %s;", (DB_PASSWORD,)) #verify password creation according to the criteria for RDS DB.

                        connection.commit()
                        cursor.close()
                        connection.close()

                        print(f"SUCCESS: New database {NEW_DB_NAME} created, and access granted to {NEW_USR_NAME}.")
                    except mysql.connector.Error as err:
                        print(f"ERROR: error while creating the DB {NEW_DB_NAME}, and granting access to {NEW_USR_NAME}. {err}")

                    try:
                        #Attempt to get the secret value
                        response = client.get_secret_value(SecretId=SECRET_NAME)
                        #Parse the secret value as JSON
                        current_secret = json.loads(response['SecretString']) if 'SecretString' in response else {}
                        current_secret["db.name"] = NEW_DB_NAME
                        current_secret["db.user"] = NEW_USR_NAME
                        current_secret["db.password"] = DB_PASSWORD

                        if service_name == "keycloak":
                            DB_URL_KEY = "KC_DB_URL"
                            DB_URL_KEY_VALUE = f"jdbc:mysql://{db_host_endpoint}/{NEW_DB_NAME}?characterEncoding=UTF-8"
                            DB_HOST_KEY = "db.host"
                            DB_HOST_KEY_VALUE = db_host_endpoint
                            DB_PORT_KEY = "db.port"
                            DB_PORT_KEY_VALUE = "3306"
                            
                            current_secret[DB_URL_KEY] = DB_URL_KEY_VALUE
                            current_secret[DB_HOST_KEY] = DB_HOST_KEY_VALUE
                            current_secret[DB_PORT_KEY] = DB_PORT_KEY_VALUE
                        #Update the credentials in AWS secret manager
                        client.update_secret(SecretId=SECRET_NAME, SecretString=json.dumps(current_secret))
                        print(f"SUCCESS: Updated the db credentials in AWS Secrets Manager for {service_name}")
                        print(f"=====================================================================================================")
                    except mysql.connector.Error as err:
                            print(f"ERROR: error while updating the Credentials for DB in AWS Secret manager {SECRET_NAME}. {err}")
            except mysql.connector.Error as err:
                print(f"ERROR: Failed to create DB and credentials. {err}")
        elif update_db_user == "yes":
            print(f"=====================================================================================================")
            #Attempt to get the secret value
            response = client.get_secret_value(SecretId=SECRET_NAME)
            #Parse the secret value as JSON
            current_secret = json.loads(response['SecretString']) if 'SecretString' in response else {}

            #Check if the user already exists
            try:
                connection = mysql.connector.connect(
                    host=db_host_endpoint,
                    user=db_host_admin_user,
                    password=db_host_admin_password,
                    port=db_port
                )
                cursor = connection.cursor(dictionary=True)
                cursor.execute(f"SELECT user FROM mysql.user WHERE user='{NEW_USR_NAME}'")
                existing_user = cursor.fetchone()

                current_secret["db.user"] = NEW_USR_NAME
                current_secret["db.password"] = DB_PASSWORD

                if existing_user and existing_user['user'] == NEW_USR_NAME:
                    print(f"WARNING: User '{NEW_USR_NAME}' already exists for DB {NEW_DB_NAME}, Updating the credentials.")
                    cursor.execute(f"ALTER USER '{NEW_USR_NAME}'@'%' IDENTIFIED BY %s;", (DB_PASSWORD,))
                    print(f"SUCCESS: User '{NEW_USR_NAME}' Updated for DB {NEW_DB_NAME} in environment '{environment}'.")
                    client.update_secret(SecretId=SECRET_NAME, SecretString=json.dumps(current_secret))
                    print(f"SUCCESS: User Credentials for '{NEW_USR_NAME}' stored in '{SECRET_NAME}'in environment '{environment}'.")
                    print(f"=====================================================================================================")
                else:
                    cursor.execute(f"GRANT ALL PRIVILEGES ON `{NEW_DB_NAME}`.* TO '{NEW_USR_NAME}'@'%';")
                    cursor.execute(f"ALTER USER '{NEW_USR_NAME}'@'%' IDENTIFIED BY %s;", (DB_PASSWORD,))
                    cursor.execute("FLUSH PRIVILEGES")
                    connection.commit()
                    print(f"SUCCESS: User '{NEW_USR_NAME}' created for  DB '{NEW_DB_NAME}' in environment '{environment}'.")
                    client.update_secret(SecretId=SECRET_NAME, SecretString=json.dumps(current_secret))
                    print(f"SUCCESS: User Credentials for '{NEW_USR_NAME}' stored in '{SECRET_NAME}'in environment '{environment}'.")
                    print(f"=====================================================================================================")
            except mysql.connector.Error as err:
                print(f"ERROR: An error occured while Creating or Updating the '{NEW_USR_NAME}': {err}")
                print(f"=====================================================================================================")
            finally:
                if 'connection' in locals() and connection.is_connected():
                    cursor.close()
                    connection.close()      
    else:
        print(f"=====================================================================================================")
        print(f"WARNING: DB required '{db_required}' for {service_name}.")
        print(f"Exiting....")
        print(f"=====================================================================================================")
        exit()
