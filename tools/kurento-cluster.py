#!/usr/bin/python
##### IMPORTS #####
import os
import sys
import subprocess
import getopt
import datetime
import time
import json
import ConfigParser
import OpenSSL.crypto as crypto
import ssl
try:
    from Crypto.Util import asn1
except Exception as e:
    print ( "\n====================================\n"
            "\n   Crypto module not installed. Execute as administrator:"
            "\n      pip install Crypto"
            "\n"
            "\n   In order to install pip download from https://bootstrap.pypa.io/get-pip.py"
            "\n   and execute as adminstrator:"
            "\n"
            "\n      python get-pip.py"
            "\n====================================\n")
    sys.exit (1)
try:
    import boto3
except Exception as e:
    print ( "\n====================================\n"
            "\n   AWS SDK not installed. Execute as administrator:"
            "\n      pip install boto3"
            "\n"
            "\n   In order to install pip download from https://bootstrap.pypa.io/get-pip.py"
            "\n   and execute as adminstrator:"
            "\n"
            "\n      python get-pip.py"
            "\n====================================\n")
    sys.exit (1)

##### CONSTANTS #####
KMS_AMI_NAME = 'KMS-CLUSTER-6.1.1.trusty-0.0.1-SNAPSHOT-20151008125117'
TEMPLATE_FILE = "aws" + os.sep + "kurento-cluster-template.json"
AWS_CREDENTIALS_FILE = os.path.expanduser('~') + os.sep + '.aws' + os.sep + 'credentials'
AWS_CONFIG_FILE = os.path.expanduser('~') + os.sep + '.aws' + os.sep + 'config'
AWS_PROFILE = 'profile'
AWS_ACCESS_KEY_ID = 'aws_access_key_id'
AWS_SECRET_ACCESS_KEY = 'aws_secret_access_key'

# Error messages
LINE = "\n====================================\n"
CR = "\n"
I = "     "
I2 = I+I
I3 = I2+ "          "
CMD = "usage: " + os.path.basename(__file__) + " "
CMD_CREATE = "create"
CMD_DELETE = "delete"
CMD_LIST = "list"
CMDS = [ CMD_CREATE, CMD_DELETE, CMD_LIST ]

PARAM_REGION = "region"
PARAM_STACK_NAME = "stack-name"
PARAM_AWS_KEY_NAME = "aws-key-name"
PARAM_SSL_CERT = "ssl-cert"
PARAM_SSL_KEY = "ssl-key"
PARAM_SSL_PASSPHRASE = "ssl-passphrase"
PARAM_HOSTED_ZONE_ID = "hosted-zone-id"
PARAM_KURENTO_API_KEY = "kurento-api-key"

# Usage Messages
USAGE_CLI = CMD + CR
USAGE_CLI_CREATE = CMD + CMD_CREATE + CR
USAGE_CLI_DELETE = CMD + CMD_DELETE + CR
USAGE_CLI_LIST = CMD + CMD_LIST + CR
USAGE_COMMAND_LIST = CR + I + "Commands:" + CR
USAGE_PARAM_LIST = CR + I + "Options:" + CR
USAGE_CREATE_CMD = I2 + CMD_CREATE + "  Create Kurento Cluster." + CR
USAGE_DELETE_CMD = I2 + CMD_DELETE + "  Delete Kurento Cluster." + CR
USAGE_LIST_CMD =   I2 + CMD_LIST + "    List Kurento Clusters." + CR
USAGE_HELP_CMD = CR+I + "See '" + os.path.basename(__file__) + " help COMMAND' for help on a specific command." + CR

USAGE_REGION = (CR+I2+ "--"  + PARAM_REGION + " value"
    +CR+I3+ "[Mandatory] AWS region where cluster can be deployed:"
    +CR+I3+ "  ap-northeast-1   Asia Pacific (Tokyo)"
    +CR+I3+ "  ap-southeast-1   Asia Pacific (Singapore)"
    +CR+I3+ "  ap-southeast-2   Asia Pacific (Sydney)"
    +CR+I3+ "  eu-central-1     EU (Frankfurt)"
    +CR+I3+ "  eu-west-1        EU (Ireland)"
    +CR+I3+ "  sa-east-1        South America (Sao Paulo)"
    +CR+I3+ "  us-east-1        US East (N. Virginia)"
    +CR+I3+ "  us-west-1        US West (N. California)"
    +CR+I3+ "  us-west-2        US West (Oregon)"
    +CR+I3+ "Visit http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html"
    +CR+I3+ "for more information."
    +CR)

USAGE_STACK_NAME = (CR+I2+ "--" + PARAM_STACK_NAME + " value"
    +CR+I3+ "[Mandatory] Name of the KMS cluster. It must start with letter,"
    +CR+I3+ "contain only alphanumeric characters and be unique in selected"
    +CR+I3+ "region. White spaces are not allowed."
    +CR)

USAGE_AWS_KEY_NAME = (CR+I2+ "--" + PARAM_AWS_KEY_NAME + " value"
    +CR+I3+ "[Mandatory] Name of Amazon EC2 key pair to be configured in KMS"
    +CR+I3+ "nodes. More information available in:"
    +CR+I3+ "http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html"
    +CR)

USAGE_SSL = (CR+I2+ "--" + PARAM_SSL_CERT + " path"
    +CR+I3+ "[Optional] Path to the certificate file used for SSL connections."
    +CR+I3+ "Secure port will be blocked and wss protocol disabled if not provided."
    +CR+I3+ "Due to WebSocket limitation, autosigned certificates are not"
    +CR+I3+ "supported by Kurento cluster."
    +CR
    +CR+I2+ "--" + PARAM_SSL_KEY + " path"
    +CR+I3+ "[Optional] Path to the private key associated with SSL certificate. This"
    +CR+I3+ "parameter is mandatory if SSL certificate is provided."
    +CR
    +CR+I2+ "--" + PARAM_SSL_PASSPHRASE + " value"
    +CR+I3+ "[Optional] Private key's encryption passphrase. Do not use this"
    +CR+I3+ "flag unless private key is encrypted. Ignored if no private key is"
    +CR+I3+ "provided."
    +CR)

USAGE_ROUTE53 =(CR+I2+ "--" + PARAM_HOSTED_ZONE_ID + " value"
    +CR+I3+ "[Optional] A CNAME record with the name of the stack is automatically"
    +CR+I3+ "created under the hosted zone subdomain. When provided, SSL certificate "
    +CR+I3+ "domain must match the hosted zone domain."
    +CR)

USAGE_APIKEY = (CR+I2+ "--" + PARAM_KURENTO_API_KEY + " value"
    +CR+I3+ "[Optional] A secret string intended to protect access to control"
    +CR+I3+ "interface.Kurento cluster will accept requests from any client presenting"
    +CR+I3+ "this key. Kurento API key is an alphanumeric non empty string of"
    +CR+I3+ "any length that is concatenated to the cluster URL:"
    +CR
    +CR+I3+ "       ws[s]://host/<kurento-api-key>"
    +CR
    +CR+I3+ "Default value is kurento."
    +CR)

USAGE_ALL = ( USAGE_CLI
            + USAGE_COMMAND_LIST
            + USAGE_CREATE_CMD
            + USAGE_DELETE_CMD
            + USAGE_LIST_CMD
            + USAGE_PARAM_LIST
            + USAGE_REGION
            + USAGE_STACK_NAME
            + USAGE_AWS_KEY_NAME
            + USAGE_SSL
            + USAGE_ROUTE53
            + USAGE_APIKEY
            + USAGE_HELP_CMD)

USAGE_CREATE = ( USAGE_CLI_CREATE
               + USAGE_STACK_NAME
               + USAGE_AWS_KEY_NAME
               + USAGE_SSL
               + USAGE_ROUTE53
               + USAGE_APIKEY)

USAGE_DELETE = ( USAGE_CLI_DELETE
               + USAGE_REGION
               + USAGE_STACK_NAME)

USAGE_LIST = ( USAGE_CLI_LIST
             + USAGE_STACK_NAME)

MISSING_REGION = " Missing mandatory parameter --" + PARAM_REGION
MISSING_STACK_NAME = "Missing mandatory parameter --" + PARAM_STACK_NAME
MISSING_AWS_KEY_NAME = "Missing mandatory parameter --" + PARAM_AWS_KEY_NAME
MISSING_TEMPLATE = "CloudFormation template file not found: " + TEMPLATE_FILE
OPEN_TEMPLATE = "Unable to open CloudFormation template file: " + TEMPLATE_FILE
EMPTY_TEMPLATE = "Empty CloudFormation template body. Verify file exists: " + TEMPLATE_FILE

##### LIBRARY ######
def usage (message, info):
    print LINE
    if not message is "":
        print message
        print ""
    print info
    print LINE
    sys.exit(1)

def log (message):
    print "KURENTO CLUSTER: " + message

def log_error (message):
    print LINE
    print "ERROR: " + message
    print LINE
    sys.exit(1)

class KurentoClusterConfig:
    "Kurento Cluster Configuration"

    kurento_tools_home = os.path.dirname(__file__) + os.sep + ".."

    command = None

    region = None
    stack_name  = None
    desired_capacity = None
    max_capacity = None
    min_capacity = None
    instance_tenancy = None
    instance_type = None
    kurento_api_key = None
    aws_key_name = None
    control_origin = None
    hosted_zone_id = None
    health_check_grace_period = None
    ssl_cert = None
    ssl_cert_chunks = []
    ssl_key= None
    ssl_passphrase = None
    turn_username = None
    turn_password = None
    template_file = kurento_tools_home + os.sep + TEMPLATE_FILE
    template_body = None

    def __init__ (self, argv):
        if len(argv) == 0:
            usage ("", USAGE_ALL)
        elif argv[0] == 'help':
            if len(argv) > 1:
                usage ("", self._get_usage(argv[1]))
            usage ("", USAGE_ALL)
        self._read_command(argv[0])
        try:
            opts, args = getopt.getopt(argv[1:],"h",[
                PARAM_REGION + "=",
                PARAM_STACK_NAME + "=",
                PARAM_AWS_KEY_NAME + "=",
                "desired-capacity=",
                "max-capacity=",
                "min-capacity=",
                "instance-tenancy=",
                "instance-type=",
                "control-origin=",
                "kurento-api-key=",
                PARAM_HOSTED_ZONE_ID + "=",
                "health-check-grace-period=",
                PARAM_SSL_CERT + "=",
                PARAM_SSL_KEY + "=",
                PARAM_SSL_PASSPHRASE + "=",
                "turn-username=",
                "turn-password=",
            ])
            for opt, arg in opts:
                if opt == "-h":
                    usage ("", USAGE_ALL)
                elif opt == "--" + PARAM_REGION:
                    self.region = arg
                elif opt == "--" + PARAM_STACK_NAME:
                    self.stack_name = arg
                elif opt == "--" + PARAM_AWS_KEY_NAME:
                    self.aws_key_name = arg
                elif opt == "--desired-capacity":
                    self.desired_capacity = arg
                elif opt == "--max-capacity":
                    self.max_capacity = arg
                elif opt == "--min-capacity":
                    self.min_capacity = arg
                elif opt == "--instance-tenancy":
                    self.instance_tenancy = arg
                elif opt == "--instance-type":
                    self.instance_type = arg
                elif opt == "--control-origin":
                    self.control_origin = arg
                elif opt == "--kurento-api-key":
                    self.kurento_api_key = arg
                elif opt == "--" + PARAM_HOSTED_ZONE_ID:
                    self.hosted_zone_id = arg
                elif opt == "--health-check-grace-period":
                    self.health_check_grace_period = arg
                elif opt == "--" + PARAM_SSL_CERT:
                    self.ssl_cert = arg
                elif opt == "--" + PARAM_SSL_KEY:
                    self.ssl_key = arg
                elif opt == "--" + PARAM_SSL_PASSPHRASE:
                    self.ssl_passphrase = arg
                elif opt == "--turn-username":
                    self.turn_username = arg
                elif opt == "--turn-password":
                    self.turn_password = arg
                else:
                    usage("Unknown option" + USAGE_ALL)
        except Exception as e:
            usage ("Unable to parse command line options\n\n   " + str(e), USAGE_ALL)

    def _read_command(self, command):
        self._get_usage(command)
        self.command = command

    def _get_usage(self, command):
        try:
            return {
                CMD_CREATE : USAGE_CREATE,
                CMD_DELETE : USAGE_DELETE,
                CMD_LIST : USAGE_LIST
                }[command]
        except Exception as e:
            usage ("Unknown command: " + command , USAGE_ALL)

class AwsSession:
    config  = None
    aws_session = None
    aws_credentials = []

    def __init__ (self, config):
        self.config = config
        self._create_aws_session()

    def _create_aws_session (self):
        self._get_aws_configuration()
        aws_access_key_id, aws_secret_access_key = self._select_aws_credentials ()
        self.aws_session = boto3.Session(aws_access_key_id = aws_access_key_id,
                            aws_secret_access_key = aws_secret_access_key,
                            region_name = self.config.region)

    def _select_aws_credentials (self):
        if len(self.aws_credentials) == 1:
            return self.aws_credentials[0][AWS_ACCESS_KEY_ID], self.aws_credentials[0][AWS_SECRET_ACCESS_KEY]
        while True:
            menu = LINE + "Following AWS credential profiles have been found:\n"
            for i in range (0, len (self.aws_credentials)):
                menu += "   " + str(i+1) + " - " + self.aws_credentials[i][AWS_PROFILE] + "\n"
            menu += "Select credentials profile:"
            profile = int(raw_input(menu))
            if profile >= 1 and profile <= len(self.aws_credentials):
                return self.aws_credentials[profile - 1][AWS_ACCESS_KEY_ID], self.aws_credentials[profile - 1][AWS_SECRET_ACCESS_KEY]
            else:
                print "Invalid selection"

    def _get_aws_configuration (self):
        config_locations = [AWS_CREDENTIALS_FILE, AWS_CONFIG_FILE]
        for location in config_locations:
            if os.path.exists(location):
                aws_config = ConfigParser.RawConfigParser()
                aws_config.read(location)
                self._get_aws_credentials(aws_config)
        if len(self.aws_credentials) == 0:
            aws_config = self._gather_aws_credentials ()
            self._get_aws_credentials(aws_config)

    def _get_aws_credentials (self,aws_config):
        sections =  aws_config.sections() + ['DEFAULT']
        for profile in sections:
            access = None
            secret = None
            if aws_config.has_option(profile, AWS_ACCESS_KEY_ID):
                access = aws_config.get(profile, AWS_ACCESS_KEY_ID)
            if aws_config.has_option(profile, AWS_SECRET_ACCESS_KEY):
                secret = aws_config.get(profile, AWS_SECRET_ACCESS_KEY)
            if not access is None and not secret is None:
                log ("Found AWS profile: " + profile)
                self.aws_credentials.append({
                    AWS_PROFILE : profile,
                    AWS_ACCESS_KEY_ID : access,
                    AWS_SECRET_ACCESS_KEY : secret
                })

    def _gather_aws_credentials(self):
        print (LINE +
              "AWS credentials not configured. Access and secret keys must be \n"
              "provided in order to allow Kurento tools to access AWS APIs.\n"
              "\n"
              "If you're the account administrator execute following procedure:\n"
              "  1 - Navigate to https://console.aws.amazon.com/iam/home?#security_credential\n"
              "  2 - Open section Access Keys (Access Key ID and Secret Access Key)\n"
              "  3 - Press button Create New Access Key\n"
              "\n"
              "If you're not the account adminstrator you still can generate credentials\n"
              "with following procedure\n"
              "  1 - Navigate to https://myaccount.signin.aws.amazon.com/console. Your AWS\n"
              "      adminstrator will provide you the value for myaccount\n"
              "  2 - Login to AWS console with you IAM user and password. Ask your AWS\n"
              "      administrator if you don't have an IAM user\n"
              "  3 - Navigate to IAM home https://console.aws.amazon.com/iam/home#home\n"
              "  4 - Open section 'Rotate your access keys' and click 'Manage User Access Key'\n"
              "  5 - Go to section 'Security Credentials' and click 'Create Access Key'\n"
              + LINE)
        aws_config = ConfigParser.RawConfigParser()
        while True:
            aws_access_key_id = raw_input ("Enter AWS Access Key ID:")
            if not aws_access_key_id is "":
                aws_config.set('DEFAULT', AWS_ACCESS_KEY_ID, aws_access_key_id)
                break
        while True:
            aws_secret_access_key = raw_input ("Enter AWS Secret Access Key:")
            if not aws_secret_access_key is "":
                aws_config.set('DEFAULT', AWS_SECRET_ACCESS_KEY, aws_secret_access_key)
                break
        aws_config.write (open(AWS_CREDENTIALS_FILE, 'w'))
        return aws_config

    def client (self,service):
        return self.aws_session.client(service)

class KurentoCluster:
    "Kurento Cluster"

    config = None
    template = None
    params = []
    session = None

    def __init__ (self, session, config):
        self.config = config
        self.session = session
        self._validate_mandatory_parameters()
        if self.config.command == CMD_CREATE:
            self._validate_mandatory_parameters_stack()
            self._validate_mandatory_parameters_create()
            self._validate_ssl()
            self._build_cloudformation_template()

            # Set parameters
            self._add_param ("KeyName", config.aws_key_name)
            self._add_param ("KurentoLoadBalancerName",(config.stack_name + "KurentoLoadBalancer")[:32])
            self._add_param ("DesiredCapacity",config.desired_capacity)
            self._add_param ("InstanceTenancy",config.instance_tenancy)
            self._add_param ("InstanceType",config.instance_type)
            self._add_param ("ApiKey",config.kurento_api_key)
            self._add_param ("ControlOrigin",config.control_origin)
            self._add_param ("HealthCheckGracePeriod",config.health_check_grace_period)
            self._add_param ("TurnUsername",config.turn_username)
            self._add_param ("TurnPassword",config.turn_password)
            self._add_param ("HostedZoneId",config.hosted_zone_id)
            # Certificate must be split in chunks of 4096 due to AWS limitation
            for i in range (len(self.config.ssl_cert_chunks)):
                self._add_param("SslCertificate" + str(i+1), self.config.ssl_cert_chunks[i] )
                self._add_param("SslKey", self.config.ssl_key)
        elif self.config.command == CMD_DELETE:
            self._validate_mandatory_parameters_stack()

    def _validate_mandatory_parameters (self):
        if self.config.region is None:
            usage (MISSING_REGION, USAGE_REGION )

    def _validate_mandatory_parameters_stack (self):
        if self.config.stack_name is None:
            usage (MISSING_STACK_NAME, USAGE_STACK_NAME)

    def _validate_mandatory_parameters_create (self):
        if self.config.aws_key_name is None:
            usage(MISSING_AWS_KEY_NAME, USAGE_AWS_KEY_NAME)
        if os.path.exists(self.config.template_file):
            try:
                self.config.template_body = open(self.config.template_file).read()
            except Exception as e:
                log_error (OPEN_TEMPLATE + "\n\n   " + str(e))
        else:
            log_error (MISSING_TEMPLATE)
        if self.config.template_body is None:
            log_error (EMPTY_TEMPLATE)

    def _validate_ssl (self):
        # SSL verifications
        if  not self.config.ssl_cert is None and self.config.ssl_key is None:
            usage ("Private Key must be provided with SSL certificate", USAGE_SSL)
        if not self.config.ssl_cert is None:
            cert = None
            priv = None
            pub = None

            # Verify PEM file exists for CERT
            if os.path.exists(self.config.ssl_cert):
                cert_str = open(self.config.ssl_cert).read()
                config.ssl_cert_chunks = [cert_str[i:i+4096] for i in range(0, len(cert_str), 4096)]
                cert = crypto.load_certificate (crypto.FILETYPE_PEM, cert_str)
                pub = cert.get_pubkey()
            else:
                usage ("SSL certificate not found or unable to open: " + self.config.ssl_cert, USAGE_SSL)

            # Verify PEM file exists for KEY
            if os.path.exists(self.config.ssl_key):
                priv_str = open(self.config.ssl_key).read()
                priv = crypto.load_privatekey(crypto.FILETYPE_PEM, priv_str)
            else:
                usage ("SSL private key not found or unable to open: " + self.config.ssl_key, USAGE_SSL)

            # Verify KEY matches CERT
            pub_asn1 = crypto.dump_privatekey(crypto.FILETYPE_ASN1, pub)
            priv_asn1 = crypto.dump_privatekey(crypto.FILETYPE_ASN1, priv)

            pub_der = asn1.DerSequence()
            pub_der.decode(pub_asn1)
            priv_der = asn1.DerSequence()
            priv_der.decode(priv_asn1)

            pub_modulus=pub_der[1]
            priv_modulus=priv_der[1]

            if pub_modulus != priv_modulus:
                usage(("SSL key and certificate do not match:\n "
                       "\n   CERT: " + self.config.ssl_cert +
                       "\n   KEY : " + self.config.ssl_key), USAGE_SSL)

            # Verify CERT chain
            try:
                store = crypto.X509Store()
                store_ctx = crypto.X509StoreContext(store, cert)
                store_ctx.verify_certificate()
            except Exception as e:
                log_error("Self signed certificate not supported.\n\n   " + str(e))

        if not self.config.hosted_zone_id  is None:
            aws_route53 = self.session.client('route53')
            try:
                hosted_zone = aws_route53.get_hosted_zone ( Id = self.config.hosted_zone_id )
            except Exception as e:
                log_error("Unable to get AWS hosted zone info\n\n   " + str(e))
            fqdn = hosted_zone['HostedZone']['Name'].rstrip('.')

            #TODO  Verify this alternative :  ssl.match_hostname(cert,fqdn)

            cn = ""
            for cmp, val in cert.get_subject().get_components():
                if cmp == 'CN':
                    cn = val
                    if not fqdn in val:
                        usage("SSL certificate name does not match hosted zone FQDN\n"
                              "\n  SSL common name   : " + cn +
                              "\n  Hosted zone domain: " + fqdn, USAGE_ROUTE53)

    def _build_cloudformation_template (self):
        log ("Build CloudFormation template")
        try:
            self.template = json.loads(self.config.template_body)
        except Exception as e:
            log_error ("Malformed CloudFormation template\n\n   " + str(e) )

        # Get image ID of base AMI
        log ("Get Kurento Media Server AMI for region: " + self.config.region)
        try:
            aws_ec2 = self.session.client('ec2')
            kmscluster_images = aws_ec2.describe_images(
                Filters = [
                    {
                        'Name' : 'name',
                        'Values' : [ KMS_AMI_NAME ]
                    }
                    ]
            )
            # Map AMI
            if len(kmscluster_images['Images']) > 0:
                mappings = {
                    'RegionMap' : {
                        self.config.region : {
                            'KmsImageId' : kmscluster_images['Images'][0]['ImageId']
                        }
                    }
                }
                self.template['Mappings'] = mappings
            else:
                log_error ("Unable to find AMI: " + KMS_AMI_NAME + " in region: " + self.config.region)
        except Exception as e:
            log_error("Failure searching KMS AMI: " + KMS_AMI_NAME + " in region:" + self.config.region + "\n\n   " + str(e))

    def _add_param (self, paramger_key, parameter_value):
        if not parameter_value is None:
            self.params.append ({
                "ParameterKey" : paramger_key,
                "ParameterValue" : parameter_value
            })

    def _wait_cf_cmd (self, wait_state, end_state, message):
        sys.stdout.write(message)
        sys.stdout.flush()
        while True:
            try:
                request = self.aws_cf.describe_stacks ( StackName = self.config.stack_name )
            except Exception as e:
                log_error("Unable to retrieve info for stack: " + self.config.stack_name)
            if len (request['Stacks']) == 1:
                status = request['Stacks'][0]
                if status['StackStatus'] in wait_state:
                    sys.stdout.write('.')
                    sys.stdout.flush()
                elif status['StackStatus'] in end_state:
                    sys.stdout.write('[OK]\n')
                    sys.stdout.flush()
                    break
                else:
                    log_error ("Unsupported AWS status:\n\n   " + status['StackStatus'])
            elif len (request['Stacks']) == 0:
                log_error("AWS reports unknown stack: " + self.config.stack_name )
            else:
                log_error("AWS reports to many stacks:\n\n " + resquest)
            time.sleep(5)

    def _wait_cf_delete (self):
        sys.stdout.write('Deleting stack')
        sys.stdout.flush()
        while True:
            try:
                request = self.aws_cf.describe_stacks ( StackName = self.config.stack_name )
            except Exception as e:
                if 'exist' in str(e):
                    sys.stdout.write('[OK]\n')
                    sys.stdout.flush()
                    break
                else:
                    log_error("Unable to retrieve info for stack: " + self.config.stack_name +
                        " due to:\n\n   " + str(e))
            if len (request['Stacks']) == 1:
                status = request['Stacks'][0]
                if status['StackStatus'] in 'DELETE_IN_PROGRESS':
                    sys.stdout.write('.')
                    sys.stdout.flush()
                elif status['StackStatus'] in 'DELETE_COMPLETE':
                    sys.stdout.write('[OK]\n')
                    sys.stdout.flush()
                    break
                else:
                    log_error ("Unsupported AWS status:\n\n   " + status['StackStatus'])
            elif len (request['Stacks']) == 0:
                log_error("AWS reports unknown stack: " + self.config.stack_name )
            else:
                log_error("AWS reports to many stacks:\n\n " + resquest)
            time.sleep(5)

    def _create (self):
        # Build CloudFormation stack
        log ("Start CloudFormation stack: " + self.config.stack_name )
        try:
            self.aws_cf.create_stack(
                StackName = self.config.stack_name,
                TemplateBody = json.dumps(self.template),
                Capabilities = [
                    'CAPABILITY_IAM',
                ],
                Parameters = self.params
            )
        except Exception as e:
            log_error("CloudFormation did not complete creation of stack: " + self.config.stack_name +
                " due to:\n\n   " + str(e))

        self._wait_cf_cmd('CREATE_IN_PROGRESS', 'CREATE_COMPLETE', 'Creating stack')

        # TODO: Add CNAME in case Hosted zone is provided

    def _delete(self):
        log ("Delete CloudFormation stack: " + self.config.stack_name )
        try:
            # Do not delete any stack not being Kurento Cluster
            request = self.aws_cf.get_template(StackName = self.config.stack_name)
            if not 'KurentoCluster' in request['TemplateBody']['Parameters']:
                log_error("Not a Kurento Cluster: " + self.config.stack_name)
            self.aws_cf.delete_stack(StackName = self.config.stack_name)
        except Exception as e:
            log_error("CloudFormation did not complete deletion of stack: " + self.config.stack_name +
                " due to:\n\n   " + str(e))

        self._wait_cf_delete()

    def _list (self):
        print LINE + "List Kurento Cluster stacks:"
        try:
            for stack in self.aws_cf.list_stacks()['StackSummaries']:
                if self.config.region in stack['StackId'] and stack['StackStatus'] != 'DELETE_COMPLETE':
                    request = self.aws_cf.get_template(StackName = stack['StackName'])
                    if 'KurentoCluster' in request['TemplateBody']['Parameters']:
                        print I + "Name: " + stack['StackName'] + ", Status: " + stack['StackStatus']
            print LINE
        except Exception as e:
            log_error("Unable to retrieve list of clusters due to:\n\n   " + str(e))

    def execute (self):
        self.aws_cf = self.session.client('cloudformation')
        if self.config.command == CMD_CREATE:
            self._create()
        elif self.config.command == CMD_DELETE:
            self._delete()
        elif self.config.command == CMD_LIST:
            self._list()
        else:
            usage ("Unknown command: " + self.config.command, USAGE_ALL)

##### MAIN #####

# Parse command line arguments
config = KurentoClusterConfig(sys.argv[1:])
session = AwsSession(config)

# Execute cluster command
cluster = KurentoCluster(session, config)
cluster.execute()

# TODO: Cloudwatch log collection
# TODO: Autoscaling
