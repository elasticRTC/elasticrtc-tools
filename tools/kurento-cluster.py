#!/usr/bin/python
##### IMPORTS #####
import os
import sys
if sys.version_info[0] > 2:
    print (  "\n====================================\n"
            +"\n   Python version not supported : " + str(sys.version_info[0]) + "." + str(sys.version_info[1]) + "\n"
            +"\n====================================\n")
    sys.exit(1)
def require (module, description):
    print ( "\n====================================\n"
            "\n   "+ description +" not installed. Execute as administrator:"
            "\n      pip install " + module +
            "\n"
            "\n   In order to install pip download from https://bootstrap.pypa.io/get-pip.py"
            "\n   and execute as adminstrator:"
            "\n"
            "\n      python get-pip.py"
            "\n====================================\n")
    sys.exit (1)

import subprocess
import getopt
import datetime
import time
import json
import pprint
import ConfigParser
try:
    import OpenSSL.crypto as crypto
except Exception as e:
    require ('Open SSL', 'OpenSSL')
import ssl
import re

try:
    from Crypto.Util import asn1
except Exception as e:
    require ('Crypto module', 'Crypto')
try:
    import boto3
except Exception as e:
    require ('AWS SDK', 'boto3')
try:
    import dns.resolver
except Exception as e:
    require ('DNS module', 'dnspython')

##### CONSTANTS #####
#KMS_AMI_NAME = 'KMS-CLUSTER-6.1.1.trusty-0.0.1-SNAPSHOT-20151115110730'
KMS_AMI_DESCRIPTION = 'kurento-cluster-kms-6'
TEMPLATE_FILE = "aws" + os.sep + "kurento-cluster-template.json"
AWS_CONFIG_DIR = os.path.expanduser('~') + os.sep + '.aws'
AWS_CREDENTIALS_FILE = AWS_CONFIG_DIR + os.sep + 'credentials'
AWS_CONFIG_FILE = AWS_CONFIG_DIR + os.sep + 'config'
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
CMD_SHOW = "show"
CMDS = [ CMD_CREATE, CMD_DELETE, CMD_LIST, CMD_SHOW ]

PARAM_AWS_KEY_NAME = "aws-key-name"
PARAM_DESIRED_CAPACITY = "desired-capacity"
PARAM_HOSTED_ZONE_ID = "hosted-zone-id"
PARAM_KURENTO_API_KEY = "kurento-api-key"
PARAM_REGION = "region"
PARAM_SSL_CERT = "ssl-cert"
PARAM_SSL_KEY = "ssl-key"
PARAM_SSL_PASSPHRASE = "ssl-passphrase"
PARAM_STACK_NAME = "stack-name"

# Usage Messages
USAGE_CLI = CMD + CR
USAGE_CLI_CREATE = CMD + CMD_CREATE + CR
USAGE_CLI_DELETE = CMD + CMD_DELETE + CR
USAGE_CLI_LIST = CMD + CMD_LIST + CR
USAGE_CLI_SHOW = CMD + CMD_SHOW + CR
USAGE_COMMAND_LIST = CR + I + "Commands:" + CR
USAGE_PARAM_LIST = CR + I + "Options:" + CR
USAGE_CREATE_CMD = I2 + CMD_CREATE + "  Create Kurento Cluster." + CR
USAGE_DELETE_CMD = I2 + CMD_DELETE + "  Delete Kurento Cluster." + CR
USAGE_LIST_CMD =   I2 + CMD_LIST + "    List Kurento Clusters." + CR
USAGE_SHOW_CMD =   I2 + CMD_SHOW + "    Show Kurento Cluster details." + CR
USAGE_HELP_CMD = CR+I2 + "See '" + os.path.basename(__file__) + " help COMMAND' for help on a specific command." + CR

USAGE_DESIRED_CAPACITY = (CR+I2 + "--" + PARAM_DESIRED_CAPACITY + " num"
    +CR+I3+ "[Optional] Number of KMS instances to be deployed by Kurento"
    +CR+I3+ "Cluster. AWS will take care to terminate failed instances in order"
    +CR+I3+ "to maintain desired cluster capacity"
    +CR+I3+ "Visit http://docs.aws.amazon.com/AutoScaling/latest/DeveloperGuide/as-manual-scaling.html"
    +CR+I3+ "for more information on autoscaling"
    +CR)

USAGE_REGION = (CR+I2+ "--"  + PARAM_REGION + " value"
    +CR+I3+ "[Mandatory] AWS region where cluster is deployed. Can be any of:"
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
    +CR+I3+ "[Mandatory] Cluster name. It must start with letter, contain only"
    +CR+I3+ "alphanumeric characters and be unique in selected region. White"
    +CR+I3+ "spaces are not allowed."
    +CR)

USAGE_AWS_KEY_NAME = (CR+I2+ "--" + PARAM_AWS_KEY_NAME + " value"
    +CR+I3+ "[Mandatory] Name of Amazon EC2 key pair to be configured in nodes."
    +CR+I3+ "More information available in:"
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
    +CR+I3+ "created for the hosted zone subdomain. If a SSL certificate is"
    +CR+I3+ "provided its common name (CN) must match the hosted zone domain."
    +CR)

USAGE_APIKEY = (CR+I2+ "--" + PARAM_KURENTO_API_KEY + " value"
    +CR+I3+ "[Optional] A secret string intended to control access to cluster"
    +CR+I3+ "API. Kurento cluster will accept requests from any client presenting"
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
            + USAGE_SHOW_CMD
            + USAGE_HELP_CMD
            + USAGE_PARAM_LIST
            + USAGE_REGION
            + USAGE_STACK_NAME
            + USAGE_AWS_KEY_NAME
            + USAGE_DESIRED_CAPACITY
            + USAGE_SSL
            + USAGE_ROUTE53
            + USAGE_APIKEY
            )

USAGE_CREATE = ( USAGE_CLI_CREATE
               + USAGE_REGION
               + USAGE_STACK_NAME
               + USAGE_AWS_KEY_NAME
               + USAGE_DESIRED_CAPACITY
               + USAGE_SSL
               + USAGE_ROUTE53
               + USAGE_APIKEY)

USAGE_DELETE = ( USAGE_CLI_DELETE
               + USAGE_REGION
               + USAGE_STACK_NAME)

USAGE_LIST = ( USAGE_CLI_LIST
             + USAGE_REGION)

USAGE_SHOW = ( USAGE_CLI_SHOW
             + USAGE_REGION
             + USAGE_STACK_NAME )

MISSING_REGION = " Missing mandatory parameter --" + PARAM_REGION
MISSING_STACK_NAME = "Missing mandatory parameter --" + PARAM_STACK_NAME
MISSING_AWS_KEY_NAME = "Missing mandatory parameter --" + PARAM_AWS_KEY_NAME
MISSING_TEMPLATE = "CloudFormation template file not found: " + TEMPLATE_FILE
OPEN_TEMPLATE = "Unable to open CloudFormation template file: " + TEMPLATE_FILE
EMPTY_TEMPLATE = "Empty CloudFormation template body. Verify file exists: " + TEMPLATE_FILE

##### LIBRARY ######
def usage (message, info):
    print (LINE)
    if not message is "":
        print (message) + CR
    print (info)
    print (LINE)
    sys.exit(1)

def log (message):
    print ("KURENTO CLUSTER: " + message)

def log_warn (message):
    print ("WARN: " + message)

def log_error (message):
    print (LINE)
    print ("ERROR: " + message)
    print (LINE)
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
    hosted_zone_fqdn = None
    cluster_fqdn = None
    health_check_grace_period = None
    ssl_cert = None
    ssl_cert_chunks = []
    ssl_key= None
    ssl_passphrase = None
    ssl_common_name = None
    ssl_fqdn = None
    ssl_wildcard = None
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
                PARAM_DESIRED_CAPACITY + "=",
                "max-capacity=",
                "min-capacity=",
                "instance-tenancy=",
                "instance-type=",
                "control-origin=",
                PARAM_KURENTO_API_KEY + "=",
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
                elif opt == "--" + PARAM_DESIRED_CAPACITY:
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
                elif opt == "--" + PARAM_KURENTO_API_KEY:
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
                CMD_LIST : USAGE_LIST,
                CMD_SHOW : USAGE_SHOW
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
                print ("Invalid selection")

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
        if not os.path.exists(AWS_CONFIG_DIR):
            os.makedirs(AWS_CONFIG_DIR)
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
    pp = pprint.PrettyPrinter(indent=4)


    def __init__ (self, session, config):
        # Record basic config
        self.config = config
        self.session = session
        # Create AWS clients
        self.aws_cf = self.session.client('cloudformation')
        self.aws_autosc = self.session.client('autoscaling')
        self.aws_ec2 = self.session.client('ec2')
        self.aws_route53 = self.session.client('route53')
        # Validate configuration
        self._validate_mandatory_parameters()
        if self.config.command == CMD_CREATE:
            self._validate_mandatory_parameters_stack ()
            self._validate_mandatory_parameters_create ()
            self._validate_route53 ()
            self._validate_ssl ()
            self._validate_dns ()
            self._build_cloudformation_template ()

            # Set parameters
            self._add_param ("KeyName", self.config.aws_key_name)
            self._add_param ("KurentoLoadBalancerName",(self.config.stack_name + "KurentoLoadBalancer")[:32])
            self._add_param ("DesiredCapacity",self.config.desired_capacity)
            self._add_param ("InstanceTenancy",self.config.instance_tenancy)
            self._add_param ("InstanceType",self.config.instance_type)
            self._add_param ("ApiKey",self.config.kurento_api_key)
            self._add_param ("ControlOrigin",self.config.control_origin)
            self._add_param ("HealthCheckGracePeriod",self.config.health_check_grace_period)
            self._add_param ("TurnUsername",self.config.turn_username)
            self._add_param ("TurnPassword",self.config.turn_password)
            self._add_param ("HostedZoneId",self.config.hosted_zone_id)
            self._add_param ("DnsName", self.config.cluster_fqdn)
            # Certificate must be split in chunks of 4096 due to AWS limitation
            for i in range (len(self.config.ssl_cert_chunks)):
                self._add_param("SslCertificate" + str(i+1), self.config.ssl_cert_chunks[i] )
                self._add_param("SslKey", self.config.ssl_key_chunk)
                self._add_param("SslKeyPassphrase", self.config.ssl_passphrase)
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

    def _validate_route53 (self):
        if not self.config.hosted_zone_id  is None:
            try:
                hosted_zone = self.aws_route53.get_hosted_zone ( Id = self.config.hosted_zone_id )
            except Exception as e:
                log_error("Unable to get AWS hosted zone info\n\n   " + str(e))
            self.config.hosted_zone_fqdn = hosted_zone['HostedZone']['Name'].rstrip('.')

    def _validate_ssl (self):
        # SSL verifications
        if  not self.config.ssl_cert is None and self.config.ssl_key is None:
            usage ("Private Key must be provided with SSL certificate", USAGE_SSL)
        if self.config.ssl_cert is None:
            # Nothing to validate
            return

        cert = None
        priv = None
        pub = None

        # Verify PEM file exists for CERT
        if os.path.exists(self.config.ssl_cert):
            cert_str = open(self.config.ssl_cert).read()
            self.config.ssl_cert_chunks = [cert_str[i:i+4096] for i in range(0, len(cert_str), 4096)]
            cert = crypto.load_certificate (crypto.FILETYPE_PEM, cert_str)
            pub = cert.get_pubkey()
        else:
            usage ("SSL certificate not found or unable to open: " + self.config.ssl_cert, USAGE_SSL)

        # Verify PEM file exists for KEY
        if os.path.exists(self.config.ssl_key):
            priv_str = open(self.config.ssl_key).read()
            self.config.ssl_key_chunk=priv_str
            if self.config.ssl_passphrase is None:
                priv = crypto.load_privatekey(crypto.FILETYPE_PEM, priv_str)
            else:
                priv = crypto.load_privatekey(crypto.FILETYPE_PEM, priv_str, self.config.ssl_passphrase)
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
            if 'X509Store' in dir(crypto):
                store = crypto.X509Store()
                store_ctx = crypto.X509StoreContext(store, cert)
                store_ctx.verify_certificate()
            else:
                log_warn("Unable to validate certificate chain. Requires python >= 2.7.10")
        except Exception as e:
            log_warn("Detected self signed certificate. Make sure Websocket client will accept cluster crendentials")

        # Record SSL cert Common Name
        for cmp, val in cert.get_subject().get_components():
            if cmp == 'CN':
                self.config.ssl_common_name = val
                self.config.ssl_fqdn = val.lstrip('*').lstrip('.')
                # Check if certificate is wildcard
                if val.startswith('*.'):
                    self.config.ssl_wildcard = True
                    log ("Found wildcard certificate with CN: " + self.config.ssl_common_name)
                else:
                    self.config.ssl_wildcard = False
                    log ("Found certificate with CN: " + self.config.ssl_common_name)
                break

        # Validate Certificate matches hosted zone, if provided
        if not self.config.hosted_zone_fqdn is None:
            if ((self.config.ssl_wildcard == True and self.config.hosted_zone_fqdn != self.config.ssl_fqdn) or
                    (self.config.hosted_zone_fqdn != re.sub('^.+?\.','',self.config.ssl_fqdn))):
                usage("SSL certificate name does not match hosted zone FQDN\n"
                  "\n  SSL common name   : " + self.config.ssl_common_name +
                  "\n  Hosted zone domain: " + self.config.hosted_zone_fqdn, USAGE_ROUTE53)

    def _validate_dns (self):
        if self.config.ssl_wildcard == False:
            self.config.cluster_fqdn = self.config.ssl_fqdn
        elif not self.config.hosted_zone_fqdn is None:
            self.config.cluster_fqdn = self.config.stack_name + "." + self.config.hosted_zone_fqdn
        elif not self.config.ssl_fqdn is None:
             self.config.cluster_fqdn = self.config.stack_name + "." + self.config.ssl_fqdn

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
                #        'Name' : 'name',
                #        'Values' : [ KMS_AMI_NAME ]
                        'Name' : 'description',
                        'Values' : [ KMS_AMI_DESCRIPTION ]
                    }
                ]
            )
            # Map AMI
            #self.pp.pprint (kmscluster_images)
            latest_ts = 0
            image_id = None
            for image in kmscluster_images['Images']:
                creation_ts = int(datetime.datetime.strptime(re.sub('\..*?$','',image['CreationDate']),"%Y-%m-%dT%H:%M:%S").strftime("%s"))
                #log ("creation_ts:" + str(creation_ts) + ", latest_ts: " + str(latest_ts))
                if latest_ts < creation_ts:
                    image_id = image['ImageId']
                    #log ("image_id: " + image_id)

            if not image_id is None:
                mappings = {
                    'RegionMap' : {
                        self.config.region : {
                            'KmsImageId' : image_id
                        }
                    }
                }
                self.template['Mappings'] = mappings
            else:
                log_error ("Kurento Cluster not supported in region: " + self.config.region)
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
                if 'exist' in str(e):
                    # This is very specific for command delete
                    request['Stacks'][0]['StackStatus'] = end_state
                else:
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
        self._wait_cf_cmd('CREATE_IN_PROGRESS', 'CREATE_COMPLETE', 'Creating cluster')
        # Wait for DNS name to be AvailabilityZoneresolver = dns.resolver.Resolver()
        if not self.config.hosted_zone_fqdn is None:
            resolver = dns.resolver.Resolver()
            while True:
                dns_info = resolver.query(self.config.cluster_fqdn, 'CNAME')
                if len (dns_info) > 0 :
                    break
                time.sleep (5)

        # Print stack details
        self._show()

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

        self._wait_cf_cmd('DELETE_IN_PROGRESS', 'DELETE_COMPLETE', 'Deleting cluster')

    def _list (self):
        print (LINE + "List Kurento Cluster stacks:")
        try:
            for stack in self.aws_cf.list_stacks()['StackSummaries']:
                if self.config.region in stack['StackId'] and stack['StackStatus'] != 'DELETE_COMPLETE':
                    request = self.aws_cf.get_template(StackName = stack['StackName'])
                    if 'KurentoCluster' in request['TemplateBody']['Parameters']:
                        print (I + "Name: " + stack['StackName'] + ", Status: " + stack['StackStatus'])
            print (LINE)
        except Exception as e:
            log_error("Unable to retrieve list of clusters due to:\n\n   " + str(e))

    def _show (self):
        cluster={}
        try:
            # Get cluster info
            stack = self._describe_stack()
            cluster['url'] = stack['url']
            cluster['group'] = self._describe_auto_scaling_group()
            # print cluster INFO
            #pp.pprint (stack)
            print (LINE)
            print ("Kurento Cluster: " + self.config.stack_name + CR)
            print (I + "URL")
            print (I2 + cluster['url'] + CR)
            if not stack['dns-auto'] and not stack['cluster-cname'] == '':
                print (I2 + "Note: Following CNAME record must be manually created: " + CR )
                print (I2 + "    " + stack['cluster-cname'] + "  CNAME  " + stack['aws-cname'] + CR)
            print (I + "Instances : " +  str(len (cluster['group']['instances'])))
            for instance in cluster['group']['instances']:
                print (I2 + instance['id'] + " : " + instance['private_ip']+ "/" + instance['public_ip'])
            #pp.pprint (cluster)
            print (LINE)
        except Exception as e:
            log_error("Unable to retrieve cluster info:\n\n   " + str(e))

    def _describe_stack (self):
        stack = {}
        try:
            # Get stack output data
            stack_list = self.aws_cf.describe_stacks ( StackName = self.config.stack_name )
            for s in stack_list['Stacks']:
                if s['StackName'] == self.config.stack_name:
                    for output in s['Outputs']:
                        if output['OutputKey'] == 'URL':
                            stack['url'] = output['OutputValue']
                        elif output['OutputKey'] == 'AWSCname':
                            stack['aws-cname'] = output ['OutputValue']
                        elif output['OutputKey'] == 'ClusterCname':
                            stack['cluster-cname'] = output ['OutputValue']
                    break
            # Get resource details
            stack['dns-auto'] = False
            stack_resources = self.aws_cf.describe_stack_resources ( StackName = self.config.stack_name )
            for resource in stack_resources['StackResources']:
                if resource['LogicalResourceId'] == 'KurentoResourceSet':
                    stack['dns-auto'] = True
                    break
            return stack
        except Exception as e:
            log_error("Unable to retrieve info from cluster stack:\n\n   " + str(e))

    def _describe_auto_scaling_group(self):
        auto_scaling_group = {}
        try:
            # pp = pprint.PrettyPrinter(indent=4)
            # Get autoscaling group name
            stack_resources = self.aws_cf.describe_stack_resources( StackName = self.config.stack_name )
            # pp.pprint (stack_resources)
            for resource in stack_resources['StackResources']:
                if resource['LogicalResourceId'] == 'KurentoGroup':
                    auto_scaling_group['name'] = resource['PhysicalResourceId']
                    break

            auto_scaling_groups = self.aws_autosc.describe_auto_scaling_groups ( AutoScalingGroupNames = [ auto_scaling_group['name'] ])
            for group in auto_scaling_groups['AutoScalingGroups']:
                if group['AutoScalingGroupName'] == auto_scaling_group['name']:
                    # Get instance info
                    auto_scaling_group['instances'] = []
                    for instance in group['Instances']:
                        auto_scaling_group['instances'].append ( self._describe_instance(instance['InstanceId']) )
            return auto_scaling_group

        except Exception as e:
            log_error("Unable to retrieve autoscaling group info:\n\n   " + str(e))

    def _describe_instance (self, instance_id):
        instance = {}
        try:
            pp = pprint.PrettyPrinter(indent=4)
            instance_info = self.aws_ec2.describe_instances( InstanceIds = [ instance_id ])
            instance['id'] = instance_id
            instance['public_ip'] = instance_info['Reservations'][0]['Instances'][0]['NetworkInterfaces'][0]['Association']['PublicIp']
            instance['private_ip'] = instance_info['Reservations'][0]['Instances'][0]['NetworkInterfaces'][0]['PrivateIpAddress']
            #pp.pprint(instance_list)
            return instance
        except Exception as e:
            log_error("Unable to retrieve instance info:\n\n   " + str(e))

    def execute (self):
        if self.config.command == CMD_CREATE:
            self._create()
        elif self.config.command == CMD_DELETE:
            self._delete()
        elif self.config.command == CMD_LIST:
            self._list()
        elif self.config.command == CMD_SHOW:
            self._show()
        else:
            usage ("Unknown command: " + self.config.command, USAGE_ALL)

##### MAIN #####

# Parse command line arguments
config = KurentoClusterConfig(sys.argv[1:])
session = AwsSession(config)

# Execute cluster command
cluster = KurentoCluster(session, config)
cluster.execute()

# TODO: Implement KURENTO API-KEY
# TODO: Implement INSTANCE TYPE
# TODO: Autoscaling
# TODO: Allow deployment of older API versions
