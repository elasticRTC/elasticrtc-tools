ElasticRTC tools
=============

ElasticRTC is a cluster infrastructure based in Kurento Media Server and Amazon Web Services (AWS), that provides following capabilities:

* **Easy to deploy**: Straightforward deployment of any number of nodes.
* **Security**: Out of the box security, including SSL and access control.
* **Monitoring**: Deployed with ElasticRTC Inspector. An application intended to dig into pipeline topology, to monitor and to get statistics from every single media element.

# Getting started

To use ElasticRTC you’ll need to setup an Amazon Web Services (AWS) account. Make sure to go through all topics below:

* [Signup for an AWS account](http://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/signup.html).
* [Create AWS EC2 key pair](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair)
* [Install the AWS CLI](http://docs.aws.amazon.com/cli/latest/userguide/installing.html)
* [Configure the AWS CLI](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html)

You will need Python installed in your machine. Verify your current version or install from [Python site](https://www.python.org/downloads/).
```
python -V
```
Download ElasticRTC tools
```
git clone git@github.com:ElasticRTC/elasticrtc-tools.git
cd elasticrtc-tools/tools
```
Build your first cluster
```
./elasticrtc create \
   --region eu-west-1 \
   --aws-key-name mykey \
   --stack-name mycluster
```
where
```
--region value
      [Mandatory] AWS region where cluster is deployed.
      Can be any of:
         ap-northeast-1   Asia Pacific (Tokyo)
         ap-southeast-1   Asia Pacific (Singapore)
         ap-southeast-2   Asia Pacific (Sydney)
         eu-central-1     EU (Frankfurt)
         eu-west-1        EU (Ireland)
         sa-east-1        South America (Sao Paulo)
         us-east-1        US East (N. Virginia)
         us-west-1        US West (N. California)
         us-west-2        US West (Oregon)
--aws-key-name value
      [Mandatory] Name of Amazon EC2 key pair to be configured in nodes
--stack-name value
      [Mandatory] Cluster name. It must start with letter, contain only
      alphanumeric characters and be unique in selected region. White
      spaces are not allowed.
```
On successful run you’ll see following logs in the screen
```
ElasticRTC: Found AWS profile: default
ElasticRTC: Build CloudFormation template
ElasticRTC: Get Kurento Media Server AMI for region: eu-west-1
ElasticRTC: Start CloudFormation stack: mycluster1
Creating cluster..............................................[OK]

====================================
ElasticRTC Cluster: mycluster1
     URL
          ws://mycluster1KurentoLoadBalancer-559451190.eu-west-1.elb.amazonaws.com/kurento

     Instances : 1
          i-37dcdbbc : 10.0.237.125/52.48.35.246

====================================
```
where
```
URL
  Is the URL that must be configured in the application using the cluster.
Instances
  List of nodes belonging to the cluster.
```

IMPORTANT NOTE: elasticrtc is an asynchronous tool based in AWS Cloudformation APIs. Stopping the tool won’t cancel cluster creation.

You can list all your active clusters in one AWS region
```
./elasticrtc list --region eu-west-1
  ElasticRTC: Found AWS profile: default
  ====================================
  List ElasticRTC stacks:
       Name: mycluster, Status: CREATE_COMPLETE
  ====================================
```
You can get specific information from one cluster
```
./elasticrtc show --region eu-west-1 --stack-name mycluster
ElasticRTC: Found AWS profile: default
====================================
ElasticRTC Cluster: mycluster
     URL
          mycluster1KurentoLoadBalancer-559451190.eu-west-1.elb.amazonaws.com/kurento
     Instances : 1
          i-a7aa9d1e : 10.0.194.254/52.48.35.246
====================================
```
You can also delete clusters
```
./elasticrtc delete --region eu-west-1 --stack-name mycluster
ElasticRTC: Found AWS profile: default
ElasticRTC: Delete CloudFormation stack: mycluster
Deleting cluster................................................[OK]
```

# Cluster security

## Enable SSL

ElasticRTC implements native SSL support that can be enabled using following flags:
```
--ssl-cert path
     [Optional] Path to the certificate file used for SSL
     connections. Secure port will be blocked and wss protocol
     disabled if not provided.
--ssl-key path
     [Optional] Path to the private key associated with SSL
     certificate. This parameter is mandatory if SSL certificate
     is provided.
```
Before SSL is enabled you’ll need a certificate and private key pair (for an overview of public key certificate, go to this [Wikipedia Article](https://en.wikipedia.org/wiki/Public_key_certificate)). You can get a valid one from any Certificate Authority or you can generate your own auto signed certificate for test purposes. Following procedure shows how to create an auto signed certificate with [openssl](https://www.openssl.org/).

* Create private key.
```
  openssl genrsa -out cluster.key 2048
```
* Create a certificate signing request. CN is the common name and should match the domain name where server will listen for requests:
```
  openssl req -new -out cluster.csr -key cluster.key \
  -subj "/C=/ST=/L=/O=/OU=/CN=cluster.elasticrtc.com"
```
* Generate certificate
```
  openssl x509 -req -days 365 \
  -in cluster.csr -signkey cluster.key -out cluster.crt
```
Due to security reasons, websocket clients might reject connections using auto signed certificates. You’ll need to find out how to force your websocket client to ignore security constraints.

Now that you have your certificate and private key you’re ready to create a cluster with secure connection:
```
./elasticrtc create \
   --region eu-west-1 \
   --aws-key-name mykey \
   --ssl-cert cluster.crt \
   --ssl-key cluster.key \
   --stack-name mycluster
```
If everything runs fine you’ll see following messages in the screen
```
ElasticRTC: Found AWS profile: default
ElasticRTC: Found certificate with CN: cluster.elasticrtc.com
ElasticRTC: Build CloudFormation template
ElasticRTC: Get Kurento Media Server AMI for region: eu-west-1
ElasticRTC: Start CloudFormation stack: mycluster
Creating cluster............................................[OK]
====================================
ElasticRTC Cluster: mycluster
 URL
   wss://cluster.elasticrtc.com/kurento
   Note: Following CNAME record must be manually created:
    cluster.elasticrtc.com  CNAME  mycluster-1626328687.eu-west-1.elb.amazonaws.com
Instances : 1
   i-98751520 : 10.0.88.225/52.31.202.142
====================================
```
Notice the tool is requesting you to create a CNAME for the cluster. This is very important as SSL requires certificate’s Common Name (CN) to match connection origin (DNS name).

## API security

ElasticRTC listens for API requests in an URL of the form:
```
  [ws|wss]://hostname/<api-key>
```
WS or WSS protocol schema will depend on SSL being disabled or enabled, as shown in section *Enable SSL*. Hostname is the IP or FQND (*Fully Qualified Domain Name*) where cluster is listening for requests and *api-key* is a secret code that gives access to the API. The cluster will ignore requests not addressing a valid API key.

It is important for you to understand that *api-key* is the access key to control your cluster and behaves in the same way a password does, so it is important for you to keep this  piece of information secret in your application and make sure it is not distributed to clients.

Default value of *api-key* is *kurento*, but this can be easily changed with flag:
```
--api-key value
    [Optional] A secret string intended to control access to cluster
    API. ElasticRTC cluster will accept requests from any client
    presenting this key. This key is an alphanumeric non empty
    string of any length that is concatenated to the cluster URL:
       ws[s]://host/<api-key>
```
Default value is *kurento*.

You can also add a firewall rule, allowing requests only from a given CIDR (for an overview of CIDR ranges, go to the [Wikipedia Tutorial](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing)). Use following flag for this purpose:
```
--api-origin cidr
   [Optional] CIDR from where KMS API requests will be allowed.
   Default value is 0.0.0.0/0, allowing connections from anywhere.
```
In order to secure access to your cluster you’ll need to run following command
```
elasticrtc create \
   --region eu-west-1 \
   --aws-key-name mykey \
   --ssl-cert cluster.crt \
   --ssl-key cluster.key \
   --api-key myveryprivatesecret \
   --api-origin 72.80.10.0/24 \
   --stack-name mycluster
```
Notice *api-key* is required to be an alphanumeric string with no white spaces.

## Control & management security

ElasticRTC provides following control and management interfaces intended for administration and supervision. They all require special security considerations:

### SSH console
Cluster nodes allow remote shell for any SSH client presenting private key specified by flag `--aws-key-name`. Following command can be used from unix like systems:
```
  ssh -i aws-key.pem ubuntu@node
```
where
```
aws-key.pem
  Name of the file where private key is stored.

ubuntu
  Username of KMS instances. Notice this is user is sudo and has full
  admin privileges.

node
  Any of the ip addresses shown in the instances list provided by
  command elasticrtc show <name>.
```
### KMS inspector
ElasticRTC includes a management application allowing inspection and control of deployed services to the element level. This application implements a password based security mechanism that can be configured during cluster deployment.

Even though all control and management interfaces provide its own security mechanism, ElasticRTC implements flag `--control-origin` that creates a firewall rule allowing connections only from a given CIDR. This prevent outsiders even to knock the door on sensible ports.
```
--control-origin cidr
   [Optional] CIDR from where control and management requests will be
   allowed. Default value is 0.0.0.0/0, allowing connections from
   anywhere.
```
If this flag is not provided the cluster will allow connection from everywhere in the Internet.

# Cluster naming

ElasticRTC is integrated with [AWS Route 53](https://aws.amazon.com/route53/) and provides DNS name auto-registering. You’ll need to provide a [Hosted Zone ](http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/AboutHostedZones.html)ID by means of flag below In order to enable this capability:
```
--hosted-zone-id value
     [Optional] Route 53 hosted zone ID used by cluster to automatically
     register a CNAME record with the name of the stack. If a SSL
     certificate is provided its common name (CN) must match the hosted
     zone domain.
```
Hosted Zone is the administrative tool provided by AWS to manage [DNS zones](https://en.wikipedia.org/wiki/DNS_zone). A DNS zone consist of all information required to manage a domain (*elasticrtc.com*) or subdomain (*subdomain.elasticrtc.com*). Amazon provides a set of 4 nameservers for each hosted zone. They are shown as *NS* records in the [Route 53 console](https://console.aws.amazon.com/route53/home). In order to enable DNS resolution you’ll need to register at least one of those nameservers with you DNS provider. How this is done is very dependant on provider, but in general you should be able to add a new record of type *NS* (*nameserver*) where you’ll provide following info:

* *Host*: This is the subdomain name associated to Hosted Zone, i.e. *cluster*

* *Points To*: This is the Hosted Zone nameserver provided by Amazon, i.e. *ns-314.awsdns-39.com.*

When a valid Hosted Zone ID is provided you can expect ElasticRTC to create a *CNAME* record of the form:
```
<stack-name>.<hosted-zone-subdomain>
```
For example imagine a Hosted Zone with ID *Z15S5R1YM6PTWA* is provided for domain *elasticrtc.org* in command below:
```
elasticrtc create \
   --region eu-west-1 \
   --aws-key-name mykey \
   --hosted-zone-id Z15S5R1YM6PTWA \
   --stack-name mycluster
```
ElasticRTC will automatically create following *CNAME*
```
mycluster.elasticrtc.com
```
Cluster creation will fail if *CNAME* already exists in the Hosted Zone.

## SSL and naming rules

As you might already know *SSL* connections require *CN* (*Common Name*) of remote endpoint’s certificate to match their domain names. This causes subtle interactions between *DNS* and *SSL* that ElasticRTC handles as stated in following rules:

* **Hosted Zone: not provided, SSL: not provided**
 ElasticRTC will enable WS protocol in port 80 for the CNAME automatically assigned by AWS.
* **Hosted Zone: not provided, SSL: provided**
  ElasticRTC will enable WSS protocol in port 443. CNAME must be manually created for certificate’s CN.
* **Hosted Zone: provided, SSL: not provided:**
  ElasticRTC will create a CNAME for the stack name and will enable WS protocol in port 80.
* **Hosted Zone: provided, SSL: provided wildcard:**
  ElasticRTC will verify certificate’s CN matches Hosted Zone subdomain. On successful verification it will create a CNAME of the form <stack-name>.<hosted-zone-subdomain> and will enable WSS protocol in port 443.
  ElasticRTC deployment will fail If certificate’s CN and Hosted Zone subdomain don’t match.
* **Hosted Zone: provided, SSL: provided non-wildcard:**
  ElasticRTC will verify certificate’s CN matches Hosted Zone subdomain. On successful verification it will create a CNAME for certificate’s CN and will enable WSS protocol in port 443. Deployment will fail If certificate’s CN and Hosted Zone subdomain don’t match.
 Notice that stack name is ignored for non-wildcard certificates.

For more information on wildcard certificates, go to following [Wikipedia Article](https://en.wikipedia.org/wiki/Wildcard_certificate).

# Amazon Web Services (AWS)

## AWS API Key & Secret

As you might already know, AWS provides a very well [documented](http://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html)  API used by ElasticRTC to build cluster resources. This API is protected by credentials consisting of two basic elements: **AWS Access Key ID **and **AWS Access Secret Key**. You can find out how to generate a credential pair in the official [documentation site](http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSGettingStartedGuide/AWSCredentials.html).

There are several mechanism that can be used to configure AWS API credentials before deploying a cluster:

* Use [AWS CLI ](https://aws.amazon.com/cli/)interface: Download AWS command line interface and run following command
```
aws configure
```
You’ll be prompted to enter required configurations, including credentials
```
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-west-2
Default output format [None]: ENTER
```
* Use ElasticRTC: Credentials will be requested by tool if they’re not previously configured.
```
./elasticrtc create …

====================================
AWS credentials not configured. Access and secret keys must be
provided in order to allow ElasticRTC to access AWS APIs.
If you're the account administrator execute following procedure:
  1 - Navigate to https://console.aws.amazon.com/iam/home?#security_credential
  2 - Open section Access Keys (Access Key ID and Secret Access Key)
  3 - Press button Create New Access Key
If you're not the account administrator you still can generate credentials
with following procedure
  1 - Navigate to https://myaccount.signin.aws.amazon.com/console. Your AWS
      administrator will provide you the value for myaccount
  2 - Login to AWS console with you IAM user and password. Ask your AWS
      administrator if you don't have an IAM user
  3 - Navigate to IAM home https://console.aws.amazon.com/iam/home#home
  4 - Open section 'Rotate your access keys' and click 'Manage User Access Key'
  5 - Go to section 'Security Credentials' and click 'Create Access Key'
====================================
Enter AWS Access Key ID:AKIAIOSFODNN7EXAMPLE
Enter AWS Secret Access Key:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```
* Command line credentials: Flags --aws-access-key-id and --aws-secret-access-key allow to specify credentials in the command line. They are very convenient for continuous deployment environments, where local configurations can be hard to manage.
```
./elasticrtc create \
   --aws-access-key-id ****AKIAIOSFODNN7EXAMPLE
   --aws-secret-access-key ****wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
   --region eu-west-1 \
   --aws-key-name mykey \
   --stack-name mycluster
```
## S3 Storage

ElasticRTC uses AWS S3 service for persistent storage. This includes media files recorded by KMS and logs.

* Use an existing S3 bucket: For this you just specify the S3 bucket name with flag below. Make sure the bucket has been created in the same region where cluster is deployed or write operations will fail.
```
--aws-s3-bucket-name value
    [Optional] Name of Amazon S3 bucket used for permanent storage. A new
    bucket named: <region>-<stack-name> will be created if this parameter
    is not provided. Notice buckets are never deleted on termination, even
    if they have been created by ElasticRTC.
```
* ElasticRTC will create its own S3 bucket if none is provided. Bucket name will be constructed from region and stack name, as shown below:
```
<region>-<stack-name>
```
Notice S3 buckets used by ElasticRTC remains untouched after cluster termination, even if it was created by cluster itself.
Independently of S3 bucket being provided or created by ElasticRTC following directories will be created.

* **log**
  Cluster logs will be placed within this location when S3 log storage is selected, otherwise this directory won’t
  be even created.
* **repository**
  This is the root location for Kurento Media Server default URL. Any recording request not including schema will
  be automatically placed within this directory

## AWS Infrastructure

### Instance type

AWS EC2 provides an extensive catalog of machine types intended to match computing resources to software requirements (Go to [AWS instance catalogue ](https://aws.amazon.com/ec2/instance-types) for more details on this topic) . ElasticRTC takes advantage of this capabilities, allowing administrators to select what type of instance will be used. Flag --aws-instance-type is intended for this purpose.
```
--aws-instance-type value
    [Optional] EC2 instance type used by cluster nodes. Default
    instance type is m3.medium
```
Notice all nodes in a cluster use the same EC2 instance type.

### Instance Tenancy

ElasticRTC exposes AWS capability allowing users to deploy EC2 instances in a dedicated hardware (Go to [AWS documentation](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/dedicated-instance.html) for more information on dedicated hardware). Following alternatives are available:

* **default**
Your instance runs on shared hardware.
* **dedicated**
Your instance runs on single-tenant hardware.
* **host**
Your instance runs on a Dedicated host, which is an isolated server with configurations that you can control.

ElasticRTC implements flag `--aws-instance-tenancy` for this purpose:
```
--aws-instance-tenancy [default|dedicated|host]
    [Optional] EC2 tenancy of cluster nodes. Default value is default.
```
# Logging

ElasticRTC persists logs in order to allow forensic analysis of errors. Following storage alternatives are available:

* **CloudWatch Logs**
Upload logs to AWS CloudWatch service allowing cluster administrator to take advantage of all filtering features already provided by AWS. A *Log Group *named **ELASTICRTC-<stack-name>** is created with three streams:
  * **controller**
    Collects cluster controller logs.
  * **media-server**
    Collects logs from Kurento Media Server instances.
  * **turn**
    Collects logs from STUN/TURN servers deployed with the cluster.
* **S3**
  Upload logs to directory **log** of the S3 bucket associated to cluster. Following subdirectories will be created:
  * **controller**
    Contains controller logs.
  * **media-server**
    Contains logs from Kurento Media Server instances.
  * **turn**
    Contains logs from STUN/TURN servers deployed with the cluster.
Log files are named using the rule `kms-<stack-name>-<node-ip-addr>`.

In general, S3 will provide more flexibility than CloudWatch, but it requires to implement ad-hoc log management procedures, including retention policy.

In order to select storage location following flag can be used:
```
--log-storage [cloudwatch|s3]
    [Optional] Storage location of cluster logs. it can be any of AWS
    Cloudwatch Logs or AWS S3 services. Default value is cloudwatch.
```

# Inspector

ElasticRTC Inspector is a web based administration tool available at URL:
```
http|https://cluster-url/inspector
```
where

* **http | https**: URL schema will depend on SSL configuration
* **cluster-url**: Is the cluster hostname or ip address

ElasticRTC Inspector is password protected with the following default credentials:
```
  user: admin
  password: admin
```

Cluster tools implements flags `--inspector-user --inspector-pass`, so you can change them avoiding uncontrolled access.

 As already explained in section *Control & management security*, the inspector is also protected by firewall rules defined by flag `--control-origin`. It is recommended to implement all security measurements as inspector provides full access to MediaElements, allowing even to watch video streams flowing through the media server.
