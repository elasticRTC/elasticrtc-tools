ElasticRTC tools
=============

ElasticRTC is a cluster infrastructure based in Kurento Media Server and Amazon Web Services (AWS), that provides following capabilities:

* **Easy to deploy**: Straightforward deployment of any number of nodes.
* **Versioning**: Select what version of Kurento Media Server you want to deploy
* **Security**: Out of the box security, including SSL and access control.
* **Monitoring**: Deployed with ElasticRTC Inspector. An application intended to dig into pipeline topology, to monitor and to get statistics from every single media element.

# Getting started

In order to use ElasticRTC you’ll need to [Signup for an Amazon Web Services (AWS) account](http://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/signup.html). If you already have one you can skip this step.

You will need Python installed in your machine. Verify your current version or install from [Python site](https://www.python.org/downloads/).
```
python -V
```
Execute following commands as administrator in order to install required Python modules. Following [instructions](https://pip.pypa.io/en/stable/installing/) will help you to install pip if it is not yet available in your system.
```
sudo pip install boto3
sudo pip install pyOpenSSL
sudo pip install dnspython
```

You need to make sure pip and python match versions. If you get errors related to missing libraries already
installed, then reinstall pip for your current python version, as shown below.

```
wget https://bootstrap.pypa.io/get-pip.py
sudo python get-pip.py
```

Download ElasticRTC tools from [github](https://github.com/elasticrtc) using commands below. You'll need to [install git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for this purpose.
```
git clone https://github.com/ElasticRTC/elasticrtc-tools.git
cd elasticrtc-tools/tools
```
Build your first cluster
```
./elasticrtc create \
   --region eu-west-1 \
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
--stack-name value
      [Mandatory] Cluster name. It must start with letter, contain only
      alphanumeric characters and be unique in selected region. White
      spaces are not allowed.

 IMPORTANT NOTE
    ElasticRTC currently is only supported in eu-west-1
```

The first time you run ElasticRTC you might see following message. It basically
means AWS credentials are not configured. You just follow instructions,
depending whether you are AWS administrator or not, and enter you secret and access keys
in order to continue. For more information on AWS API keys go to section
*Amazon Web Services (AWS)* below.

```
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

On successful run you’ll see following logs in the screen
```
ElasticRTC: Found AWS profile: default
ElasticRTC: Build CloudFormation template
ElasticRTC: Get Kurento Media Server AMI for region: eu-west-1
ElasticRTC: Start CloudFormation stack: mycluster1
Creating cluster..............................................[OK]

====================================
ElasticRTC Cluster: mycluster
     Status:
          CREATE_COMPLETE
     Version:
          6.3.4
     Cluster URL
          ws://mycluster1KurentoLoadBalancer-559451190.eu-west-1.elb.amazonaws.com/kurento
     Cluster Instances : 1
          i-37dcdbbc : m3.medium - 10.0.237.125/52.48.35.246
     APP:
          none
     Build parameters:
          api-key                 : kurento
          api-origin              : 0.0.0.0/0
          aws-app-instance-type   : m3.medium
          aws-instance-tenancy    : default
          aws-instance-type       : m3.medium
          aws-key-name            : aws_key
          aws-s3-bucket-name      : eu-west-1-mycluster
          control-origin          : 0.0.0.0/0
          desired-capacity        : 1
          elasticsearch-password  :
          elasticsearch-ssl       :
          elasticsearch-transport :
          elasticsearch-user      :
          hosted-zone-id          :
          inspector-pass          :
          inspector-user          :
          log-storage             : cloudwatch
          max-capacity            : 1
          min-capacity            : 1
          ssl-cert                :
          ssl-key                 :
          version                 : 6.3.4
====================================
```
where
```
Status
  Cluster status. Should be CREATE_COMPLETE in order to be operational
Version:
   Is the actual software version used in the cluster
Cluster URL
  Is the URL that must be configured in the application using the cluster.
Cluster Instances
  List of nodes belonging to the cluster.
Build parameters
  Parameter values used for cluster deployment. They include user provided and default values
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
     Status:
          CREATE_COMPLETE
     Version:
          6.3.4
     Cluster URL
          mycluster1KurentoLoadBalancer-559451190.eu-west-1.elb.amazonaws.com/kurento
     Cluster Instances : 1
          i-a7aa9d1e : m3.medium - 10.0.194.254/52.48.35.246
    . . .
====================================
```
You can also delete clusters
```
./elasticrtc delete --region eu-west-1 --stack-name mycluster
ElasticRTC: Found AWS profile: default
ElasticRTC: Delete CloudFormation stack: mycluster
Deleting cluster................................................[OK]
```

# Software versions

ElasticRTC provides support for multiple versions of Kurento Media Server, so you can select the one that better integrates with your application. This allows a better control of application lifecycle and to
schedule upgrades independently of Kurento Media Server versioning cycle.

In order to find out available versions in your region you'll need to execute command below:

```
./elasticrtc version --region eu-west-1

====================================
ElasticRTC versions:
          6.2.0
          6.3.0
          6.3.2
====================================
```

You can use flag `--version` to select the version used for your cluster, as shown in command below:
```
./elasticrtc create \
   --region eu-west-1 \
   --stack-name mycluster \
   --version 6.2.0
```
If no version is provided, ElasticRTC will select the latest available.

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
    Status:
        CREATE_COMPLETE
    Version:
        6.3.4
    Cluster URL
        wss://cluster.elasticrtc.com/kurento
            Note: Following CNAME record must be manually created:
                cluster.elasticrtc.com  CNAME  mycluster-1626328687.eu-west-1.elb.amazonaws.com
    Cluster Instances : 1
        i-98751520 : m3.medium - 10.0.88.225/52.31.202.142
    . . .
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
   --ssl-cert cluster.crt \
   --ssl-key cluster.key \
   --api-key myveryprivatesecret \
   --api-origin 72.80.10.0/24 \
   --stack-name mycluster
```
Notice *api-key* is required to be an alphanumeric string with no white spaces.

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

As you might already know, AWS provides a very well [documented](http://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html) API used by ElasticRTC to build cluster resources. This API is protected by credentials consisting of two basic elements: **AWS Access Key ID** and **AWS Access Secret Key**. You can find out how to generate a credential pair in the official [documentation site](http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSGettingStartedGuide/AWSCredentials.html).

There are several mechanism that can be used to configure AWS API credentials before deploying a cluster:

* **Use [AWS CLI ](https://aws.amazon.com/cli/)**: You'll need to [Install the AWS CLI tools](http://docs.aws.amazon.com/cli/latest/userguide/installing.html) and then run following command
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
* **Use ElasticRTC**: Credentials will be requested by tool if they’re not previously configured.
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
* **Use command line** : Flags `--aws-access-key-id and` `--aws-secret-access-key` allow to specify credentials in the command line. They are very convenient for continuous deployment environments, where local configurations can be hard to manage.
```
./elasticrtc create \
   --aws-access-key-id ****AKIAIOSFODNN7EXAMPLE
   --aws-secret-access-key ****wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
   --region eu-west-1 \
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

### Cluster capacity

By default ElasticRTC creates a single node cluster, but most likely you'll need clusters with more than one node for real life applications. Flag `--desired-capacity` is intended to define the amount of nodes that ElasticRTC must deploy. It is used as shown in command below:
```
./elasticrtc create \
   --region eu-west-1 \
   --stack-name mycluster
   --desired-capacity 10
```
Command above will create a 10 nodes cluster and will monitor their health status replacing dead nodes. In the same way if one node is accidentally killed a new instance will be created and joined to the cluster, so you can make sure the cluster capacity remains constant, no matter what goes wrong.

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

## IAM Policies
[Amazon IAM](http://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html)
(Identity and Access Management) implements the AAA (Authentication, Authorization and Accounting) mechanisms controlling access
to AWS infrastructure. If you're using a master account or you have administration
permissions you can probably skip this section.
Below are listed the minimum set of permissions required by a IAM user in order
to deploy ElasticRTC. You'll need to create a policy with this access rights and assign it to all users entitled to create ElasticRTC clusters.

 ```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateUser",
                "iam:PutUserPolicy",
                "iam:CreateRole",
                "iam:CreateAccessKey",
                "iam:PutRolePolicy",
                "iam:CreateInstanceProfile",
                "iam:AddRoleToInstanceProfile",
                "iam:PassRole",
                "iam:GetRole",
                "s3:CreateBucket",
                "s3:ListBucket",
                "cloudformation:CreateStack",
                "cloudformation:DescribeStacks",
                "cloudformation:DescribeStackEvents",
                "cloudformation:DescribeStackResources",
                "cloudformation:GetTemplate",
                "ec2:DescribeImages",
                "ec2:CreateInternetGateway",
                "ec2:DescribeInternetGateways",
                "ec2:AttachInternetGateway",
                "ec2:CreateVpc",
                "ec2:DescribeVpcs",
                "ec2:ModifyVpcAttribute",
                "ec2:CreateSubnet",
                "ec2:DescribeSubnets",
                "ec2:CreateRoute",
                "ec2:CreateRouteTable",
                "ec2:DescribeRouteTables",
                "ec2:AssociateRouteTable",
                "ec2:CreateSecurityGroup",
                "ec2:DescribeSecurityGroups",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:DescribeInstances",
                "autoscaling:CreateLaunchConfiguration",
                "autoscaling:CreateAutoScalingGroup",
                "autoscaling:DescribeAutoScalingGroups",
                "autoscaling:UpdateAutoScalingGroup",
                "autoscaling:DescribeLaunchConfigurations",
                "autoscaling:DescribeAutoScalingInstances",
                "autoscaling:PutScalingPolicy",
                "autoscaling:PutLifecycleHook",
                "autoscaling:PutScalingPolicy",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:CreateLoadBalancer",
                "elasticloadbalancing:ConfigureHealthCheck",
                "elasticloadbalancing:SetLoadBalancerPoliciesOfListener",
                "elasticloadbalancing:ModifyLoadBalancerAttributes",
                "sqs:CreateQueue",
                "sqs:GetQueueAttributes",
                "cloudwatch:PutMetricAlarm"
            ],
            "Resource": "*"
        }
    ]
}
 ```
Above policy will allow users to create ElastiRTC clusters, but is you require these users to be able to delete them, you'll need to add also following policy
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:ListAccessKeys",
                "iam:DeleteUserPolicy",
                "iam:DeleteRolePolicy",
                "iam:RemoveRoleFromInstanceProfile",
                "iam:DeleteAccessKey",
                "iam:DeleteRole",
                "iam:DeleteUser",
                "iam:DeleteInstanceProfile",
                "ec2:DeleteVpc",
                "ec2:DeleteSubnet",
                "ec2:DeleteInternetGateway",
                "ec2:DeleteSecurityGroup",
                "ec2:DetachInternetGateway",
                "ec2:DeleteRoute",
                "ec2:DeleteRouteTable",
                "ec2:DisassociateRouteTable",
                "autoscaling:DeleteLaunchConfiguration",
                "autoscaling:DescribeScalingActivities",
                "autoscaling:DeletePolicy",
                "autoscaling:DeleteLifecycleHook",
                "autoscaling:DeleteAutoScalingGroup",
                "elasticloadbalancing:DeleteLoadBalancer",
                "cloudformation:DeleteStack",
                "sqs:DeleteQueue",
                "cloudwatch:DeleteAlarms"
            ],
            "Resource": "*"
        }
    ]
}
```

# Autoscaling

ElasticRTC takes advantage of AWS autoscaling features, allowing cluster to increase (scale-out) and decrease (scale-in) capacity based in system usage. For more information on AWS autoscaling you can visit [AWS autoscaling documentation site](http://docs.aws.amazon.com/AutoScaling/latest/DeveloperGuide/WhatIsAutoScaling.html).

_Capacity_ and _Load_ are two fundamental concepts used in autoscaling. _Capacity_ is basically a measurement of the maximum amount of clients that can be serviced simultaneously by a given system. _Load_ represents current clients being serviced at a given time. In static system _Capacity_ is fixed and  _Load_ can never go over it. Autoscaling system have the ability to modify _Capacity_ based in _Load_.

_Capacity_ and _Load_ must take into account relevant system resources: CPU usage, memory, bandwidth, etc. For the case of ElasticRTC, CPU usage is  the main and only resource relevant to be considered.

_Load_ calculation uses an imaginary cost of MediaElements based in the assumption of a CPU having a total capacity of 100 points. MediaElement cost is calculated dividing the CPU capacity (100) by the maximum number of the MediaElement that we allow per CPU. For WebRTCEndpoint this number defaults to 1, but it can be changed with flag:
```
	--cost-map WebRtcEndpoint=1,WebRtcSfu=25
       [Optional] Map of MediaElement costs for Load calculation. This flag
       accepts a comma separated list of key-value pairs with the cost description
       of each MediaElement.

      IMPORTANT NOTE: Currently only WebRtcEndpoint is accounted for
      Load meassurements
```
Notice decimal values can be used, allowing more than 100 WebRTC connections per CPU, but this is not recommended as it might lead to overload scenarios affecting performance.

Overall system _Load_ is obtained from the sum of costs of every MediaElement normalized to total amount of CPUs in the system, being actually the usage percentage of the system
```
	LOAD = SUM(MEDIA_ELEMENT_COST) / #CPU
```
Current ElasticRTC implementation only takes into account costs derived by WebRTCEndpoint, but future versions will provide more sophisticated cost descriptions, implementing even resource reservation mechanisms.

ElasticRTC allows to create policies defining cluster _Capacity_ changes based on _Load_. These policies are directly based in AWS Dynamic Scaling Policies and it is recommended to read the [AWS documentation](http://docs.aws.amazon.com/AutoScaling/latest/DeveloperGuide/as-scale-based-on-demand.html)  about dynamic scaling and more specifically the Step Scaling Policies. ElasticRTC defines two policies: one  for scale-in and one for scale-out. They both are used to control capacity change for load ranges starting at 50% usage.

Scale-out policy defines how to increase capacity when Load goes over 50%. Flag `--scale-out-policy` is used for that purpose as shown below:
```
	--scale-out-policy 20=10,30=40
```
Scale-out policy is a list of key-value pairs that define capacity increase for different Load thresholds. Example above can be depicted as follows:
```
	50 -------------------- 70 ---------- 80 -------->
	 n ------------------- +10% -------  +40% ------->
```
Interval `20=10` is interpreted in the following way. When _Load_ is between 50 and 70 no capacity change is required, but when it goes over threshold (20 over 50 = 70) an increase of 10% in capacity is required. For a cluster with 10 nodes this will mean a new node addiction to the cluster. It is important to understand how AWS manages decimals, because 10% of a cluster with 2 nodes is 0.2. AWS rounds decimals to the lowest number except for numbers between 0 and 1 that are rounded to 1. Hence an increase of 1.5 will stay to 1, but 0.2 will be changed to 1 also, meaning a 10% change in a cluster with 2 nodes will lead to a cluster with 3 nodes. After a warmup period of the newly incorporated node, Load is measured again if it remains over 70 a new scale-out procedure is triggered to increase capacity until load falls in the range 50 to 70 or the maximum cluster capacity is reached. Default scale out policy is:
```
25=10
```
Scale-in policy uses flag `--scale-in-policy` defines how capacity is decreased when _Load_ goes below 50% .
	--scale-out-policy 20=10,30=40
This flag requires a set of key-value pairs defining Load thresholds and capacity reduction as depicted below
````
	< ------- 20 -------- 30 ------------------- 50
	< ------ -40% ------ -10% ------------------ 50
````
Interval `20=10` of the scale-in configuraiton is interpreted in the following way now. When _Load_ stays between 30 and 50 no change in capacity is required. Going below threshold (20 below 50 = 30) requires a reduction of 10% in capacity. For a cluster with 11 nodes this will mean a reduction of 1, but in a cluster with 2 nodes this will also mean a reduction of 1 node because the same rounding strategy of decimal numbers used for scale-out is also applied here. Is up to AWS to decide what node will be deleted. You can go to this [AWS article](http://docs.aws.amazon.com/AutoScaling/latest/DeveloperGuide/AutoScalingBehavior.InstanceTermination.html) to find out how instances are selected for termination. Before the instance is actually removed a notification is sent to the cluster, so the node is blocked. It then waits until its last session is finished and then it terminates gracefully. Default scale in policy is:
```
	25=10
```
Upper and lower limits to scaling policies can be set to force cluster to keep a minimum and maximum number of nodes. Following flags are used for that purpose:
```
	--mim-capacity num
	--max-capacity num
```
In general you want `mim-capacity` to be lower or equal to `max-capacity`. If none of above flags are provided, then autoscaling is disabled and the cluster will remain with its initial capacity.

By default cluster will start with the minimum capacity, although this can also be changed with flag
```
	--desired-capacity num
```
Value of this flag must be lower or equal than `max-capacity` and larger or equal than `min-capacity`. If this flag is not provided it will default to `min-capacity`, when provided, or 1 if no capacity configuration is provided at all.

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
* **Elasticsearch**
  ElasticRTC can stream logs to index `kurento-YYYY.MM.dd` of an external
  Elasticsearch search service.

In order to select storage location following flag can be used:
```
--log-storage [cloudwatch|s3|elasticsearch]
    [Optional] Storage location of cluster logs. It can be any of AWS
    Cloudwatch Logs, AWS S3 services or an external Elasticsearch
    service. Default value is cloudwatch. If Elasticsearch is selected
    but no transport is provided, the system switches to default.
```
You'll need to provide configuration details in order send logs to Elasticsearch. Following flags  allows you to configure connection details. Notice that Elasticsearch default port is `9200`.

```
--elasticsearch-transport address[:port]
   [Optional] This flag must be provided when log storage is set to
   elasticsearch. It defines the transport address and port where the
   Elasticsearch service listens for requests. If no port is provided,
   default value, 9200, is used. If this flag is not provided when log
   storage is set to elasticsearch, then log storage defaults to cloudwatch.

--elasticsearch-ssl boolean
   [Optional] Wheter to use SSL or not when connecting to Elasticsearch. Default
   value is false.
```

You can also provide access credentials in case service is password protected
```
--elasticsearch-user value
   [Optional] Elasticsearch username. Anonymous access will be configured if
   not provided.

--elasticsearch-password value
    [Optional] Elasticsearch password. Anonymous access will be configured if
    not provided.
```


# Inspector

ElasticRTC Inspector is a web based administration tool available at URL:
```
http://cluster-url/inspector

   Note: Use https if SSL certificate has been provided
```
where

* **http (or https)**: URL schema will depend on SSL configuration. If SSL certificate is provided *https* is required otherwise use *http*
* **cluster-url**: Is the cluster hostname or ip address

ElasticRTC Inspector is password protected with the following default credentials:
```
  user: admin
  password: admin
```

Cluster tools implements flags `--inspector-user --inspector-pass`, so you can change them avoiding uncontrolled access.

 As already explained in section *Control & management security*, the inspector is also protected by firewall rules defined by flag `--control-origin`. It is recommended to implement all security measurements as inspector provides full access to MediaElements, allowing even to watch video streams flowing through the media server.

# Control & security management

ElasticRTC provides following control and management interfaces intended for administration and supervision. They all require special security considerations:

## SSH console
In order to enable SSH access to cluster nodes you'll need to [Create an AWS EC2 key pair](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair)
and then configure its name with flag `--aws-key-name`.
```
--aws-key-name value
      [Optional] Name of Amazon EC2 key pair to be configured in nodes.
```
Now you'll be able to open SSH sessions with cluster nodes using any compatible
SSH client. Following command can be used on unix like systems:
```
  ssh -i aws-key ubuntu@node
```
where
```
aws-key
  Name of the file where private key is stored.

ubuntu
  Username of KMS instances. Notice this is user is sudo and has full
  admin privileges.

node
  Any of the ip addresses shown in the instances list provided by
  command elasticrtc show <name>.
```
## KMS inspector
ElasticRTC includes a management application allowing inspection and control of deployed services to the element level. This application implements a password based security mechanism that can be configured during cluster deployment.

Even though all control and management interfaces provide its own security mechanism, ElasticRTC implements flag `--control-origin` that creates a firewall rule allowing connections only from a given CIDR. This prevent outsiders even to knock the door on sensible ports.
```
--control-origin cidr
   [Optional] CIDR from where control and management requests will be
   allowed. Default value is 0.0.0.0/0, allowing connections from
   anywhere.
```
If this flag is not provided the cluster will allow connection from everywhere in the Internet.

# Troubleshooting

## ERROR: Unable to validate S3 bucket name
ElasticRTC requires one S3 bucket with read/write permissions, otherwise following message
is displayed and cluster deployment is stopped.
```
====================================
ERROR: Unable to validate S3 bucket name
   An error occurred (AccessDenied) when calling the ListBuckets operation: Access Denied
====================================
```
In order to fix this problem you'll need to add following policy to AWS user.
```
  {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetBucketLocation"
            ],
            "Resource": [
                "arn:aws:s3:::bucketname"
            ]
        },
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::bucketname/*"
            ]
        }
    ]
  }
```
where `bucketname` is the S3 bucket used by cluster.
