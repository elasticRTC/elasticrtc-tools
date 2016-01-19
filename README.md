ElasticRTC tools
================

ElasticRTC is a cluster infrastructure based in Kurento Media Server and Amazon Web Services (AWS), that
provides following capabilities:
 * *Easy to deploy*: Straightforward deployment of any number of Kurento Media Server (KMS) instances.
 * *Security*: Out of the box security, including SSL and access control.
 * *Monitoring*: Deployed with Kurento Media Server Inspector. An application intended to dig into pipeline topology, to monitor and to get statistics from every single media element.

Getting started
---------------

To use Kurento Cluster you’ll need to setup an Amazon Web Services (AWS) account. Make sure to go through all topics below:

  * [Signup for an AWS account](http://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/signup.html)
  * [Create AWS EC2 key pair](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair)
  * [Install the AWS CLI](http://docs.aws.amazon.com/cli/latest/userguide/installing.html)
  * [Configure the AWS CLI](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html)

You will need Python installed in your machine. Verify your current version or install from Python site.

 ```
 python -V
 ```
Download ElasticRTC tools

 ```
git clone git@github.com:ElasticRTC/elasticrtc-tools.git
cd elasticrtc-tools
```

Build your first cluster

```
elasticrtc create \
--region eu-west-1 \
--aws-key-name elasticrtc \
--stack-name elasticrtc
```

where

```
--region value
      [Mandatory] AWS region where cluster is deployed. Can be any of:
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
      [Mandatory] Cluster name. It must start with letter, contain only alphanumeric characters and be unique in selected region. White spaces are not allowed.
```

On successful run you’ll see following logs in the screen
