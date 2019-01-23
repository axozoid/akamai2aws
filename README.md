## Overview
This script performs syncing Akamai's IP ranges for SiteShield and AWS security groups.

Initially this was written with an idea to run as a CronJob in Kubernetes to perform checks and syncing (if needed) regularly, but you can run it as a CLI tool as well.

## High level logic
When executed, the script does the following:
1. Calls Akamai's API to get a map containing IP ranges;
2. Syncing the SG rules with the Akamai IP ranges;
3. Acknowledges the map (by default it does not);

### Notes
1. Removing of rules from the SG is **incremental** - which means that only CIDRs deleted since previous acknowledgement of an Akamai map will be deleted. In other words, we don't "remove all rules from a SG and add all CIDRs from Akamai". This approach allows to bring the script into use without worrying of some existing non-Akamai rules being deleted.
2. Adding of rules to the SG is done by syncing with the Akamai's "Proposed CIDR".

## Getting started
### Step 1. Variables
The following environment variables are accepted when using a Docker image created from this repo:

| Name | Default value | Required | Description |
|---|---|---|---|
|AKAMAI_HOST|none|**yes**|Used for Akamai's API calls|
|AKAMAI_CLIENT_TOKEN|none|**yes**|Used for Akamai's API calls|
|AKAMAI_CLIENT_SECRET|none|**yes**|Used for Akamai's API calls|
|AKAMAI_ACCESS_TOKEN|none|**yes**|Used for Akamai's API calls|
|AKMGOAPP_SECURITY_GROUPS|none|**yes**|A comma separated list of AWS security groups to sync with a map|
|AKMGOAPP_MAP_ID|none|**yes**|ID of an Akamai map to sync with|
|AKMGOAPP_LOG_LEVEL|info|no|A level of verbosity|
|AKMGOAPP_SG_RULE_DESCRIPTION|Akamai SiteShield IP.|no|Description for a security group rule|
|AKMGOAPP_MAP_ADDR|/siteshield/v1/maps/|no|Akamai's endpoint URL|
|AKMGOAPP_AWS_REGION|ap-southeast-2|no|AWS region to operate in|
|AKMGOAPP_ACK_MAP|false|no|If set to `true`, the map will be acknowledged after syncing|

Variable `AKMGOAPP_LOG_LEVEL` might have these values:
* `silence` - only errors will be printed;
* `info` - default level, printing major steps;
* `debug` - will output details for all actions;

Note: If none of these values are supplied or an incorrect value passed to the script, it will fallback to `info`.

### Step 2. AWS credentials
In order to perform actions in AWS we need valid credentials.
Depending on your use case you might do it, for example, with:
1. IAM roles;
2. Environment variables;
3. CLI credentials file;

For more information, please read and follow [this article](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html).

### Step 3. Run it
You may run a binary or a source code itself, but below I just put few examples on how you can run it as a Docker container.

Assuming, you're providing an environment file like one we have under `examples/env-file` in this repo:
```
docker run --rm --env-file=examples/env-file ozmate/akamai2aws:latest
```
If you already have AWS credentials configured on your machine you may provide them by mounting `.aws` folder:

```
docker run --rm --env-file=<YOUR_ENV_FILE> -v $HOME/.aws:/root/.aws:ro ozmate/akamai2aws:latest
```

The commands above will start a container and run a binary of the script. The progress will be printed to stdout. When it's done, the container will be removed (`--rm` switch).

### TODO
- [ ] Making clean 1-to-1 sync (when a SG contains nothing but Akamai's CIDRs only);
- [ ] Slack notifications on errors;
- [ ] Example of resource templates for deploying in k8s;

## Links
* How to setup Akamai credentials for API calls: https://developer.akamai.com/legacy/introduction/Prov_Creds.html
* SiteShield API: https://developer.akamai.com/api/cloud_security/site_shield/v1.html
