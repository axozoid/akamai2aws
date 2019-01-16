# Overview
This script performs syncing Akamai's IP ranges for SiteShield and AWS security groups.

It's supposed to run this service as a CronJob to perform checks and syncing (if needed) regularly.

The service is written in Golang.

# High level logic
When executed, the script does the following:
1. Calls Akamai's API to get a map containing IP ranges;
2. Syncing the SG rules with the Akamai IP ranges;
3. Acknowledges the Akamai's map (by default it does not);

## Notes
1. Removing of rules from the SG is incremental - which means that only CIDRs deleted since previous acknowledgement of a map will be deleted.
2. Adding of rules to the SG is done by syncing with the Akamai's "Proposed CIDR".

## Passing parameters to the script
The following environment variables can be passed:
| Name | Default value | Required | Description |

<to-be-continued>