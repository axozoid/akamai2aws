package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	s "strings"

	client "github.com/akamai/AkamaiOPEN-edgegrid-golang/client-v1"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/edgegrid"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

const (
	logLevelInfo    = "info"
	logLevelDebug   = "debug"
	logLevelError   = "error"
	logLevelSilence = "silence"

	// sgRulesLimit = 60
	// something to consider in the future
	// https://docs.aws.amazon.com/vpc/latest/userguide/amazon-vpc-limits.html#vpc-limits-security-groups
)

// AkamaiMap is a structure of Akamai's get map request.
type AkamaiMap struct {
	Acknowledged          bool
	AcknowledgedBy        string
	AcknowledgedOn        uint64
	AcknowledgeRequiredBy uint64
	Contacts              []string
	CurrentCidrs          []string
	EnvType               string
	ID                    uint32
	LatestTicketID        uint16
	MapAlias              string
	McmMapRuleID          uint16
	ProposedCidrs         []string
	RuleName              string
	Service               string
	Shared                bool
	SureRouteName         string
}

var (
	akamaiMapReady                       AkamaiMap
	currentLogLevel                      string
	cidrsPort443, cidrsPort80, secGroups []string
	debugMode                            bool

	secGroupsEnvar    = kingpin.Flag("secgroups", "Comma separated list of AWS security groups to update.").Envar("AKMGOAPP_SECURITY_GROUPS").Required().String()
	mapID             = kingpin.Flag("mapid", "Akamai map ID.").Envar("AKMGOAPP_MAP_ID").Required().String()
	logLevelEnvar     = kingpin.Flag("loglevel", "silence | info | debug").Default("info").Envar("AKMGOAPP_LOG_LEVEL").String()
	sgRuleDescription = kingpin.Flag("sgruledesc", "Description for a security group rule.").Default("Akamai SiteShield IP.").Envar("AKMGOAPP_SG_RULE_DESCRIPTION").String()
	mapAddress        = kingpin.Flag("mapaddress", "URL of Akamai endpoint.").Default("/siteshield/v1/maps/").Envar("AKMGOAPP_MAP_ADDR").String()
	awsRegion         = kingpin.Flag("awsregion", "AWS region to operate in.").Default("ap-southeast-2").Envar("AKMGOAPP_AWS_REGION").String()
	ackMap            = kingpin.Flag("ackmap", "If true, the map will be acknowledged.").Default("false").Envar("AKMGOAPP_ACK_MAP").Bool()

	tmplRemoveCidrOk   = "REMOVED from SG '%s': Protocol=%s, Port=%d, CIDR=%s."
	tmplRemoveCidrFail = "Unable to remove '%s' from security group '%s'. Error code: '%s', message: '%s'"
	tmplAddSgRuleOk    = "ADDED to SG %s: Protocol=%s, FromPort=%d, ToPort=%d, CIDR=%s."
	tmplRemoveSgRuleOk = "REMOVED from SG %s: Protocol=%s, FromPort=%d, ToPort=%d, CIDR=%s."
	tmplUpdateSgFail   = "Security group update failed with the code: '%s' and message: '%s'"
)

func sendNotification() {

}

// outputMsg is a wrapper that takes into account logLevel value.
// We also try to intercept and handle error notifications here.
func outputMsg(msg, level string) {
	// if we get logLevelError we disregard currentLogLevel
	if level == logLevelError {
		sendNotification()
		log.Fatalln("ERROR:", msg)
	}
	// in debug mode we print messages for bot logLevelInfo and logLevelDebug
	if currentLogLevel == logLevelDebug {
		if level == logLevelDebug || level == logLevelInfo {
			fmt.Println(msg)
		}
	} else {
		if currentLogLevel == logLevelInfo && level == logLevelInfo {
			fmt.Println(msg)
		}
	}
}

// initAndCheckEnvars performs initialization and some checks against passed variables
func initAndCheckEnvars() {
	kingpin.Parse()

	// put security groups into a slice
	secGroups = s.Split(*secGroupsEnvar, ",")

	// check logLevelEnvar
	currentLogLevel = s.ToLower(*logLevelEnvar)
	validLogLevels := []string{logLevelDebug, logLevelInfo, logLevelSilence}
	if !sliceContainsElement(validLogLevels, currentLogLevel) {
		currentLogLevel = logLevelInfo
		outputMsg("Warning: Invalid value of the log level. Switching to "+currentLogLevel, logLevelInfo)
	} else {
		if currentLogLevel == logLevelDebug {
			debugMode = true
		}
	}

	// check AWS region
	if !validAWSregion(*awsRegion) {
		outputMsg("Warning: "+*awsRegion+" doesn't seem to be a valid AWS region.", logLevelInfo)
	}

}

// akamaiMakeRequest performs a GET request to Akamai's API
// using the supplied address. The result is a response body.
func akamaiMakeRequest(address, method string) []byte {
	config, err := edgegrid.Init("~/.edgerc", "default")
	if err != nil {
		outputMsg("Unable to init an Akamai client.", logLevelError)
	}

	req, err := client.NewRequest(config, s.ToUpper(method), address, nil)
	if err != nil {
		outputMsg("Unable to create a new request.", logLevelError)
	}

	resp, err := client.Do(config, req)
	if err != nil {
		//	fmt.Printf("DEBUG: %+#v\n", err)
		outputMsg("Unable to perform an HTTP request to an Akamai endpoint.", logLevelError)
	}
	defer func(r *http.Response) {
		q := r.Body.Close()
		if q != nil {
			outputMsg("Unable to close the body.", logLevelError)
		}
	}(resp)

	//	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return body
}

func getAkamaiMap(reqAddr string) (akamaiMapToReturn AkamaiMap) {
	akmReq := akamaiMakeRequest(reqAddr, "GET")
	err := json.Unmarshal(akmReq, &akamaiMapToReturn)
	if err != nil {
		outputMsg("Unable to parse the response body.", logLevelError)
	}
	return akamaiMapToReturn
}

func acknowledgeAkamaiMap(mapAddrURL string) []byte {
	return akamaiMakeRequest(mapAddrURL+"/acknowledge", "POST")
}

// checkMap performs some validation checks against a map.
func checkMap(aMap *AkamaiMap) (checkPassed bool, errMsg string) {
	checkPassed = true

	// check if the map has been acknowledged?
	if aMap.Acknowledged {
		tmp := fmt.Sprintf("The map '%s' has already been acknowledged by %s. No need to continue.", aMap.MapAlias, aMap.AcknowledgedBy)
		outputMsg(tmp, logLevelInfo)
		// since we don't need to proceed the job is done, exit with success code.
		os.Exit(0)
	}
	return
}
func printMapInfo(bMap *AkamaiMap, expandCIDR bool) {
	tmp := ""
	outputMsg("--- Map info ---", logLevelInfo)
	outputMsg("Map alias: "+bMap.MapAlias, logLevelInfo)
	tmp = fmt.Sprintf("Current CIDRs: %d\nProposed CIDRs: %d", len(bMap.CurrentCidrs), len(bMap.ProposedCidrs))
	outputMsg(tmp, logLevelInfo)

	// by design its for debug purposes only so we don't use outputMsg() here
	if expandCIDR {
		fmt.Println("Current CIDR (expanded): ", bMap.CurrentCidrs)
		fmt.Println("Proposed CIDR (expanded) ", bMap.ProposedCidrs)
	}
	addedSlice, removedSlice := returnDiff(bMap.CurrentCidrs, bMap.ProposedCidrs)
	tmp = fmt.Sprintf("Changes:\n- Added: %s\n- Removed: %s", addedSlice, removedSlice)
	outputMsg(tmp, logLevelInfo)

}

// findDiff shows the difference between 2 slices.
// It returns elements from newSlice that don't exist in oldSlice.
// in other words it performs "newSlice minus OldSlice".
func findDiff(oldSlice, newSlice []string) []string {
	diffSlice := []string{}
	sOld := s.Join(oldSlice, ",")
	for _, i := range newSlice {
		if !s.Contains(sOld, i) {
			diffSlice = append(diffSlice, i)
		}
	}
	return diffSlice
}

func sliceContainsElement(sliceToCheck []string, elem string) bool {
	elemSlice := []string{elem}
	if x := findDiff(sliceToCheck, elemSlice); len(x) == 1 && x[0] == elem {
		return false
	}
	return true

}

// func slicesAreEqual(slice1, slice2 []string) bool {
// 	if findDiff(slice1, slice2) == nil && findDiff(slice2, slice1) == nil && len(slice1) == len(slice2) {
// 		return true
// 	}
// 	return false
// }

func returnDiff(oldSlice, newSlice []string) (addedItems, removedItems []string) {
	addedItems = findDiff(oldSlice, newSlice)
	removedItems = findDiff(newSlice, oldSlice)
	return
}

// extractIP returns a string value containing an IP address
// func extractIP(inpStr string) string {
// 	ipAddrRegexp := regexp.MustCompile(`([\d]){1,3}\.([\d]){1,3}\.([\d]){1,3}\.([\d]){1,3}`)
// 	return ipAddrRegexp.FindString(inpStr)
// }

// validAWSregion returns true if a string representing a region
// matches format from
// https://docs.aws.amazon.com/general/latest/gr/rande.html
func validAWSregion(inpStr string) bool {
	regionRegexp := regexp.MustCompile(`([a-z]){2}-([a-z]){3,20}-([\d]){1,2}`)
	return regionRegexp.MatchString(inpStr)
}

func printSgInfo(grp *ec2.SecurityGroup, expandRules bool) {
	tmp := ""
	//outputMsg("--- Security Group info ---", logLevelInfo)
	tmp = fmt.Sprintf("\nGroupID: %s \nGroupName: %s \nNumber of protocols: %d", *grp.GroupId, *grp.GroupName, len(grp.IpPermissions))
	outputMsg(tmp, logLevelInfo)

	// by design its for debug purposes only so we don't use outputMsg() here
	if expandRules {
		for ii, q := range grp.IpPermissions {
			tmp = fmt.Sprintf("Protocol %d: %s,%d -> %d, total CIDRs: %d", ii+1, *q.IpProtocol, *q.FromPort, *q.ToPort, len(q.IpRanges))
			fmt.Println(tmp)
			for i, q1 := range q.IpRanges {
				tmp = fmt.Sprintf("- CIDR %d: %s", i+1, *q1.CidrIp)
				outputMsg(tmp, logLevelDebug)
			}

		}
	}
}

// extractCIDRs returns a slice containing IP ranges for a specific port within a security group
func extractCIDRs(securityGroup *ec2.SecurityGroup, matchFromPort int64) []string {
	varToSaveCIDRs := []string{}
	for _, sgPerm := range securityGroup.IpPermissions {
		// custom protocols in a SG don't have fields with ports.
		if sgPerm.FromPort != nil {
			if matchFromPort == *sgPerm.FromPort {
				for _, ipBlock := range sgPerm.IpRanges {
					varToSaveCIDRs = append(varToSaveCIDRs, *ipBlock.CidrIp)
				}
			}
		}
	}
	return varToSaveCIDRs
}

// editSecurityGroupRules updates a security group by adding (addThisRule=true) or removing a rule (addThisRule=false).
// In case of removing a rule, the value of 'descr' is ignored, that allows us deleting rules with any description.
func editSecurityGroupRules(ec2object *ec2.EC2, group *ec2.DescribeSecurityGroupsOutput, groupIndex int, portFrom, portTo int64, cidr string, descr *string, prot string, addThisRule, verbose bool) {
	var err error
	var msg string
	ipPerm := []*ec2.IpPermission{
		{
			FromPort:   aws.Int64(portFrom),
			IpProtocol: aws.String(prot),
			IpRanges: []*ec2.IpRange{
				{
					CidrIp: aws.String(cidr),
				},
			},
			ToPort: aws.Int64(portTo),
		},
	}

	// action
	if addThisRule {
		// put a description only when adding a rule.
		// since we're adding just one element, its index is 0.
		ipPerm[0].IpRanges[0].Description = descr

		input := &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:       aws.String(*group.SecurityGroups[groupIndex].GroupId),
			IpPermissions: ipPerm,
		}
		_, err = ec2object.AuthorizeSecurityGroupIngress(input)
		msg = fmt.Sprintf(tmplAddSgRuleOk, *group.SecurityGroups[groupIndex].GroupId, prot, portFrom, portTo, cidr)
	} else {
		input := &ec2.RevokeSecurityGroupIngressInput{
			GroupId:       aws.String(*group.SecurityGroups[groupIndex].GroupId),
			IpPermissions: ipPerm,
		}
		_, err = ec2object.RevokeSecurityGroupIngress(input)
		msg = fmt.Sprintf(tmplRemoveSgRuleOk, *group.SecurityGroups[groupIndex].GroupId, prot, portFrom, portTo, cidr)
	}

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			msgTxt := fmt.Sprintf(tmplUpdateSgFail, aerr.Code(), aerr.Message())
			outputMsg(msgTxt, logLevelError)
		}
		//return
	} else {
		if verbose {
			// this will execute when in debug mode
			fmt.Println("[Success]", msg)
		}
	}
}

// removeIpv4CIDR removes a given IPv4 CIDR block
func removeIpv4CIDR(ec2object *ec2.EC2, group *ec2.DescribeSecurityGroupsOutput, groupIndex int, CIDRtoRemove string, verbose bool) {
	var err error
	var msg string
	// loop through protocols
	for _, sgPerm := range group.SecurityGroups[groupIndex].IpPermissions {
		// loop through CIDR blocks
		for _, ipBlock := range sgPerm.IpRanges {
			// checking if the CIDR exist
			if *ipBlock.CidrIp == CIDRtoRemove {
				ipPerm := []*ec2.IpPermission{
					{
						IpProtocol: aws.String(*sgPerm.IpProtocol),
						FromPort:   aws.Int64(*sgPerm.FromPort),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp: aws.String(CIDRtoRemove),
							},
						},
						ToPort: aws.Int64(*sgPerm.ToPort),
					},
				}

				input := &ec2.RevokeSecurityGroupIngressInput{
					GroupId:       aws.String(*group.SecurityGroups[groupIndex].GroupId),
					IpPermissions: ipPerm,
				}

				_, err = ec2object.RevokeSecurityGroupIngress(input)

				if err != nil {
					if aerr, ok := err.(awserr.Error); ok {
						msg = fmt.Sprintf(tmplRemoveCidrFail, CIDRtoRemove, *group.SecurityGroups[groupIndex].GroupId, aerr.Code(), aerr.Message())
						outputMsg(msg, logLevelError)
					}
				} else {
					msg = fmt.Sprintf(tmplRemoveCidrOk, *group.SecurityGroups[groupIndex].GroupId, *sgPerm.IpProtocol, *sgPerm.FromPort, CIDRtoRemove)
					if verbose {
						outputMsg(msg, logLevelInfo)
					}
				}
			} // exists
		} // end loop through CIDR blocks
	} // end loop through protocols

}

// removeIpv6CIDR removes a given IPv6 CIDR block
func removeIpv6CIDR(ec2object *ec2.EC2, group *ec2.DescribeSecurityGroupsOutput, groupIndex int, CIDRtoRemove string, verbose bool) {
	var err error
	var msg string
	// loop through protocols
	for _, sgPerm := range group.SecurityGroups[groupIndex].IpPermissions {
		// loop through CIDR blocks
		for _, ipBlock := range sgPerm.Ipv6Ranges {
			// checking if the CIDR exist
			if *ipBlock.CidrIpv6 == CIDRtoRemove {
				ipPerm := []*ec2.IpPermission{
					{
						IpProtocol: aws.String(*sgPerm.IpProtocol),
						FromPort:   aws.Int64(*sgPerm.FromPort),
						Ipv6Ranges: []*ec2.Ipv6Range{
							{
								CidrIpv6: aws.String(CIDRtoRemove),
							},
						},
						ToPort: aws.Int64(*sgPerm.ToPort),
					},
				}

				input := &ec2.RevokeSecurityGroupIngressInput{
					GroupId:       aws.String(*group.SecurityGroups[groupIndex].GroupId),
					IpPermissions: ipPerm,
				}

				_, err = ec2object.RevokeSecurityGroupIngress(input)

				if err != nil {
					if aerr, ok := err.(awserr.Error); ok {
						msg = fmt.Sprintf(tmplRemoveCidrFail, CIDRtoRemove, *group.SecurityGroups[groupIndex].GroupId, aerr.Code(), aerr.Message())
						outputMsg(msg, logLevelError)
					}
				} else {
					msg = fmt.Sprintf(tmplRemoveCidrOk, *group.SecurityGroups[groupIndex].GroupId, *sgPerm.IpProtocol, *sgPerm.FromPort, CIDRtoRemove)
					if verbose {
						outputMsg(msg, logLevelInfo)
					}
				}
			} // exists
		} // end loop through CIDR blocks
	} // end loop through protocols

}

func main() {
	initAndCheckEnvars()

	// ------------------------------------------
	//		Stage 1. Get an Akamai map
	akamaiMapReady = getAkamaiMap(*mapAddress + *mapID)
	printMapInfo(&akamaiMapReady, debugMode)

	checkPassed, checkErrMsg := checkMap(&akamaiMapReady)
	if !checkPassed {
		log.Fatalln(checkErrMsg)
	}

	// ------------------------------------------
	//		Stage 2. Query AWS security groups

	// create a new AWS session object
	awsSession, err := session.NewSession(&aws.Config{
		CredentialsChainVerboseErrors: aws.Bool(true),
		Region:                        aws.String(*awsRegion),
		MaxRetries:                    aws.Int(3),
	})
	if err != nil {
		outputMsg("Can't create AWS session.", logLevelError)
	}

	// create a new ec2 client
	svcEC2 := ec2.New(awsSession)
	// filter the security groups
	DescribeSecurityGroupsInput := &ec2.DescribeSecurityGroupsInput{
		GroupIds: aws.StringSlice(secGroups),
	}
	resEC2, errEC2 := svcEC2.DescribeSecurityGroups(DescribeSecurityGroupsInput)

	if errEC2 != nil {
		if aerr, ok := errEC2.(awserr.Error); ok {
			outputMsg("An error occurred while querying security groups: "+aerr.Message(), logLevelError)
		}

	}

	// ------------------------------------------
	//		Stage 3. Syncing CIDRs

	// loop through the returned SGs and update them
	for idx, group := range resEC2.SecurityGroups {
		printSgInfo(group, debugMode)
		// putting current AWS SG IP ranges into slices
		cidrsPort80 = extractCIDRs(group, 80)
		cidrsPort443 = extractCIDRs(group, 443)

		// loop through the Akamai's proposed list of CIDR blocks
		// and add CIDR blocks that don't present in the SG
		for _, ipAddr := range akamaiMapReady.ProposedCidrs {
			if !sliceContainsElement(cidrsPort80, ipAddr) {
				editSecurityGroupRules(svcEC2, resEC2, idx, 80, 80, ipAddr, sgRuleDescription, "tcp", true, debugMode)
			}
			if !sliceContainsElement(cidrsPort443, ipAddr) {
				editSecurityGroupRules(svcEC2, resEC2, idx, 443, 443, ipAddr, sgRuleDescription, "tcp", true, debugMode)
			}
		}

		// removing CIDRs from AWS SG that have been deleted from last map's acknowledgement
		_, removedCIDR := returnDiff(akamaiMapReady.CurrentCidrs, akamaiMapReady.ProposedCidrs)
		for _, ipAddr := range removedCIDR {
			if sliceContainsElement(cidrsPort80, ipAddr) {
				editSecurityGroupRules(svcEC2, resEC2, idx, 80, 80, ipAddr, sgRuleDescription, "tcp", false, debugMode)
			}
			if sliceContainsElement(cidrsPort443, ipAddr) {
				editSecurityGroupRules(svcEC2, resEC2, idx, 443, 443, ipAddr, sgRuleDescription, "tcp", false, debugMode)
			}
		}
		// removing wide IP ranges
		removeIpv4CIDR(svcEC2, resEC2, idx, "0.0.0.0/0", debugMode)
		removeIpv6CIDR(svcEC2, resEC2, idx, "::/0", debugMode)
	} // finished loop

	// ------------------------------------------
	//		Stage 4. Acknowledge the Akamai map

	// we acknowledge the map only when the switch is set.
	// By default we don't.
	if *ackMap {
		outputMsg("\nThe map has been acknowledged.", logLevelInfo)
		acknowledgeAkamaiMap(*mapAddress + *mapID)
	} else {
		outputMsg("\nThe map has NOT been acknowledged.", logLevelInfo)
	}

}
