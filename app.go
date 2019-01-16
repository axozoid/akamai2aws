package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"regexp"
	s "strings"

	client "github.com/akamai/AkamaiOPEN-edgegrid-golang/client-v1"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/edgegrid"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elb"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

const (
	sgRulesLimit = 60
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

type akamaiMapAcknoledgeResponse struct {
	_ struct{}
}

var (
	akamaiMapReady                       AkamaiMap
	logLevel                             string
	cidrsPort443, cidrsPort80, secGroups []string
	debugMode                            bool

	secGroupsEnvar    = kingpin.Flag("secgroups", "Comma separated list of AWS security groups to update.").Envar("AKMGOAPP_SECURITY_GROUPS").Required().String()
	mapID             = kingpin.Flag("mapid", "Akamai map ID.").Envar("AKMGOAPP_MAP_ID").Required().String()
	logLevelEnvar     = kingpin.Flag("loglevel", "debug | info | error").Default("info").Envar("AKMGOAPP_LOG_LEVEL").String()
	sgRuleDescription = kingpin.Flag("sgruledesc", "Description for a security group rule.").Default("Akamai SiteShield IP.").Envar("AKMGOAPP_SG_RULE_DESCRIPTION").String()
	mapAddress        = kingpin.Flag("mapaddress", "URL of Akamai endpoint.").Default("/siteshield/v1/maps/").Envar("AKMGOAPP_MAP_ADDR").String()
	awsRegion         = kingpin.Flag("awsregion", "AWS region to operate in.").Default("ap-southeast-2").Envar("AKMGOAPP_AWS_REGION").String()
	ackMap            = kingpin.Flag("ackmap", "If true, the map will be acknowledged.").Default("false").Envar("AKMGOAPP_ACK_MAP").Bool()
)

// outputMsg is a wrapper that takes into account logLevel value
func outputMsg(msg, level string) {
	if level == logLevel {
		switch level {
		case "debug", "info":
			log.Println(msg)
		case "error":
			log.Fatalln(msg)
		}

	}
}

// initAndCheckEnvars performs initialization and some checks against passed variables
func initAndCheckEnvars() {
	kingpin.Parse()

	// put security groups into a slice
	secGroups = s.Split(*secGroupsEnvar, ",")

	// check logLevelEnvar
	logLevel = s.ToLower(*logLevelEnvar)
	validLogLevels := []string{"info", "debug", "warning"}
	if !sliceContainsElement(validLogLevels, logLevel) {
		log.Println("Invalid value of the log level. Switching to 'info'.")
		logLevel = "info"
	} else {
		if logLevel == "debug" {
			debugMode = true
		}
	}

	// check AWS region
	if !validAWSregion(*awsRegion) {
		fmt.Println("Error:", *awsRegion, "doesn't seem to be a valid AWS region.")
	}

}

// akamaiMakeRequest performs a GET request to Akamai's API
// using the supplied address. The result is a response body.
func akamaiMakeRequest(address, method string) []byte {
	config, err := edgegrid.Init("~/.edgerc", "default")
	if err != nil {
		log.Fatal("Error: Unable to init Akamai client.")
	}

	req, err := client.NewRequest(config, s.ToUpper(method), address, nil)
	if err != nil {
		log.Fatal("Error: Unable to create a new request.")
	}

	resp, err := client.Do(config, req)
	if err != nil {
		log.Fatal("Error: Unable to perform an HTTP request.")
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	//fmt.Println(string(byt))
	return body
}

func getAkamaiMap(reqAddr string) (akamaiMapToReturn AkamaiMap) {
	akmReq := akamaiMakeRequest(reqAddr, "GET")
	err := json.Unmarshal(akmReq, &akamaiMapToReturn)
	if err != nil {
		log.Fatal("Error: Unable to parse the response body.")
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
		errMsg = fmt.Sprintf("The map '%s' has already been acknowledged by %s. No need to continue.", aMap.MapAlias, aMap.AcknowledgedBy)
		// since we don't need to update a SG the job is done.
		checkPassed = false
	}
	return
}
func printMapInfo(bMap *AkamaiMap, expandCIDR bool) {
	fmt.Println("--- Map info ---")
	fmt.Println("Map alias:", bMap.MapAlias)
	fmt.Printf("- Current CIDRs: %d\n- Proposed CIDRs: %d.\n", len(bMap.CurrentCidrs), len(bMap.ProposedCidrs))
	if expandCIDR {
		fmt.Println("Current CIDR: ", bMap.CurrentCidrs)
		fmt.Println("Proposed CIDR: ", bMap.ProposedCidrs)
	}
	addedSlice, removedSlice := returnDiff(bMap.CurrentCidrs, bMap.ProposedCidrs)
	fmt.Printf("Changes:\n- Added: %s\n- Removed: %s\n\n", addedSlice, removedSlice)
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
	} else {
		return true
	}
}

func slicesAreEqual(slice1, slice2 []string) bool {
	if findDiff(slice1, slice2) == nil && findDiff(slice2, slice1) == nil && len(slice1) == len(slice2) {
		return true
	} else {
		return false
	}
}

func returnDiff(oldSlice, newSlice []string) (addedItems, removedItems []string) {
	addedItems = findDiff(oldSlice, newSlice)
	removedItems = findDiff(newSlice, oldSlice)
	return
}

// extractIP returns a string value containing an IP address
func extractIP(inpStr string) string {
	ipAddrRegexp := regexp.MustCompile(`([\d]){1,3}\.([\d]){1,3}\.([\d]){1,3}\.([\d]){1,3}`)
	return ipAddrRegexp.FindString(inpStr)
}

// validAWSregion returns true if a string representing a region
// matches format from
// https://docs.aws.amazon.com/general/latest/gr/rande.html
func validAWSregion(inpStr string) bool {
	regionRegexp := regexp.MustCompile(`([a-z]){2}-([a-z]){3,20}-([\d]){1,2}`)
	return regionRegexp.MatchString(inpStr)
}

func printELBInfo(elbObject *elb.LoadBalancerDescription) {
	fmt.Println("--- ELB info ---")
	//fmt.Printf()
	fmt.Printf(" - Name: %s, \n - DNS-name: %s \n", *elbObject.LoadBalancerName, *elbObject.DNSName)
	fmt.Println(" - Attached security groups: ", len(elbObject.SecurityGroups))
}

func printSgInfo(grp *ec2.SecurityGroup, expandRules bool) {
	fmt.Println("")
	fmt.Println("--- Security Group info ---")
	fmt.Printf(" - GroupID: %s \n - GroupName: %s \n", *grp.GroupId, *grp.GroupName)
	fmt.Println(" - Number of rules: ", len(grp.IpPermissions))
	if expandRules {
		for _, q := range grp.IpPermissions {
			ss := fmt.Sprintf(" -- %s,%d -> %d, total CIDRs: %d", *q.IpProtocol, *q.FromPort, *q.ToPort, len(q.IpRanges))
			fmt.Println(ss)
		}
	}
}

// extractCIDRs returns a slice containing IP ranges for a specific port within a security group
func extractCIDRs(securityGroup *ec2.SecurityGroup, matchFromPort int64) []string {
	varToSaveCIDRs := []string{}
	for _, sgPerm := range securityGroup.IpPermissions {
		// fmt.Println("--->>>", sgPerm) // debug
		if matchFromPort == *sgPerm.FromPort {
			for _, ipBlock := range sgPerm.IpRanges {
				varToSaveCIDRs = append(varToSaveCIDRs, *ipBlock.CidrIp)
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
		// put a description only when adding a rule
		ipPerm[0].IpRanges[0].Description = descr

		input := &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:       aws.String(*group.SecurityGroups[groupIndex].GroupId),
			IpPermissions: ipPerm,
		}
		_, err = ec2object.AuthorizeSecurityGroupIngress(input)
		msg = fmt.Sprintf("ADDED to SG name: %s, Protocol: %s, FromPort: %d, ToPort: %d, CIDR: %s.", *group.SecurityGroups[groupIndex].GroupId, prot, portFrom, portTo, cidr)
	} else {
		input := &ec2.RevokeSecurityGroupIngressInput{
			GroupId:       aws.String(*group.SecurityGroups[groupIndex].GroupId),
			IpPermissions: ipPerm,
		}
		_, err = ec2object.RevokeSecurityGroupIngress(input)
		msg = fmt.Sprintf("REMOVED from SG name: %s, Protocol: %s, FromPort: %d, ToPort: %d, CIDR: %s.", *group.SecurityGroups[groupIndex].GroupId, prot, portFrom, portTo, cidr)
	}

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Fatalln(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Fatalln(err.Error())
		}
		//return
	} else {
		if verbose {
			fmt.Println("[Success]", msg)
		}
	}
}

func main() {
	initAndCheckEnvars()

	// ------------------------------------------
	//		Request the map from Akamai
	akamaiMapReady = getAkamaiMap(*mapAddress + *mapID)
	printMapInfo(&akamaiMapReady, debugMode)
	checkPassed, checkErrMsg := checkMap(&akamaiMapReady)
	if !checkPassed {
		log.Fatalln(checkErrMsg)
	}

	// create a new AWS session object
	awsSession, err := session.NewSession(&aws.Config{
		Region:     aws.String(*awsRegion),
		MaxRetries: aws.Int(3),
	})
	if err != nil {
		log.Fatalln("Error: Can't create AWS session.")
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
			log.Fatalln("Error:", aerr.Code(), aerr.Message())
		}

	}
	// showing a notice if not all SGs are found
	if df := len(secGroups) - len(resEC2.SecurityGroups); df > 0 {
		fmt.Println(fmt.Printf("Warning: %d of %d security groups not found.", df, len(secGroups)))
	}

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
				editSecurityGroupRules(svcEC2, resEC2, idx, 80, 80, ipAddr, sgRuleDescription, "tcp", true, true)
			}
			if !sliceContainsElement(cidrsPort443, ipAddr) {
				editSecurityGroupRules(svcEC2, resEC2, idx, 443, 443, ipAddr, sgRuleDescription, "tcp", true, true)
			}
		}

		// removing CIDRs from AWS SG that have been deleted from Akamai
		_, removedCIDR := returnDiff(akamaiMapReady.CurrentCidrs, akamaiMapReady.ProposedCidrs)
		for _, ipAddr := range removedCIDR {
			if sliceContainsElement(cidrsPort80, ipAddr) {
				editSecurityGroupRules(svcEC2, resEC2, idx, 80, 80, ipAddr, sgRuleDescription, "tcp", false, true)
			}
			if sliceContainsElement(cidrsPort443, ipAddr) {
				editSecurityGroupRules(svcEC2, resEC2, idx, 443, 443, ipAddr, sgRuleDescription, "tcp", false, true)
			}
		}

	}

	// ------------------------------------------
	//		Acknowledge the Akamai map

	if *ackMap {
		fmt.Println("The map has been acknowledged.")
		acknowledgeAkamaiMap(*mapAddress + *mapID)
	} else {
		fmt.Println("The map has NOT been acknowledged.")
	}

	fmt.Println("Done.")
}
