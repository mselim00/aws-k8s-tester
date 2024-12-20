package eksapi

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cloudformationtypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"k8s.io/klog"

	"github.com/aws/aws-k8s-tester/kubetest2/internal/deployers/eksapi/templates"
	"github.com/aws/aws-k8s-tester/kubetest2/internal/metrics"
)

const (
	infraStackCreationTimeout         = time.Minute * 15
	infraStackDeletionTimeout         = time.Minute * 15
	networkInterfaceDetachmentTimeout = time.Minute * 5
)

const (
	// the VPC CNI will always add this tag to ENI's that it creates
	vpcCNIENITagKey = "node.k8s.amazonaws.com/createdAt"
)

// eksEndpointURLTag is the key for an optional tag on the infrastructure CloudFormation stack,
// which indicates which EKS environment is associated with the stack's resources.
// The tag is only added when --endpoint-url is passed to the deployer.
const eksEndpointURLTag = "eks-endpoint-url"

var (
	infraMetricNamespace     = path.Join(DeployerMetricNamespace, "infrastructure")
	infraStackDeletionFailed = &metrics.MetricSpec{
		Namespace: infraMetricNamespace,
		Metric:    "StackDeletionFailed",
		Unit:      cloudwatchtypes.StandardUnitCount,
	}
	infraLeakedENIs = &metrics.MetricSpec{
		Namespace: infraMetricNamespace,
		Metric:    "LeakedENIs",
		Unit:      cloudwatchtypes.StandardUnitCount,
	}
)

type InfrastructureManager struct {
	clients    *awsClients
	resourceID string
	metrics    metrics.MetricRegistry
}

func NewInfrastructureManager(clients *awsClients, resourceID string, metrics metrics.MetricRegistry) *InfrastructureManager {
	return &InfrastructureManager{
		clients:    clients,
		resourceID: resourceID,
		metrics:    metrics,
	}
}

type Infrastructure struct {
	vpc              string
	subnetsPublic    []string
	subnetsPrivate   []string
	clusterRole      string
	nodeRole         string
	sshSecurityGroup string
	sshKeyPair       string
}

func (i *Infrastructure) subnets() []string {
	return append(i.subnetsPublic, i.subnetsPrivate...)
}

func (m *InfrastructureManager) createInfrastructureStack(opts *deployerOptions) (*Infrastructure, error) {
	publicKeyMaterial, err := loadSSHPublicKey()
	if err != nil {
		return nil, err
	}
	// get two AZs for the subnets
	azs, err := m.clients.EC2().DescribeAvailabilityZones(context.TODO(), &ec2.DescribeAvailabilityZonesInput{})
	if err != nil {
		return nil, err
	}
	var subnetAzs []string
	if opts.CapacityReservation {
		subnetAzs, err = m.getAZsWithCapacity(opts)
		if err != nil {
			return nil, err
		}
		for _, az := range azs.AvailabilityZones {
			if len(subnetAzs) == 2 {
				break
			}
			if !slices.Contains(subnetAzs, *az.ZoneName) {
				subnetAzs = append(subnetAzs, *az.ZoneName)
			}
		}
	} else {
		for i := 0; i < 2; i++ {
			subnetAzs = append(subnetAzs, *azs.AvailabilityZones[i].ZoneName)
		}
	}
	klog.Infof("creating infrastructure stack with AZs: %v", subnetAzs)
	input := cloudformation.CreateStackInput{
		StackName:    aws.String(m.resourceID),
		TemplateBody: aws.String(templates.Infrastructure),
		Capabilities: []cloudformationtypes.Capability{cloudformationtypes.CapabilityCapabilityIam},
		Parameters: []cloudformationtypes.Parameter{
			{
				ParameterKey:   aws.String("SSHPublicKeyMaterial"),
				ParameterValue: aws.String(publicKeyMaterial),
			},
			{
				ParameterKey:   aws.String("ResourceId"),
				ParameterValue: aws.String(m.resourceID),
			},
			{
				ParameterKey:   aws.String("Subnet01AZ"),
				ParameterValue: aws.String(subnetAzs[0]),
			},
			{
				ParameterKey:   aws.String("Subnet02AZ"),
				ParameterValue: aws.String(subnetAzs[1]),
			},
		},
	}
	if opts.ClusterRoleServicePrincipal != "" {
		input.Parameters = append(input.Parameters, cloudformationtypes.Parameter{
			ParameterKey:   aws.String("AdditionalClusterRoleServicePrincipal"),
			ParameterValue: aws.String(opts.ClusterRoleServicePrincipal),
		})
	}
	if opts.EKSEndpointURL != "" {
		input.Tags = []cloudformationtypes.Tag{
			{
				Key:   aws.String(eksEndpointURLTag),
				Value: aws.String(opts.EKSEndpointURL),
			},
		}
	}
	klog.Infof("creating infrastructure stack...")
	out, err := m.clients.CFN().CreateStack(context.TODO(), &input)
	if err != nil {
		return nil, err
	}
	klog.Infof("waiting for infrastructure stack to be created: %s", *out.StackId)
	err = cloudformation.NewStackCreateCompleteWaiter(m.clients.CFN()).
		Wait(context.TODO(),
			&cloudformation.DescribeStacksInput{
				StackName: out.StackId,
			},
			infraStackCreationTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for infrastructure stack creation: %w", err)
	}
	klog.Infof("getting infrastructure stack resources: %s", *out.StackId)
	infra, err := m.getInfrastructureStackResources()
	if err != nil {
		return nil, fmt.Errorf("failed to get infrastructure stack resources: %w", err)
	}
	klog.Infof("created infrastructure: %+v", infra)

	return infra, nil
}

func (m *InfrastructureManager) getInfrastructureStackResources() (*Infrastructure, error) {
	stack, err := m.clients.CFN().DescribeStacks(context.TODO(), &cloudformation.DescribeStacksInput{
		StackName: aws.String(m.resourceID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe infrastructure stack: %w", err)
	}
	infra := Infrastructure{}
	for _, output := range stack.Stacks[0].Outputs {
		value := *output.OutputValue
		switch *output.OutputKey {
		case "VPC":
			infra.vpc = value
		case "SubnetsPublic":
			infra.subnetsPublic = strings.Split(value, ",")
		case "SubnetsPrivate":
			infra.subnetsPrivate = strings.Split(value, ",")
		case "ClusterRole":
			infra.clusterRole = value
		case "NodeRole":
			infra.nodeRole = value
		case "SSHSecurityGroup":
			infra.sshSecurityGroup = value
		case "SSHKeyPair":
			infra.sshKeyPair = value
		}
	}
	return &infra, nil
}

func (m *InfrastructureManager) deleteInfrastructureStack() error {
	input := cloudformation.DeleteStackInput{
		StackName: aws.String(m.resourceID),
	}
	klog.Infof("deleting infrastructure stack: %s", m.resourceID)
	_, err := m.clients.CFN().DeleteStack(context.TODO(), &input)
	if err != nil {
		var notFound *cloudformationtypes.StackNotFoundException
		if errors.As(err, &notFound) {
			klog.Infof("infrastructure stack does not exist: %s", m.resourceID)
			return nil
		}
		return fmt.Errorf("failed to delete infrastructure stack: %w", err)
	}
	klog.Infof("waiting for infrastructure stack to be deleted: %s", m.resourceID)
	err = cloudformation.NewStackDeleteCompleteWaiter(m.clients.CFN()).
		Wait(context.TODO(),
			&cloudformation.DescribeStacksInput{
				StackName: aws.String(m.resourceID),
			},
			infraStackDeletionTimeout)
	if err != nil {
		// don't fail the overall test, the janitor can clean this up
		klog.Warningf("failed to wait for infrastructure stack deletion: %v", err)
		m.metrics.Record(infraStackDeletionFailed, 1, nil)
		return nil
	}
	klog.Infof("deleted infrastructure stack: %s", m.resourceID)
	return nil
}

// deleteLeakedENIs deletes Elastic Network Interfaces that may have been allocated (and left behind) by the VPC CNI.
// These leaked ENIs will prevent deletion of their associated subnets and security groups.
func (m *InfrastructureManager) deleteLeakedENIs() error {
	infra, err := m.getInfrastructureStackResources()
	if err != nil {
		var notFound *cloudformationtypes.StackNotFoundException
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("failed to get infrastructure stack resources: %w", err)
	}
	enis, err := m.getVPCCNINetworkInterfaceIds(infra.vpc)
	if err != nil {
		return err
	}
	if len(enis) == 0 {
		return nil
	}
	klog.Infof("waiting for %d leaked ENI(s) to become available: %v", len(enis), enis)
	if err := ec2.NewNetworkInterfaceAvailableWaiter(m.clients.EC2()).Wait(context.TODO(), &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: enis,
	}, networkInterfaceDetachmentTimeout); err != nil {
		return fmt.Errorf("failed to wait for ENI(s) to become available: %v", err)
	}
	for _, eni := range enis {
		klog.Infof("deleting leaked ENI: %s", eni)
		_, err := m.clients.EC2().DeleteNetworkInterface(context.TODO(), &ec2.DeleteNetworkInterfaceInput{
			NetworkInterfaceId: aws.String(eni),
		})
		if err != nil {
			return fmt.Errorf("failed to delete leaked ENI: %w", err)
		}
	}
	klog.Infof("deleted %d leaked ENI(s)!", len(enis))
	m.metrics.Record(infraLeakedENIs, float64(len(enis)), nil)
	return nil
}

// getVPCCNINetworkInterfaceIds returns the IDs of ENIs in the specified VPC that were created by the VPC CNI
func (m *InfrastructureManager) getVPCCNINetworkInterfaceIds(vpcId string) ([]string, error) {
	paginator := ec2.NewDescribeNetworkInterfacesPaginator(m.clients.EC2(), &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []string{vpcId},
			},
			{
				Name:   aws.String("interface-type"),
				Values: []string{"interface"},
			},
			{
				Name:   aws.String("tag-key"),
				Values: []string{vpcCNIENITagKey},
			},
		},
	})
	var enis []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("failed to describe ENIs: %w", err)
		}
		for _, eni := range page.NetworkInterfaces {
			enis = append(enis, *eni.NetworkInterfaceId)
		}
	}
	return enis, nil
}

func (m *InfrastructureManager) getAZsWithCapacity(opts *deployerOptions) ([]string, error) {
	var subnetAzs []string
	capacityReservations, err := m.clients.EC2().DescribeCapacityReservations(context.TODO(), &ec2.DescribeCapacityReservationsInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("instance-type"),
				Values: opts.InstanceTypes,
			},
			{
				Name:   aws.String("state"),
				Values: []string{"active"},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	for _, cr := range capacityReservations.CapacityReservations {
		if *cr.AvailableInstanceCount >= int32(opts.Nodes) {
			subnetAzs = append(subnetAzs, *cr.AvailabilityZone)
			break
		}
	}
	return subnetAzs, nil
}
