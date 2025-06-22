package eksapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"strings"
	"time"

	vpccniv1alpha1 "github.com/aws/amazon-vpc-cni-k8s/pkg/apis/crd/v1alpha1"

	vpccontrollerv1beta1 "github.com/aws/amazon-vpc-resource-controller-k8s/apis/vpcresources/v1beta1"

	"github.com/aws/aws-k8s-tester/internal/deployers/eksapi/templates"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
)

const (
	addonCreationTimeout = 5 * time.Minute
)

type AddonManager struct {
	clients *awsClients
}

func NewAddonManager(clients *awsClients) *AddonManager {
	return &AddonManager{
		clients: clients,
	}
}

func (m *AddonManager) createAddons(infra *Infrastructure, cluster *Cluster, opts *deployerOptions) error {
	for _, addon := range opts.Addons {
		addonParts := strings.Split(addon, ":")
		if len(addonParts) != 2 {
			return fmt.Errorf("invalid addon: %s", addon)
		}
		name := addonParts[0]
		version := addonParts[1]
		klog.Infof("resolving addon %s version: %s", name, version)
		resolvedVersion, err := m.resolveAddonVersion(name, version, opts.KubernetesVersion)
		if err != nil {
			return err
		}
		klog.Infof("creating addon %s version: %s", name, resolvedVersion)
		input := eks.CreateAddonInput{
			AddonName:    aws.String(name),
			AddonVersion: aws.String(resolvedVersion),
			ClusterName:  aws.String(cluster.name),
		}
		_, err = m.clients.EKS().CreateAddon(context.TODO(), &input)
		if err != nil {
			return fmt.Errorf("failed to create addon: %v", err)
		}
		klog.Infof("waiting for addon to be active: %s", name)
		err = eks.NewAddonActiveWaiter(m.clients.EKS()).
			Wait(context.TODO(), &eks.DescribeAddonInput{
				ClusterName: aws.String(cluster.name),
				AddonName:   aws.String(name),
			}, addonCreationTimeout)
		if err != nil {
			return fmt.Errorf("failed to wait for addon to be active: %v", err)
		}
	}
	return nil
}

func (m *AddonManager) resolveAddonVersion(name string, versionMarker string, kubernetesVersion string) (string, error) {
	input := eks.DescribeAddonVersionsInput{
		AddonName:         aws.String(name),
		KubernetesVersion: aws.String(kubernetesVersion),
	}
	descOutput, err := m.clients.EKS().DescribeAddonVersions(context.TODO(), &input)
	if err != nil {
		return "", err
	}
	for _, addon := range descOutput.Addons {
		for _, versionInfo := range addon.AddonVersions {
			switch versionMarker {
			case "latest":
				return *versionInfo.AddonVersion, nil
			case "default":
				for _, compatibility := range versionInfo.Compatibilities {
					if compatibility.DefaultVersion {
						return *versionInfo.AddonVersion, nil
					}
				}
			default:
				if *versionInfo.AddonVersion == versionMarker {
					return *versionInfo.AddonVersion, nil
				}
			}
		}
	}
	return "", fmt.Errorf("failed to resolve addon version: %s=%s", name, versionMarker)
}

func generateVPCCNIEnvVars(opts *deployerOptions) []templates.EnvironmentVariable {
	envVarMap := make(map[string]string)
	if opts.EnableCustomNetworking {
		envVarMap["AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG"] = "true"
	}
	if opts.EnableSecurityGroupsForPods {
		envVarMap["ENABLE_POD_ENI"] = "true"
		envVarMap["DISABLE_TCP_EARLY_DEMUX"] = "true"
	}
	if opts.TuneVPCCNI {
		envVarMap["ENABLE_PREFIX_DELEGATION"] = "true"
		envVarMap["MINIMUM_IP_TARGET"] = "80"
		envVarMap["WARM_IP_TARGET"] = "10"
	}

	// merge with user provided config, overrides defaults
	maps.Copy(envVarMap, opts.VPCCNIEnvVars)

	var envVars []templates.EnvironmentVariable
	for name, value := range envVarMap {
		envVars = append(envVars, templates.EnvironmentVariable{
			Name:  name,
			Value: value,
		})
	}
	return envVars
}

func (m *AddonManager) createSecurityGroupPolicy(d *deployer) error {
	klog.Infof("Creating default SecurityGroupPolicy to mach sgpp=true")
	if err := d.k8sClient.client.Create(context.TODO(), &vpccontrollerv1beta1.SecurityGroupPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "vpcresources.k8s.aws/v1beta1",
			Kind:       "SecurityGroupPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "default-security-group-policy",
		},
		Spec: vpccontrollerv1beta1.SecurityGroupPolicySpec{
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"sgpp": "true",
				},
			},
			SecurityGroups: vpccontrollerv1beta1.GroupIds{
				// TODO: use a different security group
				Groups: []string{d.cluster.securityGroupId},
			},
		},
	}); err != nil {
		return err
	}
	klog.Infof("Finished creating default SecurityGroupPolicy")
	return nil
}

func (m *AddonManager) createENIConfigs(d *deployer) error {
	// as a simplification, use private subnet for ENIConfig. assumes nodes are launched in public
	// subnet, and helps meet guarantee that SGPP pods, if used, are in private subnets
	// https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html
	targetSubnets := d.infra.subnetsPrivate
	klog.Infof("Creating ENIConfigs with subnets %v", targetSubnets)
	describeResponse, err := m.clients.EC2().DescribeSubnets(context.TODO(), &ec2.DescribeSubnetsInput{
		SubnetIds: targetSubnets,
	})
	if err != nil {
		return err
	}
	// TODO: set up a separate security group for ENI config
	for _, subnet := range describeResponse.Subnets {
		azID := aws.ToString(subnet.AvailabilityZoneId)
		klog.Infof("Creating ENIConfigs %s", azID)
		d.k8sClient.client.Create(context.TODO(), &vpccniv1alpha1.ENIConfig{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "crd.k8s.amazonaws.com/v1alpha1",
				Kind:       "ENIConfig",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: azID,
			},
			Spec: vpccniv1alpha1.ENIConfigSpec{
				SecurityGroups: []string{d.cluster.securityGroupId},
				Subnet:         aws.ToString(subnet.SubnetId),
			},
		})
	}
	klog.Infof("Finished creating ENIConfigs")
	return nil
}

func (m *AddonManager) patchVPCCNI(d *deployer) error {
	envVars := generateVPCCNIEnvVars(&d.deployerOptions)
	patchTemplate := templates.VPCCNITemplateData{
		EnvironmentVariables: envVars,
		AWSNodeImageURI:      d.deployerOptions.VPCCNIImageURI,
	}

	if reflect.DeepEqual(patchTemplate, templates.VPCCNITemplateData{}) {
		klog.Info("Skipping patching the VPC CNI, no change detected")
		return nil
	}
	klog.Info("Patching the VPC CNI...")
	var buf bytes.Buffer
	if err := templates.VPCCNIDaemonSetPatch.Execute(&buf, patchTemplate); err != nil {
		return err
	}
	var patch bytes.Buffer
	if err := json.Compact(&patch, buf.Bytes()); err != nil {
		return err
	}
	if _, err := d.k8sClient.clientset.AppsV1().DaemonSets("kube-system").Patch(context.TODO(), "aws-node", types.StrategicMergePatchType, patch.Bytes(), metav1.PatchOptions{}); err != nil {
		return err
	}
	klog.Info("Finished patching the VPC CNI...")
	return nil
}

func (m *AddonManager) configureVPCCNI(d *deployer) error {
	if err := m.patchVPCCNI(d); err != nil {
		return err
	}

	if d.deployerOptions.EnableCustomNetworking {
		if err := m.createENIConfigs(d); err != nil {
			return err
		}
	}

	if d.deployerOptions.EnableSecurityGroupsForPods {
		if err := m.createSecurityGroupPolicy(d); err != nil {
			return err
		}
	}
	return nil
}
