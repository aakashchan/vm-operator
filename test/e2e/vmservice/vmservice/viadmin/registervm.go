// Copyright (c) 2024-2025 Broadcom. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package viadmin

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vmopv1a3 "github.com/vmware-tanzu/vm-operator/api/v1alpha3"
	backupapi "github.com/vmware-tanzu/vm-operator/pkg/backup/api"
	"github.com/vmware/govmomi/alarm"
	"github.com/vmware/govmomi/cns"
	cnstypes "github.com/vmware/govmomi/cns/types"
	"github.com/vmware/govmomi/event"
	"github.com/vmware/govmomi/fault"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
	"github.com/vmware/govmomi/vslm"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	e2eframework "k8s.io/kubernetes/test/e2e/framework"
	capiutil "sigs.k8s.io/cluster-api/util"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	sigsyaml "sigs.k8s.io/yaml"

	mopv1a4 "github.com/vmware-tanzu/vm-operator/external/mobility-operator/api/v1alpha4"
	cnsv1alpha1 "github.com/vmware-tanzu/vm-operator/external/vsphere-csi-driver/api/v1alpha1"
	"github.com/vmware-tanzu/vm-operator/test/e2e/infrastructure/vsphere/dcli"
	"github.com/vmware-tanzu/vm-operator/test/e2e/infrastructure/vsphere/testbed"
	"github.com/vmware-tanzu/vm-operator/test/e2e/infrastructure/vsphere/vcenter"
	"github.com/vmware-tanzu/vm-operator/test/e2e/infrastructure/vsphere/wcp"
	"github.com/vmware-tanzu/vm-operator/test/e2e/manifestbuilders"
	"github.com/vmware-tanzu/vm-operator/test/e2e/testutils"
	"github.com/vmware-tanzu/vm-operator/test/e2e/utils"
	"github.com/vmware-tanzu/vm-operator/test/e2e/vmservice/common"
	config "github.com/vmware-tanzu/vm-operator/test/e2e/vmservice/config"
	"github.com/vmware-tanzu/vm-operator/test/e2e/vmservice/consts"
	"github.com/vmware-tanzu/vm-operator/test/e2e/vmservice/lib/vmoperator"
	"github.com/vmware-tanzu/vm-operator/test/e2e/vmservice/skipper"
	"github.com/vmware-tanzu/vm-operator/test/e2e/vmservice/vmservice"
	"github.com/vmware-tanzu/vm-operator/test/e2e/wcpframework"
)

const (
	trueString = "true"

	// crvImportOpLabelKey and crvOriginalPVCLabelKey are the label keys that the
	// ImportOperation controller stamps on every CnsRegisterVolume it creates.
	// They mirror pkg/restore.ImportOperationLabelKey and OriginalPVCNameLabelKey.
	crvImportOpLabelKey    = "mobility-operator.vmware.com/import-operation"
	crvOriginalPVCLabelKey = "mobility-operator.vmware.com/original-pvc-name"
)

type VIAdminRegisterVMSpecInput struct {
	ClusterProxy     wcpframework.WCPClusterProxyInterface
	Config           *config.E2EConfig
	WCPClient        wcp.WorkloadManagementAPI
	WCPNamespaceName string
	LinuxVMName      string
}

func VIAdminRegisterVMSpec(ctx context.Context, inputGetter func() VIAdminRegisterVMSpecInput) {
	const (
		specName = "register-vm"
	)

	var (
		input                         VIAdminRegisterVMSpecInput
		wcpClient                     wcp.WorkloadManagementAPI
		config                        *config.E2EConfig
		clusterProxy                  *common.VMServiceClusterProxy
		svClusterClient               ctrlclient.Client
		svClusterClientSet            *kubernetes.Clientset
		vmServiceBackupRestoreEnabled bool
		incrementalRestoreEnabled     bool
		linuxImageDisplayName         string
		linuxVMIName                  string
	)

	BeforeEach(func() {
		input = inputGetter()
		Expect(input.Config).ToNot(BeNil(), "Invalid argument. input.E2EConfig can't be nil when calling %s spec", specName)
		Expect(input.Config.InfraConfig).ToNot(BeNil(), "Invalid argument. input.E2EConfig.InfraConfig can't be nil when calling %s spec", specName)
		skipper.SkipUnlessInfraIs(input.Config.InfraConfig.InfraName, consts.WCP)

		Expect(input.ClusterProxy).ToNot(BeNil(), "Invalid argument. input.SVClusterProxy can't be nil when calling %s spec", specName)
		Expect(input.WCPNamespaceName).ToNot(BeEmpty(), "Invalid argument. input.WCPNamespaceName can't be empty when calling %s spec", specName)
		Expect(input.LinuxVMName).ToNot(BeEmpty(), "Invalid argument. input.LinuxVMName can't be empty when calling %s spec", specName)

		wcpClient = input.WCPClient
		config = input.Config
		clusterProxy = input.ClusterProxy.(*common.VMServiceClusterProxy)
		svClusterClient = clusterProxy.GetClient()
		svClusterClientSet = clusterProxy.GetClientSet()

		linuxImageDisplayName = vmservice.GetDefaultImageDisplayName(config.InfraConfig.ManagementClusterConfig.Resources)

		var vmiErr error
		linuxVMIName, vmiErr = vmoperator.WaitForVirtualMachineImageName(ctx, &config.Config, svClusterClient, input.WCPNamespaceName, linuxImageDisplayName)
		Expect(vmiErr).NotTo(HaveOccurred(), "failed to get VMI name for display name %q in namespace %q", linuxImageDisplayName, input.WCPNamespaceName)

		vmServiceBackupRestoreEnabled = utils.IsFssEnabled(ctx, svClusterClient, config.GetVariable("VMOPNamespace"), config.GetVariable("VMOPDeploymentName"), config.GetVariable("VMOPManagerCommand"), config.GetVariable("EnvFSSVMServiceBackupRestore"))
		incrementalRestoreEnabled = utils.IsFssEnabled(ctx, svClusterClient, config.GetVariable("VMOPNamespace"), config.GetVariable("VMOPDeploymentName"), config.GetVariable("VMOPManagerCommand"), config.GetVariable("EnvFSSIncrementalRestore"))
	})

	Context("Authorization test", func() {
		var (
			vCenterHostname                    string
			authTestWCPClient                  wcp.WorkloadManagementAPI
			vimClient                          *vim25.Client
			user                               *vcenter.User
			testUserWithoutPrivilege           = "test-user-without-privilege"
			password                           = "Password!23"
			testUserWithoutPrivilegeWithDomain = "test-user-without-privilege@vsphere.local"
		)

		BeforeEach(func() {
			vCenterAdminCreds := dcli.VCenterUserCredentials{Username: testbed.AdminUsername, Password: testbed.AdminPassword}
			vCenterHostname = vcenter.GetVCPNIDFromKubeconfig(context.TODO(), clusterProxy.GetKubeconfigPath())
			Expect(vCenterHostname).NotTo(BeZero(), "Unable to determine VC PNID")

			sshCommandRunner, _, _ := testutils.GetHelpersFromKubeconfig(ctx, clusterProxy.GetKubeconfigPath())
			user = vcenter.NewUser(testUserWithoutPrivilege, password).WithAdminCreds(vCenterAdminCreds).WithSSHCommandRunner(sshCommandRunner)

			var err error

			err = user.Create()
			Expect(err).ToNot(HaveOccurred())

			authTestWCPClient, err = wcp.NewWCPAPIClient(vCenterHostname, testUserWithoutPrivilegeWithDomain, password, testbed.RootUsername, testbed.RootPassword)
			Expect(err).NotTo(HaveOccurred())
			vimClient, err = vcenter.NewVimClient(vCenterHostname, testbed.AdminUsername, testbed.AdminPassword)
			Expect(err).NotTo(HaveOccurred())
			err = vcenter.AddToGroup(ctx, vimClient, testUserWithoutPrivilege, "ReadOnlyUsers")
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			// Delete the SSO user.
			vcenter.DeleteUserOrFail(user)
		})

		It("A user without namespaces.Configure privilege should not be able to invoke RegisterVM API", Label("smoke"), func() {
			if !vmServiceBackupRestoreEnabled {
				Skip("WCP_VMService_BackupRestore FSS is not enabled")
			}

			// authTestWCPClient is retained here for future re-enablement of the RegisterVM API auth check.
			_ = authTestWCPClient

			By("Create ImportOperation CR directly in the supervisor cluster")

			// taskID, err := authTestWCPClient.RegisterVM(input.WCPNamespaceName, "fake-vm-moid")
			// Expect(taskID).To(BeEmpty())
			// Expect(err).To(HaveOccurred())
			// var dcliErr wcp.DcliError
			// Expect(errors.As(err, &dcliErr)).Should(BeTrue())
			// Expect(dcliErr.Response()).Should(ContainSubstring(lib.VapiUnauthorizedErrMsg))

			importOpName := fmt.Sprintf("auth-test-%s", capiutil.RandomString(4))
			importOperation := &mopv1a4.ImportOperation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      importOpName,
					Namespace: input.WCPNamespaceName,
				},
				Spec: mopv1a4.ImportOperationSpec{
					VirtualMachineID: "fake-vm-moid",
					StorageClass:     config.InfraConfig.ManagementClusterConfig.Resources.StorageClassName,
					RestoreConfig: &mopv1a4.RestoreConfig{
						ProcessRestoreData: mopv1a4.RestoreDataModeEnabled,
					},
				},
			}
			Expect(svClusterClient.Create(ctx, importOperation)).To(Succeed(), "Failed to create ImportOperation")
			defer func() { _ = svClusterClient.Delete(ctx, importOperation) }()
		})
	})

	Context("RegisterVM with invalid params", func() {
		It("If the VM does not exist, returns not found error", func() {
			if !vmServiceBackupRestoreEnabled {
				Skip("WCP_VMService_BackupRestore FSS is not enabled")
			}

			By("Create ImportOperation CR directly in the supervisor cluster")

			// taskID, err := wcpClient.RegisterVM(input.WCPNamespaceName, "non-exist-vm-moid")
			// Expect(err).To(HaveOccurred())
			// var dcliErr wcp.DcliError
			// Expect(errors.As(err, &dcliErr)).Should(BeTrue())
			// Expect(dcliErr.Response()).Should(ContainSubstring(lib.VapiNotFoundErrMsg))
			// Expect(taskID).To(BeEmpty())

			importOpName := fmt.Sprintf("invalid-vm-%s", capiutil.RandomString(4))
			importOperation := &mopv1a4.ImportOperation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      importOpName,
					Namespace: input.WCPNamespaceName,
				},
				Spec: mopv1a4.ImportOperationSpec{
					VirtualMachineID: "non-exist-vm-moid",
					StorageClass:     config.InfraConfig.ManagementClusterConfig.Resources.StorageClassName,
					RestoreConfig: &mopv1a4.RestoreConfig{
						ProcessRestoreData: mopv1a4.RestoreDataModeEnabled,
					},
				},
			}
			Expect(svClusterClient.Create(ctx, importOperation)).To(Succeed(), "Failed to create ImportOperation")
			defer func() { _ = svClusterClient.Delete(ctx, importOperation) }()
		})

		It("If the namespace does not exist, returns not found error", func() {
			if !vmServiceBackupRestoreEnabled {
				Skip("WCP_VMService_BackupRestore FSS is not enabled")
			}

			By("Create ImportOperation CR directly - expect failure due to non-existent namespace")

			// taskID, err := wcpClient.RegisterVM("non-existent-namespace", "vm-moid")
			// Expect(err).To(HaveOccurred())
			// var dcliErr wcp.DcliError
			// Expect(errors.As(err, &dcliErr)).Should(BeTrue())
			// Expect(dcliErr.Response()).Should(ContainSubstring(lib.VapiNotFoundErrMsg))
			// Expect(taskID).To(BeEmpty())

			importOperation := &mopv1a4.ImportOperation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-invalid-ns",
					Namespace: "non-existent-namespace",
				},
				Spec: mopv1a4.ImportOperationSpec{
					VirtualMachineID: "vm-moid",
					RestoreConfig: &mopv1a4.RestoreConfig{
						ProcessRestoreData: mopv1a4.RestoreDataModeEnabled,
					},
				},
			}
			err := svClusterClient.Create(ctx, importOperation)
			Expect(err).To(HaveOccurred())
		})

		It("If the VM is already registered, returns already in desired state error", func() {
			if !vmServiceBackupRestoreEnabled {
				Skip("WCP_VMService_BackupRestore FSS is not enabled")
			}

			if incrementalRestoreEnabled {
				Skip("WCP_VMService_Incremental_Restore FSS is enabled")
			}

			By("Get an existing VM Service VM MoID in Supervisor")
			vmoperator.WaitForVirtualMachineMOID(ctx, config, svClusterClient, input.WCPNamespaceName, input.LinuxVMName)
			existingVM, err := utils.GetVirtualMachine(ctx, svClusterClient, input.WCPNamespaceName, input.LinuxVMName)
			Expect(err).ToNot(HaveOccurred())
			Expect(existingVM.Status.UniqueID).ToNot(BeEmpty())

			By("Create ImportOperation CR directly in the supervisor cluster")

			// taskID, err := wcpClient.RegisterVM(input.WCPNamespaceName, existingVM.Status.UniqueID)
			// Expect(err).To(HaveOccurred())
			// var dcliErr wcp.DcliError
			// Expect(errors.As(err, &dcliErr)).Should(BeTrue())
			// Expect(dcliErr.Response()).Should(ContainSubstring(lib.VapiAlreadyInDesiredStateErrMsg))
			// Expect(taskID).To(BeEmpty())

			importOpName := fmt.Sprintf("already-reg-%s", capiutil.RandomString(4))
			importOperation := &mopv1a4.ImportOperation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      importOpName,
					Namespace: input.WCPNamespaceName,
				},
				Spec: mopv1a4.ImportOperationSpec{
					VirtualMachineID: existingVM.Status.UniqueID,
					StorageClass:     config.InfraConfig.ManagementClusterConfig.Resources.StorageClassName,
					RestoreConfig: &mopv1a4.RestoreConfig{
						ProcessRestoreData: mopv1a4.RestoreDataModeEnabled,
					},
				},
			}
			Expect(svClusterClient.Create(ctx, importOperation)).To(Succeed(), "Failed to create ImportOperation")
			defer func() { _ = svClusterClient.Delete(ctx, importOperation) }()
		})
	})

	Context("Incremental Restore - Register VM with pre-existing VM CR", func() {
		It("Should register VM successfully", func() {
			if !incrementalRestoreEnabled {
				Skip("WCP_VMService_Incremental_Restore FSS is not enabled")
			}

			vCenterClient := vcenter.NewVimClientFromKubeconfig(ctx, clusterProxy.GetKubeconfigPath())
			defer vcenter.LogoutVimClient(vCenterClient)

			vmName := fmt.Sprintf("%s-%s", specName, capiutil.RandomString(4))
			secretName := vmName + "-cloud-config-data"
			secret := manifestbuilders.Secret{
				Namespace: input.WCPNamespaceName,
				Name:      secretName,
			}
			secretYaml := manifestbuilders.GetSecretYamlCloudConfig(secret)
			Expect(clusterProxy.CreateWithArgs(ctx, secretYaml)).To(Succeed(), "failed to create the Secret with cloud-config data", string(secretYaml))

			resources := config.InfraConfig.ManagementClusterConfig.Resources

			vmParameters := manifestbuilders.VirtualMachineYaml{
				Namespace:        input.WCPNamespaceName,
				Name:             vmName,
				VMClassName:      resources.VMClassName,
				StorageClassName: resources.StorageClassName,
				ResourcePolicy:   resources.VMResourcePolicyName,
				ImageName:        linuxVMIName,
				Bootstrap: manifestbuilders.Bootstrap{
					CloudInit: &manifestbuilders.CloudInit{
						RawCloudConfig: &manifestbuilders.KeySelector{
							Key:  "user-data",
							Name: secretName,
						},
					},
				},
				PowerState: "PoweredOn",
			}
			vmYaml := manifestbuilders.GetVirtualMachineYamlA2(vmParameters)
			Expect(clusterProxy.CreateWithArgs(ctx, vmYaml)).To(Succeed(), "failed to create Linux VM:\n%s", string(vmYaml))
			// End create new VM

			vmoperator.WaitForVirtualMachineCreation(ctx, config, svClusterClient, input.WCPNamespaceName, vmName)
			vmoperator.WaitForVirtualMachineMOID(ctx, config, svClusterClient, input.WCPNamespaceName, vmName)

			existingVM, err := utils.GetVirtualMachine(ctx, svClusterClient, input.WCPNamespaceName, vmName)
			Expect(err).ToNot(HaveOccurred())

			// Wait for backup to complete before reading the backup data
			vmservice.WaitForBackupToComplete(ctx, existingVM, clusterProxy, config)

			vmMoRef := types.ManagedObjectReference{Type: "VirtualMachine", Value: existingVM.Status.UniqueID}
			vmObj := object.NewVirtualMachine(vCenterClient, vmMoRef)

			var vmMO mo.VirtualMachine

			var (
				backupVersion string
				resourceYAML  string
			)
			// VM Operator starts recording backup when disk promotion and volume registration has happened.
			propCollector := property.DefaultCollector(vCenterClient)
			Expect(propCollector.RetrieveOne(ctx, vmMoRef, []string{"config.extraConfig"}, &vmMO)).To(Succeed())
			Expect(vmMO.Config).ToNot(BeNil(), "VM Config should not be nil")

			ecList := object.OptionValueList(vmMO.Config.ExtraConfig)
			resourceYAML, _ = ecList.GetString(backupapi.VMResourceYAMLExtraConfigKey)
			backupVersion, _ = ecList.GetString(backupapi.BackupVersionExtraConfigKey)

			Expect(resourceYAML).ToNot(BeEmpty())
			Expect(backupVersion).ToNot(BeEmpty())

			By("Power off the VM")
			vmoperator.UpdateVirtualMachinePowerState(ctx, config, svClusterClient, input.WCPNamespaceName, vmName, "PoweredOff")
			vmoperator.WaitForVirtualMachinePowerState(ctx, config, svClusterClient, input.WCPNamespaceName, vmName, "PoweredOff")

			By("Add the pause annotation to VM")

			vm, err := utils.GetVirtualMachine(ctx, svClusterClient, input.WCPNamespaceName, vmName)
			Expect(err).ToNot(HaveOccurred())

			if vm.Annotations == nil {
				vm.Annotations = make(map[string]string)
			}

			vm.Annotations[vmopv1a3.PauseAnnotation] = trueString
			Expect(svClusterClient.Update(ctx, vm)).To(Succeed())

			// Collect all PVC names from the VM spec
			var pvcNames []string

			for _, volume := range vm.Spec.Volumes {
				if volume.PersistentVolumeClaim != nil {
					pvcNames = append(pvcNames, volume.PersistentVolumeClaim.ClaimName)
				}
			}

			// Unregister all PVCs using the helper function
			vmservice.UnregisterPVCVolumes(ctx, svClusterClient, clusterProxy, input.WCPNamespaceName, vmName, pvcNames, config)

			// reconfigBeforeRegister changes the VM's resource.yaml, backupVersion to the given value.
			reconfigBeforeRegister := func(value []string) {
				vmSpec := types.VirtualMachineConfigSpec{
					ExtraConfig: []types.BaseOptionValue{
						&types.OptionValue{Key: backupapi.VMResourceYAMLExtraConfigKey, Value: value[0]},
						&types.OptionValue{Key: backupapi.BackupVersionExtraConfigKey, Value: value[1]},
					},
				}

				task, err := vmObj.Reconfigure(ctx, vmSpec)
				Expect(err).NotTo(HaveOccurred())
				Expect(task.Wait(ctx)).To(Succeed())
			}

			By(fmt.Sprintf("Reconfigure VM with saved vm yaml %v: %s\n, backupVersion %v: %s\n",
				backupapi.VMResourceYAMLExtraConfigKey, resourceYAML,
				backupapi.BackupVersionExtraConfigKey, backupVersion))
			reconfigBeforeRegister([]string{resourceYAML, backupVersion})

			// taskInfo, err := vmservice.InvokeRegisterVM(ctx, existingVM.Status.UniqueID, existingVM.Namespace, clusterProxy, wcpClient)
			// By("Verify task state is success")
			// Expect(err).ToNot(HaveOccurred())
			// Expect(taskInfo).ToNot(BeNil())
			// Expect(taskInfo.Error).To(BeNil())
			// Expect(taskInfo.State).To(Equal(types.TaskInfoStateSuccess))

			By("Create ImportOperation CR directly in the supervisor cluster")
			importOpName := fmt.Sprintf("inc-restore-%s", capiutil.RandomString(4))
			importOperation := &mopv1a4.ImportOperation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      importOpName,
					Namespace: existingVM.Namespace,
				},
				Spec: mopv1a4.ImportOperationSpec{
					VirtualMachineID: existingVM.Status.UniqueID,
					StorageClass:     resources.StorageClassName,
					RestoreConfig: &mopv1a4.RestoreConfig{
						ProcessRestoreData: mopv1a4.RestoreDataModeEnabled,
					},
				},
			}
			Expect(svClusterClient.Create(ctx, importOperation)).To(Succeed(), "Failed to create ImportOperation")

			By("Wait for ImportOperation to complete successfully")
			Eventually(func(g Gomega) {
				err := svClusterClient.Get(ctx, ctrlclient.ObjectKey{
					Namespace: importOperation.Namespace,
					Name:      importOperation.Name,
				}, importOperation)
				g.Expect(err).ToNot(HaveOccurred())
				for _, cond := range importOperation.Status.Conditions {
					if cond.Type == "Completed" && cond.Status == metav1.ConditionTrue {
						return
					}
				}
				g.Expect(false).To(BeTrue(), "ImportOperation not yet completed")
			}, config.GetIntervals("default", "wait-config-map-creation")...).
				Should(Succeed(), "ImportOperation should complete successfully")

			vmservice.VerifyPostRegisterVM(ctx, existingVM.Name, existingVM.Namespace, nil, len(existingVM.Spec.Volumes), clusterProxy, config, svClusterClient, wcpClient)
			Expect(clusterProxy.DeleteWithArgs(ctx, vmYaml)).To(Succeed(), "failed to delete virtualmachine")
		})
	})

	Context("Incremental Restore - Register VM with pre-existing VM CR and PVCs", func() {
		It("Should register VM successfully", func() {
			if !incrementalRestoreEnabled {
				Skip("WCP_VMService_Incremental_Restore FSS is not enabled")
			}

			vCenterClient := vcenter.NewVimClientFromKubeconfig(ctx, clusterProxy.GetKubeconfigPath())
			defer vcenter.LogoutVimClient(vCenterClient)

			vmName := fmt.Sprintf("%s-%s", specName, capiutil.RandomString(4))
			secretName := vmName + "-cloud-config-data"
			secret := manifestbuilders.Secret{
				Namespace: input.WCPNamespaceName,
				Name:      secretName,
			}
			secretYaml := manifestbuilders.GetSecretYamlCloudConfig(secret)
			Expect(clusterProxy.CreateWithArgs(ctx, secretYaml)).To(Succeed(), "failed to create the Secret with cloud-config data", string(secretYaml))

			resources := config.InfraConfig.ManagementClusterConfig.Resources
			pvcNameA := vmName + "-pvc-a"
			testutils.AssertCreatePVC(svClusterClientSet, pvcNameA, input.WCPNamespaceName, resources.StorageClassName)

			vmParameters := manifestbuilders.VirtualMachineYaml{
				Namespace:        input.WCPNamespaceName,
				Name:             vmName,
				VMClassName:      resources.VMClassName,
				StorageClassName: resources.StorageClassName,
				ResourcePolicy:   resources.VMResourcePolicyName,
				ImageName:        linuxVMIName,
				Bootstrap: manifestbuilders.Bootstrap{
					CloudInit: &manifestbuilders.CloudInit{
						RawCloudConfig: &manifestbuilders.KeySelector{
							Key:  "user-data",
							Name: secretName,
						},
					},
				},
				PowerState: "PoweredOn",
				PVCNames:   []string{pvcNameA},
			}
			vmYaml := manifestbuilders.GetVirtualMachineYamlA2(vmParameters)
			Expect(clusterProxy.CreateWithArgs(ctx, vmYaml)).To(Succeed(), "failed to create Linux VM:\n%s", string(vmYaml))
			// End create new VM

			// Wait for IP, a valid moID and the PVC attachment.
			vmoperator.WaitForVirtualMachineCreation(ctx, config, svClusterClient, input.WCPNamespaceName, vmName)
			vmoperator.WaitForVirtualMachineMOID(ctx, config, svClusterClient, input.WCPNamespaceName, vmName)
			vmoperator.WaitForPVCAttachment(ctx, config, svClusterClient, input.WCPNamespaceName, vmName, pvcNameA)

			existingVM, err := utils.GetVirtualMachine(ctx, svClusterClient, input.WCPNamespaceName, vmName)
			Expect(err).ToNot(HaveOccurred())

			// Wait for backup to complete before reading the backup data
			vmservice.WaitForBackupToComplete(ctx, existingVM, clusterProxy, config)

			vmMoRef := types.ManagedObjectReference{Type: "VirtualMachine", Value: existingVM.Status.UniqueID}
			vmObj := object.NewVirtualMachine(vCenterClient, vmMoRef)

			var vmMO mo.VirtualMachine

			// take a copy of the backed up vm resource and pvc backup data.
			By("Save original VM resource, backup version and PVC backup from ExtraConfig")

			propCollector := property.DefaultCollector(vCenterClient)
			Expect(propCollector.RetrieveOne(ctx, vmMoRef, []string{"config.extraConfig"}, &vmMO)).To(Succeed())
			Expect(vmMO.Config).ToNot(BeNil(), "VM Config should not be nil")

			var (
				backupVersion string
				resourceYAML  string
			)

			ecList := object.OptionValueList(vmMO.Config.ExtraConfig)
			resourceYAML, _ = ecList.GetString(backupapi.VMResourceYAMLExtraConfigKey)
			pvcBackup, _ := ecList.GetString(backupapi.PVCDiskDataExtraConfigKey)
			backupVersion, _ = ecList.GetString(backupapi.BackupVersionExtraConfigKey)

			Expect(resourceYAML).ToNot(BeEmpty())
			Expect(pvcBackup).ToNot(BeEmpty())
			Expect(backupVersion).ToNot(BeEmpty())

			// Create and attach another pvc to the VM.
			pvcNameB := vmName + "-pvc-b"
			testutils.AssertCreatePVC(svClusterClientSet, pvcNameB, input.WCPNamespaceName, resources.StorageClassName)

			// Use v1alpha3 here to make sure this doesn't blow up in product branches older than v1a5.
			By(fmt.Sprintf("Updating the VM with two PVCs: '%v'", vmParameters.PVCNames))

			vm, err := utils.GetVirtualMachineA3(ctx, svClusterClient, input.WCPNamespaceName, vmName)
			Expect(err).ToNot(HaveOccurred())

			vm.Spec.Volumes = append(vm.Spec.Volumes, vmopv1a3.VirtualMachineVolume{
				Name: pvcNameB,
				VirtualMachineVolumeSource: vmopv1a3.VirtualMachineVolumeSource{
					PersistentVolumeClaim: &vmopv1a3.PersistentVolumeClaimVolumeSource{
						PersistentVolumeClaimVolumeSource: corev1.PersistentVolumeClaimVolumeSource{
							ClaimName: pvcNameB,
						},
					},
				},
			})
			Expect(svClusterClient.Update(ctx, vm)).To(Succeed())

			vmoperator.WaitForPVCAttachment(ctx, config, svClusterClient, input.WCPNamespaceName, vmName, pvcNameB)
			// Both PVC A and B are now attached to VM.

			By("Power off the VM")
			vmoperator.UpdateVirtualMachinePowerState(ctx, config, svClusterClient, input.WCPNamespaceName, vmName, "PoweredOff")
			vmoperator.WaitForVirtualMachinePowerState(ctx, config, svClusterClient, input.WCPNamespaceName, vmName, "PoweredOff")

			By("Add the pause annotation to VM")

			vm, err = utils.GetVirtualMachineA3(ctx, svClusterClient, input.WCPNamespaceName, vmName)
			Expect(err).ToNot(HaveOccurred())

			if vm.Annotations == nil {
				vm.Annotations = make(map[string]string)
			}

			vm.Annotations[vmopv1a3.PauseAnnotation] = trueString
			Expect(svClusterClient.Update(ctx, vm)).To(Succeed())

			// Collect all PVC names from the VM spec
			var pvcNames []string

			for _, volume := range vm.Spec.Volumes {
				if volume.PersistentVolumeClaim != nil {
					pvcNames = append(pvcNames, volume.PersistentVolumeClaim.ClaimName)
				}
			}

			// Unregister all PVCs using the helper function
			vmservice.UnregisterPVCVolumes(ctx, svClusterClient, clusterProxy, input.WCPNamespaceName, vmName, pvcNames, config)

			// reconfigBeforeRegister changes the VM's resource.yaml, backupVersion and PVC properties to the given value.
			reconfigBeforeRegister := func(value []string) {
				vmSpec := types.VirtualMachineConfigSpec{
					ExtraConfig: []types.BaseOptionValue{
						&types.OptionValue{Key: backupapi.VMResourceYAMLExtraConfigKey, Value: value[0]},
						&types.OptionValue{Key: backupapi.PVCDiskDataExtraConfigKey, Value: value[1]},
						&types.OptionValue{Key: backupapi.BackupVersionExtraConfigKey, Value: value[2]},
					},
				}

				task, err := vmObj.Reconfigure(ctx, vmSpec)
				Expect(err).NotTo(HaveOccurred())
				Expect(task.Wait(ctx)).To(Succeed())
			}

			By(fmt.Sprintf("Reconfigure VM with saved vm yaml %v: %s\n, backupVersion %v: %s\n, and PVC backup with one PVC (pvc-a) %v: %s\n",
				backupapi.VMResourceYAMLExtraConfigKey, resourceYAML,
				backupapi.BackupVersionExtraConfigKey, backupVersion,
				backupapi.PVCDiskDataExtraConfigKey, pvcBackup))
			reconfigBeforeRegister([]string{resourceYAML, pvcBackup, backupVersion})

			// Call registerVM on existing VM CR currently having two PVCs (a and b) with backup VM yaml having one PVC (a)
			// taskInfo, err := vmservice.InvokeRegisterVM(ctx, existingVM.Status.UniqueID, existingVM.Namespace, clusterProxy, wcpClient)
			// By("Verify task state is success")
			// Expect(err).ToNot(HaveOccurred())
			// Expect(taskInfo).ToNot(BeNil())
			// Expect(taskInfo.Error).To(BeNil())
			// Expect(taskInfo.State).To(Equal(types.TaskInfoStateSuccess))

			By("Create ImportOperation CR directly in the supervisor cluster")
			importOpName := fmt.Sprintf("inc-restore-pvcs-%s", capiutil.RandomString(4))
			importOperation := &mopv1a4.ImportOperation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      importOpName,
					Namespace: existingVM.Namespace,
				},
				Spec: mopv1a4.ImportOperationSpec{
					VirtualMachineID: existingVM.Status.UniqueID,
					StorageClass:     resources.StorageClassName,
					RestoreConfig: &mopv1a4.RestoreConfig{
						ProcessRestoreData: mopv1a4.RestoreDataModeEnabled,
					},
				},
			}
			Expect(svClusterClient.Create(ctx, importOperation)).To(Succeed(), "Failed to create ImportOperation")

			By("Wait for ImportOperation to complete successfully")
			Eventually(func(g Gomega) {
				err := svClusterClient.Get(ctx, ctrlclient.ObjectKey{
					Namespace: importOperation.Namespace,
					Name:      importOperation.Name,
				}, importOperation)
				g.Expect(err).ToNot(HaveOccurred())
				for _, cond := range importOperation.Status.Conditions {
					if cond.Type == "Completed" && cond.Status == metav1.ConditionTrue {
						return
					}
				}
				g.Expect(false).To(BeTrue(), "ImportOperation not yet completed")
			}, config.GetIntervals("default", "wait-config-map-creation")...).
				Should(Succeed(), "ImportOperation should complete successfully")

			// Expected registered VM should have pvc-a-restored in vm.spec.volumes
			// There should be two restored volumes: one from classic disk, and one for pvc-a since pvc-b was added after backup.
			expectedRestoredPVCCount := 2
			vmservice.VerifyPostRegisterVM(ctx, existingVM.Name, existingVM.Namespace, nil, expectedRestoredPVCCount, clusterProxy, config, svClusterClient, wcpClient)
			Expect(clusterProxy.DeleteWithArgs(ctx, vmYaml)).To(Succeed(), "failed to delete virtualmachine")
		})
	})

	Context("RegisterVM Alarm", func() {
		// Predefined Alarm definition added in main/9.0 (CLN 13918662)
		// If using a VC without the predefined alarm, create with:
		//  govc alarm.create -n WCPRegisterVMFailedAlarm \
		//   -d "registervm failed (for gce2e)" \
		//   -green com.vmware.wcp.RegisterVM.success \
		//   -yellow com.vmware.wcp.RegisterVM.failure
		// Note: "alarm." prefix can only be used in predefined SystemName
		const (
			alarmName    = "WCPRegisterVMFailedAlarm"
			eventPrefix  = "com.vmware.wcp.RegisterVM."
			eventSuccess = eventPrefix + "success"
			eventFailure = eventPrefix + "failure"
		)

		alarmMatches := func(info types.AlarmInfo) bool {
			return info.SystemName == "alarm."+alarmName || info.Name == alarmName
		}

		// Test summary:
		// - DeleteVMResource, removing the K8s CR
		// - Reconfig VM's resource.yaml to invalid
		// - Create ImportOperation (expected to fail) to trigger alarm
		// - Reconfig VM's resource.yaml to valid
		// - Create ImportOperation (expected to succeed) and clear triggered alarm
		// - VerifyPostRegisterVM, expecting VM is powered on, has IP, etc
		It("Should trigger on failure", func() {
			if !vmServiceBackupRestoreEnabled {
				Skip("WCP_VMService_BackupRestore FSS is not enabled")
			}

			vCenterClient := vcenter.NewVimClientFromKubeconfig(ctx, clusterProxy.GetKubeconfigPath())
			defer vcenter.LogoutVimClient(vCenterClient)

			alarmManager := alarm.NewManager(vCenterClient)
			alarms, err := alarmManager.GetAlarm(ctx, vCenterClient.ServiceContent.RootFolder)
			Expect(err).NotTo(HaveOccurred())

			var wcpAlarm *mo.Alarm

			for _, alarm := range alarms {
				if alarmMatches(alarm.Info) {
					wcpAlarm = &alarm
					break
				}
			}

			if wcpAlarm == nil {
				Skip(alarmName + " not defined in this vCenter")
			}

			// Create a new VM (copy-n-paste of vmservicee2e.deployVMWithCloudInit)
			vmName := fmt.Sprintf("%s-%s", specName, capiutil.RandomString(4))
			vmsvcClusterProxy := input.ClusterProxy.(*common.VMServiceClusterProxy)
			secretName := vmName + "-cloud-config-data"
			secret := manifestbuilders.Secret{
				Namespace: input.WCPNamespaceName,
				Name:      secretName,
			}
			secretYaml := manifestbuilders.GetSecretYamlCloudConfig(secret)
			Expect(vmsvcClusterProxy.CreateWithArgs(ctx, secretYaml)).To(Succeed(), "failed to create the Secret with cloud-config data", string(secretYaml))

			resources := config.InfraConfig.ManagementClusterConfig.Resources
			vmParameters := manifestbuilders.VirtualMachineYaml{
				Namespace:        input.WCPNamespaceName,
				Name:             vmName,
				VMClassName:      resources.VMClassName,
				StorageClassName: resources.StorageClassName,
				ResourcePolicy:   resources.VMResourcePolicyName,
				ImageName:        linuxVMIName,
				Bootstrap: manifestbuilders.Bootstrap{
					CloudInit: &manifestbuilders.CloudInit{
						RawCloudConfig: &manifestbuilders.KeySelector{
							Key:  "user-data",
							Name: secretName,
						},
					},
				},
				PowerState: "PoweredOn",
			}
			vmYaml := manifestbuilders.GetVirtualMachineYamlA2(vmParameters)
			Expect(vmsvcClusterProxy.CreateWithArgs(ctx, vmYaml)).To(Succeed(), "failed to create Linux VM:\n%s", string(vmYaml))

			vmoperator.WaitForVirtualMachineCreation(ctx, config, svClusterClient, input.WCPNamespaceName, vmName)
			existingVM, err := utils.GetVirtualMachine(ctx, svClusterClient, input.WCPNamespaceName, vmName)
			Expect(err).ToNot(HaveOccurred())

			// Wait for backup to complete before reading the backup data
			vmservice.WaitForBackupToComplete(ctx, existingVM, clusterProxy, config)

			// Delete the VM Service VM CR, keeping the vCenter VM in inventory.
			vmMoID := vmservice.DeleteVMResource(ctx, existingVM.Name, existingVM.Namespace, nil, clusterProxy, config, svClusterClient)
			vmMoRef := types.ManagedObjectReference{Type: "VirtualMachine", Value: vmMoID}
			vmObj := object.NewVirtualMachine(vCenterClient, vmMoRef)

			var vmMO mo.VirtualMachine

			var resourceYAML string

			By("Save original VM ExtraConfig")

			Eventually(func(g Gomega) {
				propCollector := property.DefaultCollector(vCenterClient)
				g.Expect(propCollector.RetrieveOne(ctx, vmMoRef, []string{"config.extraConfig"}, &vmMO)).To(Succeed())
				g.Expect(vmMO.Config).ToNot(BeNil(), "VM Config should not be nil")
				ecList := object.OptionValueList(vmMO.Config.ExtraConfig)
				resourceYAML, _ = ecList.GetString(backupapi.VMResourceYAMLExtraConfigKey)
				g.Expect(resourceYAML).ToNot(BeEmpty())
			}, config.GetIntervals("default", "wait-backup-to-complete")...).
				Should(Succeed(), "Waiting for VM resource to be saved in ExtraConfig")

			// Create EventHistoryCollector for verifying events
			eventSpec := types.EventFilterSpec{
				EventTypeId: []string{eventSuccess, eventFailure},
				Entity: &types.EventFilterSpecByEntity{
					Entity:    vmMoRef,
					Recursion: types.EventFilterSpecRecursionOptionSelf,
				},
			}

			eventCollector, err := event.NewManager(vCenterClient).CreateCollectorForEvents(ctx, eventSpec)
			Expect(err).NotTo(HaveOccurred())

			defer func() { _ = eventCollector.Destroy(ctx) }()

			// latestEvents returns any new events of type spec.EventTypeId
			latestEvents := func() (map[string][]types.EventEx, error) {
				alarmEvents := make(map[string][]types.EventEx)

				for {
					events, err := eventCollector.ReadNextEvents(ctx, 10)
					if err != nil {
						return nil, err
					}

					if len(events) == 0 { // no more new events
						break
					}

					for i := range events {
						// spec.EventTypeId filters out other types
						event := events[i].(*types.EventEx)
						alarmEvents[event.EventTypeId] = append(alarmEvents[event.EventTypeId], *event)

						// Fields below set by the client PostEvent
						// calls in vapi/impl/wcp/registervm.go
						Expect(event.Message).ToNot(BeEmpty())
						Expect(event.EventTypeId).To(HavePrefix(eventPrefix))
						// This message set by VC for predefined alarms only, see:
						//  vpx/vpxd/extensions/VirtualCenter/locale/en/event.vmsg
						if wcpAlarm.Info.SystemName != "" {
							Expect(event.FullFormattedMessage).ToNot(BeEmpty())
						}
					}
				}

				return alarmEvents, nil
			}

			// triggeredAlarm gets the current triggeredAlarmState property and related info
			triggeredAlarm := func() *alarm.StateInfo {
				options := alarm.StateInfoOptions{Event: true}
				alarmStates, err := alarmManager.GetStateInfo(ctx, vmMoRef, options)
				Expect(err).NotTo(HaveOccurred())

				for _, state := range alarmStates {
					if alarmMatches(*state.Info) {
						return &state
					}
				}

				return nil
			}

			// reconfigResourceYAML changes the VM's resource.yaml property to the given value
			reconfigResourceYAML := func(value any) {
				vmSpec := types.VirtualMachineConfigSpec{
					ExtraConfig: []types.BaseOptionValue{
						&types.OptionValue{Key: backupapi.VMResourceYAMLExtraConfigKey, Value: value},
					},
				}

				task, err := vmObj.Reconfigure(ctx, vmSpec)
				Expect(err).NotTo(HaveOccurred())
				Expect(task.Wait(ctx)).To(Succeed())
			}

			By("Checking events before registervm")

			alarmEvents, err := latestEvents()
			Expect(err).NotTo(HaveOccurred())
			Expect(alarmEvents).To(HaveLen(0))
			By("Checking triggered alarms before registervm")
			Expect(triggeredAlarm()).To(BeNil())

			By("Reconfigure VM with invalid " + backupapi.VMResourceYAMLExtraConfigKey)
			reconfigResourceYAML("invalid-yaml")

			// taskInfo, err := vmservice.InvokeRegisterVM(ctx, vmMoID, existingVM.Namespace, clusterProxy, wcpClient)
			// By("Verify task state is error")
			// Expect(err).NotTo(BeNil())
			// Expect(taskInfo.Error).NotTo(BeNil())
			// Expect(taskInfo.State).To(Equal(types.TaskInfoStateError))

			By("Create ImportOperation CR directly in the supervisor cluster (expected to fail due to invalid resource YAML)")
			importOpNameFail := fmt.Sprintf("alarm-fail-%s", capiutil.RandomString(4))
			importOperationFail := &mopv1a4.ImportOperation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      importOpNameFail,
					Namespace: existingVM.Namespace,
				},
				Spec: mopv1a4.ImportOperationSpec{
					VirtualMachineID: vmMoID,
					StorageClass:     resources.StorageClassName,
					RestoreConfig: &mopv1a4.RestoreConfig{
						ProcessRestoreData: mopv1a4.RestoreDataModeEnabled,
					},
				},
			}
			Expect(svClusterClient.Create(ctx, importOperationFail)).To(Succeed(), "Failed to create ImportOperation")
			defer func() { _ = svClusterClient.Delete(ctx, importOperationFail) }()

			By("Verify failure event was emitted after registervm failure")
			Eventually(func(g Gomega) {
				alarmEvents, err = latestEvents()
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(alarmEvents).To(HaveLen(1))
				g.Expect(alarmEvents[eventFailure]).To(HaveLen(1))
			}, config.GetIntervals("default", "wait-config-map-creation")...).Should(Succeed(), "Timed out waiting for failure event")

			By("Verify alarm was triggered by failure event")

			warningAlarm := triggeredAlarm()
			Expect(warningAlarm).ToNot(BeNil())
			Expect(warningAlarm.OverallStatus).To(Equal(types.ManagedEntityStatusYellow))
			Expect(warningAlarm.Event).ToNot(BeNil())
			event := warningAlarm.Event.(*types.EventEx)
			Expect(event).ToNot(BeNil())
			Expect(event.EventTypeId).To(Equal(eventFailure))
			Expect(warningAlarm.EventKey).To(Equal(alarmEvents[eventFailure][0].Key))

			By("Reconfigure VM with original ExtraConfig")
			reconfigResourceYAML(resourceYAML)

			// taskInfo, err = vmservice.InvokeRegisterVM(ctx, vmMoID, existingVM.Namespace, clusterProxy, wcpClient)
			// By("Verify task state is success")
			// Expect(err).ToNot(HaveOccurred())
			// Expect(taskInfo).ToNot(BeNil())
			// Expect(taskInfo.Error).To(BeNil())
			// Expect(taskInfo.State).To(Equal(types.TaskInfoStateSuccess))

			By("Create ImportOperation CR directly in the supervisor cluster (expected to succeed)")
			importOpNameSuccess := fmt.Sprintf("alarm-success-%s", capiutil.RandomString(4))
			importOperationSuccess := &mopv1a4.ImportOperation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      importOpNameSuccess,
					Namespace: existingVM.Namespace,
				},
				Spec: mopv1a4.ImportOperationSpec{
					VirtualMachineID: vmMoID,
					StorageClass:     resources.StorageClassName,
					RestoreConfig: &mopv1a4.RestoreConfig{
						ProcessRestoreData: mopv1a4.RestoreDataModeEnabled,
					},
				},
			}
			Expect(svClusterClient.Create(ctx, importOperationSuccess)).To(Succeed(), "Failed to create ImportOperation")

			By("Wait for ImportOperation to complete successfully")
			Eventually(func(g Gomega) {
				err := svClusterClient.Get(ctx, ctrlclient.ObjectKey{
					Namespace: importOperationSuccess.Namespace,
					Name:      importOperationSuccess.Name,
				}, importOperationSuccess)
				g.Expect(err).ToNot(HaveOccurred())
				for _, cond := range importOperationSuccess.Status.Conditions {
					if cond.Type == "Completed" && cond.Status == metav1.ConditionTrue {
						return
					}
				}
				g.Expect(false).To(BeTrue(), "ImportOperation not yet completed")
			}, config.GetIntervals("default", "wait-config-map-creation")...).
				Should(Succeed(), "ImportOperation should complete successfully")

			vmservice.VerifyPostRegisterVM(ctx, existingVM.Name, existingVM.Namespace, nil, len(existingVM.Spec.Volumes), clusterProxy, config, svClusterClient, wcpClient)

			By("Verify success event was emitted after successful registervm")
			Eventually(func(g Gomega) {
				alarmEvents, err = latestEvents()
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(alarmEvents).To(HaveLen(1))
				g.Expect(alarmEvents[eventSuccess]).To(HaveLen(1))
			}, config.GetIntervals("default", "wait-config-map-creation")...).Should(Succeed(), "Timed out waiting for success event")
			By("Verify triggered alarm was cleared by success event")
			Expect(triggeredAlarm()).To(BeNil())

			Expect(clusterProxy.DeleteWithArgs(ctx, vmYaml)).To(Succeed(), "failed to delete virtualmachine")
		})
	})

	Context("Restore disk only", func() {
		It("Should register restored disk", func() {
			if !vmServiceBackupRestoreEnabled {
				Skip("WCP_VMService_BackupRestore FSS is not enabled")
			}

			if !incrementalRestoreEnabled {
				Skip("WCP_VMService_Incremental_Restore FSS is not enabled")
			}

			adminClusterProxy, err := clusterProxy.NewAdminClusterProxy(ctx)
			Expect(err).ToNot(HaveOccurred())

			defer adminClusterProxy.Dispose(ctx)

			vCenterHostname := vcenter.GetVCPNIDFromKubeconfig(ctx, clusterProxy.GetKubeconfigPath())
			adminClient, err := adminClusterProxy.GetAdminClient()
			Expect(err).ToNot(HaveOccurred())
			vmopSecret, err := utils.GetSecret(ctx, adminClient, "vmware-system-vmop", "wcp-vmop-sa-vc-auth")
			Expect(err).ToNot(HaveOccurred())
			vmopvCenterClient, err := vcenter.NewVimClient(vCenterHostname, string(vmopSecret.Data["username"]), string(vmopSecret.Data["password"]))
			Expect(err).ToNot(HaveOccurred())

			defer vcenter.LogoutVimClient(vmopvCenterClient)

			vCenterClient := vcenter.NewVimClientFromKubeconfig(ctx, clusterProxy.GetKubeconfigPath())
			defer vcenter.LogoutVimClient(vCenterClient)

			// Create a new VM
			vmNamespace := input.WCPNamespaceName
			vmName := fmt.Sprintf("%s-%s", specName, capiutil.RandomString(4))
			vmsvcClusterProxy := input.ClusterProxy.(*common.VMServiceClusterProxy)
			secretName := vmName + "-cloud-config-data"
			secret := manifestbuilders.Secret{
				Namespace: vmNamespace,
				Name:      secretName,
			}
			secretYaml := manifestbuilders.GetSecretYamlCloudConfig(secret)
			Expect(vmsvcClusterProxy.CreateWithArgs(ctx, secretYaml)).To(Succeed(), "failed to create the Secret with cloud-config data", string(secretYaml))

			resources := config.InfraConfig.ManagementClusterConfig.Resources
			pvcNameA := vmName + "-pvc-a"
			testutils.AssertCreatePVC(svClusterClientSet, pvcNameA, input.WCPNamespaceName, resources.StorageClassName)

			vmParameters := manifestbuilders.VirtualMachineYaml{
				Namespace:        vmNamespace,
				Name:             vmName,
				VMClassName:      resources.VMClassName,
				StorageClassName: resources.StorageClassName,
				ResourcePolicy:   resources.VMResourcePolicyName,
				ImageName:        linuxVMIName,
				Bootstrap: manifestbuilders.Bootstrap{
					CloudInit: &manifestbuilders.CloudInit{
						RawCloudConfig: &manifestbuilders.KeySelector{
							Key:  "user-data",
							Name: secretName,
						},
					},
				},
				PowerState: "PoweredOn",
				PVCNames:   []string{pvcNameA},
			}
			vmYaml := manifestbuilders.GetVirtualMachineYamlA2(vmParameters)
			Expect(vmsvcClusterProxy.CreateWithArgs(ctx, vmYaml)).To(Succeed(), "failed to create Linux VM:\n%s", string(vmYaml))
			// End create new VM

			// Wait for IP, a valid moID and the PVC attachment.
			vmoperator.WaitForVirtualMachineCreation(ctx, config, svClusterClient, input.WCPNamespaceName, vmName)
			vmoperator.WaitForVirtualMachineMOID(ctx, config, svClusterClient, input.WCPNamespaceName, vmName)
			vmoperator.WaitForPVCAttachment(ctx, config, svClusterClient, input.WCPNamespaceName, vmName, pvcNameA)

			existingVM, err := utils.GetVirtualMachine(ctx, svClusterClient, vmNamespace, vmName)
			Expect(err).ToNot(HaveOccurred())

			// Wait for backup to complete before powering off the VM
			vmservice.WaitForBackupToComplete(ctx, existingVM, clusterProxy, config)

			vmMoID := existingVM.Status.UniqueID

			vmMoRef := types.ManagedObjectReference{Type: "VirtualMachine", Value: vmMoID}
			vmObj := object.NewVirtualMachine(vmopvCenterClient, vmMoRef)

			By("Power off the VM")
			vmoperator.UpdateVirtualMachinePowerState(ctx, config, svClusterClient, vmNamespace, vmName, "PoweredOff")
			vmoperator.WaitForVirtualMachinePowerState(ctx, config, svClusterClient, vmNamespace, vmName, "PoweredOff")

			By("Add the pause annotation to VM")

			vm, err := utils.GetVirtualMachine(ctx, svClusterClient, input.WCPNamespaceName, vmName)
			Expect(err).ToNot(HaveOccurred())

			if vm.Annotations == nil {
				vm.Annotations = make(map[string]string)
			}

			vm.Annotations[vmopv1a3.PauseAnnotation] = trueString
			Expect(svClusterClient.Update(ctx, vm)).To(Succeed())

			var vmMO mo.VirtualMachine

			propCollector := property.DefaultCollector(vCenterClient)
			Expect(propCollector.RetrieveOne(ctx, vmMoRef, []string{"config.files"}, &vmMO)).To(Succeed())

			// getVolumeHandle fetches the PVC, gets its PV, and returns the VolumeHandle
			getVolumeHandle := func(g Gomega, pvcName, namespace string) string {
				// Get the PVC
				pvc := &corev1.PersistentVolumeClaim{}
				pvcKey := ctrlclient.ObjectKey{
					Namespace: namespace,
					Name:      pvcName,
				}
				err := svClusterClient.Get(ctx, pvcKey, pvc)
				g.Expect(err).ToNot(HaveOccurred(), "Failed to get PVC %s in namespace %s", pvcName, namespace)
				g.Expect(pvc.Spec.VolumeName).ToNot(BeEmpty(), "PVC %s does not have a bound volume", pvcName)

				// Get the PV
				pv := &corev1.PersistentVolume{}
				pvKey := ctrlclient.ObjectKey{
					Name: pvc.Spec.VolumeName,
				}
				err = svClusterClient.Get(ctx, pvKey, pv)
				g.Expect(err).ToNot(HaveOccurred(), "Failed to get PV %s", pvc.Spec.VolumeName)

				// Get the VolumeHandle from the CSI PersistentVolumeSource
				g.Expect(pv.Spec.CSI).ToNot(BeNil(), "PV %s does not have a CSI source", pv.Name)
				g.Expect(pv.Spec.CSI.VolumeHandle).ToNot(BeEmpty(), "PV %s does not have a VolumeHandle", pv.Name)

				return pv.Spec.CSI.VolumeHandle
			}

			var (
				datastorePath, vmPath object.DatastorePath
				disk                  *types.VirtualDisk
				backing               *types.VirtualDiskFlatVer2BackingInfo
			)

			findDisk := func(g Gomega, pvcName string, shouldExist bool) {
				volumeHandle := getVolumeHandle(g, pvcName, vmNamespace)

				deviceList, err := vmObj.Device(ctx)
				g.Expect(err).ToNot(HaveOccurred())

				found := false

				for _, device := range deviceList.SelectByType((*types.VirtualDisk)(nil)) {
					// Find the disk that matches the VolumeHandle from the PVC/PV
					if vDiskID := device.(*types.VirtualDisk).VDiskId; vDiskID != nil {
						if vDiskID.Id == volumeHandle {
							disk = device.(*types.VirtualDisk)
							backing = disk.Backing.(*types.VirtualDiskFlatVer2BackingInfo)
							found = datastorePath.FromString(backing.FileName)

							break
						}
					}
				}

				g.Expect(found).To(Equal(shouldExist))
			}

			vmPath.FromString(vmMO.Config.Files.VmPathName)
			vmHome := path.Dir(vmPath.Path)

			findDisk(Default, pvcNameA, true)

			dir := path.Dir(datastorePath.Path)
			Expect(dir).ToNot(Equal(vmHome)) // "fcd" (or vsan object id) initially

			cnsClient, err := cns.NewClient(ctx, vCenterClient)
			Expect(err).ToNot(HaveOccurred())

			queryVolume := func() string {
				filter := cnstypes.CnsQueryFilter{
					VolumeIds: []cnstypes.CnsVolumeId{cnstypes.CnsVolumeId(*disk.VDiskId)},
				}
				res, err := cnsClient.QueryVolume(ctx, &filter)
				Expect(err).ToNot(HaveOccurred())
				Expect(res.Volumes).To(HaveLen(1))

				return res.Volumes[0].StoragePolicyId
			}
			storageProfileID := queryVolume()

			ds := object.NewDatastore(vCenterClient, *backing.Datastore)

			fcdManager := vslm.NewObjectManager(vCenterClient)
			// Validate FCD backing
			_, err = fcdManager.Retrieve(ctx, ds, disk.VDiskId.Id)
			Expect(err).ToNot(HaveOccurred())

			Expect(ds.FindInventoryPath(ctx)).To(Succeed())

			dc, err := find.NewFinder(vCenterClient).Datacenter(ctx, ds.DatacenterPath)
			Expect(err).ToNot(HaveOccurred())

			fileManager := ds.NewFileManager(dc, false)

			// "Delete" existing disk
			Expect(vmObj.RemoveDevice(ctx, true, disk)).To(Succeed())
			findDisk(Default, pvcNameA, false)

			// Create "new" disk
			dst := path.Join(vmHome, path.Base(datastorePath.Path))
			Expect(fileManager.Copy(ctx, datastorePath.Path, dst)).To(Succeed())
			Expect(fileManager.Delete(ctx, datastorePath.Path)).To(Succeed())

			// Expect to fail w/ orphaned FCD
			_, err = fcdManager.Retrieve(ctx, ds, disk.VDiskId.Id)
			Expect(err).To(HaveOccurred())
			Expect(fault.Is(err, &types.NotFound{})).To(BeTrue())

			// The Volume still exists
			queryVolume()

			// Attach new disk with storage profile (required for cns)
			datastorePath.Path = dst
			backing.FileName = datastorePath.String()

			profile := []types.BaseVirtualMachineProfileSpec{
				&types.VirtualMachineDefinedProfileSpec{
					ProfileId: storageProfileID,
				},
			}

			// Attach existing vmdk, rather than create a new backing
			disk.CapacityInKB = 0
			disk.CapacityInBytes = 0
			Expect(vmObj.AddDeviceWithProfile(ctx, profile, disk)).To(Succeed())

			// Since we deleted (moved) the disk backing, this causes the FCD and CNS Volume objects to be
			// removed on the vSphere side.. emulating what Veeam's restore flow does.
			task, err := fcdManager.ReconcileDatastoreInventory(ctx, ds.Reference())
			Expect(err).ToNot(HaveOccurred())
			err = task.Wait(ctx)
			Expect(err).ToNot(HaveOccurred())

			// taskInfo, err := vmservice.InvokeRegisterVM(ctx, vmMoID, existingVM.Namespace, clusterProxy, wcpClient)
			// By("Verify task state is success")
			// Expect(err).ToNot(HaveOccurred())
			// Expect(taskInfo).ToNot(BeNil())
			// Expect(taskInfo.Error).To(BeNil())
			// Expect(taskInfo.State).To(Equal(types.TaskInfoStateSuccess))

			By("Create ImportOperation CR directly in the supervisor cluster")
			importOpName := fmt.Sprintf("restore-disk-%s", capiutil.RandomString(4))
			importOperation := &mopv1a4.ImportOperation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      importOpName,
					Namespace: existingVM.Namespace,
				},
				Spec: mopv1a4.ImportOperationSpec{
					VirtualMachineID: vmMoID,
					StorageClass:     resources.StorageClassName,
					RestoreConfig: &mopv1a4.RestoreConfig{
						ProcessRestoreData: mopv1a4.RestoreDataModeEnabled,
					},
				},
			}
			Expect(svClusterClient.Create(ctx, importOperation)).To(Succeed(), "Failed to create ImportOperation")

			By("Wait for ImportOperation to complete successfully")
			Eventually(func(g Gomega) {
				err := svClusterClient.Get(ctx, ctrlclient.ObjectKey{
					Namespace: importOperation.Namespace,
					Name:      importOperation.Name,
				}, importOperation)
				g.Expect(err).ToNot(HaveOccurred())
				for _, cond := range importOperation.Status.Conditions {
					if cond.Type == "Completed" && cond.Status == metav1.ConditionTrue {
						return
					}
				}
				g.Expect(false).To(BeTrue(), "ImportOperation not yet completed")
			}, config.GetIntervals("default", "wait-config-map-creation")...).
				Should(Succeed(), "ImportOperation should complete successfully")

			e2eframework.Logf("VM has been restored: %v", vm)

			// Fetch the restored VM and verify that it has the expected number of volumes.
			restoredVM, err := utils.GetVirtualMachineA3(ctx, svClusterClient, existingVM.Namespace, existingVM.Name)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(restoredVM.Spec.Volumes)).To(Equal(2)) // one base disk and one PVC

			var restoredVol *vmopv1a3.VirtualMachineVolume

			for _, vol := range restoredVM.Spec.Volumes {
				// The volume with restored- prefix is the one that was restored.
				if vol.PersistentVolumeClaim != nil && strings.HasPrefix(vol.PersistentVolumeClaim.ClaimName, "restored-") {
					restoredVol = &vol
					break
				}
			}

			Expect(restoredVol).ToNot(BeNil())

			findDisk(Default, restoredVol.PersistentVolumeClaim.ClaimName, true)

			dir = path.Dir(datastorePath.Path)
			Expect(dir).To(Equal(vmHome))

			// Validate FCD backing is restored
			_, err = fcdManager.Retrieve(ctx, ds, disk.VDiskId.Id)
			Expect(err).ToNot(HaveOccurred())

			// Validate new Volume is created
			queryVolume()

			// We can't use len(existingVM.Spec.Volumes) here because we are only restoring one disk.
			vmservice.VerifyPostRegisterVM(ctx, existingVM.Name, existingVM.Namespace, nil, 1, clusterProxy, config, svClusterClient, wcpClient)
			Expect(clusterProxy.DeleteWithArgs(ctx, vmYaml)).To(Succeed(), "failed to delete virtualmachine")
		})
	})

	Context("FlatVer2 disk backing exclusion", func() {
		It("Should skip FlatVer2-backed classic disks and report them in SkippedDiskBackings", Label("extended-functional", "restore-status"), func() {
			if !vmServiceBackupRestoreEnabled {
				Skip("WCP_VMService_BackupRestore FSS is not enabled")
			}
			if !incrementalRestoreEnabled {
				Skip("WCP_VMService_Incremental_Restore FSS is not enabled")
			}

			adminClusterProxy, err := clusterProxy.NewAdminClusterProxy(ctx)
			Expect(err).ToNot(HaveOccurred())
			defer adminClusterProxy.Dispose(ctx)

			vCenterHostname := vcenter.GetVCPNIDFromKubeconfig(ctx, clusterProxy.GetKubeconfigPath())
			adminClient, err := adminClusterProxy.GetAdminClient()
			Expect(err).ToNot(HaveOccurred())
			vmopSecret, err := utils.GetSecret(ctx, adminClient, "vmware-system-vmop", "wcp-vmop-sa-vc-auth")
			Expect(err).ToNot(HaveOccurred())
			vmopvCenterClient, err := vcenter.NewVimClient(vCenterHostname, string(vmopSecret.Data["username"]), string(vmopSecret.Data["password"]))
			Expect(err).ToNot(HaveOccurred())
			defer vcenter.LogoutVimClient(vmopvCenterClient)

			vCenterClient := vcenter.NewVimClientFromKubeconfig(ctx, clusterProxy.GetKubeconfigPath())
			defer vcenter.LogoutVimClient(vCenterClient)

			vmNamespace := input.WCPNamespaceName
			vmName := fmt.Sprintf("%s-%s", specName, capiutil.RandomString(4))
			vmsvcClusterProxy := input.ClusterProxy.(*common.VMServiceClusterProxy)
			secretName := vmName + "-cloud-config-data"
			secretYaml := manifestbuilders.GetSecretYamlCloudConfig(manifestbuilders.Secret{
				Namespace: vmNamespace,
				Name:      secretName,
			})
			Expect(vmsvcClusterProxy.CreateWithArgs(ctx, secretYaml)).To(Succeed(), "failed to create Secret")

			resources := config.InfraConfig.ManagementClusterConfig.Resources
			pvcNameA := vmName + "-pvc-a"
			testutils.AssertCreatePVC(svClusterClientSet, pvcNameA, vmNamespace, resources.StorageClassName)

			vmYaml := manifestbuilders.GetVirtualMachineYamlA2(manifestbuilders.VirtualMachineYaml{
				Namespace:        vmNamespace,
				Name:             vmName,
				VMClassName:      resources.VMClassName,
				StorageClassName: resources.StorageClassName,
				ResourcePolicy:   resources.VMResourcePolicyName,
				ImageName:        linuxVMIName,
				Bootstrap: manifestbuilders.Bootstrap{
					CloudInit: &manifestbuilders.CloudInit{
						RawCloudConfig: &manifestbuilders.KeySelector{Key: "user-data", Name: secretName},
					},
				},
				PowerState: "PoweredOn",
				PVCNames:   []string{pvcNameA},
			})
			Expect(vmsvcClusterProxy.CreateWithArgs(ctx, vmYaml)).To(Succeed(), "failed to create VM")

			vmoperator.WaitForVirtualMachineCreation(ctx, config, svClusterClient, vmNamespace, vmName)
			vmoperator.WaitForVirtualMachineMOID(ctx, config, svClusterClient, vmNamespace, vmName)
			vmoperator.WaitForPVCAttachment(ctx, config, svClusterClient, vmNamespace, vmName, pvcNameA)

			existingVM, err := utils.GetVirtualMachine(ctx, svClusterClient, vmNamespace, vmName)
			Expect(err).ToNot(HaveOccurred())
			vmservice.WaitForBackupToComplete(ctx, existingVM, clusterProxy, config)

			vmMoRef := types.ManagedObjectReference{Type: "VirtualMachine", Value: existingVM.Status.UniqueID}
			vmObj := object.NewVirtualMachine(vmopvCenterClient, vmMoRef)

			By("Save original ExtraConfig backup data")
			propCollector := property.DefaultCollector(vCenterClient)
			var vmMO mo.VirtualMachine
			Expect(propCollector.RetrieveOne(ctx, vmMoRef, []string{"config.extraConfig"}, &vmMO)).To(Succeed())
			Expect(vmMO.Config).ToNot(BeNil())
			ecList := object.OptionValueList(vmMO.Config.ExtraConfig)
			resourceYAML, _ := ecList.GetString(backupapi.VMResourceYAMLExtraConfigKey)
			pvcBackup, _ := ecList.GetString(backupapi.PVCDiskDataExtraConfigKey)
			backupVersion, _ := ecList.GetString(backupapi.BackupVersionExtraConfigKey)
			Expect(resourceYAML).ToNot(BeEmpty())
			Expect(pvcBackup).ToNot(BeEmpty())
			Expect(backupVersion).ToNot(BeEmpty())

			By("Power off the VM")
			vmoperator.UpdateVirtualMachinePowerState(ctx, config, svClusterClient, vmNamespace, vmName, "PoweredOff")
			vmoperator.WaitForVirtualMachinePowerState(ctx, config, svClusterClient, vmNamespace, vmName, "PoweredOff")

			By("Add the pause annotation to VM")
			vm, err := utils.GetVirtualMachine(ctx, svClusterClient, vmNamespace, vmName)
			Expect(err).ToNot(HaveOccurred())
			if vm.Annotations == nil {
				vm.Annotations = make(map[string]string)
			}
			vm.Annotations[vmopv1a3.PauseAnnotation] = trueString
			Expect(svClusterClient.Update(ctx, vm)).To(Succeed())

			By("Retrieve VM hardware to find SCSI controller, free unit slot, and datastore")
			var vmMOHardware mo.VirtualMachine
			Expect(propCollector.RetrieveOne(ctx, vmMoRef,
				[]string{"config.hardware.device", "datastore"}, &vmMOHardware)).To(Succeed())
			Expect(vmMOHardware.Datastore).ToNot(BeEmpty(), "VM has no datastores")
			datastoreRef := vmMOHardware.Datastore[0]

			// Scan devices to collect existing disk keys and find the SCSI controller.
			var controllerKey int32
			existingDiskKeys := make(map[int32]bool)
			for _, dev := range vmMOHardware.Config.Hardware.Device {
				if _, isDisk := dev.(*types.VirtualDisk); isDisk {
					existingDiskKeys[dev.GetVirtualDevice().Key] = true
				}
				switch c := dev.(type) {
				case *types.ParaVirtualSCSIController:
					controllerKey = c.Key
				case *types.VirtualLsiLogicSASController:
					if controllerKey == 0 {
						controllerKey = c.Key
					}
				case *types.VirtualLsiLogicController:
					if controllerKey == 0 {
						controllerKey = c.Key
					}
				}
			}
			Expect(controllerKey).ToNot(BeZero(), "expected to find a SCSI controller on the VM")

			// Find a free unit number on the controller (0–15, unit 7 is reserved for the HBA).
			usedUnits := make(map[int32]bool)
			for _, dev := range vmMOHardware.Config.Hardware.Device {
				vd := dev.GetVirtualDevice()
				if vd.ControllerKey == controllerKey && vd.UnitNumber != nil {
					usedUnits[*vd.UnitNumber] = true
				}
			}
			var freeUnit int32 = -1
			for i := int32(1); i <= 15; i++ {
				if i == 7 {
					continue // unit 7 is the SCSI HBA slot
				}
				if !usedUnits[i] {
					freeUnit = i
					break
				}
			}
			Expect(freeUnit).ToNot(Equal(int32(-1)), "expected to find a free SCSI unit number")

			By("Attach a non-FlatVer2 SE sparse disk to trigger SkippedDiskBackings")
			// The controller adds a disk to SkippedDiskBackings when its backing type is NOT
			// VirtualDiskFlatVer2BackingInfo. SE sparse (VirtualDiskSeSparseBackingInfo) is
			// the most accessible non-FlatVer2 virtual disk type creatable without special hardware.
			seSparseRawDisk := &types.VirtualDisk{
				VirtualDevice: types.VirtualDevice{
					Key:           -100, // negative key → vCenter auto-assigns
					ControllerKey: controllerKey,
					UnitNumber:    &freeUnit,
					Backing: &types.VirtualDiskSeSparseBackingInfo{
						DiskMode: string(types.VirtualDiskModePersistent),
						VirtualDeviceFileBackingInfo: types.VirtualDeviceFileBackingInfo{
							Datastore: &datastoreRef,
						},
					},
				},
				CapacityInKB: 512 * 1024, // 512 MiB
			}
			reconfigDiskTask, err := vmObj.Reconfigure(ctx, types.VirtualMachineConfigSpec{
				DeviceChange: []types.BaseVirtualDeviceConfigSpec{
					&types.VirtualDeviceConfigSpec{
						Operation:     types.VirtualDeviceConfigSpecOperationAdd,
						FileOperation: types.VirtualDeviceConfigSpecFileOperationCreate,
						Device:        seSparseRawDisk,
					},
				},
			})
			Expect(err).ToNot(HaveOccurred(), "failed to issue reconfigure task for SE sparse disk")
			Expect(reconfigDiskTask.Wait(ctx)).To(Succeed(), "failed to attach SE sparse disk to VM")

			By("Verify the SE sparse disk was attached (not in existingDiskKeys)")
			deviceList, err := vmObj.Device(ctx)
			Expect(err).ToNot(HaveOccurred())
			var seSparseFound bool
			for _, dev := range deviceList.SelectByType((*types.VirtualDisk)(nil)) {
				vd := dev.(*types.VirtualDisk)
				if existingDiskKeys[vd.Key] {
					continue
				}
				if _, ok := vd.Backing.(*types.VirtualDiskSeSparseBackingInfo); ok {
					seSparseFound = true
					break
				}
			}
			Expect(seSparseFound).To(BeTrue(), "expected to find the newly added SE sparse disk on the VM")
			e2eframework.Logf("SE sparse disk successfully attached (non-FlatVer2 backing)")

			// Re-inject original ExtraConfig unchanged: the backup was taken before the SE sparse
			// disk was added, so the controller sees a disk not in the backup → SkippedDiskBackings.
			reconfigTask, err := vmObj.Reconfigure(ctx, types.VirtualMachineConfigSpec{
				ExtraConfig: []types.BaseOptionValue{
					&types.OptionValue{Key: backupapi.VMResourceYAMLExtraConfigKey, Value: resourceYAML},
					&types.OptionValue{Key: backupapi.PVCDiskDataExtraConfigKey, Value: pvcBackup},
					&types.OptionValue{Key: backupapi.BackupVersionExtraConfigKey, Value: backupVersion},
				},
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(reconfigTask.Wait(ctx)).To(Succeed())

			By("Create ImportOperation CR")
			importOpName := fmt.Sprintf("skip-flatver2-%s", capiutil.RandomString(4))
			importOperation := &mopv1a4.ImportOperation{
				ObjectMeta: metav1.ObjectMeta{Name: importOpName, Namespace: existingVM.Namespace},
				Spec: mopv1a4.ImportOperationSpec{
					VirtualMachineID: existingVM.Status.UniqueID,
					StorageClass:     resources.StorageClassName,
					RestoreConfig:    &mopv1a4.RestoreConfig{ProcessRestoreData: mopv1a4.RestoreDataModeEnabled},
				},
			}
			Expect(svClusterClient.Create(ctx, importOperation)).To(Succeed(), "Failed to create ImportOperation")

			By("Wait for SkippedDiskBackings to be populated")
			// SkippedDiskBackings is written during the disk-precheck phase, which runs
			// before (and independently of) CNS volume registration. Polling only for this
			// field avoids blocking on the full CNS registration path that can be slow or
			// error out when the PVC is already registered from a prior restore.
			Eventually(func(g Gomega) {
				g.Expect(svClusterClient.Get(ctx, ctrlclient.ObjectKey{
					Namespace: importOperation.Namespace, Name: importOperation.Name,
				}, importOperation)).To(Succeed())
				g.Expect(importOperation.Status.RestoreStatus).ToNot(BeNil())
				g.Expect(importOperation.Status.RestoreStatus.VolumeRegistration).ToNot(BeNil())
				g.Expect(importOperation.Status.RestoreStatus.VolumeRegistration.SkippedDiskBackings).
					ToNot(BeEmpty(), "SkippedDiskBackings not yet populated")
			}, config.GetIntervals("default", "wait-config-map-creation")...).
				Should(Succeed(), "ImportOperation should have SkippedDiskBackings populated")

			By("Verify SkippedDiskBackings contains the non-FlatVer2 SE sparse disk")
			// The controller stores fmt.Sprintf("%T", disk.Backing) — the Go type name — not a filename.
			skipped := importOperation.Status.RestoreStatus.VolumeRegistration.SkippedDiskBackings
			Expect(skipped).To(ContainElement(ContainSubstring("SeSparse")),
				"SE sparse disk (non-FlatVer2) should appear in SkippedDiskBackings as its type name")

			By("Verify FlatVer2 disks are NOT in SkippedDiskBackings")
			for _, s := range skipped {
				Expect(s).ToNot(ContainSubstring("FlatVer2"),
					"FlatVer2 disks should NOT appear in SkippedDiskBackings")
			}

			By("Wait for CnsRegisterVolume to be created for pvc-a")
			// The controller creates a CnsRegisterVolume (name prefixed "restored-") for each
			// PVC disk in the backup that needs CNS registration. The CRV's Spec.PvcName equals
			// its own generated name — it creates a NEW PVC so it does not collide with the
			// pre-existing pvcNameA. The original PVC name is preserved in the label.
			// The CRV is transient: once CNS sets Status.Registered=true the controller deletes it,
			// so we capture its properties here while it is still present.
			var observedCRVName string
			Eventually(func(g Gomega) {
				var crvList cnsv1alpha1.CnsRegisterVolumeList
				g.Expect(svClusterClient.List(ctx, &crvList,
					ctrlclient.InNamespace(vmNamespace),
					ctrlclient.MatchingLabels{crvImportOpLabelKey: importOpName},
				)).To(Succeed())
				g.Expect(crvList.Items).ToNot(BeEmpty(), "CnsRegisterVolume not yet created")
				crv := crvList.Items[0]
				observedCRVName = crv.Name
				g.Expect(observedCRVName).To(HavePrefix("restored-"),
					"CnsRegisterVolume should have a generated 'restored-' prefix name")
				g.Expect(crv.Labels[crvOriginalPVCLabelKey]).To(Equal(pvcNameA),
					"CnsRegisterVolume should be labeled with the original PVC name")
				g.Expect(crv.Spec.PvcName).To(Equal(observedCRVName),
					"CnsRegisterVolume Spec.PvcName must equal its own name (the new PVC)")
				g.Expect(crv.Spec.DiskURLPath).ToNot(BeEmpty(),
					"CnsRegisterVolume DiskURLPath should be populated with the backing disk URL")
			}, config.GetIntervals("default", "wait-config-map-creation")...).
				Should(Succeed(), "CnsRegisterVolume should be created for pvc-a")
			e2eframework.Logf("CnsRegisterVolume %q created for original PVC %q", observedCRVName, pvcNameA)

			By("Wait for ImportOperation RestoreVolumesRegistered=True")
			// The controller marks this condition True only after every CnsRegisterVolume it owns
			// reports Status.Registered=true (CNS accepted the disk registration). It then deletes
			// the CRVs and writes PVCNameMappings, so the condition being True is the authoritative
			// signal that the FlatVer2 disk was successfully registered with CNS.
			Eventually(func(g Gomega) {
				g.Expect(svClusterClient.Get(ctx, ctrlclient.ObjectKey{
					Namespace: importOperation.Namespace, Name: importOperation.Name,
				}, importOperation)).To(Succeed())
				var registered bool
				for _, cond := range importOperation.Status.Conditions {
					if cond.Type == "RestoreVolumesRegistered" && cond.Status == metav1.ConditionTrue {
						registered = true
						break
					}
				}
				g.Expect(registered).To(BeTrue(), "ImportOperation RestoreVolumesRegistered condition not yet true")
			}, config.GetIntervals("default", "wait-config-map-creation")...).
				Should(Succeed(), "ImportOperation should have RestoreVolumesRegistered=true")

			By("Verify PVCNameMappings records pvc-a registered to a new generated PVC")
			// PVCNameMappings is written by the controller after all CRVs complete.
			// OldName = original backup PVC name; NewName = generated "restored-..." PVC name.
			Expect(importOperation.Status.RestoreStatus.VolumeRegistration).ToNot(BeNil())
			pvcMappings := importOperation.Status.RestoreStatus.VolumeRegistration.PVCNameMappings
			Expect(pvcMappings).ToNot(BeEmpty(), "PVCNameMappings should be populated after registration")
			var mappingFound bool
			for _, m := range pvcMappings {
				if m.OldName == pvcNameA {
					mappingFound = true
					Expect(m.NewName).To(HavePrefix("restored-"),
						"restored PVC name should carry the 'restored-' prefix")
					Expect(m.NewName).ToNot(Equal(pvcNameA),
						"restored PVC must have a new generated name, not the original")
					e2eframework.Logf("PVC mapping recorded: %q → %q", m.OldName, m.NewName)
					break
				}
			}
			Expect(mappingFound).To(BeTrue(),
				"PVCNameMappings should contain an entry for %q", pvcNameA)

			By("Delete ImportOperation before VM to prevent reconcile blocking VM termination")
			Expect(svClusterClient.Delete(ctx, importOperation)).To(Succeed())

			Expect(clusterProxy.DeleteWithArgs(ctx, vmYaml)).To(Succeed(), "failed to delete virtualmachine")
		})
	})

	Context("RestoreToNew - pause annotation preserves backup ExtraConfig", func() {
		It("Should infer RestoreToNew and recreate the VM CR from backup",
			Label("extended-functional", "restore-to-new"), func() {
				if !vmServiceBackupRestoreEnabled {
					Skip("WCP_VMService_BackupRestore FSS is not enabled")
				}
				if !incrementalRestoreEnabled {
					Skip("WCP_VMService_Incremental_Restore FSS is not enabled")
				}

				vmNamespace := input.WCPNamespaceName
				vmName := fmt.Sprintf("%s-%s", specName, capiutil.RandomString(4))
				vmsvcClusterProxy := input.ClusterProxy.(*common.VMServiceClusterProxy)
				secretName := vmName + "-cloud-config-data"
				secretYaml := manifestbuilders.GetSecretYamlCloudConfig(manifestbuilders.Secret{
					Namespace: vmNamespace,
					Name:      secretName,
				})
				Expect(vmsvcClusterProxy.CreateWithArgs(ctx, secretYaml)).To(Succeed(), "failed to create Secret")

				resources := config.InfraConfig.ManagementClusterConfig.Resources

				vmYaml := manifestbuilders.GetVirtualMachineYamlA2(manifestbuilders.VirtualMachineYaml{
					Namespace:        vmNamespace,
					Name:             vmName,
					VMClassName:      resources.VMClassName,
					StorageClassName: resources.StorageClassName,
					ResourcePolicy:   resources.VMResourcePolicyName,
					ImageName:        linuxVMIName,
					Bootstrap: manifestbuilders.Bootstrap{
						CloudInit: &manifestbuilders.CloudInit{
							RawCloudConfig: &manifestbuilders.KeySelector{Key: "user-data", Name: secretName},
						},
					},
					PowerState: "PoweredOn",
				})
				Expect(vmsvcClusterProxy.CreateWithArgs(ctx, vmYaml)).To(Succeed(), "failed to create VM")

				vmoperator.WaitForVirtualMachineCreation(ctx, config, svClusterClient, vmNamespace, vmName)
				vmoperator.WaitForVirtualMachineMOID(ctx, config, svClusterClient, vmNamespace, vmName)

				existingVM, err := utils.GetVirtualMachine(ctx, svClusterClient, vmNamespace, vmName)
				Expect(err).ToNot(HaveOccurred())
				vmservice.WaitForBackupToComplete(ctx, existingVM, clusterProxy, config)

				adminClusterProxy, err := clusterProxy.NewAdminClusterProxy(ctx)
				Expect(err).ToNot(HaveOccurred())
				defer adminClusterProxy.Dispose(ctx)
				adminClient, err := adminClusterProxy.GetAdminClient()
				Expect(err).ToNot(HaveOccurred())

				By("Orphan PVCs owned by the VM to prevent disk detachment during force-delete")
				// When the VM CR is force-deleted (finalizer stripped), K8s GC immediately
				// deletes objects owned by the VM CR. PVC deletion triggers CSI to call
				// ControllerUnpublishVolume, detaching the FCD disk from the vSphere VM.
				// Without the disk in hardware, ImportOperation fails with
				// "backup disk X not found in VM hardware". Remove ownerReferences before
				// stripping the finalizer so GC leaves the PVCs (and their disks) intact.
				pvcList := &corev1.PersistentVolumeClaimList{}
				Expect(svClusterClient.List(ctx, pvcList, ctrlclient.InNamespace(vmNamespace))).To(Succeed())
				var orphanedPVCNames []string
				for i := range pvcList.Items {
					pvc := &pvcList.Items[i]
					var filteredOwners []metav1.OwnerReference
					for _, ref := range pvc.OwnerReferences {
						if ref.Kind != "VirtualMachine" || ref.Name != vmName {
							filteredOwners = append(filteredOwners, ref)
						}
					}
					if len(filteredOwners) == len(pvc.OwnerReferences) {
						continue // PVC not owned by this VM
					}
					pvcPatch := ctrlclient.MergeFrom(pvc.DeepCopy())
					pvc.OwnerReferences = filteredOwners
					Expect(svClusterClient.Patch(ctx, pvc, pvcPatch)).To(Succeed())
					orphanedPVCNames = append(orphanedPVCNames, pvc.Name)
				}

				By("Orphan CnsNodeVMBatchAttachment owned by the VM to prevent CSI disk detachment")
				// CnsNodeVMBatchAttachment is controller-owned by the VM CR (SetControllerReference
				// in the volumebatch controller). When the VM CR is force-deleted, K8s GC deletes
				// this attachment object. CSI reacts to the deletion by issuing
				// ControllerUnpublishVolume for every listed volume, physically detaching FCD
				// disks BEFORE the ImportOperation controller has a chance to validate hardware.
				// This is the second GC chain causing "backup disk X not found in VM hardware",
				// independent of the PVC chain above. Removing the ownerReference prevents GC
				// from deleting the attachment; CSI continues to see a valid attachment spec and
				// keeps the disks attached through the delete. The attachment is named after the
				// VM (CNSBatchAttachmentNameForVM(vmName) == vmName). After the ImportOperation
				// completes and the new VM CR is created, the volumebatch controller will
				// re-adopt and update this attachment for the restored VM.
				cnsAttachment := &cnsv1alpha1.CnsNodeVMBatchAttachment{}
				if getErr := svClusterClient.Get(ctx, ctrlclient.ObjectKey{
					Namespace: vmNamespace,
					Name:      vmName,
				}, cnsAttachment); getErr == nil {
					attachmentPatch := ctrlclient.MergeFrom(cnsAttachment.DeepCopy())
					cnsAttachment.OwnerReferences = nil
					Expect(adminClient.Patch(ctx, cnsAttachment, attachmentPatch)).To(Succeed())
				}

				By("Add pause annotation to prevent ReconcileDelete from wiping ExtraConfig")
				// With PauseAnnotation set, ReconcileDelete returns nil immediately, skipping
				// CleanupVirtualMachine. The vSphere VM retains all backup ExtraConfig keys
				// (VMResourceYAML, PVCDiskData, BackupVersion) intact through the deletion.
				vm, err := utils.GetVirtualMachineA3(ctx, svClusterClient, vmNamespace, vmName)
				Expect(err).ToNot(HaveOccurred())
				if vm.Annotations == nil {
					vm.Annotations = map[string]string{}
				}
				vm.Annotations[vmopv1a3.PauseAnnotation] = trueString
				Expect(svClusterClient.Update(ctx, vm)).To(Succeed())

				By("Delete VM CR (pause annotation blocks ReconcileDelete; CR enters Terminating)")
				Expect(svClusterClient.Delete(ctx, vm)).To(Succeed())

				By("Wait for deletionTimestamp, then strip finalizer so K8s GC deletes the CR")
				// ReconcileDelete is a no-op when paused; force-remove the finalizer so K8s
				// garbage-collects the CR without VM Operator ever calling CleanupVirtualMachine.
				// The vSphere VM and all its backup ExtraConfig keys remain intact.
				Eventually(func(g Gomega) {
					vm, err = utils.GetVirtualMachineA3(ctx, svClusterClient, vmNamespace, vmName)
					g.Expect(err).ToNot(HaveOccurred())
					g.Expect(vm.DeletionTimestamp).ToNot(BeNil())
				}, config.GetIntervals("default", "wait-config-map-creation")...).Should(Succeed())

				patchBase := ctrlclient.MergeFrom(vm.DeepCopy())
				vm.Finalizers = []string{}
				Expect(svClusterClient.Patch(ctx, vm, patchBase)).To(Succeed())

			vmoperator.WaitForVirtualMachineToBeDeleted(ctx, config, svClusterClient, vmNamespace, vmName)

			By("Invoke RegisterVM API — WCP dispatches to ImportOperation controller")
			// VM CR is absent; backup ExtraConfig is intact on the vSphere VM.
			// WCP creates an ImportOperation CR which the controller reconciles,
			// infers RestoreToNew, and recreates the VM CR from VMResourceYAML.
			taskInfo, err := vmservice.InvokeRegisterVM(ctx, existingVM.Status.UniqueID, vmNamespace, clusterProxy, wcpClient)
			Expect(err).ToNot(HaveOccurred())
			Expect(taskInfo).ToNot(BeNil())

			vmservice.VerifyPostRegisterVM(ctx, vmName, vmNamespace, nil, len(existingVM.Spec.Volumes), clusterProxy, config, svClusterClient, wcpClient)

			// Delete PVCs we orphaned earlier; GC cannot clean them up since we removed
			// their ownerReferences, and they are no longer needed after the restore.
			for _, pvcName := range orphanedPVCNames {
				pvc := &corev1.PersistentVolumeClaim{}
				if getErr := svClusterClient.Get(ctx, ctrlclient.ObjectKey{
					Namespace: vmNamespace, Name: pvcName,
				}, pvc); getErr == nil {
					_ = svClusterClient.Delete(ctx, pvc)
				}
			}

			Expect(clusterProxy.DeleteWithArgs(ctx, vmYaml)).To(Succeed(), "failed to delete virtualmachine")
			})
	})

	Context("DiskOnlyRestore - dangling PVC detection", func() {
		It("Should detect dangling PVCs when the PVC→PV→CNS chain is broken", Label("extended-functional", "restore-status"), func() {
			if !vmServiceBackupRestoreEnabled {
				Skip("WCP_VMService_BackupRestore FSS is not enabled")
			}
			if !incrementalRestoreEnabled {
				Skip("WCP_VMService_Incremental_Restore FSS is not enabled")
			}

			adminClusterProxy, err := clusterProxy.NewAdminClusterProxy(ctx)
			Expect(err).ToNot(HaveOccurred())
			defer adminClusterProxy.Dispose(ctx)

			vCenterHostname := vcenter.GetVCPNIDFromKubeconfig(ctx, clusterProxy.GetKubeconfigPath())
			adminClient, err := adminClusterProxy.GetAdminClient()
			Expect(err).ToNot(HaveOccurred())
			vmopSecret, err := utils.GetSecret(ctx, adminClient, "vmware-system-vmop", "wcp-vmop-sa-vc-auth")
			Expect(err).ToNot(HaveOccurred())
			vmopvCenterClient, err := vcenter.NewVimClient(vCenterHostname, string(vmopSecret.Data["username"]), string(vmopSecret.Data["password"]))
			Expect(err).ToNot(HaveOccurred())
			defer vcenter.LogoutVimClient(vmopvCenterClient)

			vCenterClient := vcenter.NewVimClientFromKubeconfig(ctx, clusterProxy.GetKubeconfigPath())
			defer vcenter.LogoutVimClient(vCenterClient)

			vmNamespace := input.WCPNamespaceName
			vmName := fmt.Sprintf("%s-%s", specName, capiutil.RandomString(4))
			vmsvcClusterProxy := input.ClusterProxy.(*common.VMServiceClusterProxy)
			secretName := vmName + "-cloud-config-data"
			secretYaml := manifestbuilders.GetSecretYamlCloudConfig(manifestbuilders.Secret{
				Namespace: vmNamespace,
				Name:      secretName,
			})
			Expect(vmsvcClusterProxy.CreateWithArgs(ctx, secretYaml)).To(Succeed(), "failed to create Secret")

			resources := config.InfraConfig.ManagementClusterConfig.Resources
			pvcNameA := vmName + "-pvc-a"
			pvcNameB := vmName + "-pvc-b"
			testutils.AssertCreatePVC(svClusterClientSet, pvcNameA, vmNamespace, resources.StorageClassName)
			testutils.AssertCreatePVC(svClusterClientSet, pvcNameB, vmNamespace, resources.StorageClassName)

			vmYaml := manifestbuilders.GetVirtualMachineYamlA2(manifestbuilders.VirtualMachineYaml{
				Namespace:        vmNamespace,
				Name:             vmName,
				VMClassName:      resources.VMClassName,
				StorageClassName: resources.StorageClassName,
				ResourcePolicy:   resources.VMResourcePolicyName,
				ImageName:        linuxVMIName,
				Bootstrap: manifestbuilders.Bootstrap{
					CloudInit: &manifestbuilders.CloudInit{
						RawCloudConfig: &manifestbuilders.KeySelector{Key: "user-data", Name: secretName},
					},
				},
				PowerState: "PoweredOn",
				PVCNames:   []string{pvcNameA, pvcNameB},
			})
			Expect(vmsvcClusterProxy.CreateWithArgs(ctx, vmYaml)).To(Succeed(), "failed to create VM")

			vmoperator.WaitForVirtualMachineCreation(ctx, config, svClusterClient, vmNamespace, vmName)
			vmoperator.WaitForVirtualMachineMOID(ctx, config, svClusterClient, vmNamespace, vmName)
			vmoperator.WaitForPVCAttachment(ctx, config, svClusterClient, vmNamespace, vmName, pvcNameA)
			vmoperator.WaitForPVCAttachment(ctx, config, svClusterClient, vmNamespace, vmName, pvcNameB)

			existingVM, err := utils.GetVirtualMachine(ctx, svClusterClient, vmNamespace, vmName)
			Expect(err).ToNot(HaveOccurred())
			vmservice.WaitForBackupToComplete(ctx, existingVM, clusterProxy, config)

			vmMoRef := types.ManagedObjectReference{Type: "VirtualMachine", Value: existingVM.Status.UniqueID}
			vmObj := object.NewVirtualMachine(vmopvCenterClient, vmMoRef)

			By("Save ExtraConfig backup data")
			propCollector := property.DefaultCollector(vCenterClient)
			var vmMO mo.VirtualMachine
			Expect(propCollector.RetrieveOne(ctx, vmMoRef, []string{"config.extraConfig"}, &vmMO)).To(Succeed())
			Expect(vmMO.Config).ToNot(BeNil())
			ecList := object.OptionValueList(vmMO.Config.ExtraConfig)
			resourceYAML, _ := ecList.GetString(backupapi.VMResourceYAMLExtraConfigKey)
			pvcBackup, _ := ecList.GetString(backupapi.PVCDiskDataExtraConfigKey)
			backupVersion, _ := ecList.GetString(backupapi.BackupVersionExtraConfigKey)
			Expect(resourceYAML).ToNot(BeEmpty())
			Expect(pvcBackup).ToNot(BeEmpty())
			Expect(backupVersion).ToNot(BeEmpty())

			By("Power off the VM")
			vmoperator.UpdateVirtualMachinePowerState(ctx, config, svClusterClient, vmNamespace, vmName, "PoweredOff")
			vmoperator.WaitForVirtualMachinePowerState(ctx, config, svClusterClient, vmNamespace, vmName, "PoweredOff")

			By("Add the pause annotation to VM")
			vm, err := utils.GetVirtualMachine(ctx, svClusterClient, vmNamespace, vmName)
			Expect(err).ToNot(HaveOccurred())
			if vm.Annotations == nil {
				vm.Annotations = make(map[string]string)
			}
			vm.Annotations[vmopv1a3.PauseAnnotation] = trueString
			Expect(svClusterClient.Update(ctx, vm)).To(Succeed())

			By("Read the current backup-version annotation from the VM CR to derive a safely newer ExtraConfig version")
			// Re-read the VM CR after the pause annotation was added, so that any backup that ran
			// between "Save ExtraConfig" and "pause" is accounted for.  Incrementing the annotation
			// value by 1 ms guarantees that restoreBackupTime >= lastBackupTime in inferRestoreType,
			// which causes the controller to infer DiskOnlyRestore instead of RestoreToExisting.
			vmAfterPause, err := utils.GetVirtualMachine(ctx, svClusterClient, vmNamespace, vmName)
			Expect(err).ToNot(HaveOccurred())
			currentAnnotationVer := vmAfterPause.Annotations[vmopv1a3.VirtualMachineBackupVersionAnnotation]
			Expect(currentAnnotationVer).ToNot(BeEmpty(), "expected backup-version annotation on VM CR after pause")
			bvInt, err := strconv.ParseInt(currentAnnotationVer, 10, 64)
			Expect(err).ToNot(HaveOccurred(), "backup version annotation must be a numeric string, got: %s", currentAnnotationVer)
			newerBackupVersion := strconv.FormatInt(bvInt+1, 10)

			By("Re-inject ExtraConfig with the incremented backup version")
			reconfigTask, err := vmObj.Reconfigure(ctx, types.VirtualMachineConfigSpec{
				ExtraConfig: []types.BaseOptionValue{
					&types.OptionValue{Key: backupapi.VMResourceYAMLExtraConfigKey, Value: resourceYAML},
					&types.OptionValue{Key: backupapi.PVCDiskDataExtraConfigKey, Value: pvcBackup},
					&types.OptionValue{Key: backupapi.BackupVersionExtraConfigKey, Value: newerBackupVersion},
				},
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(reconfigTask.Wait(ctx)).To(Succeed())

			By("Retrieve VM home directory and find pvcA's FCD-backed disk")
			var vmMOFiles mo.VirtualMachine
			Expect(propCollector.RetrieveOne(ctx, vmMoRef, []string{"config.files"}, &vmMOFiles)).To(Succeed())
			var vmDiskPath object.DatastorePath
			vmDiskPath.FromString(vmMOFiles.Config.Files.VmPathName)
			vmHome := path.Dir(vmDiskPath.Path)

			pvcA := &corev1.PersistentVolumeClaim{}
			Expect(svClusterClient.Get(ctx, ctrlclient.ObjectKey{Namespace: vmNamespace, Name: pvcNameA}, pvcA)).
				To(Succeed())
			Expect(pvcA.Spec.VolumeName).ToNot(BeEmpty(), "pvcA must be bound to a PV")

			pvA := &corev1.PersistentVolume{}
			Expect(adminClient.Get(ctx, ctrlclient.ObjectKey{Name: pvcA.Spec.VolumeName}, pvA)).To(Succeed())
			Expect(pvA.Spec.CSI).ToNot(BeNil())
			volumeHandle := pvA.Spec.CSI.VolumeHandle
			Expect(volumeHandle).ToNot(BeEmpty())

			deviceList, err := vmObj.Device(ctx)
			Expect(err).ToNot(HaveOccurred())

			var (
				diskA     *types.VirtualDisk
				backingA  *types.VirtualDiskFlatVer2BackingInfo
				diskAPath object.DatastorePath
			)
			for _, dev := range deviceList.SelectByType((*types.VirtualDisk)(nil)) {
				vd := dev.(*types.VirtualDisk)
				if vd.VDiskId != nil && vd.VDiskId.Id == volumeHandle {
					diskA = vd
					backingA = vd.Backing.(*types.VirtualDiskFlatVer2BackingInfo)
					diskAPath.FromString(backingA.FileName)
					break
				}
			}
			Expect(diskA).ToNot(BeNil(), "expected to find pvcA's FCD disk on the VM")

			cnsVCClient, err := cns.NewClient(ctx, vCenterClient)
			Expect(err).ToNot(HaveOccurred())

			cnsQueryResult, err := cnsVCClient.QueryVolume(ctx, &cnstypes.CnsQueryFilter{
				VolumeIds: []cnstypes.CnsVolumeId{cnstypes.CnsVolumeId(*diskA.VDiskId)},
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(cnsQueryResult.Volumes).To(HaveLen(1))
			storageProfileID := cnsQueryResult.Volumes[0].StoragePolicyId

			dsA := object.NewDatastore(vCenterClient, *backingA.Datastore)
			fcdManager := vslm.NewObjectManager(vCenterClient)
			_, err = fcdManager.Retrieve(ctx, dsA, diskA.VDiskId.Id)
			Expect(err).ToNot(HaveOccurred())

			Expect(dsA.FindInventoryPath(ctx)).To(Succeed())
			dcA, err := find.NewFinder(vCenterClient).Datacenter(ctx, dsA.DatacenterPath)
			Expect(err).ToNot(HaveOccurred())
			fileManagerA := dsA.NewFileManager(dcA, false)

			By("Simulate disk-only restore: move pvcA backing to VM home folder and re-attach without FCD metadata")
			Expect(vmObj.RemoveDevice(ctx, true, diskA)).To(Succeed())

			dstA := path.Join(vmHome, path.Base(diskAPath.Path))
			Expect(fileManagerA.Copy(ctx, diskAPath.Path, dstA)).To(Succeed())
			Expect(fileManagerA.Delete(ctx, diskAPath.Path)).To(Succeed())

			// FCD is now orphaned — its backing file was moved out of the FCD path.
			_, err = fcdManager.Retrieve(ctx, dsA, diskA.VDiskId.Id)
			Expect(err).To(HaveOccurred())
			Expect(fault.Is(err, &types.NotFound{})).To(BeTrue())

			// Re-attach the VMDK as a plain (non-FCD) disk, emulating what Veeam produces.
			diskAPath.Path = dstA
			backingA.FileName = diskAPath.String()
			diskA.CapacityInKB = 0
			diskA.CapacityInBytes = 0
			Expect(vmObj.AddDeviceWithProfile(ctx, []types.BaseVirtualMachineProfileSpec{
				&types.VirtualMachineDefinedProfileSpec{ProfileId: storageProfileID},
			}, diskA)).To(Succeed())

			// ReconcileDatastoreInventory removes the orphaned FCD and its associated CNS volume,
			// leaving pvcA's PVC/PV pointing at a non-existent CNS entry — the "dangling" state.
			reconcileTask, err := fcdManager.ReconcileDatastoreInventory(ctx, dsA.Reference())
			Expect(err).ToNot(HaveOccurred())
			Expect(reconcileTask.Wait(ctx)).To(Succeed())

			By("Create ImportOperation CR directly in the supervisor cluster")
			importOpName := fmt.Sprintf("dangling-pvc-%s", capiutil.RandomString(4))
			importOperation := &mopv1a4.ImportOperation{
				ObjectMeta: metav1.ObjectMeta{Name: importOpName, Namespace: existingVM.Namespace},
				Spec: mopv1a4.ImportOperationSpec{
					VirtualMachineID: existingVM.Status.UniqueID,
					StorageClass:     resources.StorageClassName,
					RestoreConfig:    &mopv1a4.RestoreConfig{ProcessRestoreData: mopv1a4.RestoreDataModeEnabled},
				},
			}
			Expect(svClusterClient.Create(ctx, importOperation)).To(Succeed(), "Failed to create ImportOperation")

			By("Wait for ImportOperation to complete successfully")
			Eventually(func(g Gomega) {
				g.Expect(svClusterClient.Get(ctx, ctrlclient.ObjectKey{
					Namespace: importOperation.Namespace, Name: importOperation.Name,
				}, importOperation)).To(Succeed())
				for _, cond := range importOperation.Status.Conditions {
					if cond.Type == "Completed" && cond.Status == metav1.ConditionTrue {
						return
					}
				}
				g.Expect(false).To(BeTrue(), "ImportOperation not yet completed")
			}, config.GetIntervals("default", "wait-config-map-creation")...).
				Should(Succeed(), "ImportOperation should complete successfully")

			By("Verify RestoreType is DiskOnlyRestore")
			Expect(importOperation.Status.RestoreStatus).ToNot(BeNil())
			Expect(importOperation.Status.RestoreStatus.RestoreTypeInfo).ToNot(BeNil())
			Expect(importOperation.Status.RestoreStatus.RestoreTypeInfo.RestoreType).
				To(Equal(mopv1a4.RestoreTypeDiskOnlyRestore))

			By("Verify DetectedDanglingPVCs contains pvcA (broken CNS chain)")
			Expect(importOperation.Status.RestoreStatus.VolumeRegistration).ToNot(BeNil())
			dangling := importOperation.Status.RestoreStatus.VolumeRegistration.DetectedDanglingPVCs
			Expect(dangling).To(ContainElement(pvcNameA),
				"pvcA with broken CNS chain should appear in DetectedDanglingPVCs")

			By("Verify pvcB is NOT in DetectedDanglingPVCs (intact CNS chain)")
			Expect(dangling).ToNot(ContainElement(pvcNameB),
				"pvcB with intact CNS chain should NOT appear in DetectedDanglingPVCs")

			Expect(clusterProxy.DeleteWithArgs(ctx, vmYaml)).To(Succeed(), "failed to delete virtualmachine")
		})
	})

	Context("CrossVC failover - AlreadyRegistered PVCs", func() {
		It("Should report PVCs as already registered when CNS chain is intact and backup UUID differs (CrossVC)", Label("extended-functional", "restore-status1"), func() {
			if !vmServiceBackupRestoreEnabled {
				Skip("WCP_VMService_BackupRestore FSS is not enabled")
			}
			if !incrementalRestoreEnabled {
				Skip("WCP_VMService_Incremental_Restore FSS is not enabled")
			}

			adminClusterProxy, err := clusterProxy.NewAdminClusterProxy(ctx)
			Expect(err).ToNot(HaveOccurred())
			defer adminClusterProxy.Dispose(ctx)

			vCenterHostname := vcenter.GetVCPNIDFromKubeconfig(ctx, clusterProxy.GetKubeconfigPath())
			adminClient, err := adminClusterProxy.GetAdminClient()
			Expect(err).ToNot(HaveOccurred())
			vmopSecret, err := utils.GetSecret(ctx, adminClient, "vmware-system-vmop", "wcp-vmop-sa-vc-auth")
			Expect(err).ToNot(HaveOccurred())
			vmopvCenterClient, err := vcenter.NewVimClient(vCenterHostname, string(vmopSecret.Data["username"]), string(vmopSecret.Data["password"]))
			Expect(err).ToNot(HaveOccurred())
			defer vcenter.LogoutVimClient(vmopvCenterClient)

			vCenterClient := vcenter.NewVimClientFromKubeconfig(ctx, clusterProxy.GetKubeconfigPath())
			defer vcenter.LogoutVimClient(vCenterClient)

			vmNamespace := input.WCPNamespaceName
			vmName := fmt.Sprintf("%s-%s", specName, capiutil.RandomString(4))
			vmsvcClusterProxy := input.ClusterProxy.(*common.VMServiceClusterProxy)
			secretName := vmName + "-cloud-config-data"
			secretYaml := manifestbuilders.GetSecretYamlCloudConfig(manifestbuilders.Secret{
				Namespace: vmNamespace,
				Name:      secretName,
			})
			Expect(vmsvcClusterProxy.CreateWithArgs(ctx, secretYaml)).To(Succeed(), "failed to create Secret")

			resources := config.InfraConfig.ManagementClusterConfig.Resources
			pvcNameA := vmName + "-pvc-a"
			testutils.AssertCreatePVC(svClusterClientSet, pvcNameA, vmNamespace, resources.StorageClassName)

			vmYaml := manifestbuilders.GetVirtualMachineYamlA2(manifestbuilders.VirtualMachineYaml{
				Namespace:        vmNamespace,
				Name:             vmName,
				VMClassName:      resources.VMClassName,
				StorageClassName: resources.StorageClassName,
				ResourcePolicy:   resources.VMResourcePolicyName,
				ImageName:        linuxVMIName,
				Bootstrap: manifestbuilders.Bootstrap{
					CloudInit: &manifestbuilders.CloudInit{
						RawCloudConfig: &manifestbuilders.KeySelector{Key: "user-data", Name: secretName},
					},
				},
				PowerState: "PoweredOn",
				PVCNames:   []string{pvcNameA},
			})
			Expect(vmsvcClusterProxy.CreateWithArgs(ctx, vmYaml)).To(Succeed(), "failed to create VM")

			vmoperator.WaitForVirtualMachineCreation(ctx, config, svClusterClient, vmNamespace, vmName)
			vmoperator.WaitForVirtualMachineMOID(ctx, config, svClusterClient, vmNamespace, vmName)
			vmoperator.WaitForPVCAttachment(ctx, config, svClusterClient, vmNamespace, vmName, pvcNameA)

			existingVM, err := utils.GetVirtualMachine(ctx, svClusterClient, vmNamespace, vmName)
			Expect(err).ToNot(HaveOccurred())
			vmservice.WaitForBackupToComplete(ctx, existingVM, clusterProxy, config)

			vmMoRef := types.ManagedObjectReference{Type: "VirtualMachine", Value: existingVM.Status.UniqueID}
			vmObj := object.NewVirtualMachine(vmopvCenterClient, vmMoRef)

			By("Save ExtraConfig backup data")
			propCollector := property.DefaultCollector(vCenterClient)
			var vmMO mo.VirtualMachine
			Expect(propCollector.RetrieveOne(ctx, vmMoRef, []string{"config.extraConfig"}, &vmMO)).To(Succeed())
			Expect(vmMO.Config).ToNot(BeNil())
			ecList := object.OptionValueList(vmMO.Config.ExtraConfig)
			resourceYAML, _ := ecList.GetString(backupapi.VMResourceYAMLExtraConfigKey)
			pvcBackupEncoded, _ := ecList.GetString(backupapi.PVCDiskDataExtraConfigKey)
			backupVersion, _ := ecList.GetString(backupapi.BackupVersionExtraConfigKey)
			Expect(resourceYAML).ToNot(BeEmpty())
			Expect(pvcBackupEncoded).ToNot(BeEmpty())
			Expect(backupVersion).ToNot(BeEmpty())

			By("Power off the VM")
			vmoperator.UpdateVirtualMachinePowerState(ctx, config, svClusterClient, vmNamespace, vmName, "PoweredOff")
			vmoperator.WaitForVirtualMachinePowerState(ctx, config, svClusterClient, vmNamespace, vmName, "PoweredOff")

			By("Add the pause annotation to VM")
			vm, err := utils.GetVirtualMachine(ctx, svClusterClient, vmNamespace, vmName)
			Expect(err).ToNot(HaveOccurred())
			if vm.Annotations == nil {
				vm.Annotations = make(map[string]string)
			}
			vm.Annotations[vmopv1a3.PauseAnnotation] = trueString
			Expect(svClusterClient.Update(ctx, vm)).To(Succeed())

			By("Patch manager-id annotation in backup VM YAML to simulate a CrossVC origin")
			// The controller reads the manager-id annotation from the VM resource YAML
			// stored in ExtraConfig and compares it to the live VM's manager-id. A mismatch
			// indicates CrossVC failover. We replace the annotation with a fake VC UUID while
			// leaving the PVC backup data intact (CNS chain remains valid → AlreadyRegisteredPVCs).
			backupYAMLRaw, err := vmservice.DecodeGzipBase64(resourceYAML)
			Expect(err).ToNot(HaveOccurred(), "failed to decode VMResourceYAML")

			var vmObj2 map[string]interface{}
			Expect(sigsyaml.Unmarshal([]byte(backupYAMLRaw), &vmObj2)).To(Succeed(), "failed to unmarshal backup VM YAML")

			annotations, _ := vmObj2["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})
			if annotations == nil {
				annotations = make(map[string]interface{})
				vmObj2["metadata"].(map[string]interface{})["annotations"] = annotations
			}
			annotations["vmoperator.vmware.com/manager-id"] = "00000000-dead-beef-cafe-000000000000"

			patchedYAMLBytes, err := sigsyaml.Marshal(vmObj2)
			Expect(err).ToNot(HaveOccurred(), "failed to marshal patched backup VM YAML")
			patchedResourceYAML, err := vmservice.EncodeGzipBase64(string(patchedYAMLBytes))
			Expect(err).ToNot(HaveOccurred(), "failed to re-encode patched VM YAML")

			By("Re-inject ExtraConfig with CrossVC-simulated VM YAML (PVC backup data left intact)")
			reconfigTask, err := vmObj.Reconfigure(ctx, types.VirtualMachineConfigSpec{
				ExtraConfig: []types.BaseOptionValue{
					&types.OptionValue{Key: backupapi.VMResourceYAMLExtraConfigKey, Value: patchedResourceYAML},
					&types.OptionValue{Key: backupapi.PVCDiskDataExtraConfigKey, Value: pvcBackupEncoded},
					&types.OptionValue{Key: backupapi.BackupVersionExtraConfigKey, Value: backupVersion},
				},
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(reconfigTask.Wait(ctx)).To(Succeed())

			By("Assert pvcA PV is bound and has a CSI VolumeHandle before creating ImportOperation")
			// AlreadyRegistered detection requires: disk.VDiskId.Id == pv.Spec.CSI.VolumeHandle.
			// Verify the PVC/PV chain is intact so the controller's buildVolumeIDToPVCName
			// can find it via r.APIReader.List(PersistentVolumes).
			{
				pvcA := &corev1.PersistentVolumeClaim{}
				Expect(svClusterClient.Get(ctx, ctrlclient.ObjectKey{Namespace: vmNamespace, Name: pvcNameA}, pvcA)).
					To(Succeed())
				Expect(pvcA.Spec.VolumeName).ToNot(BeEmpty(),
					"pvcA must be bound to a PV before creating ImportOperation")
				pvA := &corev1.PersistentVolume{}
				Expect(adminClient.Get(ctx, ctrlclient.ObjectKey{Name: pvcA.Spec.VolumeName}, pvA)).
					To(Succeed())
				Expect(pvA.Spec.CSI).ToNot(BeNil(),
					"pvcA PV must have a CSI spec for AlreadyRegistered detection")
				Expect(pvA.Spec.CSI.VolumeHandle).ToNot(BeEmpty(),
					"pvcA PV CSI VolumeHandle must be non-empty")
			}

			By("Create ImportOperation CR")
			importOpName := fmt.Sprintf("crossvc-failover-%s", capiutil.RandomString(4))
			importOperation := &mopv1a4.ImportOperation{
				ObjectMeta: metav1.ObjectMeta{Name: importOpName, Namespace: existingVM.Namespace},
				Spec: mopv1a4.ImportOperationSpec{
					VirtualMachineID: existingVM.Status.UniqueID,
					StorageClass:     resources.StorageClassName,
					RestoreConfig:    &mopv1a4.RestoreConfig{ProcessRestoreData: mopv1a4.RestoreDataModeEnabled},
				},
			}
			Expect(svClusterClient.Create(ctx, importOperation)).To(Succeed(), "Failed to create ImportOperation")

			By("Wait for ImportOperation to complete")
			Eventually(func(g Gomega) {
				g.Expect(svClusterClient.Get(ctx, ctrlclient.ObjectKey{
					Namespace: importOperation.Namespace, Name: importOperation.Name,
				}, importOperation)).To(Succeed())
				for _, cond := range importOperation.Status.Conditions {
					if cond.Type == "Completed" && cond.Status == metav1.ConditionTrue {
						return
					}
				}
				g.Expect(false).To(BeTrue(), "ImportOperation not yet completed")
			}, config.GetIntervals("default", "wait-config-map-creation")...).
				Should(Succeed(), "ImportOperation should complete successfully")

			By("Verify RestoreTypeInfo shows CrossVC failover")
			Expect(importOperation.Status.RestoreStatus).ToNot(BeNil())
			Expect(importOperation.Status.RestoreStatus.RestoreTypeInfo).ToNot(BeNil())
			Expect(importOperation.Status.RestoreStatus.RestoreTypeInfo.Failover).
				To(Equal(mopv1a4.CrossVC))

			By("Verify AlreadyRegisteredPVCs contains pvcA (intact CNS chain, CrossVC)")
			Expect(importOperation.Status.RestoreStatus.VolumeRegistration).ToNot(BeNil())
			alreadyReg := importOperation.Status.RestoreStatus.VolumeRegistration.AlreadyRegisteredPVCs
			Expect(alreadyReg).To(ContainElement(pvcNameA),
				"pvcA with intact CNS chain should appear in AlreadyRegisteredPVCs during CrossVC failover")

			By("Verify pvcA is NOT in DetectedDanglingPVCs")
			Expect(importOperation.Status.RestoreStatus.VolumeRegistration.DetectedDanglingPVCs).
				ToNot(ContainElement(pvcNameA))

			Expect(clusterProxy.DeleteWithArgs(ctx, vmYaml)).To(Succeed(), "failed to delete virtualmachine")
		})
	})
}
