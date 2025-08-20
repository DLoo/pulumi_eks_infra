from typing import List, Optional, Dict, Any
import pulumi
from pulumi import Input, Output
import pulumi_aws as aws
# import pulumi_awsx as awsx
import pulumi_eks as eks
import pulumi_kubernetes as k8s
from pulumi_kubernetes.helm.v3 import Chart, ChartOpts, FetchOpts
import pulumi_kubernetes.yaml # Required for ConfigGroup
import json
import requests

config = pulumi.Config()
project_name = config.require("project_name") + "-" + pulumi.get_stack()
aws_region = aws.get_region().region
eks_cluster_name = config.get("eks_cluster_name") or f"{project_name}-cluster"
existing_vpc_id = config.require("existing_vpc_id")
existing_public_subnet_ids = config.require_object("existing_public_subnet_ids")
existing_private_subnet_ids = config.require_object("existing_private_subnet_ids")
# vpc_cidr = config.require("vpc_cidr")

eks_cluster_version = config.get("eks_cluster_version") or "1.33"
eks_cloudwatch_observability_version = config.get("eks_cloudwatch_observability_version") or "v4.3.1-eksbuild.1"
eks_ebs_csi_driver_version = config.get("eks_ebs_csi_driver_version") or "v1.44.0-eksbuild.1"
eks_efs_csi_driver_version = config.get("eks_efs_csi_driver_version") or " 3.1.9"
eks_volume_snapshotter_version = config.get("eks_volume_snapshotter_version") or "4.1.0"
eks_cert_manager_version = config.get("eks_cert_manager_version") or "v1.18.0"
eks_velero_version = config.get("eks_velero_version") or "10.0.4"
eks_aws_load_balancer_controller_version = config.get("eks_aws_load_balancer_controller_version") or "1.13.4"
# eks_cluster_autoscaler_version = config.get("eks_cluster_autoscaler_version") or "9.46.6" # Helm chart version for CAS
# eks_velero_aws_plugin_version = config.require("eks_velero_aws_plugin_version")
route53_hosted_zone_id = config.require("route53_hosted_zone_id")
external_dns_domains = config.require_object("external_dns_domains")


eks_efs_protect = config.get_bool("eks_efs_protect") if config.get("eks_efs_protect") is not None else True
eks_cluster_protect = config.get_bool("eks_cluster_protect") if config.get("eks_cluster_protect") is not None else False
eks_velero_protect = config.get_bool("eks_velero_protect") if config.get("eks_velero_protect") is not None else True














def create_common_tags(name: str, additional_tags: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Create a consistent set of tags for resources."""
    tags = {
        "Name": f"{project_name}-{name}",
        "Project": project_name,
        "Environment": config.get("environment") or "development",
        "ManagedBy": "pulumi"
    }
    if additional_tags:
        tags.update(additional_tags)
    return tags




















# Node configuration with defaults
node_config = {
    "instance_types": config.get_object("eks_node_instance_types") or ["t3.medium"],
    "desired_count": config.get_int("eks_node_desired_count") or 2,
    "min_count": config.get_int("eks_node_min_count") or 1,
    "max_count": config.get_int("eks_node_max_count") or 3,
}


vpc = aws.ec2.get_vpc(id=existing_vpc_id)






# --- IAM Roles ---
eks_service_role = aws.iam.Role(f"{project_name}-eks-service-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "eks.amazonaws.com"},
            "Action": [
                "sts:AssumeRole",
                "sts:TagSession"
            ],
        }],
    }),
    tags=create_common_tags("eks-service-role"))

aws.iam.RolePolicyAttachment(f"{project_name}-eks-service-policy-attachment",
    role=eks_service_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
aws.iam.RolePolicyAttachment(f"{project_name}-eks-vpc-resource-controller-attachment",
    role=eks_service_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonEKSVPCResourceController")
aws.iam.RolePolicyAttachment(f"{project_name}-eks-block-storage-attachment",
    role=eks_service_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonEKSBlockStoragePolicy")
aws.iam.RolePolicyAttachment(f"{project_name}-eks-compute-policy-attachment",
    role=eks_service_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonEKSComputePolicy")
aws.iam.RolePolicyAttachment(f"{project_name}-eks-loadbalancing-policy-attachment",
    role=eks_service_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonEKSLoadBalancingPolicy")
aws.iam.RolePolicyAttachment(f"{project_name}-eks-networking-policy-attachment",
    role=eks_service_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonEKSNetworkingPolicy")

eks_node_instance_role = aws.iam.Role(f"{project_name}-eks-node-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags=create_common_tags("eks-node-role"))

managed_node_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
]
for i, policy_arn in enumerate(managed_node_policy_arns):
    aws.iam.RolePolicyAttachment(f"{project_name}-nodegroup-policy-attachment-{i}",
        role=eks_node_instance_role.name,
        policy_arn=policy_arn)



# --- EKS Cluster ---
primary_instance_type = node_config["instance_types"][0] if node_config["instance_types"] else "t3.medium"


eks_cluster = eks.Cluster(f"{project_name}-eks",
    name=eks_cluster_name,
    service_role=eks_service_role,
    instance_role=eks_node_instance_role,
    vpc_id=vpc.id,
    public_subnet_ids=existing_public_subnet_ids,
    private_subnet_ids=existing_private_subnet_ids,
    create_oidc_provider=True,
    version=eks_cluster_version,
    enabled_cluster_log_types=["api", "audit", "authenticator", "controllerManager", "scheduler"],
    tags=create_common_tags("eks"),
    skip_default_node_group=True,
    # node_group_options=eks.ClusterNodeGroupOptionsArgs(
    #     instance_type=primary_instance_type,
    #     desired_capacity=node_config["desired_count"],
    #     min_size=node_config["min_count"],
    #     max_size=node_config["max_count"],
    #     labels={"ondemand": "true"}
    # ),
        
    opts=pulumi.ResourceOptions(
        protect=eks_cluster_protect,
        delete_before_replace=False,
        # depends_on=[vpc]
    ))

kubeconfig = eks_cluster.kubeconfig
k8s_provider = k8s.Provider(f"{project_name}-k8s-provider", kubeconfig=kubeconfig)


# ==============================================================================
# --- MANAGED NODE GROUPS (Following Official Pulumi Pattern) ---
# ==============================================================================

# 1. Create the primary node group that replaces the old "default" one.
#    It will automatically use the cluster's shared security group.
primary_node_group = eks.ManagedNodeGroup(f"{project_name}-primary-ng",
    cluster=eks_cluster, # Associate with our cluster
    node_group_name=f"{project_name}-primary-nodes",
    node_role=eks_node_instance_role, # Use the role you already defined
    instance_types=node_config["instance_types"],
    scaling_config=aws.eks.NodeGroupScalingConfigArgs(
        desired_size=node_config["desired_count"],
        min_size=node_config["min_count"],
        max_size=node_config["max_count"],
    ),
    subnet_ids=existing_private_subnet_ids,
    labels={"ondemand": "true", "workload-type": "primary"},
    tags=create_common_tags("primary-ng"),
    opts=pulumi.ResourceOptions(
        depends_on=[eks_cluster]
    )
)

# 2. Create your second node group. It's now a simple, repeatable pattern.
#    It will also automatically use the same shared security group.
m5_large_node_group = eks.ManagedNodeGroup(f"{project_name}-m5-large-ng",
    cluster=eks_cluster, # Associate with the SAME cluster
    node_group_name=f"{project_name}-m5-large-nodes",
    node_role=eks_node_instance_role, # Use the SAME role
    instance_types=["m5.large"],
    scaling_config=aws.eks.NodeGroupScalingConfigArgs(
        desired_size=node_config["desired_count"],
        min_size=node_config["min_count"],
        max_size=node_config["max_count"],
    ),
    subnet_ids=existing_private_subnet_ids,
    labels={"workload-type": "general-purpose", "instance-type": "m5-large"},
    tags=create_common_tags("m5-large-ng"),
    opts=pulumi.ResourceOptions(
        depends_on=[eks_cluster]
    )
)







# ==============================================================================
# --- 4. CERT-MANAGER (Certificate Management) ---
# ==============================================================================

cert_manager_namespace = k8s.core.v1.Namespace("cert-manager-ns",
    metadata={
        "name": "cert-manager",
        "labels": {
            # This label is for an older EKS Pod Identity system and is not required for IRSA.
            # It's harmless to keep but can be removed.
            "eks.amazonaws.com/pod-identity-webhook-enabled": "true"
        }
    },
    opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=[eks_cluster]))

# --- IAM for Cert-Manager ---

cert_manager_sa_name = f"{project_name}-cert-manager"
cert_manager_role_name = f"{project_name}-cert-manager-irsa-role"

# Manually construct the ARN to break the circular dependency for the permissions policy.
aws_account_id = eks_cluster.core.oidc_provider.arn.apply(lambda arn: arn.split(':')[4])
cert_manager_role_arn = pulumi.Output.concat("arn:aws:iam::", aws_account_id, ":role/", cert_manager_role_name)

# Define a single, consolidated permissions policy for cert-manager.
cert_manager_iam_policy = aws.iam.Policy(f"{project_name}-cert-manager-policy",
    name=f"{project_name}-CertManagerRoute53Policy",
    policy=pulumi.Output.all(
        hosted_zone_id=route53_hosted_zone_id,
        role_arn=cert_manager_role_arn
    ).apply(lambda args: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            # Standard Route53 permissions for DNS-01 challenge
            {
                "Effect": "Allow",
                "Action": ["route53:GetChange"],
                "Resource": "arn:aws:route53:::change/*"
            },
            {
                "Effect": "Allow",
                "Action": ["route53:ChangeResourceRecordSets", "route53:ListResourceRecordSets"],
                "Resource": f"arn:aws:route53:::hostedzone/{args['hosted_zone_id']}"
            },
            # Permission to discover the correct delegated hosted zone
            {
                "Effect": "Allow",
                "Action": ["route53:ListHostedZones", "route53:ListHostedZonesByName"],
                "Resource": "*"
            },
            # THE FINAL FIX: Permissions for the solver to get role info and assume itself
            {
                "Effect": "Allow",
                "Action": [
                    "iam:GetRole",
                    "sts:AssumeRole"
                ],
                "Resource": args['role_arn']
            }
        ]
    }))
)

# Create the IAM Role with the standard IRSA Trust Policy.
cert_manager_irsa_role = aws.iam.Role(f"{project_name}-cert-manager-irsa-role",
    name=cert_manager_role_name,
    assume_role_policy=pulumi.Output.all(
        oidc_provider_arn=eks_cluster.core.oidc_provider.arn,
        oidc_provider_url=eks_cluster.core.oidc_provider.url
    ).apply(
        lambda args: json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": args["oidc_provider_arn"]},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        f"{args['oidc_provider_url'].replace('https://', '')}:sub": f"system:serviceaccount:cert-manager:{cert_manager_sa_name}"
                    }
                }
            }]
        })
    ),
    tags=create_common_tags("cert-manager-irsa-role"),
    opts=pulumi.ResourceOptions(depends_on=[eks_cluster.core.oidc_provider])
)

# Attach the single, complete policy to the role.
aws.iam.RolePolicyAttachment(f"{project_name}-cert-manager-irsa-policy-attachment",
    role=cert_manager_irsa_role.name,
    policy_arn=cert_manager_iam_policy.arn
)

# --- Helm Chart for cert-manager ---

public_dns_resolvers = [
    "8.8.8.8:53",
    "8.8.4.4:53",
    "1.1.1.1:53"
]

cert_manager_chart = Chart(cert_manager_sa_name,
    ChartOpts(
        chart="cert-manager",
        version=eks_cert_manager_version,
        fetch_opts=FetchOpts(repo="https://charts.jetstack.io"),
        namespace=cert_manager_namespace.metadata["name"],
        values={
            "installCRDs": True,
            "prometheus": {"enabled": False},
            "serviceAccount": {
                "create": True,
                "name": cert_manager_sa_name,
                "annotations": {
                    "eks.amazonaws.com/role-arn": cert_manager_irsa_role.arn
                }
            },
            "extraArgs": [
                "--dns01-recursive-nameservers-only=true",
                f"--dns01-recursive-nameservers={','.join(public_dns_resolvers)}"
            ]
        }
    ),
    opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=[
        cert_manager_irsa_role,
        cert_manager_iam_policy # Explicit dependency on the policy
    ])
)









# --- EKS Add-ons & Cluster Services ---

ebs_csi_sa_name = "ebs-csi-controller-sa"
ebs_csi_namespace = "kube-system"

ebs_csi_policy_json = aws.iam.get_policy_document_output(
    statements=[
        aws.iam.GetPolicyDocumentStatementArgs(
            effect="Allow",
            actions=[
                "ec2:CreateSnapshot",
                "ec2:AttachVolume",
                "ec2:DetachVolume",
                "ec2:ModifyVolume",
                "ec2:DescribeAvailabilityZones",
                "ec2:DescribeInstances",
                "ec2:DescribeSnapshots",
                "ec2:DescribeTags",
                "ec2:DescribeVolumes",
                "ec2:DescribeVolumesModifications",
            ],
            resources=["*"],
        ),
        aws.iam.GetPolicyDocumentStatementArgs(
            effect="Allow",
            actions=[
                "ec2:CreateTags",
            ],
            resources=[f"arn:aws:ec2:{aws_region}:*:volume/*", f"arn:aws:ec2:{aws_region}:*:snapshot/*"],
            conditions=[
                aws.iam.GetPolicyDocumentStatementConditionArgs(
                    test="StringEquals",
                    variable="ec2:CreateAction",
                    values=["CreateVolume", "CreateSnapshot"],
                ),
            ],
        ),
        aws.iam.GetPolicyDocumentStatementArgs(
            effect="Allow",
            actions=[
                "ec2:DeleteTags",
            ],
            resources=[f"arn:aws:ec2:{aws_region}:*:volume/*", f"arn:aws:ec2:{aws_region}:*:snapshot/*"],
        ),
        aws.iam.GetPolicyDocumentStatementArgs(
            effect="Allow",
            actions=[
                "ec2:CreateVolume",
            ],
            resources=["*"],
            conditions=[
                aws.iam.GetPolicyDocumentStatementConditionArgs(
                    test="StringEquals",
                    variable="aws:RequestTag/ebs.csi.aws.com/cluster",
                    values=["true"],
                ),
            ],
        ),
        aws.iam.GetPolicyDocumentStatementArgs(
            effect="Allow",
            actions=[
                "ec2:CreateVolume",
            ],
            resources=["*"],
            conditions=[
                aws.iam.GetPolicyDocumentStatementConditionArgs(
                    test="StringEquals",
                    variable="aws:RequestTag/CSIVolumeName",
                    values=["*"],
                ),
            ],
        ),
        aws.iam.GetPolicyDocumentStatementArgs(
            effect="Allow",
            actions=[
                "ec2:DeleteVolume",
            ],
            resources=["*"],
            conditions=[
                aws.iam.GetPolicyDocumentStatementConditionArgs(
                    test="StringEquals",
                    variable="ec2:ResourceTag/ebs.csi.aws.com/cluster",
                    values=["true"],
                ),
            ],
        ),
        aws.iam.GetPolicyDocumentStatementArgs(
            effect="Allow",
            actions=[
                "ec2:DeleteVolume",
            ],
            resources=["*"],
            conditions=[
                aws.iam.GetPolicyDocumentStatementConditionArgs(
                    test="StringEquals",
                    variable="ec2:ResourceTag/CSIVolumeName",
                    values=["*"],
                ),
            ],
        ),
        aws.iam.GetPolicyDocumentStatementArgs(
            effect="Allow",
            actions=[
                "ec2:DeleteSnapshot",
            ],
            resources=["*"],
            conditions=[
                aws.iam.GetPolicyDocumentStatementConditionArgs(
                    test="StringEquals",
                    variable="ec2:ResourceTag/CSIVolumeSnapshotName",
                    values=["*"],
                ),
            ],
        ),
    ]
)

ebs_csi_policy = aws.iam.Policy(f"{project_name}-ebs-csi-policy",
    name=f"{project_name}-AmazonEKS_EBS_CSI_Driver_Policy",
    policy=ebs_csi_policy_json.json)

# 2. Create the IAM Role for the Service Account.
ebs_csi_irsa_role = aws.iam.Role(f"{project_name}-ebs-csi-irsa-role",
    assume_role_policy=pulumi.Output.all(
        oidc_provider_arn=eks_cluster.core.oidc_provider.arn,
        oidc_provider_url=eks_cluster.core.oidc_provider.url
    ).apply(
        lambda args: json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": args["oidc_provider_arn"]},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {f"{args['oidc_provider_url'].replace('https://', '')}:sub": f"system:serviceaccount:{ebs_csi_namespace}:{ebs_csi_sa_name}"}
                }
            }]
        })
    ),
    tags=create_common_tags("ebs-csi-irsa-role"))

# 3. Attach the policy to the role.
aws.iam.RolePolicyAttachment(f"{project_name}-ebs-csi-irsa-policy-attachment",
    role=ebs_csi_irsa_role.name,
    policy_arn=ebs_csi_policy.arn)



# ==============================================================================
# --- VOLUME SNAPSHOTTING SUPPORT (CRDs and Controller) ---
# This is the fix for the csi-snapshotter errors.
# It installs the required CRDs (VolumeSnapshotClass, VolumeSnapshot, etc.)
# and the snapshot-controller that manages them. This must be installed
# BEFORE any CSI drivers that use the snapshotting feature.
# ==============================================================================
volume_snapshotter_chart = Chart(f"{project_name}-snapshot-controller",
    ChartOpts(
        # The chart name from your successful command
        chart="snapshot-controller",
        version=eks_volume_snapshotter_version,
        fetch_opts=FetchOpts(
            # The repository from your successful command
            repo="https://piraeus.io/helm-charts/"
        ),
        namespace="kube-system",
        # The Piraeus chart installs CRDs by default, so no extra values are needed.
    ),
    opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=[eks_cluster]))


# Now, update the Addon to use the role we just created.
ebs_csi_driver_addon = eks.Addon(f"{project_name}-ebs-csi-driver",
    cluster=eks_cluster,
    addon_name="aws-ebs-csi-driver",
    addon_version=eks_ebs_csi_driver_version,
    service_account_role_arn=ebs_csi_irsa_role.arn,
    # --- FIX: Add an explicit dependency on the snapshotter chart ---
    # This ensures the CRDs are created before the EBS CSI driver starts.
    opts=pulumi.ResourceOptions(
        provider=k8s_provider,
        depends_on=[
            eks_cluster,
            volume_snapshotter_chart # Add this dependency
        ]
    )
)



gp3_storage_class = k8s.storage.v1.StorageClass("gp3-storage-class",
    metadata={"name": "gp3"},
    provisioner="ebs.csi.aws.com",
    parameters={"type": "gp3", "fsType": "ext4"},
    volume_binding_mode="WaitForFirstConsumer",
    allow_volume_expansion=True,
    reclaim_policy="Delete",
    opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=[ebs_csi_driver_addon]))









# 2. AWS Load Balancer Controller

iam_policy_url = "https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.13.2/docs/install/iam_policy.json" # Use the version matching your chart, or a recent one like v2.7.2
response = requests.get(iam_policy_url)
response.raise_for_status() # This will raise an error if the download fails
iam_policy_json = response.text


lbc_iam_policy = aws.iam.Policy(f"{project_name}-lbc-policy",
    name=f"{project_name}-AWSLoadBalancerControllerIAMPolicy",
    # policy=lbc_policy_document.json,
    policy=iam_policy_json,
    description="IAM policy for AWS Load Balancer Controller")

# Create a NEW, separate policy just for the ACM permissions.
lbc_acm_policy = aws.iam.Policy(f"{project_name}-lbc-acm-policy",
    name=f"{project_name}-LBC-ACMPermissions",
    description="Permissions for LBC to import and manage ACM certificates for Ingress",
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "acm:ImportCertificate",      # <- Crucial for adding certs to ACM
                    "acm:DeleteCertificate",      # <- Crucial for cleaning up certs from ACM
                    "acm:DescribeCertificate",    # <- Allows checking if a cert exists
                    "acm:ListCertificates",       # <- Allows listing certs
                    "acm:GetCertificate",         # <- Allows retrieving cert details
                    "acm:ListTagsForCertificate"  # <- Allows checking tags on certs
                ],
                "Resource": "*" # These actions generally require a wildcard resource
            },
            # The actions below are for a legacy method (IAM Server Certificates).
            # They are often included for backward compatibility but are not strictly
            # necessary for modern ALB+ACM integration. It's safe to include them.
            {
                "Effect": "Allow",
                "Action": [
                    "iam:CreateServerCertificate",
                    "iam:DeleteServerCertificate",
                    "iam:GetServerCertificate",
                    "iam:ListServerCertificates",
                    "iam:UpdateServerCertificate",
                    "iam:UploadServerCertificate"
                ],
                "Resource": "*"
            }
        ]
    })
)

lbc_sa_name = "aws-load-balancer-controller"
lbc_sa_namespace = "kube-system"

lbc_irsa_role = aws.iam.Role(f"{project_name}-lbc-irsa-role",
    assume_role_policy=pulumi.Output.all(oidc_provider_arn=eks_cluster.core.oidc_provider.arn, oidc_provider_url=eks_cluster.core.oidc_provider.url).apply(
        lambda args: json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": args["oidc_provider_arn"]},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {f"{args['oidc_provider_url'].replace('https://', '')}:sub": f"system:serviceaccount:{lbc_sa_namespace}:{lbc_sa_name}"}
                }
            }]
        })
    ),
    tags=create_common_tags("lbc-irsa-role"))

aws.iam.RolePolicyAttachment(f"{project_name}-lbc-irsa-policy-attachment",
    role=lbc_irsa_role.name,
    policy_arn=lbc_iam_policy.arn,
    opts=pulumi.ResourceOptions(depends_on=[lbc_irsa_role, lbc_iam_policy]))

aws.iam.RolePolicyAttachment(f"{project_name}-lbc-irsa-acm-policy-attachment",
    role=lbc_irsa_role.name, # Attaches to the SAME role
    policy_arn=lbc_acm_policy.arn, # Attaches our NEW policy
    opts=pulumi.ResourceOptions(depends_on=[lbc_irsa_role, lbc_acm_policy])
)


aws_load_balancer_controller_chart = Chart(f"{project_name}-lbc-chart",
    ChartOpts(
        chart="aws-load-balancer-controller",
        version=eks_aws_load_balancer_controller_version,
        fetch_opts=FetchOpts(repo="https://aws.github.io/eks-charts"),
        namespace=lbc_sa_namespace,
        values={
            "clusterName": eks_cluster.eks_cluster.name,
            "installCRDs": True,
            "serviceAccount": {
                "create": True,
                "name": lbc_sa_name,
                "annotations": {
                    "eks.amazonaws.com/role-arn": lbc_irsa_role.arn
                }
            },
            "region": aws_region,
            "vpcId": vpc.id,
            "rbac": {
                "create": True,
                # "extraRules": [
                #     {
                #         "apiGroups": [""],
                #         "resources": ["secrets"],
                #         "verbs": ["get", "list", "watch"],
                #     }
                # ]
            }
        }
    ), opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=[lbc_irsa_role, ebs_csi_driver_addon, cert_manager_chart]))

# kubectl apply -k "github.com/aws/eks-charts/stable/aws-load-balancer-controller/crds?ref=master"
# kubectl apply -f aws-lbc-crds.yaml




# 1. IAM Policy for ExternalDNS
external_dns_policy_doc = aws.iam.get_policy_document_output(statements=[
    aws.iam.GetPolicyDocumentStatementArgs(
        effect="Allow",
        actions=[
            "route53:ChangeResourceRecordSets"
        ],
        resources=[f"arn:aws:route53:::hostedzone/{route53_hosted_zone_id}"] # Scopes permissions to your specific zone
    ),
    aws.iam.GetPolicyDocumentStatementArgs(
        effect="Allow",
        actions=[
            "route53:ListHostedZones",
            "route53:ListResourceRecordSets"
        ],
        resources=["*"] # These actions require a wildcard resource
    )
])

external_dns_iam_policy = aws.iam.Policy(f"{project_name}-external-dns-policy",
    name=f"{project_name}-ExternalDNSRoute53Policy",
    policy=external_dns_policy_doc.json
)

# 2. IAM Role and Service Account for ExternalDNS
external_dns_sa_name = "external-dns"
# It's good practice to install cluster-wide tools in kube-system
external_dns_sa_namespace = "kube-system"

external_dns_irsa_role = aws.iam.Role(f"{project_name}-external-dns-irsa-role",
    assume_role_policy=pulumi.Output.all(
        oidc_provider_arn=eks_cluster.core.oidc_provider.arn,
        oidc_provider_url=eks_cluster.core.oidc_provider.url
    ).apply(
        lambda args: json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": args["oidc_provider_arn"]},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        f"{args['oidc_provider_url'].replace('https://', '')}:sub": f"system:serviceaccount:{external_dns_sa_namespace}:{external_dns_sa_name}"
                    }
                }
            }]
        })
    ),
    tags=create_common_tags("external-dns-irsa-role"),
    opts=pulumi.ResourceOptions(depends_on=[eks_cluster.core.oidc_provider])
)

aws.iam.RolePolicyAttachment(f"{project_name}-external-dns-irsa-policy-attachment",
    role=external_dns_irsa_role.name,
    policy_arn=external_dns_iam_policy.arn
)


# Get the existing kube-system namespace to avoid creation conflicts
kube_system_ns = k8s.core.v1.Namespace.get("kube-system", "kube-system", opts=pulumi.ResourceOptions(provider=k8s_provider))

# 3. Helm Chart for ExternalDNS
external_dns_chart = Chart("external-dns",
    ChartOpts(
        chart="external-dns",
        version="1.17.0", # Use a recent, stable version
        fetch_opts=FetchOpts(repo="https://kubernetes-sigs.github.io/external-dns/"),
        namespace=kube_system_ns.metadata["name"],
        values={
            "serviceAccount": {
                "create": True,
                "name": external_dns_sa_name,
                "annotations": {
                    "eks.amazonaws.com/role-arn": external_dns_irsa_role.arn
                }
            },
            "provider": "aws",
            "policy": "sync", # This ensures records are deleted when the Ingress is deleted
            "aws": {
                "region": aws_region
            },
            # IMPORTANT: This prevents ExternalDNS from touching domains it shouldn't
            "domainFilters": external_dns_domains,
            # IMPORTANT: This creates a TXT record to identify records managed by this instance
            "txtOwnerId": route53_hosted_zone_id
        }
    ), opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=[external_dns_irsa_role, aws_load_balancer_controller_chart]))





# 1. Create a dedicated Security Group for the EFS file system.
efs_security_group = aws.ec2.SecurityGroup(f"{project_name}-efs-sg",
    vpc_id=vpc.vpc_id,
    description="Allow NFS traffic from EKS nodes to EFS",
    tags=create_common_tags("efs-sg"),
    # Define the crucial ingress rule inline.
    ingress=[{
            "protocol":"tcp",
            "from_port":2049, # NFS port
            "to_port":2049,
            # This is the key: it allows traffic ONLY from the worker nodes.
            "security_groups": [eks_cluster.node_security_group_id],
            "description":"Allow NFS from EKS worker nodes"
    }],

)

# 2. Create the EFS File System.
efs_file_system = aws.efs.FileSystem(f"{project_name}-efs",
    tags=create_common_tags("efs"),
    # Adding protect is wise for production EFS file systems.
    opts=pulumi.ResourceOptions(protect=eks_efs_protect)
)


# 3. Create the EFS Mount Targets in each private subnet.
#    This now uses the dedicated EFS security group.
efs_mount_targets = []
for i, subnet_id in enumerate(existing_private_subnet_ids):
    mount_target = aws.efs.MountTarget(
        f"{project_name}-efs-mount-{i}",
        file_system_id=efs_file_system.id,
        subnet_id=subnet_id,
        # eks_cluster.node_security_group is a convenient output from the high-level eks.Cluster component
        security_groups=[efs_security_group.id]
    )
    efs_mount_targets.append(mount_target)


# This policy is sufficient for both controller and node components.
efs_csi_policy_doc = aws.iam.get_policy_document_output(statements=[aws.iam.GetPolicyDocumentStatementArgs(
    effect="Allow",
    actions=[
        "elasticfilesystem:DescribeAccessPoints",
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:DescribeMountTargets",
        "ec2:DescribeAvailabilityZones",
        "elasticfilesystem:CreateAccessPoint",
        "elasticfilesystem:DeleteAccessPoint",
        "elasticfilesystem:TagResource",
    ],
    resources=["*"])
])
efs_csi_iam_policy = aws.iam.Policy(f"{project_name}-efs-csi-policy", policy=efs_csi_policy_doc.json)

# --- IRSA for Controller ---
efs_csi_controller_sa_name = "efs-csi-controller-sa"
efs_csi_namespace = "kube-system"
efs_csi_controller_irsa_role = aws.iam.Role(f"{project_name}-efs-csi-controller-irsa-role",
    assume_role_policy=pulumi.Output.all(
        arn=eks_cluster.core.oidc_provider.arn,
        url=eks_cluster.core.oidc_provider.url
    ).apply(
        lambda args: json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": args["arn"]},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringEquals": {f"{args['url'].replace('https://', '')}:sub": f"system:serviceaccount:{efs_csi_namespace}:{efs_csi_controller_sa_name}"}}
            }]
        })
    ),
    # --- FIX: Add explicit dependency on the OIDC provider ---
    opts=pulumi.ResourceOptions(depends_on=[eks_cluster.core.oidc_provider])
)
aws.iam.RolePolicyAttachment(f"{project_name}-efs-csi-controller-irsa-attach", role=efs_csi_controller_irsa_role.name, policy_arn=efs_csi_iam_policy.arn)

# --- IRSA for Node ---
efs_csi_node_sa_name = "efs-csi-node-sa"
efs_csi_node_irsa_role = aws.iam.Role(f"{project_name}-efs-csi-node-irsa-role",
    assume_role_policy=pulumi.Output.all(
        arn=eks_cluster.core.oidc_provider.arn,
        url=eks_cluster.core.oidc_provider.url
    ).apply(
        lambda args: json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": args["arn"]},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringEquals": {f"{args['url'].replace('https://', '')}:sub": f"system:serviceaccount:{efs_csi_namespace}:{efs_csi_node_sa_name}"}}
            }]
        })
    ),
    # --- FIX: Add explicit dependency on the OIDC provider ---
    opts=pulumi.ResourceOptions(depends_on=[eks_cluster.core.oidc_provider])
)
aws.iam.RolePolicyAttachment(f"{project_name}-efs-csi-node-irsa-attach", role=efs_csi_node_irsa_role.name, policy_arn=efs_csi_iam_policy.arn)


# --- (Helm chart definition remains the same) ---
efs_csi_driver_chart = Chart(f"{project_name}-efs-csi-driver",
    ChartOpts(
        chart="aws-efs-csi-driver", version=eks_efs_csi_driver_version,
        fetch_opts=FetchOpts(repo="https://kubernetes-sigs.github.io/aws-efs-csi-driver/"),
        namespace=efs_csi_namespace,
        values={
            "controller": {
                "serviceAccount": {
                    "create": True,
                    "name": efs_csi_controller_sa_name,
                    "annotations": {"eks.amazonaws.com/role-arn": efs_csi_controller_irsa_role.arn}
                }
            },
            "node": {
                "serviceAccount": {
                    "create": True,
                    "name": efs_csi_node_sa_name,
                    "annotations": {"eks.amazonaws.com/role-arn": efs_csi_node_irsa_role.arn}
                }
            }
        }
    ), opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=efs_mount_targets))


efs_storage_class = k8s.storage.v1.StorageClass("efs-sc",
    metadata={"name": "efs-sc"},
    provisioner="efs.csi.aws.com",
    parameters={"provisioningMode": "efs-ap", "fileSystemId": efs_file_system.id, "directoryPerms": "700"},
    opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=[efs_csi_driver_chart]))




# ==============================================================================
# --- AMAZON CLOUDWATCH OBSERVABILITY ADD-ON ---
# ==============================================================================

# 1. Define the service account name and namespace the addon will use.
cloudwatch_sa_name = "cloudwatch-agent"
# The addon creates its own namespace, 'amazon-cloudwatch'
cloudwatch_sa_namespace = "amazon-cloudwatch"

# 2. Create the IAM role for the CloudWatch agent service account.
cloudwatch_observability_irsa_role = aws.iam.Role(f"{project_name}-cloudwatch-observability-irsa-role",
    assume_role_policy=pulumi.Output.all(
        oidc_provider_arn=eks_cluster.oidc_provider_arn,
        oidc_provider_url=eks_cluster.oidc_provider_url
    ).apply(
        lambda args: json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": args["oidc_provider_arn"]},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        # Condition to only allow the specific service account to assume the role
                        f"{args['oidc_provider_url'].replace('https://', '')}:sub": f"system:serviceaccount:{cloudwatch_sa_namespace}:{cloudwatch_sa_name}"
                    }
                }
            }]
        })
    ),
    tags=create_common_tags("cloudwatch-observability-irsa-role"),
    opts=pulumi.ResourceOptions(depends_on=[eks_cluster])
)

# 3. Attach the necessary AWS managed policy to the role.
# This policy grants permissions to send metrics and logs to CloudWatch.
aws.iam.RolePolicyAttachment(f"{project_name}-cloudwatch-observability-policy-attachment",
    role=cloudwatch_observability_irsa_role.name,
    policy_arn="arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
)

# 4. Install the 'amazon-cloudwatch-observability' EKS addon.
cloudwatch_observability_addon = eks.Addon(f"{project_name}-cloudwatch-observability-addon",
    cluster=eks_cluster,
    addon_name="amazon-cloudwatch-observability",
    addon_version=eks_cloudwatch_observability_version,
    # Associate the IAM role with the addon's service account.
    service_account_role_arn=cloudwatch_observability_irsa_role.arn,
    opts=pulumi.ResourceOptions(
        provider=k8s_provider,
        # Ensure the role and its policy attachment are created before the addon is installed.
        depends_on=[
            eks_cluster,
            cloudwatch_observability_irsa_role
        ]
    )
)





# --- Outputs ---
pulumi.export("vpc_id", vpc.id)
# pulumi.export("vpc_cidr_block", vpc.vpc.cidr_block)
# pulumi.export("public_subnet_ids", vpc.public_subnet_ids)
# pulumi.export("private_subnet_ids", vpc.private_subnet_ids)
# if db_subnets_ids:
#     pulumi.export("db_subnet_ids", db_subnets_ids)




# pulumi.export("eks_cluster_ca_data", eks_cluster.eks_cluster.certificate_authority.apply(lambda ca: ca.data))
# pulumi.export("kubeconfig", pulumi.Output.secret(kubeconfig))
# pulumi.export("eks_oidc_provider_url", eks_cluster.core.oidc_provider.url.apply(lambda url: url if url else "OIDC_PROVIDER_NOT_YET_AVAILABLE"))
# pulumi.export("eks_oidc_provider_arn", eks_cluster.core.oidc_provider.arn.apply(lambda arn: arn if arn else "OIDC_PROVIDER_NOT_YET_AVAILABLE"))
# pulumi.export("efs_filesystem_id", efs_file_system.id)
