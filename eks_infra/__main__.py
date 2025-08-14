from typing import List, Optional, Dict, Any
import pulumi
from pulumi import Input, Output
import pulumi_aws as aws
import pulumi_awsx as awsx
import pulumi_eks as eks
import pulumi_kubernetes as k8s
from pulumi_kubernetes.helm.v3 import Chart, ChartOpts, FetchOpts
import pulumi_kubernetes.yaml # Required for ConfigGroup
import json
import requests

# --- Configuration ---
config = pulumi.Config()
project_name = config.require("project_name")
aws_region = aws.get_region().name
eks_cluster_name = config.get("eks_cluster_name") or f"{project_name}-cluster"
vpc_cidr = config.require("vpc_cidr")
eks_cluster_version = config.get("eks_cluster_version") or "1.32"
eks_ebs_csi_driver_version = config.get("eks_ebs_csi_driver_version") or "v1.44.0-eksbuild.1"
eks_efs_csi_driver_version = config.get("eks_efs_csi_driver_version") or " 3.1.9"
eks_cert_manager_version = config.get("eks_cert_manager_version") or "v1.18.0"
eks_velero_version = config.get("eks_velero_version") or "10.0.4"
eks_aws_load_balancer_controller_version = config.get("eks_aws_load_balancer_controller_version") or "1.13.2"
eks_cluster_autoscaler_version = config.get("eks_cluster_autoscaler_version") or "9.46.6" # Helm chart version for CAS
eks_velero_aws_plugin_version = config.require("eks_velero_aws_plugin_version")
route53_hosted_zone_id = config.require("route53_hosted_zone_id")

eks_efs_protect = config.get_bool("eks_efs_protect") if config.get("eks_efs_protect") is not None else True
eks_cluster_protect = config.get_bool("eks_cluster_protect") if config.get("eks_cluster_protect") is not None else False
eks_velero_protect = config.get_bool("eks_velero_protect") if config.get("eks_velero_protect") is not None else True

def validate_subnet_cidrs(subnet_cidrs: List[str], az_count: int, subnet_type: str) -> bool:
    """Validate subnet CIDR configuration against availability zones."""
    if not subnet_cidrs:
        return False
    if len(subnet_cidrs) != az_count:
        pulumi.log.warn(
            f"Number of {subnet_type}_subnet_cidrs ({len(subnet_cidrs)}) "
            f"does not match number of availability_zones ({az_count})"
        )
        return False
    return True

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

# Error handling helper
def handle_resource_error(resource_name: str, e: Exception) -> None:
    """Centralized error handling for resource creation."""
    pulumi.log.error(f"Error creating {resource_name}: {str(e)}")
    raise e

def create_secret_string(key_id: str, secret_key: str) -> str:
    """Create a properly formatted credentials file content."""
    return f"""[default]
aws_access_key_id={key_id}
aws_secret_access_key={secret_key}
"""


# Validate CIDR format
if not vpc_cidr.strip() or not vpc_cidr.count('/') == 1:
    raise ValueError(f"Invalid VPC CIDR format: {vpc_cidr}")

# Type-safe configuration loading
public_subnet_cidrs: List[str] = config.require_object("public_subnet_cidrs")
private_subnet_cidrs: List[str] = config.require_object("private_subnet_cidrs")
db_subnet_cidrs: List[str] = config.get_object("db_subnet_cidrs") or []
availability_zones: List[str] = config.require_object("availability_zones")

# Validate availability zones
if not availability_zones:
    raise ValueError("At least one availability zone must be specified")

# Node configuration with defaults
node_config = {
    "instance_types": config.get_object("eks_node_instance_types") or ["t3.medium"],
    "desired_count": config.get_int("eks_node_desired_count") or 2,
    "min_count": config.get_int("eks_node_min_count") or 1,
    "max_count": config.get_int("eks_node_max_count") or 3,
}

# Validate node counts
if not (node_config["min_count"] <= node_config["desired_count"] <= node_config["max_count"]):
    raise ValueError("Invalid node count configuration: min <= desired <= max must be true")

velero_s3_bucket_name = config.require("velero_s3_bucket_name")

# --- Networking ---
subnet_specs = []
if validate_subnet_cidrs(public_subnet_cidrs, len(availability_zones), "public"):
    subnet_specs.append(awsx.ec2.SubnetSpecArgs(
        type=awsx.ec2.SubnetType.PUBLIC,
        cidr_blocks=public_subnet_cidrs,
        name="public"
    ))

if validate_subnet_cidrs(private_subnet_cidrs, len(availability_zones), "private"):
    subnet_specs.append(awsx.ec2.SubnetSpecArgs(
        type=awsx.ec2.SubnetType.PRIVATE,
        cidr_blocks=private_subnet_cidrs,
        name="private"
    ))

vpc = awsx.ec2.Vpc(f"{project_name}-vpc",
    cidr_block=vpc_cidr,
    availability_zone_names=availability_zones,
    subnet_specs=subnet_specs if subnet_specs else None,
    nat_gateways=awsx.ec2.NatGatewayConfigurationArgs(
        strategy=awsx.ec2.NatGatewayStrategy.ONE_PER_AZ
    ) if validate_subnet_cidrs(private_subnet_cidrs, len(availability_zones), "private") else None,
    tags=create_common_tags("vpc"))

db_subnets_ids = []
if db_subnet_cidrs:
    for i, cidr in enumerate(db_subnet_cidrs):
        az = availability_zones[i % len(availability_zones)]
        db_subnet = aws.ec2.Subnet(f"{project_name}-db-subnet-{i}",
            vpc_id=vpc.vpc_id,
            cidr_block=cidr,
            availability_zone=az,
            tags=create_common_tags(f"db-subnet-{az.split('-')[-1]}", {"Tier": "Database"}))
        db_subnets_ids.append(db_subnet.id)

if db_subnets_ids:
    db_subnet_group = aws.rds.SubnetGroup(f"{project_name}-db-sng",
        subnet_ids=db_subnets_ids,
        tags=create_common_tags("db-sng"))
    pulumi.export("db_subnet_group_name", db_subnet_group.name)

# --- IAM Roles ---
eks_service_role = aws.iam.Role(f"{project_name}-eks-service-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "eks.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags=create_common_tags("eks-service-role"))

aws.iam.RolePolicyAttachment(f"{project_name}-eks-service-policy-attachment",
    role=eks_service_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
aws.iam.RolePolicyAttachment(f"{project_name}-eks-vpc-resource-controller-attachment",
    role=eks_service_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonEKSVPCResourceController")

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


# # --- WAF (Web Application Firewall) with Let's Encrypt Exception ---
# web_acl = aws.wafv2.WebAcl(f"{project_name}-web-acl",
#     name=f"{project_name}-web-acl",
#     scope="REGIONAL",
#     default_action=aws.wafv2.WebAclDefaultActionArgs(allow={}),
#     visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
#         cloudwatch_metrics_enabled=True,
#         metric_name=f"{project_name}-web-acl-metrics",
#         sampled_requests_enabled=True,
#     ),
#     rules=[
#         # ==============================================================================
#         # === NEW RULE: Allow Let's Encrypt HTTP-01 challenge requests                 ===
#         # === This rule has the highest priority (0) to ensure it's evaluated first. ===
#         # ==============================================================================
#         aws.wafv2.WebAclRuleArgs(
#             name="Allow-LetsEncrypt-Challenge",
#             priority=0, # Highest priority
#             action=aws.wafv2.WebAclRuleActionArgs(
#                 allow=aws.wafv2.WebAclRuleActionAllowArgs() # Allow the request
#             ),
#             statement=aws.wafv2.WebAclRuleStatementArgs(
#                 byte_match_statement=aws.wafv2.WebAclRuleStatementByteMatchStatementArgs(
#                     # Look in the URI path of the request
#                     field_to_match=aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchArgs(
#                         uri_path=aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchUriPathArgs()
#                     ),
#                     # Match if the URI starts with this string
#                     search_string="/.well-known/acme-challenge/",
#                     positional_constraint="STARTS_WITH",
#                     text_transformations=[
#                         aws.wafv2.WebAclRuleStatementByteMatchStatementTextTransformationArgs(
#                             priority=0,
#                             type="NONE" # No transformation needed
#                         )
#                     ]
#                 )
#             ),
#             visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
#                 cloudwatch_metrics_enabled=True,
#                 metric_name="allow-letsencrypt",
#                 sampled_requests_enabled=True,
#             ),
#         ),
#         # ==============================================================================
#         # === Existing WAF Rules (Priorities are now shifted down by one)            ===
#         # ==============================================================================
#         # aws.wafv2.WebAclRuleArgs(
#         #     name="AWS-Managed-Rules-Common-Rule-Set",
#         #     priority=1, # Original priority was 1, stays the same relative to other block rules
#         #     override_action=aws.wafv2.WebAclRuleOverrideActionArgs(
#         #         none=aws.wafv2.WebAclRuleOverrideActionNoneArgs()
#         #     ),
#         #     statement=aws.wafv2.WebAclRuleStatementArgs(
#         #         managed_rule_group_statement=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementArgs(
#         #             vendor_name="AWS",
#         #             name="AWSManagedRulesCommonRuleSet",
#         #         )
#         #     ),
#         #     visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
#         #         cloudwatch_metrics_enabled=True,
#         #         metric_name="aws-managed-common-rules",
#         #         sampled_requests_enabled=True,
#         #     ),
#         # ),
#         # aws.wafv2.WebAclRuleArgs(
#         #     name="AWS-Managed-Rules-Amazon-Ip-Reputation-List",
#         #     priority=2, # Original priority was 2
#         #     override_action=aws.wafv2.WebAclRuleOverrideActionArgs(
#         #         none=aws.wafv2.WebAclRuleOverrideActionNoneArgs()
#         #     ),
#         #     statement=aws.wafv2.WebAclRuleStatementArgs(
#         #         managed_rule_group_statement=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementArgs(
#         #             vendor_name="AWS",
#         #             name="AWSManagedRulesAmazonIpReputationList",
#         #         )
#         #     ),
#         #     visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
#         #         cloudwatch_metrics_enabled=True,
#         #         metric_name="aws-managed-ip-reputation",
#         #         sampled_requests_enabled=True,
#         #     ),
#         # ),
#     ],
#     tags=create_common_tags("waf-acl")
# )



# --- EKS Cluster ---
primary_instance_type = node_config["instance_types"][0] if node_config["instance_types"] else "t3.medium"

eks_cluster = eks.Cluster(f"{project_name}-eks",
    name=eks_cluster_name,
    service_role=eks_service_role,
    instance_role=eks_node_instance_role,
    vpc_id=vpc.vpc_id,
    public_subnet_ids=vpc.public_subnet_ids,
    private_subnet_ids=vpc.private_subnet_ids,
    create_oidc_provider=True,
    version=eks_cluster_version,
    enabled_cluster_log_types=["api", "audit", "authenticator", "controllerManager", "scheduler"],
    tags=create_common_tags("eks"),
    node_group_options=eks.ClusterNodeGroupOptionsArgs(
        instance_type=primary_instance_type,
        desired_capacity=node_config["desired_count"],
        min_size=node_config["min_count"],
        max_size=node_config["max_count"],
        labels={"ondemand": "true"}
    ),
    opts=pulumi.ResourceOptions(
        protect=eks_cluster_protect,
        delete_before_replace=False,
        depends_on=[vpc]
    ))

kubeconfig = eks_cluster.kubeconfig
k8s_provider = k8s.Provider(f"{project_name}-k8s-provider", kubeconfig=kubeconfig)



# # ==============================================================================
# # --- 4. CERT-MANAGER (Certificate Management) ---
# # ==============================================================================

# cert_manager_namespace = k8s.core.v1.Namespace("cert-manager-ns",
#     metadata={
#         "name": "cert-manager",
#         "labels": {
#             # This label is for an older EKS Pod Identity system and is not required for IRSA.
#             # It's harmless to keep but can be removed.
#             "eks.amazonaws.com/pod-identity-webhook-enabled": "true"
#         }
#     },
#     opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=[eks_cluster]))

# # --- IAM for Cert-Manager ---

# cert_manager_sa_name = f"{project_name}-cert-manager"
# cert_manager_role_name = f"{project_name}-cert-manager-irsa-role"

# # Manually construct the ARN to break the circular dependency for the permissions policy.
# aws_account_id = eks_cluster.core.oidc_provider.arn.apply(lambda arn: arn.split(':')[4])
# cert_manager_role_arn = pulumi.Output.concat("arn:aws:iam::", aws_account_id, ":role/", cert_manager_role_name)

# # Define a single, consolidated permissions policy for cert-manager.
# cert_manager_iam_policy = aws.iam.Policy(f"{project_name}-cert-manager-policy",
#     name=f"{project_name}-CertManagerRoute53Policy",
#     policy=pulumi.Output.all(
#         hosted_zone_id=route53_hosted_zone_id,
#         role_arn=cert_manager_role_arn
#     ).apply(lambda args: json.dumps({
#         "Version": "2012-10-17",
#         "Statement": [
#             # Standard Route53 permissions for DNS-01 challenge
#             {
#                 "Effect": "Allow",
#                 "Action": ["route53:GetChange"],
#                 "Resource": "arn:aws:route53:::change/*"
#             },
#             {
#                 "Effect": "Allow",
#                 "Action": ["route53:ChangeResourceRecordSets", "route53:ListResourceRecordSets"],
#                 "Resource": f"arn:aws:route53:::hostedzone/{args['hosted_zone_id']}"
#             },
#             # Permission to discover the correct delegated hosted zone
#             {
#                 "Effect": "Allow",
#                 "Action": ["route53:ListHostedZones", "route53:ListHostedZonesByName"],
#                 "Resource": "*"
#             },
#             # THE FINAL FIX: Permissions for the solver to get role info and assume itself
#             {
#                 "Effect": "Allow",
#                 "Action": [
#                     "iam:GetRole",
#                     "sts:AssumeRole"
#                 ],
#                 "Resource": args['role_arn']
#             }
#         ]
#     }))
# )

# # Create the IAM Role with the standard IRSA Trust Policy.
# cert_manager_irsa_role = aws.iam.Role(f"{project_name}-cert-manager-irsa-role",
#     name=cert_manager_role_name,
#     assume_role_policy=pulumi.Output.all(
#         oidc_provider_arn=eks_cluster.core.oidc_provider.arn,
#         oidc_provider_url=eks_cluster.core.oidc_provider.url
#     ).apply(
#         lambda args: json.dumps({
#             "Version": "2012-10-17",
#             "Statement": [{
#                 "Effect": "Allow",
#                 "Principal": {"Federated": args["oidc_provider_arn"]},
#                 "Action": "sts:AssumeRoleWithWebIdentity",
#                 "Condition": {
#                     "StringEquals": {
#                         f"{args['oidc_provider_url'].replace('https://', '')}:sub": f"system:serviceaccount:cert-manager:{cert_manager_sa_name}"
#                     }
#                 }
#             }]
#         })
#     ),
#     tags=create_common_tags("cert-manager-irsa-role"),
#     opts=pulumi.ResourceOptions(depends_on=[eks_cluster.core.oidc_provider])
# )

# # Attach the single, complete policy to the role.
# aws.iam.RolePolicyAttachment(f"{project_name}-cert-manager-irsa-policy-attachment",
#     role=cert_manager_irsa_role.name,
#     policy_arn=cert_manager_iam_policy.arn
# )

# # --- Helm Chart for cert-manager ---

# public_dns_resolvers = [
#     "8.8.8.8:53",
#     "8.8.4.4:53",
#     "1.1.1.1:53"
# ]

# cert_manager_chart = Chart(cert_manager_sa_name,
#     ChartOpts(
#         chart="cert-manager",
#         version=eks_cert_manager_version,
#         fetch_opts=FetchOpts(repo="https://charts.jetstack.io"),
#         namespace=cert_manager_namespace.metadata["name"],
#         values={
#             "installCRDs": True,
#             "prometheus": {"enabled": False},
#             "serviceAccount": {
#                 "create": True,
#                 "name": cert_manager_sa_name,
#                 "annotations": {
#                     "eks.amazonaws.com/role-arn": cert_manager_irsa_role.arn
#                 }
#             },
#             "extraArgs": [
#                 "--dns01-recursive-nameservers-only=true",
#                 f"--dns01-recursive-nameservers={','.join(public_dns_resolvers)}"
#             ]
#         }
#     ),
#     opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=[
#         cert_manager_irsa_role,
#         cert_manager_iam_policy # Explicit dependency on the policy
#     ])
# )





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

# Now, update the Addon to use the role we just created.
ebs_csi_driver_addon = eks.Addon(f"{project_name}-ebs-csi-driver",
    cluster=eks_cluster,
    addon_name="aws-ebs-csi-driver",
    addon_version=eks_ebs_csi_driver_version,
    # --- FIX: Associate the IRSA role with the addon ---
    service_account_role_arn=ebs_csi_irsa_role.arn,
    # ---
    opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=[eks_cluster]))



# # 1. AWS EBS CSI Driver
# ebs_csi_driver_addon = eks.Addon(f"{project_name}-ebs-csi-driver",
#     cluster=eks_cluster,
#     addon_name="aws-ebs-csi-driver",
#     addon_version=eks_ebs_csi_driver_version,  # "v1.44.0-eksbuild.1" is the latest as of 2023-10-01
#     opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=[eks_cluster]))

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
            "vpcId": vpc.vpc_id,
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
    ), opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=[lbc_irsa_role, ebs_csi_driver_addon]))

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


# # Get the existing kube-system namespace to avoid creation conflicts
# kube_system_ns = k8s.core.v1.Namespace.get("kube-system", "kube-system", opts=pulumi.ResourceOptions(provider=k8s_provider))

# # 3. Helm Chart for ExternalDNS
# external_dns_chart = Chart("external-dns",
#     ChartOpts(
#         chart="external-dns",
#         version="1.17.0", # Use a recent, stable version
#         fetch_opts=FetchOpts(repo="https://kubernetes-sigs.github.io/external-dns/"),
#         namespace=kube_system_ns.metadata["name"],
#         values={
#             "serviceAccount": {
#                 "create": True,
#                 "name": external_dns_sa_name,
#                 "annotations": {
#                     "eks.amazonaws.com/role-arn": external_dns_irsa_role.arn
#                 }
#             },
#             "provider": "aws",
#             "policy": "sync", # This ensures records are deleted when the Ingress is deleted
#             "aws": {
#                 "region": aws_region
#             },
#             # IMPORTANT: This prevents ExternalDNS from touching domains it shouldn't
#             "domainFilters": ["api.mmh-global.com"],
#             # IMPORTANT: This creates a TXT record to identify records managed by this instance
#             "txtOwnerId": route53_hosted_zone_id
#         }
#     ), opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=[external_dns_irsa_role, aws_load_balancer_controller_chart]))





# --- 3. EFS & EFS CSI Driver (IRSA) ---
efs_file_system = aws.efs.FileSystem(f"{project_name}-efs", tags=create_common_tags("efs"))

efs_mount_targets = vpc.private_subnet_ids.apply(
    lambda subnet_ids: [
        aws.efs.MountTarget(
            f"{project_name}-efs-mount-{i}",
            file_system_id=efs_file_system.id,
            subnet_id=subnet_id,
            security_groups=[eks_cluster.node_security_group.id]
        )
        for i, subnet_id in enumerate(subnet_ids)
    ]
)

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


# --- Cluster Autoscaler (Compute Autoscaling) ---
cas_namespace = "kube-system" # Common namespace for CAS
cas_sa_name = "cluster-autoscaler"

# 1. IAM Policy for Cluster Autoscaler
cas_iam_policy_doc = aws.iam.get_policy_document(statements=[
    aws.iam.GetPolicyDocumentStatementArgs(
        effect="Allow",
        actions=[
            "autoscaling:DescribeAutoScalingGroups",
            "autoscaling:DescribeAutoScalingInstances",
            "autoscaling:DescribeLaunchConfigurations",
            "autoscaling:DescribeTags",
            "ec2:DescribeLaunchTemplateVersions",
            "ec2:DescribeInstanceTypes" # Added for more flexible instance type selection
        ],
        resources=["*"],
    ),
    aws.iam.GetPolicyDocumentStatementArgs(
        effect="Allow",
        actions=[
            "autoscaling:SetDesiredCapacity",
            "autoscaling:TerminateInstanceInAutoScalingGroup",
            "autoscaling:UpdateAutoScalingGroup", # Added for more comprehensive ASG management
        ],
        resources=["*"], # Should be scoped to ASGs tagged for this cluster
        # Example condition to scope to specific cluster, requires node groups to be tagged appropriately
        # conditions=[aws.iam.GetPolicyDocumentStatementConditionArgs(
        #     test="StringEquals",
        #     variable=f"autoscaling:ResourceTag/k8s.io/cluster-autoscaler/{eks_cluster.eks_cluster.name}", # Use actual cluster name
        #     values=["owned"]
        # )]
    )
])
cas_iam_policy = aws.iam.Policy(f"{project_name}-cas-policy",
    name=f"{project_name}-ClusterAutoscalerPolicy",
    policy=cas_iam_policy_doc.json,
    description="IAM policy for EKS Cluster Autoscaler")

# 2. IRSA Role for Cluster Autoscaler
cas_irsa_role = aws.iam.Role(f"{project_name}-cas-irsa-role",
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
                    "StringEquals": {f"{args['oidc_provider_url'].replace('https://', '')}:sub": f"system:serviceaccount:{cas_namespace}:{cas_sa_name}"}
                }
            }]
        })
    ),
    tags=create_common_tags("cas-irsa-role"),
    opts=pulumi.ResourceOptions(depends_on=[eks_cluster.core.oidc_provider]))

aws.iam.RolePolicyAttachment(f"{project_name}-cas-irsa-policy-attachment",
    role=cas_irsa_role.name,
    policy_arn=cas_iam_policy.arn)

# 3. Service Account for Cluster Autoscaler (annotated for IRSA)
# The Helm chart can create this, but creating it explicitly gives more control for IRSA.
cas_sa = k8s.core.v1.ServiceAccount(f"{project_name}-cas-sa",
    metadata=k8s.meta.v1.ObjectMetaArgs(
        name=cas_sa_name,
        namespace=cas_namespace,
        annotations={"eks.amazonaws.com/role-arn": cas_irsa_role.arn}
    ),
    opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=[eks_cluster.core.oidc_provider, cas_irsa_role]))


# 4. Helm Chart for Cluster Autoscaler
# Ensure your managed node groups are tagged correctly.
# pulumi-eks's `eks.Cluster` with `node_group_options` usually tags them with:
#   `k8s.io/cluster-autoscaler/enabled: "true"`
#   `k8s.io/cluster-autoscaler/<YOUR_CLUSTER_NAME>: "owned"`
# These tags are used by CAS for auto-discovery.

cluster_autoscaler_chart = Chart(f"{project_name}-cluster-autoscaler",
    ChartOpts(
        chart="cluster-autoscaler",
        version=eks_cluster_autoscaler_version,
        fetch_opts=FetchOpts(repo="https://kubernetes.github.io/autoscaler"),
        namespace=cas_namespace,
        values={
            "awsRegion": aws_region,
            "autoDiscovery": {
                # eks_cluster.eks_cluster.name is an Output, so we need to apply
                "clusterName": eks_cluster.eks_cluster.name,
            },
            "rbac": {
                "serviceAccount": {
                    "create": False, # We created it above with IRSA annotations
                    "name": cas_sa_name,
                },
                # PSP is deprecated, if your chart version still has it, set to false for K8s 1.25+
                # "pspEnabled": False 
            },
            "cloudProvider": "aws",
            # Important: Ensure this matches your EKS cluster name for tag-based discovery
            "extraArgs": {
                "balance-similar-node-groups": "true",
                "skip-nodes-with-local-storage": "false", # Default, adjust if needed
                "skip-nodes-with-system-pods": "true", # Default
                 # Example: To make CAS more aggressive about scaling down
                # "scale-down-unneeded-time": "5m",
                # "scale-down-delay-after-add": "10m",
            },
            # Add tolerations if CAS needs to run on tainted nodes (e.g. control plane or specific infra nodes)
            # "tolerations": [
            #    {"key": "CriticalAddonsOnly", "operator": "Exists"}
            # ],
        }
    ), opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=[
        cas_sa, efs_storage_class # Depends on SA and other k8s resources being ready
    ]))



# # 5. Velero
# velero_s3_bucket = aws.s3.BucketV2(f"{project_name}-velero-backups",
#     bucket=velero_s3_bucket_name,
#     tags=create_common_tags("velero-backups"))

# aws.s3.BucketPublicAccessBlock(f"{project_name}-velero-backups-public-access",
#     bucket=velero_s3_bucket.id,
#     block_public_acls=True,
#     block_public_policy=True,
#     ignore_public_acls=True,
#     restrict_public_buckets=True)

# velero_iam_user = aws.iam.User(f"{project_name}-velero-user", name=f"{project_name}-velero")

# velero_policy_json = pulumi.Output.all(bucket_name=velero_s3_bucket.bucket).apply(lambda args: json.dumps({
#     "Version": "2012-10-17",
#     "Statement": [
#         {
#             "Effect": "Allow",
#             "Action": [
#                 "ec2:DescribeVolumes", "ec2:DescribeSnapshots", "ec2:CreateTags",
#                 "ec2:CreateVolume", "ec2:CreateSnapshot", "ec2:DeleteSnapshot"
#             ],
#             "Resource": "*"
#         },
#         {
#             "Effect": "Allow",
#             "Action": [
#                 "s3:GetObject", "s3:DeleteObject", "s3:PutObject",
#                 "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"
#             ],
#             "Resource": [f"arn:aws:s3:::{args['bucket_name']}/*"]
#         },
#         {
#             "Effect": "Allow",
#             "Action": ["s3:ListBucket"],
#             "Resource": [f"arn:aws:s3:::{args['bucket_name']}"]
#         }
#     ]
# }))

# velero_iam_policy = aws.iam.Policy(f"{project_name}-velero-policy",
#     name=f"{project_name}-VeleroBackupPolicy",
#     policy=velero_policy_json)

# aws.iam.UserPolicyAttachment(f"{project_name}-velero-user-policy-attachment",
#     user=velero_iam_user.name,
#     policy_arn=velero_iam_policy.arn)

# velero_access_key = aws.iam.AccessKey(f"{project_name}-velero-access-key", user=velero_iam_user.name)

# # velero_credentials_file_content = pulumi.Output.all(
# #     key_id=velero_access_key.id,
# #     secret_key=velero_access_key.secret
# # ).apply(lambda args: f"[default]\naws_access_key_id={args['key_id']}\naws_secret_access_key={args['secret_key']}")

# velero_namespace = k8s.core.v1.Namespace("velero-ns",
#     metadata={"name": "velero"},
#     opts=pulumi.ResourceOptions(provider=k8s_provider, depends_on=[eks_cluster]))

# velero_secret = k8s.core.v1.Secret(
#     "velero-cloud-credentials",
#     metadata=k8s.meta.v1.ObjectMetaArgs(
#         name="cloud-credentials",
#         namespace=velero_namespace.metadata["name"],
#     ),
#     # THE FIX: Use pulumi.Output.all() to get both id and secret together.
#     string_data={
#         "cloud": pulumi.Output.all(
#             id=velero_access_key.id,
#             secret=velero_access_key.secret
#         ).apply(
#             lambda args: f"[default]\naws_access_key_id={args['id']}\naws_secret_access_key={args['secret']}"
#         )
#     },
#     type="Opaque",
#     opts=pulumi.ResourceOptions(
#         provider=k8s_provider,
#         depends_on=[velero_namespace, velero_access_key],
#         protect=eks_velero_protect
#     )
# )

# velero_chart = Chart(f"{project_name}-velero-chart",
#     ChartOpts(
#         chart="velero",
#         version=eks_velero_version,
#         fetch_opts=FetchOpts(repo="https://vmware-tanzu.github.io/helm-charts"),
#         namespace=velero_namespace.metadata["name"],
#         values={
#              "configuration": {
#                 "backupStorageLocation": [{
#                     "name": "default",
#                     "provider": "aws",
#                     "bucket": velero_s3_bucket.bucket,
#                     "config": {
#                         "region": aws_region
#                     }
#                 }],
#                 "volumeSnapshotLocation": [{
#                     "name": "default",
#                     "provider": "aws",
#                     "config": {
#                         "region": aws_region
#                     }
#                 }]
#             },
#             "credentials": {
#                 "useSecret": True,
#                 # The name of the k8s.core.v1.Secret resource we created earlier
#                 "existingSecret": velero_secret.metadata["name"]
#             },
#             "snapshotsEnabled": True,
#             # The `extraPlugins` key is not standard. Plugins are added via initContainers.
#             # This is the correct way to install the AWS plugin.
#             "initContainers": [
#                 {
#                     "name": "velero-plugin-for-aws",
#                     "image": "velero/velero-plugin-for-aws:v1.9.0", # Use a recent, compatible version
#                     "imagePullPolicy": "IfNotPresent",
#                     "volumeMounts": [{"mountPath": "/target", "name": "plugins"}],
#                 }
#             ],
#             "metrics": {
#                 "enabled": False
#             },
#             # This can be set to false as it is not needed for most backup/restore cases
#             # and is the source of the webhook error.
#             "deployNodeAgent": True,
#         }
#     ),     
#     opts=pulumi.ResourceOptions(
#         provider=k8s_provider,
#         # --- FIX 2: Add explicit dependency on the LBC chart ---
#         # This ensures the Velero chart waits until the LBC webhook is fully ready.
#         depends_on=[
#             velero_secret,
#             gp3_storage_class,
#             # aws_load_balancer_controller_chart # <-- This is the crucial addition for the webhook error
#         ]
#     )
# )







# # ----- [START] REPLACE THE MONITORING BLOCK WITH THIS SIMPLIFIED VERSION -----
# alert_email_address = config.get("alert_email_address") or "donaldhp.loo@mmh-global.com"

# # --- Monitoring and Alerting Setup (Infrastructure Only) ---
# # This code only creates the AWS resources (SNS, Alarms). The Kubernetes
# # agents will be deployed separately using kubectl.

# # 1. Create an SNS Topic for sending email alerts.
# alerting_sns_topic = aws.sns.Topic(f"{project_name}-alerts-topic",
#     display_name="EKS Cluster Alerts",
#     tags=create_common_tags("sns-alerts-topic")
# )

# # 2. Create an SNS Topic Subscription to send alerts to your email.
# #    IMPORTANT: You must confirm the subscription email from AWS.
# email_address_for_alerts = alert_email_address
# email_subscription = aws.sns.TopicSubscription(f"{project_name}-email-subscription",
#     topic=alerting_sns_topic.arn,
#     protocol="email",
#     endpoint=email_address_for_alerts
# )

# # --- Define CloudWatch Alarms ---
# # These alarms watch for metrics from Container Insights. They will remain in an
# # "Insufficient data" state until you deploy the agents via kubectl. This is expected.

# # Alarm for High Node CPU Utilization
# node_cpu_alarm = aws.cloudwatch.MetricAlarm(f"{project_name}-node-cpu-high",
#     name=f"{project_name}-EKSNodeCPUUtilizationHigh",
#     alarm_description="Alert when EKS node CPU utilization exceeds 80%",
#     alarm_actions=[alerting_sns_topic.arn],
#     metric_name="node_cpu_utilization",
#     namespace="ContainerInsights",
#     dimensions={"ClusterName": eks_cluster.eks_cluster.name}, # Pulumi correctly provides the cluster name here
#     comparison_operator="GreaterThanOrEqualToThreshold",
#     threshold=80, statistic="Average", period=300, evaluation_periods=2,
#     treat_missing_data="notBreaching", tags=create_common_tags("alarm-node-cpu")
# )

# # Alarm for High Node Memory Utilization
# node_memory_alarm = aws.cloudwatch.MetricAlarm(f"{project_name}-node-memory-high",
#     name=f"{project_name}-EKSNodeMemoryUtilizationHigh",
#     alarm_description="Alert when EKS node memory utilization exceeds 85%",
#     alarm_actions=[alerting_sns_topic.arn],
#     metric_name="node_memory_utilization",
#     namespace="ContainerInsights",
#     dimensions={"ClusterName": eks_cluster.eks_cluster.name},
#     comparison_operator="GreaterThanOrEqualToThreshold",
#     threshold=85, statistic="Average", period=300, evaluation_periods=2,
#     treat_missing_data="notBreaching", tags=create_common_tags("alarm-node-memory")
# )

# # Alarm for Low Node Disk Space
# node_disk_alarm = aws.cloudwatch.MetricAlarm(f"{project_name}-node-disk-full",
#     name=f"{project_name}-EKSNodeDiskSpaceLow",
#     alarm_description="Alert when EKS node disk space utilization exceeds 80%",
#     alarm_actions=[alerting_sns_topic.arn],
#     metric_name="node_filesystem_utilization",
#     namespace="ContainerInsights",
#     dimensions={"ClusterName": eks_cluster.eks_cluster.name},
#     comparison_operator="GreaterThanOrEqualToThreshold",
#     threshold=80, statistic="Average", period=300, evaluation_periods=1,
#     treat_missing_data="notBreaching", tags=create_common_tags("alarm-node-disk")
# )

# ----- [END] REPLACEMENT BLOCK -----


# --- Outputs ---
pulumi.export("vpc_id", vpc.vpc_id)
pulumi.export("vpc_cidr_block", vpc.vpc.cidr_block)
pulumi.export("public_subnet_ids", vpc.public_subnet_ids)
pulumi.export("private_subnet_ids", vpc.private_subnet_ids)
if db_subnets_ids:
    pulumi.export("db_subnet_ids", db_subnets_ids)

# pulumi.export("waf_acl_arn", web_acl.arn)

pulumi.export("eks_cluster_name_pulumi_logical", eks_cluster.name)
pulumi.export("eks_cluster_resource_name_aws", eks_cluster.eks_cluster.name)
pulumi.export("eks_cluster_endpoint", eks_cluster.eks_cluster.endpoint)
pulumi.export("eks_cluster_ca_data", eks_cluster.eks_cluster.certificate_authority.apply(lambda ca: ca.data))
pulumi.export("kubeconfig", pulumi.Output.secret(kubeconfig))
pulumi.export("eks_oidc_provider_url", eks_cluster.core.oidc_provider.url.apply(lambda url: url if url else "OIDC_PROVIDER_NOT_YET_AVAILABLE"))
pulumi.export("eks_oidc_provider_arn", eks_cluster.core.oidc_provider.arn.apply(lambda arn: arn if arn else "OIDC_PROVIDER_NOT_YET_AVAILABLE"))
pulumi.export("efs_filesystem_id", efs_file_system.id)

# pulumi.export("velero_s3_bucket_name_actual", velero_s3_bucket.bucket)
# pulumi.export("velero_iam_user_name", velero_iam_user.name)
# pulumi.export("velero_access_key_id", velero_access_key.id)
# pulumi.export("velero_secret_access_key", pulumi.Output.secret(velero_access_key.secret))