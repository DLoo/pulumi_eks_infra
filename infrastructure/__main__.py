import pulumi
import pulumi_aws as aws
# import pulumi_awsx as awsx # For higher-level components like VPC
# import pulumi_eks as eks
import json
# import pulumi_random as random # If generating passwords not using Secrets Manager

# --- Configuration ---
config = pulumi.Config()
project_name = config.require("project_name")
vpc_cidr = config.require("vpc_cidr")
public_subnet_cidrs = config.require_object("public_subnet_cidrs")
private_subnet_cidrs = config.require_object("private_subnet_cidrs")
db_subnet_cidrs = config.require_object("db_subnet_cidrs") # For RDS & ElastiCache
availability_zones = config.require_object("availability_zones")

eks_node_instance_type = config.require("eks_node_instance_type")
eks_node_desired_count = config.require_int("eks_node_desired_count")
eks_node_min_count = config.require_int("eks_node_min_count")
eks_node_max_count = config.require_int("eks_node_max_count")

db_instance_class = config.require("db_instance_class")
db_allocated_storage = config.require_int("db_allocated_storage")
db_username = config.require("db_username")
db_password = config.require_secret("db_password")

elasticache_node_type = config.require("elasticache_node_type")
elasticache_num_nodes = config.require_int("elasticache_num_nodes") # Should be >= 2 for replication group

opensearch_instance_type = config.require("opensearch_instance_type")
opensearch_instance_count = config.require_int("opensearch_instance_count")
opensearch_master_instance_type = config.require("opensearch_master_instance_type")
opensearch_master_instance_count = config.require_int("opensearch_master_instance_count")
opensearch_ebs_volume_size = config.require_int("opensearch_ebs_volume_size")

corporate_vpn_customer_gateway_ip = config.require("corporate_vpn_customer_gateway_ip")
route53_private_zone_name = config.require("route53_private_zone_name")
acm_certificate_arn = config.get("acm_certificate_arn")

# --- Networking ---

# 1. Create the VPC
vpc = aws.ec2.Vpc(f"{project_name}-vpc",
    cidr_block=vpc_cidr,
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={
        "Name": f"{project_name}-vpc",
        "Project": project_name,
    })

# 2. Create an Internet Gateway for Public Subnets
igw = aws.ec2.InternetGateway(f"{project_name}-igw",
    vpc_id=vpc.id,
    tags={"Name": f"{project_name}-igw"})

# 3. Create Public Route Table
public_route_table = aws.ec2.RouteTable(f"{project_name}-public-rt",
    vpc_id=vpc.id,
    routes=[
        aws.ec2.RouteTableRouteArgs(
            cidr_block="0.0.0.0/0",
            gateway_id=igw.id,
        )
    ],
    tags={"Name": f"{project_name}-public-rt"})

# 4. Create Public Subnets and associate the Public Route Table
public_subnets = []
for i, cidr in enumerate(public_subnet_cidrs):
    # Create the subnet
    subnet = aws.ec2.Subnet(f"{project_name}-public-subnet-{i+1}",
        vpc_id=vpc.id,
        cidr_block=cidr,
        availability_zone=availability_zones[i % len(availability_zones)], # Cycle through AZs
        map_public_ip_on_launch=True,
        tags={
            "Name": f"{project_name}-public-subnet-{i+1}",
            "Project": project_name,
        })
    # Associate the route table
    aws.ec2.RouteTableAssociation(f"{project_name}-public-rta-{i+1}",
        subnet_id=subnet.id,
        route_table_id=public_route_table.id)
    public_subnets.append(subnet)

# 5. Create NAT Gateways (one per AZ for high availability) and Private Route Tables
private_subnets = []
db_subnets = []
# Ensure we have one NAT GW per AZ where we have private subnets.
nat_gateways = []
for i in range(len(private_subnet_cidrs)):
    az_index = i % len(availability_zones)
    # Create an Elastic IP for the NAT Gateway
    eip = aws.ec2.Eip(f"{project_name}-nat-eip-{i+1}", tags={"Name": f"{project_name}-nat-eip-{i+1}"})
    # Create the NAT Gateway in a public subnet
    nat_gw = aws.ec2.NatGateway(f"{project_name}-nat-gw-{i+1}",
        allocation_id=eip.id,
        subnet_id=public_subnets[az_index].id, # Place NAT GW in a public subnet in the same AZ
        tags={"Name": f"{project_name}-nat-gw-{i+1}"})
    nat_gateways.append(nat_gw)

# 6. Create Private App Subnets
for i, cidr in enumerate(private_subnet_cidrs):
    az_index = i % len(availability_zones)
    # Create the private route table for this AZ
    private_rt = aws.ec2.RouteTable(f"{project_name}-private-rt-{i+1}",
        vpc_id=vpc.id,
        routes=[
            aws.ec2.RouteTableRouteArgs(
                cidr_block="0.0.0.0/0",
                nat_gateway_id=nat_gateways[az_index].id, # Route outbound traffic through the NAT GW in the same AZ
            )
        ],
        tags={"Name": f"{project_name}-private-rt-{i+1}"})

    # Create the subnet
    subnet = aws.ec2.Subnet(f"{project_name}-private-app-subnet-{i+1}",
        vpc_id=vpc.id,
        cidr_block=cidr,
        availability_zone=availability_zones[az_index],
        tags={
            "Name": f"{project_name}-private-app-subnet-{i+1}",
            "Project": project_name,
        })
    # Associate the route table
    aws.ec2.RouteTableAssociation(f"{project_name}-private-rta-{i+1}",
        subnet_id=subnet.id,
        route_table_id=private_rt.id)
    private_subnets.append(subnet)

# 7. Create Database Subnets (isolated, no route to internet)
db_route_table = aws.ec2.RouteTable(f"{project_name}-db-rt", vpc_id=vpc.id, tags={"Name": f"{project_name}-db-rt"})
for i, cidr in enumerate(db_subnet_cidrs):
    az_index = i % len(availability_zones)
    subnet = aws.ec2.Subnet(f"{project_name}-db-subnet-{i+1}",
        vpc_id=vpc.id,
        cidr_block=cidr,
        availability_zone=availability_zones[az_index],
        tags={
            "Name": f"{project_name}-db-subnet-{i+1}",
            "Project": project_name,
        })
    aws.ec2.RouteTableAssociation(f"{project_name}-db-rta-{i+1}",
        subnet_id=subnet.id,
        route_table_id=db_route_table.id)
    db_subnets.append(subnet)


# 8. Create Subnet Groups for RDS and ElastiCache
# Collect the IDs from the created subnet resources
public_subnet_ids = [s.id for s in public_subnets]
private_subnet_ids = [s.id for s in private_subnets]
db_subnet_ids = [s.id for s in db_subnets]

db_subnet_group = aws.rds.SubnetGroup(f"{project_name}-db-sng",
    subnet_ids=db_subnet_ids,
    tags={"Name": f"{project_name}-db-sng"})

elasticache_subnet_group = aws.elasticache.SubnetGroup(f"{project_name}-cache-sng",
    subnet_ids=db_subnet_ids, # Cache often co-located in DB subnets
    tags={"Name": f"{project_name}-cache-sng"})


# --- Exports ---
pulumi.export("vpc_id", vpc.id)
pulumi.export("public_subnet_ids", public_subnet_ids)
pulumi.export("private_subnet_ids", private_subnet_ids)
pulumi.export("db_subnet_ids", db_subnet_ids)
pulumi.export("db_subnet_group_name", db_subnet_group.name)
pulumi.export("elasticache_subnet_group_name", elasticache_subnet_group.name)


# --- Security Groups ---
# Allow all egress for now, restrict in production
allow_all_egress_args = aws.ec2.SecurityGroupEgressArgs(
    protocol="-1", # All protocols
    from_port=0,
    to_port=0,
    cidr_blocks=["0.0.0.0/0"],
)

# ALB Security Group (allow HTTP/HTTPS from Corporate via VPN + PrivateLink)
# If ALB is public, allow 0.0.0.0/0 or WAF source
alb_sg = aws.ec2.SecurityGroup(f"{project_name}-alb-sg",
    vpc_id=vpc.id,
    description="ALB Security Group",
    ingress=[
        # Assuming traffic from Corporate VPN will be from VPC CIDR after VPN
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=80, to_port=80, cidr_blocks=[vpc_cidr]),
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=443, to_port=443, cidr_blocks=[vpc_cidr]),
    ],
    egress=[allow_all_egress_args],
    tags={"Name": f"{project_name}-alb-sg", "Project": project_name}
)

# EKS Node Security Group
eks_node_sg = aws.ec2.SecurityGroup(f"{project_name}-eks-node-sg",
    vpc_id=vpc.id,
    description="EKS Node Security Group",
    ingress=[
        # Allow traffic from ALB on application ports (e.g., 80, 8080, 3000)
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=80, to_port=80, security_groups=[alb_sg.id]),
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=8080, to_port=8080, security_groups=[alb_sg.id]),
        # Allow all traffic from other nodes in the same SG (for pod-to-pod)
        aws.ec2.SecurityGroupIngressArgs(protocol="-1", from_port=0, to_port=0, self=True),
    ],
    egress=[allow_all_egress_args],
    tags={"Name": f"{project_name}-eks-node-sg", "Project": project_name}
)

# RDS Security Group
rds_sg = aws.ec2.SecurityGroup(f"{project_name}-rds-sg",
    vpc_id=vpc.id,
    description="RDS Security Group",
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(
            protocol="tcp",
            from_port=5432, # Postgres
            to_port=5432,
            security_groups=[eks_node_sg.id] # Allow from EKS Nodes
        )
    ],
    egress=[allow_all_egress_args], # Typically not needed for RDS, but good for consistency
    tags={"Name": f"{project_name}-rds-sg", "Project": project_name}
)

# ElastiCache Security Group
elasticache_sg = aws.ec2.SecurityGroup(f"{project_name}-elasticache-sg",
    vpc_id=vpc.id,
    description="ElastiCache Security Group",
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(
            protocol="tcp",
            from_port=6379, # Redis
            to_port=6379,
            security_groups=[eks_node_sg.id] # Allow from EKS Nodes
        )
    ],
    egress=[allow_all_egress_args],
    tags={"Name": f"{project_name}-elasticache-sg", "Project": project_name}
)

# OpenSearch Security Group
opensearch_sg = aws.ec2.SecurityGroup(f"{project_name}-opensearch-sg",
    vpc_id=vpc.id,
    description="OpenSearch Security Group",
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(
            protocol="tcp",
            from_port=443, # OpenSearch HTTPS
            to_port=443,
            security_groups=[eks_node_sg.id] # Allow from EKS Nodes
        ),
         aws.ec2.SecurityGroupIngressArgs( # For OpenSearch Dashboards, if needed from EKS
            protocol="tcp",
            from_port=9200, # OpenSearch HTTP (if enabled, usually HTTPS is preferred)
            to_port=9200,
            security_groups=[eks_node_sg.id]
        )
    ],
    egress=[allow_all_egress_args],
    tags={"Name": f"{project_name}-opensearch-sg", "Project": project_name}
)

# General purpose S3 bucket (as shown in diagram)
general_s3_bucket = aws.s3.BucketV2(f"{project_name}-general-storage",
    bucket=f"{project_name}-general-storage-{pulumi.get_stack()}",
    force_destroy=True, # For easy cleanup in dev, remove for prod
    tags={"Name": f"{project_name}-general-storage", "Project": project_name}
)
aws.s3.BucketPublicAccessBlock(f"{project_name}-general-storage-public-access-block",
    bucket=general_s3_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True
)
pulumi.export("general_s3_bucket_name", general_s3_bucket.bucket)


# # --- S3 Bucket for ALB Logs and general storage ---
# s3_access_logs_bucket = aws.s3.BucketV2(f"{project_name}-access-logs",
#     bucket=f"{project_name}-access-logs-{pulumi.get_stack()}", # Ensure unique name
#     force_destroy=True, # For easy cleanup in dev, remove for prod
#     tags={"Name": f"{project_name}-access-logs", "Project": project_name}
# )
# aws.s3.BucketPublicAccessBlock(f"{project_name}-access-logs-public-access-block",
#     bucket=s3_access_logs_bucket.id,
#     block_public_acls=True,
#     block_public_policy=True,
#     ignore_public_acls=True,
#     restrict_public_buckets=True
# )
# # Enable ALB logging
# alb.access_logs.apply(lambda access_logs: aws.lb.LoadBalancer(f"{project_name}-alb-logging-update", # Re-declare to update
#     arn=alb.arn, # Use the ARN of the existing ALB
#     access_logs=aws.lb.LoadBalancerAccessLogsArgs(
#         bucket=s3_access_logs_bucket.bucket,
#         enabled=True,
#         prefix="alb-logs"
#     )),
#     opts=pulumi.ResourceOptions(depends_on=[alb, s3_access_logs_bucket]) # Ensure ALB and bucket exist
# )

# # --- Application Load Balancer (Internal) ---
# # This ALB will be in public subnets to get Elastic IPs for NAT GWs if needed,
# # but traffic is intended from VPN via PrivateLink or internal VPC.
# # If truly internal and accessed only via PrivateLink, private subnets are also an option.
# alb = aws.lb.LoadBalancer(f"{project_name}-alb",
#     internal=False, # Crucial for internal ALB
#     load_balancer_type="application",
#     security_groups=[alb_sg.id],
#     subnets=public_subnet_ids, # Or private_subnet_ids if purely internal with PrivateLink access
#     enable_deletion_protection=False,
#     access_logs=aws.lb.LoadBalancerAccessLogsArgs(
#         bucket=s3_access_logs_bucket.bucket,
#         enabled=True,
#         prefix="alb-logs" # Optional prefix for log files within the bucket
#     ),
#     tags={"Name": f"{project_name}-alb", "Project": project_name}
# )
# pulumi.export("alb_dns_name", alb.dns_name)
# pulumi.export("alb_zone_id", alb.zone_id)

# # Default Target Group (can be more specific later)
# # For EKS, ALB Controller usually manages Target Groups. This is a placeholder.
# default_tg = aws.lb.TargetGroup(f"{project_name}-default-tg",
#     port=80,
#     protocol="HTTP",
#     vpc_id=vpc.id,
#     target_type="ip", # For EKS with AWS ALB Ingress Controller
#     tags={"Name": f"{project_name}-default-tg", "Project": project_name}
# )

# # Listener (HTTP for now, can add HTTPS)
# http_listener = aws.lb.Listener(f"{project_name}-http-listener",
#     load_balancer_arn=alb.arn,
#     port=80,
#     protocol="HTTP",
#     default_actions=[aws.lb.ListenerDefaultActionArgs(
#         type="forward",
#         target_group_arn=default_tg.arn
#     )],
#     tags={"Name": f"{project_name}-http-listener", "Project": project_name}
# )

# # if acm_certificate_arn and acm_certificate_arn != "":
# #     https_listener = aws.lb.Listener(f"{project_name}-https-listener",
# #         load_balancer_arn=alb.arn,
# #         port=443,
# #         protocol="HTTPS",
# #         ssl_policy="ELBSecurityPolicy-2016-08", # Example policy
# #         certificate_arn=acm_certificate_arn,
# #         default_actions=[aws.lb.ListenerDefaultActionArgs(
# #             type="forward",
# #             target_group_arn=default_tg.arn # Forward to same TG or a different one for HTTPS
# #         )],
# #         tags={"Name": f"{project_name}-https-listener", "Project": project_name}
# #     )

# # --- AWS WAF ---
# # # (Optional but Recommended) Create an IP Set for your corporate network.
# # # This allows you to create a high-priority rule to ALWAYS ALLOW traffic
# # # from your office, bypassing other rules. Use the VPN IP from your config.
# # corporate_ip_set = aws.wafv2.IpSet(f"{project_name}-corporate-ips",
# #     scope="REGIONAL",
# #     ip_address_version="IPV4",
# #     addresses=[f"{corporate_vpn_customer_gateway_ip}/32"], # Assumes a single IP, adjust CIDR if it's a range
# #     tags={"Name": f"{project_name}-corporate-ips", "Project": project_name}
# # )


# # Basic WAF WebACL. Add rules as needed.
# # For simplicity, this example doesn't include specific rules.
# web_acl = aws.wafv2.WebAcl(f"{project_name}-web-acl",
#     scope="REGIONAL", # For ALB
#     default_action=aws.wafv2.WebAclDefaultActionArgs(allow={}), # Or block={}
#     visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
#         cloudwatch_metrics_enabled=True,
#         metric_name=f"{project_name}WebAcl",
#         sampled_requests_enabled=True,
#     ),
#     rules=[
#         # # Rule 1: (Highest Priority) Allow traffic from our corporate IP set.
#         # # This ensures admin traffic is never accidentally blocked.
#         # aws.wafv2.WebAclRuleArgs(
#         #     name="Allow-Corporate-IPs",
#         #     priority=0, # Priority 0 is the highest, evaluated first.
#         #     action=aws.wafv2.WebAclRuleActionArgs(allow={}),
#         #     statement=aws.wafv2.WebAclRuleStatementArgs(
#         #         ip_set_reference_statement=aws.wafv2.WebAclRuleStatementIpSetReferenceStatementArgs(
#         #             arn=corporate_ip_set.arn
#         #         )
#         #     ),
#         #     visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
#         #         cloudwatch_metrics_enabled=True,
#         #         metric_name="AllowCorporateIPs",
#         #         sampled_requests_enabled=True,
#         #     ),
#         # ),

#         # Rule 2: AWS Managed Rules - Common Rule Set (CRS)
#         # Protects against a wide range of common vulnerabilities like SQLi, XSS, etc. (OWASP Top 10)
#         aws.wafv2.WebAclRuleArgs(
#             name="AWS-Managed-Rules-Common",
#             priority=10,
#             override_action=aws.wafv2.WebAclRuleOverrideActionArgs(none={}), # Use the actions defined in the rule group
#             statement=aws.wafv2.WebAclRuleStatementArgs(
#                 managed_rule_group_statement=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementArgs(
#                     vendor_name="AWS",
#                     name="AWSManagedRulesCommonRuleSet"
#                 )
#             ),
#             visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
#                 cloudwatch_metrics_enabled=True,
#                 metric_name="AWSManagedRulesCommon",
#                 sampled_requests_enabled=True,
#             ),
#         ),

#         # Rule 3: AWS Managed Rules - Known Bad Inputs
#         # Blocks request patterns that are known to be invalid or malicious.
#         aws.wafv2.WebAclRuleArgs(
#             name="AWS-Managed-Rules-Known-Bad-Inputs",
#             priority=20,
#             override_action=aws.wafv2.WebAclRuleOverrideActionArgs(none={}),
#             statement=aws.wafv2.WebAclRuleStatementArgs(
#                 managed_rule_group_statement=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementArgs(
#                     vendor_name="AWS",
#                     name="AWSManagedRulesKnownBadInputsRuleSet"
#                 )
#             ),
#             visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
#                 cloudwatch_metrics_enabled=True,
#                 metric_name="AWSManagedRulesKnownBadInputs",
#                 sampled_requests_enabled=True,
#             ),
#         ),

#         # Rule 4: AWS Managed Rules - Amazon IP Reputation List
#         # Blocks IPs with a bad reputation, often associated with bots or infected machines.
#         aws.wafv2.WebAclRuleArgs(
#             name="AWS-Managed-Rules-Amazon-IP-Reputation",
#             priority=30,
#             override_action=aws.wafv2.WebAclRuleOverrideActionArgs(none={}),
#             statement=aws.wafv2.WebAclRuleStatementArgs(
#                 managed_rule_group_statement=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementArgs(
#                     vendor_name="AWS",
#                     name="AWSManagedRulesAmazonIpReputationList"
#                 )
#             ),
#             visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
#                 cloudwatch_metrics_enabled=True,
#                 metric_name="AWSManagedRulesAmazonIPReputation",
#                 sampled_requests_enabled=True,
#             ),
#         ),

#         # Rule 5: Custom Rate-Based Rule to prevent DoS and brute-force attacks.
#         # This rule blocks any single IP making more than 2000 requests in a 5-minute window.
#         # Adjust the 'limit' based on your expected traffic patterns.
#         aws.wafv2.WebAclRuleArgs(
#             name="Rate-Limit-Per-IP",
#             priority=40,
#             action=aws.wafv2.WebAclRuleActionArgs(block={}), # Block requests that exceed the limit
#             statement=aws.wafv2.WebAclRuleStatementArgs(
#                 rate_based_statement=aws.wafv2.WebAclRuleStatementRateBasedStatementArgs(
#                     limit=2000,
#                     aggregate_key_type="IP"
#                 )
#             ),
#             visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
#                 cloudwatch_metrics_enabled=True,
#                 metric_name="RateLimitPerIP",
#                 sampled_requests_enabled=True,
#             ),
#         ),
#     ],
#     tags={"Name": f"{project_name}-web-acl", "Project": project_name}
# )

# # Associate WAF with ALB
# waf_alb_association = aws.wafv2.WebAclAssociation(f"{project_name}-waf-alb-assoc",
#     resource_arn=alb.arn,
#     web_acl_arn=web_acl.arn
# )


# # --- IAM Roles for EKS ---

# # 1. EKS Cluster Role (Your existing code is correct and secure)
# eks_cluster_role = aws.iam.Role(f"{project_name}-eks-cluster-role",
#     assume_role_policy=json.dumps({
#         "Version": "2012-10-17",
#         "Statement": [{
#             "Effect": "Allow",
#             "Principal": {"Service": "eks.amazonaws.com"},
#             "Action": "sts:AssumeRole"
#         }]
#     }),
#     tags={"Name": f"{project_name}-eks-cluster-role"}
# )
# aws.iam.RolePolicyAttachment(f"{project_name}-eks-cluster-policy-attachment",
#     role=eks_cluster_role.name,
#     policy_arn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
# )
# aws.iam.RolePolicyAttachment(f"{project_name}-eks-vpc-resource-controller-attachment",
#     role=eks_cluster_role.name,
#     policy_arn="arn:aws:iam::aws:policy/AmazonEKSVPCResourceController" # Recommended for VPC CNI
# )


# # 2. EKS Node Role (Stripped down to least privilege)
# # This role only has permissions for the node to function, NOT for applications.
# eks_node_role = aws.iam.Role(f"{project_name}-eks-node-role",
#     assume_role_policy=json.dumps({
#         "Version": "2012-10-17",
#         "Statement": [{
#             "Effect": "Allow",
#             "Principal": {"Service": "ec2.amazonaws.com"},
#             "Action": "sts:AssumeRole"
#         }]
#     }),
#     tags={"Name": f"{project_name}-eks-node-role"}
# )
# aws.iam.RolePolicyAttachment(f"{project_name}-eks-worker-node-policy-attachment",
#     role=eks_node_role.name,
#     policy_arn="arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
# )
# aws.iam.RolePolicyAttachment(f"{project_name}-eks-cni-policy-attachment",
#     role=eks_node_role.name,
#     policy_arn="arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
# )
# aws.iam.RolePolicyAttachment(f"{project_name}-ec2-container-registry-read-only-attachment",
#     role=eks_node_role.name,
#     policy_arn="arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
# )


# # --- EKS Cluster ---
# eks_cluster = eks.Cluster(f"{project_name}-eks-cluster",
#     # role_arn=eks_cluster_role.arn,
#     vpc_id=vpc.id,
#     # Use private subnets for worker nodes
#     subnet_ids=private_subnet_ids,
#     instance_roles=[eks_node_role], # Role for worker nodes
#     node_security_group_tags=eks_node_sg.tags, # Use the SG created for nodes
#     # Use the ALB SG for the cluster SG for control plane to node communication if needed, or specific rules
#     cluster_security_group=eks_node_sg, # Or a more specific one for control plane
#     desired_capacity=eks_node_desired_count,
#     min_size=eks_node_min_count,
#     max_size=eks_node_max_count,
#     role_mappings=[ # Optional: map IAM users/roles to k8s users/groups
#         eks.RoleMappingArgs(
#             role_arn=eks_node_role.arn,
#             username="system:node:{{EC2PrivateDNSName}}",
#             groups=["system:bootstrappers", "system:nodes"],
#         ),
#     ],
#     instance_type=eks_node_instance_type,
#     create_oidc_provider=True, # For IAM Roles for Service Accounts (IRSA)
#     tags={"Name": f"{project_name}-eks-cluster", "Project": project_name}
# )
# pulumi.export("eks_cluster_name", eks_cluster.eks_cluster.name)
# pulumi.export("kubeconfig", pulumi.Output.secret(eks_cluster.kubeconfig))


# # 3. IAM Role for a specific application (e.g., an app that needs Bedrock)
# # This requires an OIDC provider, which the pulumi_eks.Cluster component can create for you.
# # Let's assume your cluster object is named 'eks_cluster'.
# oidc_provider = eks_cluster.core.oidc_provider

# # Define the trust relationship for a Kubernetes Service Account to assume this role.
# # Replace 'default' and 'my-bedrock-app' with the namespace and service account name of your app.
# k8s_service_account_namespace = "default"
# k8s_service_account_name = "my-bedrock-app"

# bedrock_app_assume_role_policy = pulumi.Output.all(oidc_provider.url, oidc_provider.arn).apply(
#     lambda args: json.dumps({
#         "Version": "2012-10-17",
#         "Statement": [{
#             "Effect": "Allow",
#             "Principal": {"Federated": args[1]}, # The OIDC provider ARN
#             "Action": "sts:AssumeRoleWithWebIdentity",
#             "Condition": {
#                 "StringEquals": {
#                     f"{args[0]}:sub": f"system:serviceaccount:{k8s_service_account_namespace}:{k8s_service_account_name}"
#                 }
#             }
#         }]
#     })
# )

# # Create the specific IAM role for the application
# bedrock_app_role = aws.iam.Role(f"{project_name}-bedrock-app-role",
#     assume_role_policy=bedrock_app_assume_role_policy,
#     description="IAM role for the Bedrock application pod"
# )

# # Create a LEAST PRIVILEGE policy for the application
# # This policy only allows invoking one specific model.
# bedrock_app_policy = aws.iam.Policy(f"{project_name}-bedrock-app-policy",
#     description="Allow invoking a specific Bedrock model",
#     policy=json.dumps({
#         "Version": "2012-10-17",
#         "Statement": [{
#             "Effect": "Allow",
#             "Action": "bedrock:InvokeModel",
#             "Resource": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2" # EXAMPLE: Be specific!
#         }]
#     })
# )

# # Attach the least-privilege policy to the application's role
# aws.iam.RolePolicyAttachment(f"{project_name}-bedrock-app-policy-attachment",
#     role=bedrock_app_role.name,
#     policy_arn=bedrock_app_policy.arn
# )

# You would do the same for OpenSearch, creating another role and policy with specific access.
# For example: "Resource": "arn:aws:es:us-west-2:123456789012:domain/my-search-domain/*"





# # --- RDS (PostgreSQL) ---
# rds_instance = aws.rds.Instance(f"{project_name}-pg-instance",
#     allocated_storage=db_allocated_storage,
#     engine="postgres",
#     engine_version="15", # Check for latest supported versions
#     instance_class=db_instance_class,
#     db_subnet_group_name=db_subnet_group.name,
#     vpc_security_group_ids=[rds_sg.id],
#     db_name="difydb", # Example DB name
#     username=db_username,
#     password=db_password,
#     multi_az=True, # For high availability
#     skip_final_snapshot=True, # For dev, set to False for prod
#     publicly_accessible=False,
#     tags={"Name": f"{project_name}-pg-instance", "Project": project_name}
# )
# pulumi.export("rds_instance_endpoint", rds_instance.endpoint)
# pulumi.export("rds_instance_address", rds_instance.address)


# # --- ElastiCache (Redis) ---
# # If elasticache_num_nodes >= 2, it enables replication.
# # Automatic failover needs to be explicitly enabled for production.
# redis_cluster = aws.elasticache.ReplicationGroup(f"{project_name}-redis-cluster",
#     replication_group_id=f"{project_name}-redis",
#     description="Redis cluster for Dify GenAI",
#     node_type=elasticache_node_type,
#     num_cache_clusters=elasticache_num_nodes, # Min 2 for replication
#     engine="redis",
#     engine_version="7.0", # Check latest
#     port=6379,
#     parameter_group_name="default.redis7", # Or a custom one
#     subnet_group_name=elasticache_subnet_group.name,
#     security_group_ids=[elasticache_sg.id],
#     automatic_failover_enabled=True if elasticache_num_nodes > 1 else False,
#     multi_az_enabled=True if elasticache_num_nodes > 1 else False, # Depends on AZ distribution of subnets
#     tags={"Name": f"{project_name}-redis-cluster", "Project": project_name}
# )
# pulumi.export("redis_primary_endpoint", redis_cluster.primary_endpoint_address)
# pulumi.export("redis_reader_endpoint", redis_cluster.reader_endpoint_address) # If num_node_groups > 1


# # --- Amazon OpenSearch Service (for Bedrock Knowledge Base) ---
# opensearch_domain = aws.opensearch.Domain(f"{project_name}-opensearch-domain",
#     domain_name=f"{project_name}-kb-domain", # Max 28 chars, lowercase, no underscores
#     engine_version="OpenSearch_2.11", # Check latest supported
#     cluster_config=aws.opensearch.DomainClusterConfigArgs(
#         instance_type=opensearch_instance_type,
#         instance_count=opensearch_instance_count,
#         dedicated_master_enabled=True if opensearch_master_instance_count > 0 else False,
#         dedicated_master_type=opensearch_master_instance_type if opensearch_master_instance_count > 0 else None,
#         dedicated_master_count=opensearch_master_instance_count if opensearch_master_instance_count > 0 else None,
#         zone_awareness_enabled=True, # If using multiple AZs
#         zone_awareness_config=aws.opensearch.DomainClusterConfigZoneAwarenessConfigArgs(
#             availability_zone_count=len(availability_zones) if len(availability_zones) <=3 else 3 # Max 3 AZs for OpenSearch
#         ) if len(availability_zones) > 1 else None,
#     ),
#     ebs_options=aws.opensearch.DomainEbsOptionsArgs(
#         ebs_enabled=True,
#         volume_size=opensearch_ebs_volume_size,
#         volume_type="gp3" # General Purpose SSD
#     ),
#     vpc_options=aws.opensearch.DomainVpcOptionsArgs(
#         subnet_ids=private_subnet_ids[:2], # OpenSearch typically uses 1 or 2 private subnets
#         security_group_ids=[opensearch_sg.id]
#     ),
#     access_policies=pulumi.Output.all(eks_node_role.arn, aws.get_caller_identity().account_id, aws.get_region().name).apply(
#         lambda args: json.dumps({
#             "Version": "2012-10-17",
#             "Statement": [{
#                 "Effect": "Allow",
#                 "Principal": {"AWS": [args[0], f"arn:aws:iam::{args[1]}:root"]}, # Allow EKS nodes and account root (for console access)
#                 "Action": "es:*", # Restrict further in production
#                 "Resource": f"arn:aws:es:{args[2]}:{args[1]}:domain/{project_name}-kb-domain/*"
#             }]
#         })
#     ),
#     encrypt_at_rest=aws.opensearch.DomainEncryptAtRestArgs(enabled=True),
#     node_to_node_encryption=aws.opensearch.DomainNodeToNodeEncryptionArgs(enabled=True),
#     domain_endpoint_options=aws.opensearch.DomainDomainEndpointOptionsArgs(
#         enforce_https=True,
#         tls_security_policy="Policy-Min-TLS-1-2-2019-07"
#     ),
#     tags={"Name": f"{project_name}-opensearch-domain", "Project": project_name}
# )
# pulumi.export("opensearch_domain_endpoint", opensearch_domain.endpoint)
# pulumi.export("opensearch_kibana_endpoint", opensearch_domain.kibana_endpoint) # For OpenSearch Dashboards

# # Update the custom_node_policy with the specific OpenSearch domain ARN
# custom_node_policy.policy.apply(lambda p: # This is a bit tricky due to circular dependency if not careful
#     aws.iam.Policy(f"{project_name}-node-custom-policy", # Re-declare to update if needed or ensure it's correct initially
#         arn=custom_node_policy.arn, # Refer to existing ARN
#         policy=pulumi.Output.all(opensearch_domain.arn).apply(lambda os_arn: json.dumps({
#             "Version": "2012-10-17",
#             "Statement": [
#                 bedrock_policy_statement.to_dict(),
#                 aws.iam.PolicyStatementArgs(
#                     actions=["es:ESHttp*"],
#                     resources=[os_arn[0] + "/*", os_arn[0]] # Access to domain and paths
#                 ).to_dict()
#             ]
#         })),
#         opts=pulumi.ResourceOptions(depends_on=[opensearch_domain])
#     )
# )

# # --- Route 53 Private Hosted Zone & Records ---
# private_zone = aws.route53.Zone(f"{project_name}-private-zone",
#     name=route53_private_zone_name,
#     vpcs=[aws.route53.ZoneVpcArgs(vpc_id=vpc.id)],
#     comment="Private hosted zone for GenAI application",
#     tags={"Name": f"{project_name}-private-zone", "Project": project_name}
# )
# pulumi.export("private_zone_id", private_zone.id)

# # A Record for ALB
# alb_arecord = aws.route53.Record(f"{project_name}-alb-arecord",
#     zone_id=private_zone.zone_id,
#     name=pulumi.Output.concat("alb.", private_zone.name), # e.g., alb.internal.genai.example.com
#     type="A",
#     aliases=[aws.route53.RecordAliasArgs(
#         name=alb.dns_name,
#         zone_id=alb.zone_id,
#         evaluate_target_health=True
#     )]
# )

# # --- AWS PrivateLink for ALB (Interface Endpoint) ---
# # This allows corporate datacenter (via VPN) to access the internal ALB via a private IP in the VPC.
# alb_privatelink_endpoint = aws.ec2.VpcEndpoint(f"{project_name}-alb-vpce",
#     vpc_id=vpc.id,
#     service_name=pulumi.Output.concat("com.amazonaws.", aws.get_region().name, ".elasticloadbalancing"),
#     vpc_endpoint_type="Interface",
#     subnet_ids=private_subnet_ids[:1], # Endpoint ENIs in one or more private subnets
#     security_group_ids=[alb_sg.id], # Control access to the endpoint ENI
#     private_dns_enabled=False, # If True, it resolves the service's public DNS to private IPs.
#                                # For ALB, you usually point your custom Route 53 to the endpoint DNS.
#     tags={"Name": f"{project_name}-alb-vpce", "Project": project_name}
# )
# pulumi.export("alb_privatelink_endpoint_dns_entries", alb_privatelink_endpoint.dns_entries)
# # You would create a Route 53 record in your on-prem DNS or the private hosted zone
# # pointing to one of the DNS names from alb_privatelink_endpoint.dns_entries.
# # e.g., myapp.internal.genai.example.com -> vpce-xxxx.elb.ap-southeast-1.vpce.amazonaws.com


# # --- KMS Key (Example for encrypting S3, EBS, etc. if needed beyond default) ---
# kms_key = aws.kms.Key(f"{project_name}-cmk",
#     description="CMK for GenAI application resources",
#     enable_key_rotation=True,
#     tags={"Name": f"{project_name}-cmk", "Project": project_name}
# )
# pulumi.export("kms_key_arn", kms_key.arn)

# # --- CloudWatch, CloudTrail, ACM, IAM Identity Center ---
# # CloudWatch Log Groups are often created automatically by services. Alarms can be added.
# # CloudTrail: An organizational trail is often set up separately.
# # ACM Certificate: Referenced via `acm_certificate_arn` if HTTPS is used.
# # IAM Identity Center: Setup is typically manual or via specific AWS SSO APIs, not generic CloudFormation/Pulumi resources.

# # --- Bedrock LLM & Knowledge Base ---
# # As mentioned, Pulumi provisions underlying resources (IAM, OpenSearch, S3).
# # The EKS node role `custom_node_policy` includes `bedrock:*` permissions.
# # Your application running on EKS can use this role (via IRSA or node IAM role) to call Bedrock APIs.
# # For Bedrock Knowledge Base:
# # 1. Store source documents in the `general_s3_bucket`.
# # 2. The `opensearch_domain` serves as the vector store.
# # 3. Your application (or a Lambda function, not defined here) would use Bedrock SDK
# #    to create embeddings (e.g., using Titan Embeddings) and ingest them into OpenSearch.
# #    This ingestion process would also be configured in the Bedrock console or via SDK when creating the Knowledge Base.


# # --- Site-to-Site VPN ---
# customer_gateway = aws.ec2.CustomerGateway(f"{project_name}-cgw",
#     bgp_asn=65000, # Example ASN
#     ip_address=corporate_vpn_customer_gateway_ip,
#     type="ipsec.1",
#     tags={"Name": f"{project_name}-cgw", "Project": project_name}
# )

# vpn_gateway = aws.ec2.VpnGateway(f"{project_name}-vgw",
#     vpc_id=vpc.id,
#     tags={"Name": f"{project_name}-vgw", "Project": project_name}
# )

# vpn_connection = aws.ec2.VpnConnection(f"{project_name}-vpn-connection",
#     customer_gateway_id=customer_gateway.id,
#     static_routes_only=True, # Assuming static routes, can be BGP
#     type="ipsec.1",
#     vpn_gateway_id=vpn_gateway.id,
#     tags={"Name": f"{project_name}-vpn-connection", "Project": project_name}
# )
# # Note: VPN Route Propagation to route tables needs to be configured
# # Example for private route tables (assumes awsx.ec2.Vpc created them)
# for i, rt_id in enumerate(vpc.private_route_table_ids):
#     aws.ec2.VpnGatewayRoutePropagation(f"{project_name}-vgw-prop-{i}",
#         route_table_id=rt_id,
#         vpn_gateway_id=vpn_gateway.id
#     )



# ----------------------------------------------------------------
# --- OpenWebUI on Fargate ---
# ----------------------------------------------------------------

# # New config for OpenWebUI
# bedrock_default_model = config.require("bedrock_default_model")
# aws_region = aws.get_region().name

# # 1. Create RDS Postgres Instance for OpenWebUI
# rds_instance = aws.rds.Instance(f"{project_name}-pg-instance",
#     engine="postgres",
#     engine_version="17.4",
#     instance_class=db_instance_class,
#     allocated_storage=db_allocated_storage,
#     db_name="openwebuidb",
#     username=db_username,
#     password=db_password,
#     db_subnet_group_name=db_subnet_group.name,
#     vpc_security_group_ids=[rds_sg.id],
#     publicly_accessible=False,
#     skip_final_snapshot=True, # Set to False for production
#     tags={"Name": f"{project_name}-pg-instance", "Project": project_name})

# # 2. Securely store DB connection URL in Secrets Manager
# # This is the best practice for passing secrets to ECS.
# db_connection_url_secret = aws.secretsmanager.Secret(f"{project_name}-db-connection-url",
#     name=f"{project_name}/db-connection-url",
#     description="Postgres connection URL for OpenWebUI")

# db_connection_url_secret_version = aws.secretsmanager.SecretVersion("dbConnectionUrlSecretVersion",
#     secret_id=db_connection_url_secret.id,
#     secret_string=pulumi.Output.concat(
#         "postgresql://", db_username, ":", db_password,
#         "@", rds_instance.address, ":", rds_instance.port, "/", db_name
#     ))

# # 3. Create a Security Group for the Fargate Service
# fargate_sg = aws.ec2.SecurityGroup(f"{project_name}-fargate-sg",
#     vpc_id=vpc.id,
#     description="Security group for OpenWebUI Fargate service",
#     ingress=[
#         # Allow traffic from the ALB on the container port (8080)
#         aws.ec2.SecurityGroupIngressArgs(
#             protocol="tcp",
#             from_port=8080,
#             to_port=8080,
#             security_groups=[alb_sg.id]
#         )
#     ],
#     egress=[allow_all_egress_args], # Allows connection to RDS, Bedrock, ECR, etc.
#     tags={"Name": f"{project_name}-fargate-sg"})

# # Add an ingress rule to the RDS SG to allow traffic from the Fargate SG
# rds_ingress_from_fargate = aws.ec2.SecurityGroupRule(f"{project_name}-rds-ingress",
#     type="ingress",
#     from_port=5432,
#     to_port=5432,
#     protocol="tcp",
#     security_group_id=rds_sg.id,
#     source_security_group_id=fargate_sg.id,
#     description="Allow Fargate service to connect to RDS")

# # 4. IAM Roles and Policies for Fargate Task
# # a. Task Execution Role: Allows ECS to pull images and write logs
# ecs_task_execution_role = aws.iam.Role(f"{project_name}-ecs-exec-role",
#     assume_role_policy=json.dumps({
#         "Version": "2012-10-17",
#         "Statement": [{
#             "Action": "sts:AssumeRole",
#             "Effect": "Allow",
#             "Principal": {"Service": "ecs-tasks.amazonaws.com"},
#         }]
#     }))

# aws.iam.RolePolicyAttachment(f"{project_name}-ecs-exec-policy-attachment",
#     role=ecs_task_execution_role.name,
#     policy_arn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy")

# # b. Task Role: Grants the application container permissions to access other AWS services
# open_webui_task_role = aws.iam.Role(f"{project_name}-app-task-role",
#     assume_role_policy=json.dumps({
#         "Version": "2012-10-17",
#         "Statement": [{
#             "Action": "sts:AssumeRole",
#             "Effect": "Allow",
#             "Principal": {"Service": "ecs-tasks.amazonaws.com"},
#         }]
#     }))

# # Define the policy that grants Bedrock and Secrets Manager access
# open_webui_task_policy = aws.iam.Policy(f"{project_name}-app-task-policy",
#     description="Policy for OpenWebUI to access Bedrock and Secrets Manager",
#     policy=pulumi.Output.all(
#         db_connection_url_secret.arn,
#         general_s3_bucket.arn
#     ).apply(lambda args: json.dumps({
#         "Version": "2012-10-17",
#         "Statement": [
#             {
#                 "Effect": "Allow",
#                 "Action": "bedrock:InvokeModel",
#                 "Resource": "*", # For production, restrict to specific model ARNs
#             },
#             {
#                 "Effect": "Allow",
#                 "Action": "secretsmanager:GetSecretValue",
#                 "Resource": args[0], # ARN of the DB connection secret
#             },
#             {
#                 "Effect": "Allow",
#                 "Action": [
#                     "s3:GetObject",
#                     "s3:PutObject",
#                     "s3:DeleteObject",
#                     "s3:ListBucket"
#                 ],
#                 "Resource": [
#                     args[1], # S3 Bucket ARN
#                     f"{args[1]}/*" # All objects within the bucket
#                 ],
#             }
#         ]
#     })))

# aws.iam.RolePolicyAttachment(f"{project_name}-app-task-policy-attachment",
#     role=open_webui_task_role.name,
#     policy_arn=open_webui_task_policy.arn)

# # 5. ECR Repository to store the Docker image
# ecr_repo = aws.ecr.Repository(f"{project_name}-open-webui-repo",
#     name=f"{project_name}/open-webui",
#     image_tag_mutability="MUTABLE",
#     image_scanning_configuration=aws.ecr.RepositoryImageScanningConfigurationArgs(
#         scan_on_push=True,
#     ))

# # 6. ECS Cluster
# ecs_cluster = aws.ecs.Cluster(f"{project_name}-cluster")

# # 7. CloudWatch Log Group for the container
# log_group = aws.cloudwatch.LogGroup(f"{project_name}-open-webui-logs",
#     name=f"/ecs/{project_name}/open-webui",
#     retention_in_days=7)

# # 8. Application Load Balancer (ALB)
# alb = aws.lb.LoadBalancer(f"{project_name}-alb",
#     internal=False,
#     load_balancer_type="application",
#     security_groups=[alb_sg.id],
#     subnets=public_subnet_ids,
#     tags={"Name": f"{project_name}-alb", "Project": project_name})

# target_group = aws.lb.TargetGroup(f"{project_name}-tg",
#     port=8080,
#     protocol="HTTP",
#     target_type="ip",
#     vpc_id=vpc.id,
#     health_check=aws.lb.TargetGroupHealthCheckArgs(
#         path="/",
#         protocol="HTTP",
#     ))

# https_listener = aws.lb.Listener(f"{project_name}-https-listener",
#     load_balancer_arn=alb.arn,
#     port=443,
#     protocol="HTTPS",
#     ssl_policy="ELBSecurityPolicy-2016-08",
#     certificate_arn=acm_certificate_arn,
#     default_actions=[aws.lb.ListenerDefaultActionArgs(
#         type="forward",
#         target_group_arn=target_group.arn,
#     )])

# # Add an HTTP to HTTPS redirect
# http_listener = aws.lb.Listener(f"{project_name}-http-listener",
#     load_balancer_arn=alb.arn,
#     port=80,
#     protocol="HTTP",
#     default_actions=[aws.lb.ListenerDefaultActionArgs(
#         type="redirect",
#         redirect=aws.lb.ListenerDefaultActionRedirectArgs(
#             protocol="HTTPS",
#             port="443",
#             status_code="HTTP_301",
#         ),
#     )])

# # 9. ECS Task Definition
# # Generate a random secret key for OpenWebUI sessions
# webui_secret_key = random.RandomPassword(f"{project_name}-webui-secret",
#     length=32,
#     special=False).result

# container_definitions = pulumi.Output.all(
#     ecr_repo.repository_url,
#     log_group.name,
#     db_connection_url_secret.arn,
#     webui_secret_key
# ).apply(lambda args: json.dumps([
#     {
#         "name": "open-webui",
#         "image": f"{args[0]}:latest", # IMPORTANT: Push your image here with the 'latest' tag
#         "cpu": 1024,  # 1 vCPU
#         "memory": 2048, # 2 GB RAM (adjust as needed)
#         "essential": True,
#         "portMappings": [{"containerPort": 8080, "hostPort": 8080}],
#         "environment": [
#             # Enable Bedrock integration
#             {"name": "ENABLE_BEDROCK", "value": "true"},
#             {"name": "BEDROCK_AWS_REGION", "value": aws_region},
#             # Set a default model to show in the UI
#             {"name": "DEFAULT_MODELS", "value": bedrock_default_model},
#             # Needed for session security
#             {"name": "WEBUI_SECRET_KEY", "value": args[3]},
#         ],
#         "secrets": [
#             # Securely inject the database connection URL
#             {"name": "DATABASE_URL", "valueFrom": args[2]}
#         ],
#         "logConfiguration": {
#             "logDriver": "awslogs",
#             "options": {
#                 "awslogs-group": args[1],
#                 "awslogs-region": aws_region,
#                 "awslogs-stream-prefix": "webui",
#             }
#         },
#     }
# ]))

# task_definition = aws.ecs.TaskDefinition(f"{project_name}-task-def",
#     family=f"{project_name}-open-webui",
#     cpu="1024",
#     memory="2048",
#     network_mode="awsvpc",
#     requires_compatibilities=["FARGATE"],
#     execution_role_arn=ecs_task_execution_role.arn,
#     task_role_arn=open_webui_task_role.arn,
#     container_definitions=container_definitions)

# # 10. Fargate Service
# fargate_service = aws.ecs.Service(f"{project_name}-fargate-service",
#     cluster=ecs_cluster.arn,
#     task_definition=task_definition.arn,
#     desired_count=1,
#     launch_type="FARGATE",
#     network_configuration=aws.ecs.ServiceNetworkConfigurationArgs(
#         subnets=private_subnet_ids,
#         security_groups=[fargate_sg.id],
#         assign_public_ip=False, # Important for security
#     ),
#     load_balancers=[aws.ecs.ServiceLoadBalancerArgs(
#         target_group_arn=target_group.arn,
#         container_name="open-webui",
#         container_port=8080,
#     )],
#     opts=pulumi.ResourceOptions(depends_on=[https_listener]), # Ensure listener is ready before service starts
#     )

# # New Exports for OpenWebUI
# pulumi.export("open_webui_url", pulumi.Output.concat("https://", alb.dns_name))
# pulumi.export("ecr_repository_url", ecr_repo.repository_url)
# pulumi.export("rds_instance_endpoint", rds_instance.endpoint)
# pulumi.export("cloudwatch_log_group_name", log_group.name)

pulumi.log.info("Deployment script completed. Check outputs for resource details.")