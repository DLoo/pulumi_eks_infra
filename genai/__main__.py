import pulumi
import pulumi_aws as aws
import pulumi_random as random
import json

# --- Configuration (remains largely the same) ---
config = pulumi.Config()
project_name = config.require("project_name")
bedrock_default_model = config.require("bedrock_default_model")
aws_region = aws.get_region().name

# OpenWebUI RDS Configuration
db_name_webui_config = config.require("db_name_webui")
db_username_webui_config = config.require("db_username_webui")
db_password_webui_config = config.require_secret("db_password_webui")
db_aurora_pg_engine_version_webui = config.get("db_aurora_pg_engine_version_webui") or "15.5"
db_serverless_min_acu_webui = config.get_float("db_serverless_min_acu_webui") or 0.5
db_serverless_max_acu_webui = config.get_float("db_serverless_max_acu_webui") or 2.0

# N8N RDS Configuration
db_name_n8n_config = config.require("db_name_n8n")
db_username_n8n_config = config.require("db_username_n8n")
db_password_n8n_config = config.require_secret("db_password_n8n")
db_aurora_pg_engine_version_n8n = config.get("db_aurora_pg_engine_version_n8n") or "15.5"
db_serverless_min_acu_n8n = config.get_float("db_serverless_min_acu_n8n") or 0.5
db_serverless_max_acu_n8n = config.get_float("db_serverless_max_acu_n8n") or 1.0
# n8n_path_prefix = config.get("n8n_path_prefix") or "/n8n" # Still useful for N8N_PATH env var

# pgAdmin Configuration
pgadmin_default_email = config.require("pgadmin_default_email")
pgadmin_default_password = config.require_secret("pgadmin_default_password")


# --- Networking ---
vpc_id_from_config = "vpc-095d1b003a1a66fda" # EXAMPLE - REPLACE
vpc = aws.ec2.get_vpc(id=vpc_id_from_config)
public_subnet_ids = ["subnet-03fd967f3c2526348", "subnet-09ce1caf7b09c0d36"] # EXAMPLE - REPLACE
private_subnet_ids = ["subnet-05436959367c8b875", "subnet-0901670e39661d084"] # EXAMPLE - REPLACE
db_subnet_ids = ["subnet-08265f6caff45bae8", "subnet-0069988eec18dd42b"] # EXAMPLE - REPLACE

db_subnet_group_webui = aws.rds.SubnetGroup(f"{project_name}-db-sng-webui", subnet_ids=db_subnet_ids, tags={"Name": f"{project_name}-db-sng-webui"})
db_subnet_group_n8n = aws.rds.SubnetGroup(f"{project_name}-db-sng-n8n", subnet_ids=db_subnet_ids, tags={"Name": f"{project_name}-db-sng-n8n"})

# --- Security Groups ---
allow_all_egress_args = aws.ec2.SecurityGroupEgressArgs(protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"])

# Common ALB Security Group (can be split if different ingress rules are needed per ALB)
common_alb_sg = aws.ec2.SecurityGroup(f"{project_name}-common-alb-sg", vpc_id=vpc.id, description="Common ALB SG",
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=80, to_port=80, cidr_blocks=["0.0.0.0/0"]),
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=443, to_port=443, cidr_blocks=["0.0.0.0/0"]) # For HTTPS later
    ], egress=[allow_all_egress_args],
    tags={"Name": f"{project_name}-common-alb-sg"})

fargate_sg = aws.ec2.SecurityGroup(f"{project_name}-fargate-sg", vpc_id=vpc.id, description="Fargate SG",
    ingress=[ # Allow traffic from any of the ALBs
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=0, to_port=65535, security_groups=[common_alb_sg.id]), # Adjusted to common_alb_sg
        aws.ec2.SecurityGroupIngressArgs(protocol="-1", from_port=0, to_port=0, self=True)
    ], egress=[allow_all_egress_args],
    tags={"Name": f"{project_name}-fargate-sg"})

# CORRECTED RDS Security Groups
rds_sg_webui = aws.ec2.SecurityGroup(f"{project_name}-rds-sg-webui", vpc_id=vpc.id, description="RDS SG for WebUI",
    ingress=[aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=5432, to_port=5432, security_groups=[fargate_sg.id])],
    egress=[allow_all_egress_args],
    tags={"Name": f"{project_name}-rds-sg-webui"})

rds_sg_n8n = aws.ec2.SecurityGroup(f"{project_name}-rds-sg-n8n", vpc_id=vpc.id, description="RDS SG for N8N",
    ingress=[aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=5432, to_port=5432, security_groups=[fargate_sg.id])],
    egress=[allow_all_egress_args],
    tags={"Name": f"{project_name}-rds-sg-n8n"})

efs_sg = aws.ec2.SecurityGroup(f"{project_name}-efs-sg", vpc_id=vpc.id, description="EFS SG",
    ingress=[aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=2049, to_port=2049, security_groups=[fargate_sg.id])],
    egress=[allow_all_egress_args],
    tags={"Name": f"{project_name}-efs-sg"})

# --- Data Tier (RDS Instances remain the same) ---
aurora_cluster_webui = aws.rds.Cluster(f"{project_name}-aurora-webui",
    engine=aws.rds.EngineType.AURORA_POSTGRESQL, engine_mode="provisioned", engine_version=db_aurora_pg_engine_version_webui,
    database_name=db_name_webui_config, master_username=db_username_webui_config, master_password=db_password_webui_config,
    db_subnet_group_name=db_subnet_group_webui.name, vpc_security_group_ids=[rds_sg_webui.id], # Uses the .id of the EC2 SG
    skip_final_snapshot=True, backup_retention_period=7, allow_major_version_upgrade=True,
    serverlessv2_scaling_configuration=aws.rds.ClusterServerlessv2ScalingConfigurationArgs(min_capacity=db_serverless_min_acu_webui, max_capacity=db_serverless_max_acu_webui),
    tags={"Name": f"{project_name}-aurora-webui-cluster", "Service": "OpenWebUI"})
aurora_instance_webui = aws.rds.ClusterInstance(f"{project_name}-aurora-webui-instance",
    cluster_identifier=aurora_cluster_webui.id, instance_class="db.serverless", engine=aws.rds.EngineType.AURORA_POSTGRESQL,
    engine_version=aurora_cluster_webui.engine_version, publicly_accessible=False,
    tags={"Name": f"{project_name}-aurora-webui-instance", "Service": "OpenWebUI"})

aurora_cluster_n8n = aws.rds.Cluster(f"{project_name}-aurora-n8n",
    engine=aws.rds.EngineType.AURORA_POSTGRESQL, engine_mode="provisioned", engine_version=db_aurora_pg_engine_version_n8n,
    database_name=db_name_n8n_config, master_username=db_username_n8n_config, master_password=db_password_n8n_config,
    db_subnet_group_name=db_subnet_group_n8n.name, vpc_security_group_ids=[rds_sg_n8n.id], # Uses the .id of the EC2 SG
    skip_final_snapshot=True, backup_retention_period=7, allow_major_version_upgrade=True,
    serverlessv2_scaling_configuration=aws.rds.ClusterServerlessv2ScalingConfigurationArgs(min_capacity=db_serverless_min_acu_n8n, max_capacity=db_serverless_max_acu_n8n),
    tags={"Name": f"{project_name}-aurora-n8n-cluster", "Service": "N8N"})
aurora_instance_n8n = aws.rds.ClusterInstance(f"{project_name}-aurora-n8n-instance",
    cluster_identifier=aurora_cluster_n8n.id, instance_class="db.serverless", engine=aws.rds.EngineType.AURORA_POSTGRESQL,
    engine_version=aurora_cluster_n8n.engine_version, publicly_accessible=False,
    tags={"Name": f"{project_name}-aurora-n8n-instance", "Service": "N8N"})


# --- EFS (remains the same) ---
efs_file_system = aws.efs.FileSystem(f"{project_name}-efs", encrypted=True, tags={"Name": f"{project_name}-efs"})
for i, subnet_id in enumerate(private_subnet_ids): # EFS mount targets should be in private subnets where Fargate tasks run
    aws.efs.MountTarget(f"{project_name}-efs-mount-{i}", file_system_id=efs_file_system.id, subnet_id=subnet_id, security_groups=[efs_sg.id])
def create_efs_access_point(name: str, path: str, uid: int = 1000, gid: int = 1000):
    return aws.efs.AccessPoint(f"{project_name}-ap-{name}", file_system_id=efs_file_system.id,
        posix_user=aws.efs.AccessPointPosixUserArgs(uid=uid, gid=gid),
        root_directory=aws.efs.AccessPointRootDirectoryArgs(path=f"/{path}",
            creation_info=aws.efs.AccessPointRootDirectoryCreationInfoArgs(owner_uid=uid, owner_gid=gid, permissions="750")))
ap_open_webui = create_efs_access_point("open-webui", "open-webui")
ap_n8n = create_efs_access_point("n8n", "n8n")
ap_pgadmin = create_efs_access_point("pgadmin", "pgadmin", uid=5050, gid=5050)

# --- Application Tier ---
ecs_task_execution_role = aws.iam.Role(f"{project_name}-ecs-exec-role", assume_role_policy=json.dumps({"Version": "2012-10-17", "Statement": [{"Action": "sts:AssumeRole", "Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}}]}))
aws.iam.RolePolicyAttachment(f"{project_name}-ecs-exec-policy", role=ecs_task_execution_role.name, policy_arn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy")
app_task_role = aws.iam.Role(f"{project_name}-app-task-role", assume_role_policy=json.dumps({"Version": "2012-10-17", "Statement": [{"Action": "sts:AssumeRole", "Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}}]}))
app_task_policy_statements = [
    {"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": "*"},
    {"Effect": "Allow", "Action": ["ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel", "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel"], "Resource": "*"}
]
app_task_policy = aws.iam.Policy(f"{project_name}-app-task-policy", description="Policy for app services",
    policy=pulumi.Output.all(efs_arn=efs_file_system.arn, ap_webui_arn=ap_open_webui.arn, ap_n8n_arn=ap_n8n.arn, ap_pgadmin_arn=ap_pgadmin.arn).apply(
        lambda args: json.dumps({
            "Version": "2012-10-17", "Statement": app_task_policy_statements + [
                {"Effect": "Allow", "Action": ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite", "elasticfilesystem:ClientRootAccess"], "Resource": args["efs_arn"],
                 "Condition": {"StringEquals": {"elasticfilesystem:AccessPointArn": [args["ap_webui_arn"], args["ap_n8n_arn"], args["ap_pgadmin_arn"]]}}},
            ]}
    )))
aws.iam.RolePolicyAttachment(f"{project_name}-app-task-policy-attachment", role=app_task_role.name, policy_arn=app_task_policy.arn)

ecs_cluster = aws.ecs.Cluster(f"{project_name}-cluster", tags={"Name": f"{project_name}-cluster"})
service_discovery_namespace = aws.servicediscovery.PrivateDnsNamespace(f"{project_name}-ns", name=f"{project_name.lower()}.local", vpc=vpc.id, tags={"Name": f"{project_name}-ns"})

# --- AWS WAFv2 Setup (Common WebACL for all ALBs) ---
web_acl = aws.wafv2.WebAcl(f"{project_name}-web-acl",
    scope="REGIONAL", default_action=aws.wafv2.WebAclDefaultActionArgs(allow={}),
    visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(cloudwatch_metrics_enabled=True, metric_name=f"{project_name}-web-acl", sampled_requests_enabled=True),
    rules=[
        aws.wafv2.WebAclRuleArgs(name="AWS-AWSManagedRulesCommonRuleSet", priority=1, override_action=aws.wafv2.WebAclRuleOverrideActionArgs(none={}),
            statement=aws.wafv2.WebAclRuleStatementArgs(managed_rule_group_statement=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementArgs(vendor_name="AWS", name="AWSManagedRulesCommonRuleSet")),
            visibility_config=aws.wafv2.WebAclRuleVisibilityConfigArgs(cloudwatch_metrics_enabled=True, metric_name="AWSManagedRulesCommon", sampled_requests_enabled=True)),
        aws.wafv2.WebAclRuleArgs(name="AWS-AWSManagedRulesAmazonIpReputationList", priority=2, override_action=aws.wafv2.WebAclRuleOverrideActionArgs(none={}),
            statement=aws.wafv2.WebAclRuleStatementArgs(managed_rule_group_statement=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementArgs(vendor_name="AWS", name="AWSManagedRulesAmazonIpReputationList")),
            visibility_config=aws.wafv2.WebAclRuleVisibilityConfigArgs(cloudwatch_metrics_enabled=True, metric_name="AmazonIpReputation", sampled_requests_enabled=True)),
    ], tags={"Name": f"{project_name}-web-acl"})

# --- Function to create ALB, Listener, and WAF Association ---
def create_alb_with_listener_and_waf(service_name_suffix: str, default_target_group: aws.lb.TargetGroup):
    alb = aws.lb.LoadBalancer(f"{project_name}-alb-{service_name_suffix}",
        internal=False, load_balancer_type="application",
        security_groups=[common_alb_sg.id], # Using common ALB SG
        subnets=public_subnet_ids,
        enable_deletion_protection=False, # Consider setting to True in production
        tags={"Name": f"{project_name}-alb-{service_name_suffix}"})

    waf_association = aws.wafv2.WebAclAssociation(f"{project_name}-waf-assoc-{service_name_suffix}",
        resource_arn=alb.arn,
        web_acl_arn=web_acl.arn, # Using common WebACL
        opts=pulumi.ResourceOptions(depends_on=[alb, web_acl]))

    listener = aws.lb.Listener(f"{project_name}-http-listener-{service_name_suffix}",
        load_balancer_arn=alb.arn, port=80, protocol="HTTP",
        default_actions=[aws.lb.ListenerDefaultActionArgs(type="forward", target_group_arn=default_target_group.arn)],
        opts=pulumi.ResourceOptions(depends_on=[waf_association]),
        tags={"Name": f"{project_name}-http-listener-{service_name_suffix}"})
    
    return alb, listener

# --- Create ALBs and Listeners for each service ---
# 1. For OpenWebUI
tg_webui = aws.lb.TargetGroup(f"{project_name}-tg-webui", port=8080, protocol="HTTP", target_type="ip", vpc_id=vpc.id,
    health_check=aws.lb.TargetGroupHealthCheckArgs(path="/health", protocol="HTTP", port="8080", interval=30, timeout=10, healthy_threshold=2, unhealthy_threshold=2),
    tags={"Name": f"{project_name}-tg-webui"})
alb_webui, listener_webui = create_alb_with_listener_and_waf("webui", tg_webui)

# 2. For N8N
tg_n8n = aws.lb.TargetGroup(f"{project_name}-tg-n8n", port=5678, protocol="HTTP", target_type="ip", vpc_id=vpc.id,
    health_check=aws.lb.TargetGroupHealthCheckArgs(path="/healthz", protocol="HTTP", port="5678", interval=30, timeout=10, healthy_threshold=2, unhealthy_threshold=2),
    tags={"Name": f"{project_name}-tg-n8n"})
alb_n8n, listener_n8n = create_alb_with_listener_and_waf("n8n", tg_n8n)

# 3. For pgAdmin
tg_pgadmin = aws.lb.TargetGroup(f"{project_name}-tg-pgadmin", port=80, protocol="HTTP", target_type="ip", vpc_id=vpc.id,
    health_check=aws.lb.TargetGroupHealthCheckArgs(path="/misc/ping", protocol="HTTP", port="80", interval=60, timeout=30, healthy_threshold=2, unhealthy_threshold=2), # pgAdmin HC can be slower
    tags={"Name": f"{project_name}-tg-pgadmin"})
alb_pgadmin, listener_pgadmin = create_alb_with_listener_and_waf("pgadmin", tg_pgadmin)


# --- create_fargate_service function ---
def create_fargate_service(
    name: str, container_name: str, image_uri: pulumi.Output[str], container_port: int, cpu: int, memory: int,
    health_check_grace_period_seconds: int = 60, # assign_public_ip: bool = False, # Parameter commented out as we hardcode False below
    environment: list = None,
    dynamic_environment: dict = None, secrets: list = None, efs_access_point: aws.efs.AccessPoint = None,
    container_path: str = None, alb_listener: aws.lb.Listener = None,
    custom_depends_on: list = None ):
    volumes, mount_points = [], []
    if efs_access_point:
        volumes.append({"name": f"{name}-vol", "efsVolumeConfiguration": {"fileSystemId": efs_file_system.id, "transitEncryption": "ENABLED", "authorizationConfig": {"accessPointId": efs_access_point.id, "iam": "ENABLED"}}})
        mount_points.append({"sourceVolume": f"{name}-vol", "containerPath": container_path})
    all_outputs_to_resolve = {}
    if isinstance(image_uri, pulumi.Output): all_outputs_to_resolve["image_uri_resolved"] = image_uri
    else: all_outputs_to_resolve["image_uri_resolved"] = pulumi.Output.from_input(image_uri)
    env_list_processing_info = []
    if environment:
        for i, env_var in enumerate(environment):
            item_info = {"name": env_var["name"]}
            if "value" in env_var and isinstance(env_var["value"], pulumi.Output):
                placeholder = f"env_list_{i}_value"; all_outputs_to_resolve[placeholder] = env_var["value"]; item_info["is_output"] = True; item_info["placeholder"] = placeholder
            elif "value" in env_var: item_info["is_output"] = False; item_info["value"] = env_var["value"]
            env_list_processing_info.append(item_info)
    dyn_env_processing_info = {}
    if dynamic_environment:
        for key, value in dynamic_environment.items():
            item_info = {"name": key}
            if isinstance(value, pulumi.Output):
                placeholder = f"dyn_env_{key.replace('-', '_')}_value"; all_outputs_to_resolve[placeholder] = value; item_info["is_output"] = True; item_info["placeholder"] = placeholder
            else: item_info["is_output"] = False; item_info["value"] = value
            dyn_env_processing_info[key] = item_info
    secrets_list_processing_info = []
    if secrets:
        for i, secret_def in enumerate(secrets):
            item_info = {"name": secret_def["name"]}
            if "valueFrom" in secret_def and isinstance(secret_def["valueFrom"], pulumi.Output):
                placeholder = f"secret_list_{i}_valueFrom"; all_outputs_to_resolve[placeholder] = secret_def["valueFrom"]; item_info["is_output"] = True; item_info["placeholder"] = placeholder
            elif "valueFrom" in secret_def: item_info["is_output"] = False; item_info["valueFrom"] = secret_def["valueFrom"]
            secrets_list_processing_info.append(item_info)
    def build_container_definitions(resolved_args):
        final_env_vars = []
        if environment:
            for info in env_list_processing_info:
                if info["is_output"]: final_env_vars.append({"name": info["name"], "value": resolved_args[info["placeholder"]]})
                else: final_env_vars.append({"name": info["name"], "value": info["value"]})
        if dynamic_environment:
            for key, info in dyn_env_processing_info.items():
                if info["is_output"]: final_env_vars.append({"name": info["name"], "value": resolved_args[info["placeholder"]]})
                else: final_env_vars.append({"name": info["name"], "value": info["value"]})
        final_secrets_defs = []
        if secrets:
            for info in secrets_list_processing_info:
                if info["is_output"]: final_secrets_defs.append({"name": info["name"], "valueFrom": resolved_args[info["placeholder"]]})
                else: final_secrets_defs.append({"name": info["name"], "valueFrom": info["valueFrom"]})
        container_def_list = [{"name": container_name, "image": resolved_args["image_uri_resolved"], "cpu": cpu, "memory": memory, "essential": True, "portMappings": [{"containerPort": container_port, "protocol": "tcp"}], "environment": final_env_vars, "secrets": final_secrets_defs, "mountPoints": mount_points, "linuxParameters": { "initProcessEnabled": True }, "logConfiguration": {"logDriver": "awslogs", "options": {"awslogs-group": f"/ecs/{project_name}/{name}", "awslogs-region": aws_region, "awslogs-stream-prefix": "ecs"}}}]
        return json.dumps(container_def_list)
    
    task_def_tags = {"Name": f"{project_name}-{name}-td"}
    task_def = aws.ecs.TaskDefinition(f"{project_name}-{name}-td", family=f"{project_name}-{name}", cpu=str(cpu), memory=str(memory), network_mode="awsvpc", requires_compatibilities=["FARGATE"], execution_role_arn=ecs_task_execution_role.arn, task_role_arn=app_task_role.arn, volumes=volumes, container_definitions=pulumi.Output.all(**all_outputs_to_resolve).apply(build_container_definitions), tags=task_def_tags)
    
    aws.cloudwatch.LogGroup(f"{project_name}-{name}-logs", name=f"/ecs/{project_name}/{name}", retention_in_days=7, tags={"Name": f"{project_name}-{name}-logs"})
    
    discovery_service = aws.servicediscovery.Service(f"{project_name}-sd-{name}", name=name, dns_config=aws.servicediscovery.ServiceDnsConfigArgs(namespace_id=service_discovery_namespace.id, dns_records=[aws.servicediscovery.ServiceDnsConfigDnsRecordArgs(ttl=10, type="A")], routing_policy="MULTIVALUE"), health_check_custom_config=aws.servicediscovery.ServiceHealthCheckCustomConfigArgs(failure_threshold=1), tags={"Name": f"{project_name}-sd-{name}"})
    
    target_group_for_service = None
    if name == "open-webui": target_group_for_service = tg_webui
    elif name == "n8n": target_group_for_service = tg_n8n
    elif name == "pgadmin": target_group_for_service = tg_pgadmin
    
    _service_dependencies = [task_def] 
    if name == "open-webui": _service_dependencies.append(aurora_instance_webui)
    elif name == "n8n": _service_dependencies.append(aurora_instance_n8n)
    elif name == "pgadmin":_service_dependencies.extend([aurora_instance_webui, aurora_instance_n8n])

    if target_group_for_service: _service_dependencies.append(target_group_for_service)
    if alb_listener: _service_dependencies.append(alb_listener) 
    if custom_depends_on: _service_dependencies.extend(custom_depends_on)
    if efs_access_point: _service_dependencies.append(efs_access_point) 
    
    service_opts = pulumi.ResourceOptions(depends_on=_service_dependencies) if _service_dependencies else None
    
    service_tags = {"Name": f"{project_name}-svc-{name}"}
    service = aws.ecs.Service(f"{project_name}-svc-{name}", cluster=ecs_cluster.arn, task_definition=task_def.arn, desired_count=1, launch_type="FARGATE", 
        health_check_grace_period_seconds=health_check_grace_period_seconds, 
        network_configuration=aws.ecs.ServiceNetworkConfigurationArgs(
            subnets=private_subnet_ids, 
            security_groups=[fargate_sg.id], 
            assign_public_ip=False # CORRECTED: Use boolean False
        ), 
        load_balancers=[aws.ecs.ServiceLoadBalancerArgs(
            target_group_arn=target_group_for_service.arn, 
            container_name=container_name, 
            container_port=container_port
        )] if target_group_for_service else [], 
        service_registries=aws.ecs.ServiceServiceRegistriesArgs(registry_arn=discovery_service.arn), 
        enable_ecs_managed_tags=True,
        propagate_tags="SERVICE", 
        tags=service_tags,
        opts=service_opts)
    return service

# --- Define and Create Services ---
# 1. OpenWebUI Service
webui_secret_key = random.RandomPassword(f"{project_name}-webui-secret", length=32, special=False).result
webui_db_url = pulumi.Output.concat("postgresql://", db_username_webui_config, ":", db_password_webui_config, "@", aurora_cluster_webui.endpoint, ":", aurora_cluster_webui.port.apply(str), "/", db_name_webui_config)
create_fargate_service(
    name="open-webui", container_name="open-webui", image_uri=pulumi.Output.from_input("ghcr.io/open-webui/open-webui:main"),
    container_port=8080, cpu=2048, memory=4096,
    environment=[{"name": "ENABLE_BEDROCK", "value": "true"}, {"name": "BEDROCK_AWS_REGION", "value": aws_region}, {"name": "DEFAULT_MODELS", "value": bedrock_default_model}, {"name": "RAG_EMBEDDING_MODEL", "value": "amazon.titan-embed-text-v1"}, {"name": "GLOBAL_LOG_LEVEL", "value": "DEBUG"}],
    dynamic_environment={"WEBUI_SECRET_KEY": webui_secret_key, "DATABASE_URL": webui_db_url},
    efs_access_point=ap_open_webui, container_path="/app/backend/data",
    alb_listener=listener_webui
)

# # 2. N8N Service
# n8n_encryption_key = random.RandomPassword(f"{project_name}-n8n-key", length=32, special=False).result
# n8n_user_mgt_jwt = random.RandomPassword(f"{project_name}-n8n-jwt", length=32, special=False).result
# create_fargate_service(
#     name="n8n", container_name="n8n", image_uri=pulumi.Output.from_input("n8nio/n8n:latest"), 
#     container_port=5678, cpu=1024, memory=2048,
#     environment=[
#         {"name": "DB_TYPE", "value": "postgresdb"}, {"name": "DB_POSTGRESDB_HOST", "value": aurora_cluster_n8n.endpoint},
#         {"name": "DB_POSTGRESDB_PORT", "value": aurora_cluster_n8n.port.apply(str)}, {"name": "DB_POSTGRESDB_DATABASE", "value": db_name_n8n_config},
#         {"name": "DB_POSTGRESDB_USER", "value": db_username_n8n_config}, {"name": "DB_POSTGRESDB_PASSWORD", "value": db_password_n8n_config},
#         {"name": "N8N_PATH", "value": ""}, 
#         {"name": "N8N_SECURE_COOKIE", "value": "false"}, 
#         {"name": "N8N_DIAGNOSTICS_ENABLED", "value": "true"}, {"name": "N8N_ENCRYPTION_KEY", "value": n8n_encryption_key},
#         {"name": "N8N_USER_MANAGEMENT_JWT_SECRET", "value": n8n_user_mgt_jwt}, {"name": "DB_POSTGRESDB_SSL_MODE", "value": "prefer"}, 
#         {"name": "DB_POSTGRESDB_SSL_REJECT_UNAUTHORIZED", "value": "false"}, {"name": "N8N_LOG_LEVEL", "value": "debug"}, {"name": "N8N_LOG_OUTPUT", "value": "console"},
#         {"name": "WEBHOOK_URL", "value": pulumi.Output.concat("http://", alb_n8n.dns_name, "/")}, 
#     ],
#     efs_access_point=ap_n8n, container_path="/home/node/.n8n",
#     alb_listener=listener_n8n 
# )

# # 3. pgAdmin Service
# create_fargate_service(
#     name="pgadmin", container_name="pgadmin", image_uri=pulumi.Output.from_input("dpage/pgadmin4:latest"), 
#     container_port=80, cpu=512, memory=1024,
#     environment=[
#         {"name": "PGADMIN_DEFAULT_EMAIL", "value": pgadmin_default_email},
#         {"name": "PGADMIN_DEFAULT_PASSWORD", "value": pgadmin_default_password},
#         {"name": "PGADMIN_LISTEN_PORT", "value": "80"},
#     ],
#     efs_access_point=ap_pgadmin, container_path="/var/lib/pgadmin",
#     alb_listener=listener_pgadmin
# )

# --- Exports ---
pulumi.export("openwebui_url", pulumi.Output.concat("http://", alb_webui.dns_name))
pulumi.export("n8n_url", pulumi.Output.concat("http://", alb_n8n.dns_name)) 
pulumi.export("pgadmin_url", pulumi.Output.concat("http://", alb_pgadmin.dns_name)) 

pulumi.export("webui_rds_endpoint", aurora_cluster_webui.endpoint)
pulumi.export("n8n_rds_endpoint", aurora_cluster_n8n.endpoint)
pulumi.export("common_waf_web_acl_arn", web_acl.arn)
pulumi.export("vpc_id", vpc.id)
pulumi.export("fargate_sg_id", fargate_sg.id)
pulumi.export("rds_webui_sg_id", rds_sg_webui.id)
pulumi.export("rds_n8n_sg_id", rds_sg_n8n.id)
pulumi.export("efs_id", efs_file_system.id)