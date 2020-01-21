import lib.utils.ekstool_utils as utils
import os
import subprocess
import time
import shutil

# ---------------------------------------------------------------#
#	Global Variables and Constants
# ---------------------------------------------------------------#
REGION = None
PROFILE = None
USER = None
VPC = None

_awsInstanceType = {}
_awsInsTypeClass = ["General Purpose", "Compute Optimized", "Memory Optimized"]
_awsStorageType = ["EBS", "NVMeSSD", "SSD"]
_awsValues = {}

_vpctemplate = "https://amazon-eks.s3-us-west-2.amazonaws.com/cloudformation/2019-09-17/amazon-eks-vpc-sample.yaml"
_ekstemplate = "https://amazon-eks.s3-us-west-2.amazonaws.com/cloudformation/2019-09-17/amazon-eks-nodegroup.yaml"
_eks_key_name = "cb-day-se"

storage_class = ["gp2"]


# ---------------------------------------------------------------#
#	Methods
# ---------------------------------------------------------------#
def get_user():
    global USER

    if USER is None:
        USER = utils.execute_command_with_return(
            "aws iam get-user --query User.UserName --region {0} --profile {1}".format(REGION, PROFILE), False, False,
            False)[0]

    return USER


def get_vpc():
    global VPC
    if VPC is None:
        return ""
    return VPC


def list_regions(querystring):
    return utils.execute_command_with_return(
        "aws ec2 describe-regions --query {0} --region {1} --profile {2}".format(querystring, REGION, PROFILE), False,
        False, True)


def get_running_instances(querystring):
    return utils.execute_command_with_return(
        "aws ec2 describe-instances --filters \"Name=instance-state-name,Values=running\" --query {0} --region {1} --profile {2}".format(
            querystring, REGION, PROFILE), False, False, True)


def get_stacks(querystring):
    return utils.execute_command_with_return(
        "aws cloudformation describe-stacks --query {0} --region {1} --profile {2}".format(querystring, REGION,
                                                                                           PROFILE), False, False, True)


def get_current_region():
    global REGION, PROFILE

    if REGION is None:
        if PROFILE is None:
            return utils.execute_command_with_return("aws configure get region", False, False, True)
        else:
            return utils.execute_command_with_return("aws configure get region --profile {0}".format(PROFILE), False,
                                                     False, True)

    return REGION


def get_current_profile():
    global PROFILE

    if PROFILE is None:
        return "default"
    else:
        return PROFILE


def switch_region(new_region):
    global REGION
    REGION = new_region


def switch_profile(new_profile):
    global PROFILE, REGION, USER

    PROFILE = new_profile
    USER = None
    USER = get_user()
    REGION = None
    REGION = str(get_current_region()[0])


def cloud_init(myprofile):
    global REGION, PROFILE, USER

    if myprofile is not None:
        PROFILE = myprofile
    else:
        PROFILE = "default"

    REGION = str(get_current_region()[0])
    USER = get_user()


def cloud_get_values(command, delimiter):
    global _awsValues
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        line = line.decode('ascii').rstrip()
        tokens = line.split(delimiter)
        utils.write_line("Adding key {0} with value {1}".format(tokens[0], tokens[1]))
        _awsValues[tokens[0]] = tokens[1]


def get_vpc_settings(vpcname):
    cloud_get_values(
        "aws cloudformation describe-stacks --stack-name {0} --query Stacks[].Outputs[].[OutputKey,OutputValue] --output text --region {1} --profile {2} ".format(
            vpcname, REGION, PROFILE), "\t")


def print_vpc_settings():
    for key in _awsValues:
        print(key + "-> " + str(_awsValues[key]))


def build_vpc(vpcname, attempts, wait_sec):
    global VPC
    utils.execute_command_with_status(
        "aws cloudformation create-stack --stack-name {0} --template-url {1} --region {2} --profile {3}".format(vpcname,
                                                                                                                _vpctemplate,
                                                                                                                REGION,
                                                                                                                PROFILE),
        False,
        "aws cloudformation describe-stacks --stack-name {0} --query Stacks[0].StackStatus --region {1} --profile {2}".format(
            vpcname, REGION, PROFILE), "\"CREATE_COMPLETE\"",
        attempts, wait_sec)
    get_vpc_settings(vpcname)
    VPC = vpcname


# print_vpc_settings()

def connect_to_vpc(vpcname):
    global VPC
    get_vpc_settings(vpcname)
    VPC = vpcname


def build_kube_cluster(eksname, attempts, wait_sec, role_arn):
    if VPC is None:
        utils.write_warn("VPC Not set, please create or connect to VPC before creating EKS cluster")
    else:
        utils.execute_command_with_status(
            "aws eks create-cluster --name {0} --role-arn {1} --resources-vpc-config {2} --region {3} --profile {4}".format(
                eksname, role_arn,
                "subnetIds={0},securityGroupIds={1}".format(_awsValues["SubnetIds"], _awsValues["SecurityGroups"]),
                REGION, PROFILE),
            False,
            "aws eks describe-cluster --name {0} --query cluster.status --region {1} --profile {2}".format(eksname,
                                                                                                           REGION,
                                                                                                           PROFILE),
            "\"ACTIVE\"", attempts, wait_sec)


def connect_to_kube_cluster(eksname):
    utils.execute_command(
        "aws eks update-kubeconfig --name {0} --region {1} --profile {2}".format(eksname, REGION, PROFILE), False)


def list_vpc():
    return utils.execute_command_with_return("aws ec2 describe-vpcs --query {0} --region {1} --profile {2}".format(
        "'Vpcs[].{name:Tags[?Key==`aws:cloudformation:stack-name`].Value,state:State,vpc_id:VpcId}'", REGION, PROFILE), False, False,
        True)


def list_kube_clusters():
    return utils.execute_command_with_return(
        "aws eks list-clusters --query clusters[*] --region {0} --profile {1}".format(REGION, PROFILE), False, False,
        True)


def load_instance_type(file, itclass):
    global _awsInstanceType
    if itclass in _awsInsTypeClass:

        _awsInstanceType[itclass] = {}

        f = open(file, "r")
        for line in f.readlines():
            jsonData = utils.parse_results(line)
            _awsInstanceType[itclass][jsonData["1"]["InstanceType"]] = jsonData["1"]
    else:
        utils.write_line("Unrecognized Instance Type Classification: " + str(itclass))


def get_ami_all():
    command = "aws ec2 describe-images --owners self amazon --filters \"Name=name,Values=amazon-eks-node-*\" --query {0} --region {1} --profile {2}"
    results = utils.parse_results(
        utils.execute_command_with_return(command.format("\"Images[].{ami:ImageId,Name:Name}\"", REGION, PROFILE),
                                          False, False, True))
    return_set = {}
    for inst in results:
        # utils.writeline(inst)
        # utils.writeline(str(results[inst]))
        tmp_name_array = results[inst]["Name"].split("-")
        if len(tmp_name_array) == 5:
            #if return_set.has_key(tmp_name_array[3]):
            if tmp_name_array[3] in return_set:
                tmp_dict = return_set[tmp_name_array[3]]
                if tmp_dict["version"] < tmp_name_array[4]:
                    new_dict = {}
                    new_dict["ami"] = results[inst]["ami"]
                    new_dict["version"] = tmp_name_array[4]
                    return_set[tmp_name_array[3]] = new_dict
            else:
                new_dict = {}
                new_dict["ami"] = results[inst]["ami"]
                new_dict["version"] = tmp_name_array[4]
                return_set[tmp_name_array[3]] = new_dict

    return return_set


def get_ami_version(version):
    command = "aws ec2 describe-images --owners self amazon --filters \"Name=name,Values=amazon-eks-node-{3}-*\" --query {0} --region {1} --profile {2}"
    results = utils.parse_results(utils.execute_command_with_return(
        command.format("\"Images[].{ami:ImageId,Name:Name}\"", REGION, PROFILE, version), False, False, True))
    return_set = {}
    for inst in results:
        tmp_name_array = results[inst]["Name"].split("-")
        if len(tmp_name_array) == 5:

            #if return_set.has_key(tmp_name_array[3]):
            if tmp_name_array[3] in return_set:
                tmp_dict = return_set[tmp_name_array[3]]
                if tmp_dict["version"] < tmp_name_array[4]:
                    new_dict = {}
                    new_dict["ami"] = results[inst]["ami"]
                    new_dict["version"] = tmp_name_array[4]
                    return_set[tmp_name_array[3]] = new_dict
            else:
                new_dict = {}
                new_dict["ami"] = results[inst]["ami"]
                new_dict["version"] = tmp_name_array[4]
                return_set[tmp_name_array[3]] = new_dict

    return return_set[version]['ami']


def get_instances(cpuMin, cpuMax, memMin, memMax, diskType, instanceClass):
    if cpuMin is None:
        cpuMin = 0
    if cpuMax is None:
        cpuMax = 99999
    if memMin is None:
        memMin = 0
    if memMax is None:
        memMax = 99999

    try:
        cpuMin = int(cpuMin)
        cpuMax = int(cpuMax)
        memMin = int(memMin)
        memMax = int(memMax)
    except ValueError:
        cpuMin = 0
        cpuMax = 99999
        memMin = 0
        memMax = 99999

    results = []
    procItClass = []

    if instanceClass is not None:
        procItClass.append(instanceClass)
    else:
        procItClass = _awsInsTypeClass

    print("Processing [ " + str(cpuMin) + "," + str(cpuMax) + "," + str(memMin) + "," + str(memMax) + "," + str(
        procItClass))

    for currItClass in procItClass:
        for key in _awsInstanceType[currItClass]:
            currInst = _awsInstanceType[currItClass][key]
            if (int(currInst["vCpu"]) >= cpuMin) and (int(currInst["vCpu"]) <= cpuMax):
                if (int(currInst["Mem"]) >= memMin) and (int(currInst["Mem"]) <= memMax):
                    if diskType is not None:
                        #if currInst.has_key("Storage"):
                        if "Storage" in currInst:
                            if currInst["Storage"] == diskType:
                                results.append(currInst)
                        else:
                            if "EBS" == diskType:
                                results.append(currInst)
                    else:
                        results.append(currInst)

    return results


def append_auth_map(role_arn,config_name):
    if not os.path.isfile("./work/"+config_name+"/aws_auth_cm.yaml"):
        shutil.copyfile("./resources/aws_auth_cm.yaml.template","./work/"+config_name+"/aws_auth_cm.yaml")

    with open("./work/"+config_name+"/aws_auth_cm.yaml","a") as auth:
        auth.write("    - rolearn: {0}\n".format(role_arn))
        auth.write("      username: system:node:{{EC2PrivateDNSName}}\n")
        auth.write("      groups:\n")
        auth.write("        - system:bootstrappers\n")
        auth.write("        - system:nodes\n")


def build_work_nodes(wrk_node, cluster_name, attempts, wait_sec, config_name):
    try:
        command = "aws cloudformation create-stack --stack-name {0} --template-url {1} --parameters \
ParameterKey=ClusterName,ParameterValue={2} ParameterKey=ClusterControlPlaneSecurityGroup,ParameterValue={3} \
ParameterKey=NodeGroupName,ParameterValue={4} ParameterKey=NodeAutoScalingGroupMinSize,ParameterValue={5} \
ParameterKey=NodeAutoScalingGroupMaxSize,ParameterValue={6} ParameterKey=NodeInstanceType,ParameterValue={7} \
ParameterKey=NodeImageId,ParameterValue={8} ParameterKey=KeyName,ParameterValue={9} \
ParameterKey=VpcId,ParameterValue={10} ParameterKey=Subnets,ParameterValue=\'{11}\' \
ParameterKey=NodeVolumeSize,ParameterValue={12} ParameterKey=NodeAutoScalingGroupDesiredCapacity,ParameterValue={13} \
--capabilities CAPABILITY_IAM --region {14} --profile {15}".format(wrk_node.get_name(), _ekstemplate,
                                                                   cluster_name, _awsValues["SecurityGroups"],
                                                                   wrk_node.get_group_name(), wrk_node.get_group_min(),
                                                                   wrk_node.get_group_max(),
                                                                   wrk_node.get_instance_type(), wrk_node.get_ami(),
                                                                   _eks_key_name,
                                                                   _awsValues["VpcId"],
                                                                   _awsValues["SubnetIds"].replace(",", "\,"),
                                                                   wrk_node.get_volume_size(),
                                                                   wrk_node.get_group_desired(), REGION, PROFILE)

        utils.execute_command_with_status(command, False,
                                          "aws cloudformation describe-stacks --stack-name {0} --query Stacks[0].StackStatus --region {1} --profile {2}".format(
                                              wrk_node.get_name(), REGION, PROFILE), "\"CREATE_COMPLETE\"", attempts,
                                          wait_sec)

        utils.check_wrk_dir(config_name)

        command = "aws cloudformation describe-stacks --stack-name {0} --query Stacks[].Outputs[].[OutputKey,OutputValue] --output text --region {1} --profile {2}"
        #print(command.format(wrk_node.get_name(),REGION,PROFILE))
        p = subprocess.Popen(command.format(wrk_node.get_name(),REGION,PROFILE), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            line = line.decode('ascii').rstrip()
            tokens = line.split("\t")
            if tokens[0] == "NodeInstanceRole":
                append_auth_map(tokens[1], config_name)

    except KeyError:
        utils.write_warn("VPC settings not detected, please create or connect to VPC")


def apply_auth_map(config_name):
    if os.path.isfile("./work/" + config_name + "/aws_auth_cm.yaml"):
        utils.execute_command("kubectl apply -f {0}".format("./work/"+config_name+"/aws_auth_cm.yaml"), False)
    else:
        utils.write_warn("aws_auth_cm.yaml not found")


def validate_nodes_ready(attempts, wait_sec):
    run = True
    my_attempts = 1
    ready = False
    while my_attempts <= attempts and run:
        utils.write_line("Checking worker node status - Attempt {}".format(my_attempts))
        results = utils.execute_command_with_return("kubectl get nodes",False,False,True)
        my_attempts = my_attempts + 1
        ready = True
        run = False
        for line in results:
            line_arr = line.split()
            if line_arr[1] != "STATUS" and line_arr[1] != "Ready":
                run = True
                ready = False

        if run:
            time.sleep(wait_sec)

    return ready


def apply_labels(wrk_node):
    utils.write_line("Applying labels to nodes")
    #Returns the scale group in nested array
    scale_group = utils.execute_command_with_return("aws cloudformation describe-stack-resources --stack-name {0} --logical-resource-id NodeGroup --query {3} --region {1} --profile {2}".format(
            wrk_node.get_name(),
            REGION,
            PROFILE,
            "StackResources[].PhysicalResourceId"), False, False, True)[1].replace("\"", "")

    instances = utils.execute_command_with_return("aws autoscaling describe-auto-scaling-groups --auto-scaling-group-name {0} --query {1} --region {2} --profile {3}".format(
        scale_group, "AutoScalingGroups[].Instances[].InstanceId", REGION, PROFILE), False, False, True)

    for i in range(1,len(instances)-1):
        private_dns_array = utils.execute_command_with_return("aws ec2 describe-instances --instance-ids {0} --query {1} --region {2} --profile {3}".format(
            instances[i].replace(",", ""), "Reservations[].Instances[].NetworkInterfaces[].PrivateDnsName", REGION, PROFILE), False, False, True)
        for itr in range(1,len(private_dns_array)-1):
            private_dns = private_dns_array[itr].replace("\"", "")
            labels = wrk_node.get_labels()
            for label_key in labels:
                utils.execute_command("kubectl label nodes {0} {1}={2}".format(private_dns.replace(",",""), label_key, labels[label_key]), True)


def get_current_cluster():
    cluster = utils.execute_command_with_return("kubectl config current-context", False, False, False)[0].split("/")[1]
    utils.write_line(str(cluster))
    return cluster


def get_storage_type():
    return _awsStorageType


def get_instanct_type_class():
    return _awsInsTypeClass

def delete_worker_node(wrk_node, attempts, wait_sec):
    utils.execute_command_with_status("aws cloudformation delete-stack --stack-name {0} --region {1} --profile {2}".format(wrk_node, REGION, PROFILE),
                                      False, "aws cloudformation describe-stacks --stack-name {0} --query Stacks[0].StackStatus --region {1} --profile {2} 2>&1 | grep -c \"does not exist\"".format(
                                        wrk_node, REGION, PROFILE), "1", attempts, wait_sec)

def delete_eks_cluster(eksname, attempts, wait_sec):
    utils.execute_command_with_status("aws eks delete-cluster --name {0} --region {1} --profile {2}".format(
        eksname, REGION, PROFILE
    ), True, "aws eks describe-cluster --name {0} --query cluster.status --region {1} --profile {2} 2>&1 | grep -c \"No cluster found\"".format(
        eksname, REGION, PROFILE
    ), "1", attempts, wait_sec)


def delete_vpc_stack(stack_name, attempts, wait_sec):
    utils.execute_command_with_status("aws cloudformation delete-stack --stack-name {0} --region {1} --profile {2}".format(
        stack_name, REGION, PROFILE
    ), False, "aws cloudformation describe-stacks --stack-name {0} --region {1} --profile {2} --query Stacks[0].StackStatus 2>&1 | grep -c \"does not exist\"".format(
        stack_name, REGION, PROFILE
    ), "1", attempts, wait_sec)


def remove_elb(stack_name):
    elb_query = "\"LoadBalancerDescriptions[*].{vpc:VPCId,LoadBalancerName:LoadBalancerName}\""
    nwi_query = "\"NetworkInterfaces[*].{vpc:VpcId,AttachmentId:Attachment.AttachmentId,NetworkInterfaceId:NetworkInterfaceId}\""
    elb_command = "aws elb describe-load-balancers --query {0} --region {1} --profile {2}"
    vpc_command = "aws ec2 describe-vpcs --filters Name=tag:aws:cloudformation:stack-name,Values={0} --query Vpcs[*].VpcId --region {1} --profile {2}"
    nwi_command = "aws ec2 describe-network-interfaces --filters Name=vpc-id,Values={3} --query {0} --region {1} --profile {2}"
    vpc_id = utils.execute_command_with_return(vpc_command.format(stack_name, REGION, PROFILE), False, False, True)[1].replace("\"", "")

    elbs = utils.parse_results(utils.execute_command_with_return(elb_command.format(elb_query, REGION, PROFILE), False, False, True))

    for itr in elbs:
        elb = elbs[itr]
        if elb['vpc'] == vpc_id:
            utils.execute_command("aws elb delete-load-balancer --load-balancer-name {0} --region {1} --profile {2}".format(
                elb['LoadBalancerName'], REGION, PROFILE), False)

    nwis = utils.parse_results(
        utils.execute_command_with_return(nwi_command.format(nwi_query, REGION, PROFILE, vpc_id), False, False, True))

    for itr in nwis:
        nwi = nwis[itr]
        if nwi['vpc'] == vpc_id:
            utils.execute_command("aws ec2 detach-network-interface --attachment-id {0} --region {1} --profile {2}".format(
                nwi['AttachmentId'], REGION, PROFILE
            ), True)
            utils.execute_command("aws ec2 delete-network-interface --network-interface-id {0} --region {1} --profile {2}".format(
                nwi['NetworkInterfaceId'], REGION, PROFILE
            ), True)


def get_hosted_zone(dns):
    #tmphz = utils.execute_command_with_return(
    #    "aws route53 list-hosted-zones-by-name --output json --dns-name \"{0}\" | jq -r '.HostedZones[0].Id'".format(
    #        dns
    #    ), False, False, True)

    tmphz = utils.execute_command_with_return(
        "aws route53 list-hosted-zones-by-name --output json --dns-name \"{0}\" --query HostedZones[0].Id".format(
            dns
        ), False, False, True)

    if len(tmphz) >= 1:
        hz_array = tmphz[0].split("/")
        hostedzone = hz_array[len(hz_array) - 1].replace("\"", "")
    else:
        hostedzone = None

    return hostedzone


def get_role_name(config_name):
    role_array = utils.execute_command_with_return("aws iam list-roles --query Roles[].RoleName --region {0} --profile {1}".format(
        REGION, PROFILE
    ), False, False, True)
    role = None

    #print("role list = {}".format(role_array))
    for i in role_array:
        #print("Checking {}-NodeInstanceRole".format(config_name))
        if "{}-NodeInstanceRole".format(config_name) in i:
            role = i.replace(",", "")

    return role


def get_pol_arn():
    pol_arn_array = utils.execute_command_with_return(
        "aws iam list-policies --query 'Policies[?PolicyName==`ExternalDNS`].Arn' --region {0} --profile {1}".format(
            REGION, PROFILE
        ), False, False, True)

    pol_arn = None
    if len(pol_arn_array) > 1:
        pol_arn = pol_arn_array[1]

    return pol_arn


def attach_externaldns_policy(dns, config_name):
    hostedzone = get_hosted_zone(dns)

    role = get_role_name(config_name)

    pol_arn = get_pol_arn()

    #print("Role = " + str(role))
    #print("Policy ARN = " + str(pol_arn))

    if hostedzone is not None and role is not None and pol_arn is not None:
        utils.execute_command("aws iam attach-role-policy --role-name {0} --policy-arn {1} --region {2} --profile {3}".format(
            role, pol_arn, REGION, PROFILE
        ), False)

        return True
    else:
        return False


def detach_externaldns_policy(config_name):
    role = get_role_name(config_name)

    pol_arn = get_pol_arn()

    if role is not None and pol_arn is not None:
        utils.execute_command("aws iam detach-role-policy --role-name {0} --policy-arn {1} --region {2} --profile {3}".format(
            role, pol_arn, REGION, PROFILE
        ), True)


def get_vpc_id(vpc_name):
    vpc_list = utils.parse_results(list_vpc())
    for i in vpc_list:
        if vpc_list[i]['name'] is not None:
            if vpc_name == vpc_list[i]['name'][0]:
                return vpc_list[i]['vpc_id']


def link_node_groups(cb_config):

    sg_query_string = "\"SecurityGroups[].{groupName:GroupName,groupId:GroupId}\""
    sg_list = utils.parse_results(utils.execute_command_with_return(
        "aws ec2 describe-security-groups --query {0} --filters Name=vpc-id,Values={1} --region {2} --profile {3}".format(
            sg_query_string, get_vpc_id(cb_config.get_eks_config().vpc_stack_name), REGION, PROFILE),
        False, False, True))

    #Build map to create
    nodegroup_map = {}
    for i in sg_list:
        name_array = sg_list[i]['groupName'].split("-NodeSecurityGroup")
        if len(name_array) > 1:
            nodegroup_map[name_array[0]] = sg_list[i]


    sg_command = "aws ec2 authorize-security-group-ingress --group-id {0} --protocol all --port 0-65535 --source-group {1} --region {2} --profile {3}"
    for i in nodegroup_map:
        curr_group_id = nodegroup_map[i]['groupId']
        for j in nodegroup_map:
            if i != j:
                utils.execute_command(sg_command.format(curr_group_id, nodegroup_map[j]['groupId'], REGION, PROFILE),
                                      False)


def unlink_node_groups(cb_config):

    sg_query_string = "\"SecurityGroups[].{groupName:GroupName,groupId:GroupId}\""
    sg_list = utils.parse_results(utils.execute_command_with_return(
        "aws ec2 describe-security-groups --query {0} --filters Name=vpc-id,Values={1} --region {2} --profile {3}".format(
            sg_query_string, get_vpc_id(cb_config.get_eks_config().vpc_stack_name), REGION, PROFILE),
        False, False, True))

    #Build map to create
    nodegroup_map = {}
    for i in sg_list:
        name_array = sg_list[i]['groupName'].split("-NodeSecurityGroup")
        if len(name_array) > 1:
            nodegroup_map[name_array[0]] = sg_list[i]


    sg_command = "aws ec2 revoke-security-group-ingress --group-id {0} --protocol all --port 0-65535 --source-group {1} --region {2} --profile {3}"
    for i in nodegroup_map:
        curr_group_id = nodegroup_map[i]['groupId']
        for j in nodegroup_map:
            if i != j:
                utils.execute_command(sg_command.format(curr_group_id, nodegroup_map[j]['groupId'], REGION, PROFILE),
                                      False)