import lib.cloud.aws_utils as aws

TYPE = "aws"


def get_user():
    global TYPE
    if TYPE == "aws":
        return aws.get_user()


def get_vpc():
    global TYPE
    if TYPE == "aws":
        return aws.get_vpc()


def list_regions(querystring):
    global TYPE
    if TYPE == "aws":
        return aws.list_regions(querystring)


def get_running_instances(querystring):
    global TYPE
    if TYPE == "aws":
        return aws.get_running_instances(querystring)


def get_stacks(querystring):
    global TYPE
    if TYPE == "aws":
        return aws.get_stacks(querystring)


def get_current_region():
    global TYPE
    if TYPE == "aws":
        return aws.get_current_region()


def get_current_profile():
    global TYPE
    if TYPE == "aws":
        return aws.get_current_profile()


def switch_region(new_region):
    global TYPE
    if TYPE == "aws":
        aws.switch_region(new_region)


def switch_profile(new_profile):
    global TYPE
    if TYPE == "aws":
        aws.switch_profile(new_profile)


def cloud_init(myprofile):
    global TYPE
    if TYPE == "aws":
        aws.cloud_init(myprofile)


def cloud_get_values(command, delimiter):
    global TYPE
    if TYPE == "aws":
        aws.cloud_get_values(command, delimiter)


def get_vpc_settings(vpcname):
    global TYPE
    if TYPE == "aws":
        aws.get_vpc_settings(vpcname)


def print_vpc_settings():
    global TYPE
    if TYPE == "aws":
        aws.print_vpc_settings()


def build_vpc(vpcname, attempts, wait_sec):
    global TYPE
    if TYPE == "aws":
        aws.build_vpc(vpcname, attempts, wait_sec)


def connect_to_vpc(vpcname):
    global TYPE
    if TYPE == "aws":
        aws.connect_to_vpc(vpcname)


def build_kube_cluster(eksname, attempts, wait_sec, role_arn):
    global TYPE
    if TYPE == "aws":
        aws.build_kube_cluster(eksname, attempts, wait_sec, role_arn)


def connect_to_eks_cluster(eksname):
    global TYPE
    if TYPE == "aws":
        aws.connect_to_kube_cluster(eksname)


def list_vpc():
    global TYPE
    if TYPE == "aws":
        return aws.list_vpc()


def list_kube_clusters():
    global TYPE
    if TYPE == "aws":
        return aws.list_kube_clusters()


def load_instance_type(file, itclass):
    global TYPE
    if TYPE == "aws":
        aws.load_instance_type(file, itclass)


def get_ami_all():
    global TYPE
    if TYPE == "aws":
        return aws.get_ami_all()


def get_ami_version(version):
    global TYPE
    if TYPE == "aws":
        return aws.get_ami_version(version)


def get_instances(cpuMin, cpuMax, memMin, memMax, diskType, instanceClass):
    global TYPE
    if TYPE == "aws":
        return aws.get_instances(cpuMin, cpuMax, memMin, memMax, diskType, instanceClass)


def append_auth_map(role_arn, config_name):
    global TYPE
    if TYPE == "aws":
        aws.append_auth_map(role_arn, config_name)


def build_work_nodes(wrk_node, cluster_name, attempts, wait_sec, config_name):
    global TYPE
    if TYPE == "aws":
        aws.build_work_nodes(wrk_node, cluster_name, attempts, wait_sec, config_name)


def apply_auth_map(config_name):
    global TYPE
    if TYPE == "aws":
        aws.apply_auth_map(config_name)


def validate_nodes_ready(attempts, wait_sec):
    global TYPE
    if TYPE == "aws":
        return aws.validate_nodes_ready(attempts, wait_sec)


def apply_labels(wrk_node):
    global TYPE
    if TYPE == "aws":
        aws.apply_labels(wrk_node)


def get_current_cluster():
    global TYPE
    if TYPE == "aws":
        return aws.get_current_cluster()


def get_storage_type():
    global TYPE
    if TYPE == "aws":
        return aws.get_storage_type()


def get_instanct_type_class():
    global TYPE
    if TYPE == "aws":
        return aws.get_instanct_type_class()


def delete_worker_node(wrk_node, attempts, wait_sec):
    global TYPE
    if TYPE == "aws":
        aws.delete_worker_node(wrk_node, attempts, wait_sec)


def delete_eks_cluster(eksname, attempts, wait_sec):
    global TYPE
    if TYPE == "aws":
        aws.delete_eks_cluster(eksname, attempts, wait_sec)


def delete_vpc_stack(stack_name, attempts, wait_sec):
    global TYPE
    if TYPE == "aws":
        aws.delete_vpc_stack(stack_name, attempts, wait_sec)


def get_storage_class():
    global TYPE
    if TYPE == "aws":
        return aws.storage_class


def remove_elb(vpc_stack_name):
    global TYPE
    if TYPE == "aws":
        aws.remove_elb(vpc_stack_name)


def attach_externaldns_policy(dns, config_name):
    global TYPE
    if TYPE == "aws":
        return aws.attach_externaldns_policy(dns, config_name)


def get_hosted_zone(dns):
    global TYPE
    if TYPE == "aws":
        return aws.get_hosted_zone(dns)


def detach_externaldns_policy(config_name):
    global TYPE
    if TYPE == "aws":
        return aws.detach_externaldns_policy(config_name)


def link_node_groups(cb_config):
    global TYPE
    if TYPE == "aws":
        aws.link_node_groups(cb_config)


def unlink_node_groups(cb_config):
    global TYPE
    if TYPE == "aws":
        aws.unlink_node_groups(cb_config)