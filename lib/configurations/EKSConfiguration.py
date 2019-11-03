import lib.utils.ekstool_utils as utils
from lib.cloud.aws_worker_node_config import aws_worker_node_config
import lib.cloud.ICloudUtils as cloud


class EKSConfiguration:
    _eks_role_arn = "arn:aws:iam::669678783832:role/cbd-eks-role"

    def __init__(self, name):
        self.name = name
        self.vpc_stack_name = "VPC-" + name
        self.eks_cluster_name = "CLUSTER-" + name
        self.worker_nodes = {}
        self.attempts = 15
        self.wait_sec = 120
        # self.worker_nodes = {}

    def __repr__(self):
        ret_string = "{\n"
        ret_string = ret_string + " name: {}\n".format(self.name)
        ret_string = ret_string + " vpc_stack_name: {}\n".format(self.vpc_stack_name)
        ret_string = ret_string + " eks_cluster_name: {}\n".format(self.eks_cluster_name)
        ret_string = ret_string + " attempts: {}\n".format(self.attempts)
        ret_string = ret_string + " wait_sec: {}\n".format(self.wait_sec)
        ret_string = ret_string + " worker_nodes: [\n"
        for wrk_node in self.worker_nodes:
            ret_string = ret_string + "     " + str(self.worker_nodes[wrk_node]) + "\n"
        ret_string = ret_string + " ]\n"
        ret_string = ret_string + "}\n"
        return ret_string

    def __str__(self):
        ret_string = "{\n"
        ret_string = ret_string + " name: {}\n".format(self.name)
        ret_string = ret_string + " vpc_stack_name: {}\n".format(self.vpc_stack_name)
        ret_string = ret_string + " eks_cluster_name: {}\n".format(self.eks_cluster_name)
        ret_string = ret_string + " attempts: {}\n".format(self.attempts)
        ret_string = ret_string + " wait_sec: {}\n".format(self.wait_sec)
        ret_string = ret_string + " worker_nodes: [\n"
        for wrk_node in self.worker_nodes:
            ret_string = ret_string + "     " + str(self.worker_nodes[wrk_node]) + "\n"
        ret_string = ret_string + " ]\n"
        ret_string = ret_string + "}\n"
        return ret_string

    def get_arn(self):
        return EKSConfiguration._eks_role_arn

    def get_name(self):
        return self.name

    def set_name(self, name):
        self.name = name
        self.vpc_stack_name = "VPC-" + name
        self.eks_cluster_name = "CLUSTER-" + name

    def set_vpc_name(self, name):
        self.vpc_stack_name = name

    def get_vpc_stack_name(self):
        return self.vpc_stack_name

    def set_eks_cluster_name(self, name):
        self.eks_cluster_name = name

    def get_eks_cluster_name(self):
        return self.eks_cluster_name

    def set_attempts(self, newAttempts):
        self.attempts = newAttempts

    def get_attempts(self):
        return self.attempts

    def set_wait_sec(self, newWaitSec):
        self.wait_sec = newWaitSec

    def get_wait_sec(self):
        return self.wait_sec

    def get_work_nodes(self):
        return self.worker_nodes

    def get_work_node(self, name):
        return self.worker_nodes[name]

    def add_worker_node(self, wrk_node_config):
        if wrk_node_config is not None:
            self.worker_nodes[wrk_node_config.get_name()] = wrk_node_config

    def del_worker_node(self, wrk_node):
        try:
            del self.worker_nodes[wrk_node]
        except KeyError:
            pass

    def configure_worker_nodes(self, wrk_node):
        if wrk_node is None:
            name = utils.prompt_input_default("Enter a Stack Name for the nodes [" + self.get_name() + "-nodes]: ",
                                              self.get_name() + "-nodes")
            wrk_node = aws_worker_node_config(name)

        # wrk_node.set_name(utils.prompt_input_default("Enter a Stack Name for the nodes["+wrk_node.get_name()+"]: ", wrk_node.get_name()))
        wrk_node.set_group_name(
            utils.prompt_input_default("Enter a scale group name [" + wrk_node.get_group_name() + "]: ",
                                       wrk_node.get_group_name()))
        wrk_node.set_group_min(
            utils.prompt_input_default("Enter minimum number of nodes [" + str(wrk_node.get_group_min()) + "]: ",
                                       wrk_node.get_group_min()))
        wrk_node.set_group_max(
            utils.prompt_input_default("Enter maximum number of nodes [" + str(wrk_node.get_group_max()) + "]: ",
                                       wrk_node.get_group_max()))
        wrk_node.set_group_desired(
            utils.prompt_input_default("Enter desired number of nodes [" + str(wrk_node.get_group_desired()) + "]: ",
                                       wrk_node.get_group_desired()))
        wrk_node.set_instance_type(
            utils.prompt_input_default("Enter instance type [" + wrk_node.get_instance_type() + "]: ",
                                       wrk_node.get_instance_type()))

        tmp_ami = utils.prompt_input("Enter AMI to use [Blank to auto-detect]: ")
        if len(tmp_ami) >= 1:
            wrk_node.set_ami(tmp_ami)
        else:
            k8s_version = utils.prompt_input_default("Enter kubernetes version to use [Default 1.12]: ", "1.12")
            tmp_ami = cloud.get_ami_version(k8s_version)
            wrk_node.set_ami(tmp_ami)

        wrk_node.set_volume_size(
            utils.prompt_input_default("Enter volume size [" + str(wrk_node.get_volume_size()) + "]: ",
                                       wrk_node.get_volume_size()))

        add_label = True
        while add_label:
            label_key = utils.prompt_input("Enter a label key [blank to skip or end labels]: ")
            if len(label_key) >= 1:
                label_value = utils.prompt_input("Enter a label value: ")
                wrk_node.add_label(label_key, label_value)
            else:
                add_label = False

        self.add_worker_node(wrk_node)

    def print_worker_nodes(self):
        for wrk_node in self.worker_nodes:
            utils.write_line(wrk_node + " -> " + str(self.worker_nodes[wrk_node]))

    def print_configuration(self):
        printString = "{"
        printString += "vpc_stack_name:" + str(self.vpc_stack_name)
        printString += ", eks_cluster_name:" + str(self.eks_cluster_name)
        printString += ", worker_nodes: " + str(self.worker_nodes)
        printString += "}"

        utils.write_line(printString)
