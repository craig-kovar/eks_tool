import sys

from lib.configurations.EKSConfiguration import EKSConfiguration
import lib.utils.ekstool_utils as utils
import lib.cloud.ICloudUtils as cloud


class EKSConsole:
    should_run = True

    # def __init__(self):
    #	self.config = EKSConfiguration("TestCluster")

    def __init__(self, eks_config):
        self.config = eks_config

    def get_config(self):
        return self.config

    def display_prompt(self):
        utils.execute_command("clear", False)
        print("User: " + cloud.get_user())
        print("Region: " + cloud.get_current_region())
        print("VPC: " + cloud.get_vpc())
        print("------------------------------------------------------------------------------------------------")
        print("0 - List Regions")
        print("1 - Get Running Instances")
        print("2 - Switch Region")
        print("3 - Swith Profile")
        print("4 - Get Instance Types")
        print("5 - List VPCs")
        print("6 - Get Stacks")
        print("7 - Get EKS Clusters")
        print("")
        print("			Complete Steps		")
        print("")
        print("8 - Configure EKS Cluster")
        print("9 - Build Full Deployment")
        print("")
        print("			Incremental Steps	")
        print("")
        print("10 - Build VPC")
        print("11 - Connect to VPC")
        print("12 - Build EKS Cluster")
        print("13 - Connect to EKS Cluster")
        print("14 - Configure worker nodes")
        print("15 - Delete worker nodes")
        print("16 - Print worker nodes")
        print("17 - Get AMIs")
        print("18 - Build Worker Nodes")
        print("19 - Validate Worker Nodes")
        print("20 - Get current EKS Cluster")
        print("q - Return to main menu")
        print("")

    def get_instance_type(self):
        min_cpu = utils.prompt_input("Enter minimum cpu for instance [Enter for none] ")
        if len(min_cpu) < 1:
            min_cpu = None
        max_cpu = utils.prompt_input("Enter maximum cpu for instance [Enter for none] ")
        if len(max_cpu) < 1:
            max_cpu = None
        min_mem = utils.prompt_input("Enter minimum memory for instance [Enter for none] ")
        if len(min_mem) < 1:
            min_mem = None
        max_mem = utils.prompt_input("Enter maximum memory for instance [Enter for none] ")
        if len(max_mem) < 1:
            max_mem = None
        disktype = utils.prompt_input(
            "Enter disktype for instance. Valid values are (EBS,NVMeSSD,SSD) [Enter for none] ")
        if len(disktype) < 1 or disktype not in cloud.get_storage_type():
            disktype = None
        itClass = utils.prompt_input(
            "Enter instance type classification.  Valid values are (General Purpose,Compute Optimized,Memory Optimized) [Enter for none] ")
        if len(itClass) < 1 or itClass not in cloud.get_instanct_type_class():
            itClass = None

        instances = cloud.get_instances(min_cpu, max_cpu, min_mem, max_mem, disktype, itClass)
        return instances

    def read_input(self):
        myInput = ""
        myInput = utils.prompt_input("> ")

        if str(myInput) == "0":
            regions = utils.parse_results(cloud.list_regions("\"Regions[*].{RegionName:RegionName}\""))
            for reg in regions:
                utils.write_line(str(regions[reg]["RegionName"]))
        elif str(myInput) == "1":
            data = utils.parse_results(
                cloud.get_running_instances(
                    "\"Reservations[*].Instances[*].{Type:InstanceType,LaunchTime:LaunchTime,AZ:Placement.AvailabilityZone,Tags:Tags}\""))
            for inst in data:
                utils.write_line("")
                utils.write_line(str(data[inst]))
        elif str(myInput) == "2":
            region = utils.prompt_input("enter new region: ")
            cloud.switch_region(region)
        elif str(myInput) == "3":
            profile = utils.prompt_input("enter new profile: ")
            cloud.switch_profile(profile)
        elif str(myInput) == "4":
            instances = self.get_instance_type()
            for inst in instances:
                utils.write_line(inst)
        elif str(myInput) == "5":
            vpcs = utils.parse_results(cloud.list_vpc())
            for vpc in vpcs:
                utils.write_line(str(vpcs[vpc]))
        elif str(myInput) == "6":
            stacks = utils.parse_results(cloud.get_stacks("\"Stacks[*].{Name:StackName,Status:StackStatus}\""))
            for stack in stacks:
                utils.write_line(str(stacks[stack]))
        elif str(myInput) == "7":
            utils.write_line(cloud.list_kube_clusters())
        elif str(myInput) == "8":
            utils.write_line("Option not yet implemented")
        elif str(myInput) == "9":
            utils.write_line("Option not yet implemented")
        elif str(myInput) == "10":
            cloud.build_vpc(self.config.get_vpc_stack_name(), self.config.get_attempts(), self.config.get_wait_sec())
        elif str(myInput) == "11":
            vpc_name = utils.prompt_input("Enter a vpc to connect to [Blank for default name]: ")
            if len(vpc_name) > 1:
                cloud.connect_to_vpc(vpc_name)
            else:
                cloud.connect_to_vpc(self.config.get_vpc_stack_name())
        elif str(myInput) == "12":
            cloud.build_kube_cluster(self.config.get_eks_cluster_name(), self.config.get_attempts(),
                                   self.config.get_wait_sec(), EKSConfiguration._eks_role_arn)
        elif str(myInput) == "13":
            eks_name = utils.prompt_input("Enter an eks cluster [Blank for default name]: ")
            if len(eks_name) > 1:
                cloud.connect_to_kube_cluster(eks_name)
            else:
                cloud.connect_to_kube_cluster(self.config.get_eks_cluster_name())
        elif str(myInput) == "14":
            wrk_node = utils.prompt_input("Enter a worker node config to edit [Blank to create new one]: ")
            if len(wrk_node) > 1:
                self.config.configure_worker_nodes(self.config.worker_nodes[wrk_node])
            else:
                self.config.configure_worker_nodes(None)
        elif str(myInput) == "15":
            worker_node_cfg = utils.prompt_input("Enter a worker node configuration to delete")
            self.config.del_worker_node(worker_node_cfg)
        elif str(myInput) == "16":
            self.config.print_worker_nodes()
        elif str(myInput) == "17":
            version = utils.prompt_input("Enter a K8S version [Blank for all]: ")
            if len(version) >= 1:
                utils.write_line(version + " -> " + cloud.get_ami_version(version))
            else:
                results = cloud.get_ami_all()
                for inst in results:
                    utils.write_line(inst + " -> " + results[inst]['ami'])
        elif str(myInput) == "18":
            wrk_node_name = utils.prompt_input("Enter a worker node configuration to build [Blank for all]: ")
            if len(wrk_node_name) > 1:
                cloud.build_work_nodes(self.config.get_work_nodes()[wrk_node_name], self.config.get_eks_cluster_name(),
                                     self.config.get_attempts(),self.config.get_wait_sec(),self.config.get_name())
            else:
                wrk_nodes = self.config.get_work_nodes()
                for inst in wrk_nodes:
                    cloud.build_work_nodes(wrk_nodes[inst], self.config.get_eks_cluster_name(),
                                         self.config.get_attempts(), self.config.get_wait_sec(),self.config.get_name())

            cloud.apply_auth_map(self.config.get_name())
            if cloud.validate_nodes_ready(self.config.get_attempts(),self.config.get_wait_sec()):
                if len(wrk_node_name) > 1:
                    cloud.apply_labels(self.config.get_work_nodes()[wrk_node_name])
                else:
                    wrk_nodes = self.config.get_work_nodes()
                    for inst in wrk_nodes:
                        cloud.apply_labels(wrk_nodes[inst])
            else:
                utils.on_error("Worker nodes not ready")
        elif str(myInput) == "19":
            print(cloud.validate_nodes_ready(self.config.get_attempts(),self.config.get_wait_sec()))
        elif str(myInput) == "20":
            cloud.get_current_cluster()
        elif str(myInput) == "q":
            EKSConsole.should_run = False

    def pause(self):
        if sys.version_info[0] == 2:
            myInput = raw_input("hit any key to continue...")
        elif sys.version_info[0] == 3:
            myInput = input("hit any key to continue...")

    def run(self):
        while (EKSConsole.should_run):
            self.display_prompt()
            self.read_input()
            self.pause()
