import sys

import lib.utils.ekstool_utils as utils
import lib.cloud.ICloudUtils as cloud
from lib.console.EKSConsole import EKSConsole


class MainConsole:
    should_run = True

    def __init__(self, name, eks_config):
        self.name = name
        self.eks_config = eks_config

    def display_prompt(self):
        utils.execute_command("clear", False)
        print("User: " + cloud.get_user())
        print("Region: " + cloud.get_current_region())
        print("VPC: " + cloud.get_vpc())
        print("------------------------------------------------------------------------------------------------")
        print("0 - Manage EKS Cluster")
        print("1 - Manage Couchbase Cluster Deployment")
        print("2 - Display EKS Configuration")
        print("3 - Display Kubernetes Configuration")
        print("4 - Save configuration")
        print("5 - Load configuration")
        print("q - Quit")
        print("")

    def read_input(self):
        my_input = ""
        my_input = utils.prompt_input("> ")

        if str(my_input) == "0":
            EKSConsole.should_run = True
            console = EKSConsole(self.eks_config)
            console.run()
        elif str(my_input) == "1":
            print("ToDo")
        elif str(my_input) == "2":
            print(self.eks_config)
            self.pause()
        elif str(my_input) == "q":
            MainConsole.should_run = False

    def pause(self):
        if sys.version_info[0] == 2:
            my_input = raw_input("hit any key to continue...")
        elif sys.version_info[0] == 3:
            my_input = input("hit any key to continue...")

    def run(self):
        while (MainConsole.should_run):
            self.display_prompt()
            self.read_input()