import pickle

import lib.utils.ekstool_utils as utils
import lib.cloud.ICloudUtils as cloud
import sys

from lib.configurations.CBConfig import CBConfig
from lib.console.MainConsole import MainConsole
import lib.UI.MainScreen as MainScreen
import argparse

profile = None


def load_aws_instances():
    print("Loading AWS Instance Types")
    try:
        cloud.load_instance_type("./resources/aws_general.json", "General Purpose")
        cloud.load_instance_type("./resources/aws_compute.json", "Compute Optimized")
        cloud.load_instance_type("./resources/aws_memory.json", "Memory Optimized")
    except IOError:
        utils.write_line("Failed to load instance type information")

# =======================================
#       Main Program
# =======================================
if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--console", help="Run in console mode", action="store_true")
    parser.add_argument("-b", "--build", help="Build the specified components", action="store_true")
    parser.add_argument("-d", "--delete", help="Delete the specified components", action="store_true")
    parser.add_argument("-kc", "--kubecluster", help="Build the specified cloud provider kubernetes cluster",
                        action="store_true")
    parser.add_argument("-cb", "--couchbase", help="Build the specified Couchbase cluster",
                        action="store_true")
    parser.add_argument("-f", "--file", help="Specify the configuration file")
    args = parser.parse_args()

    cloud.cloud_init(profile)

    configName = "testcluster"
    cb_config = CBConfig("testcluster")

    if args.console:
        load_aws_instances()

        if sys.version_info[0] == 2:
            configName = raw_input("Enter a name for your configuration: ")
        elif sys.version_info[0] == 3:
            configName = input("Enter a name for your configuration: ")

        cb_config = CBConfig(configName.lower())
        console = MainConsole(configName, cb_config.eks_config)
        console.run()
    elif args.build:
        if args.file is None:
            print("Configuration file to build must be specified")
        try:
            cb_config = pickle.load(open(args.file, "rb"))
        except IOError:
            print("Unable to load file {}".format(args.file))
            exit(1)

        print("Building - ")
        print(" Kubernetes Cluster -- {}".format(args.kubecluster))
        print(" Couchbase Cluster -- {}".format(args.couchbase))
        if args.kubecluster:
            cloud.build_cluster(cb_config)

    elif args.delete:
        if args.file is None:
            print("Configuration file to build must be specified")
        try:
            cb_config = pickle.load(open(args.file, "rb"))
        except IOError:
            print("Unable to load file {}".format(args.file))
            exit(1)
        cloud.delete_cluster(cb_config)
    else:
        utils.set_mode("gui")
        load_aws_instances()
        try:
            MainScreen.vp_start_gui(cb_config)
        except:
            #Supress exceptions for now
            pass
        #print(str(cb_config))
