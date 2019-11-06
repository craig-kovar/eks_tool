import lib.utils.ekstool_utils as utils
import lib.cloud.ICloudUtils as cloud
import sys

from lib.configurations.CBConfig import CBConfig
from lib.console.MainConsole import MainConsole
import lib.UI.MainScreen as MainScreen
import argparse

profile = None

# =======================================
#       Main Program
# =======================================
if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--console", help="Run in console mode", action="store_true")
    args = parser.parse_args()

    cloud.cloud_init(profile)

    print("Loading AWS Instance Types")
    try:
        cloud.load_instance_type("./resources/aws_general.json", "General Purpose")
        cloud.load_instance_type("./resources/aws_compute.json", "Compute Optimized")
        cloud.load_instance_type("./resources/aws_memory.json", "Memory Optimized")
    except IOError:
        utils.write_line("Failed to load instance type information")

    configName = "testcluster"
    cb_config = CBConfig("testcluster")

    if args.console:
        if sys.version_info[0] == 2:
            configName = raw_input("Enter a name for your configuration: ")
        elif sys.version_info[0] == 3:
            configName = input("Enter a name for your configuration: ")


        cb_config = CBConfig(configName.lower())
        console = MainConsole(configName, cb_config.eks_config)
        console.run()
    else:
        utils.set_mode("gui")
        MainScreen.vp_start_gui(cb_config)
        #print(str(cb_config))
