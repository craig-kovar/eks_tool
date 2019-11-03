import os

import lib.utils.ekstool_utils as utils


def check_kube_resource(command):
    ret_val = False
    result_set = utils.execute_command_with_return(command, True, False, True)
    if len(result_set) > 1:
        if "NotFound" not in result_set[0]:
            ret_val = True

    return ret_val


def check_and_cleanup_file(path, file):
    if not os.path.isfile(path+"/"+file):
        return
    utils.execute_command("rm -f {0}".format(path+"/"+file), True)

#def check_kube_dir(config_name):
#    utils.check_dir(config_name, "kube")

def build_ns(path, namespace):
    utils.write_line("Building namespace")
    check_and_cleanup_file(path, "namespace.yaml")

    with open("{0}/{1}.yaml","w") as ns_yaml:
        ns_yaml.write("kind: Namespace\n")
        ns_yaml.write("apiVersion: v1\n")
        ns_yaml.write("metadata:\n")
        ns_yaml.write("  name: {0}\n".format(namespace))
        ns_yaml.write("  labels:\n")
        ns_yaml.write("    name: {0}\n".format(namespace))

    ns_file = path + "/" + namespace + ".yaml"
    if check_kube_resource("kubectl get -f {0}".format(ns_file)):
        utils.write_line("Resource {0} already exists, skipping")
    else:
        utils.execute_command("kubectl create -f {0} --save-config".format(ns_file))