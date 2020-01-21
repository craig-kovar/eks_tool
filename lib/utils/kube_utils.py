import os
import time

import lib.utils.ekstool_utils as utils

version = "1.2"


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


def build_resource_with_yaml(yaml_file):
    if check_kube_resource("kubectl get -f {0}".format(yaml_file)):
        utils.write_line("Resource {0} already exists, skipping\n".format(yaml_file))
    else:
        utils.execute_command("kubectl create -f {0} --save-config".format(yaml_file), False)


def build_resource_yaml_no_check(yaml_file):
    utils.execute_command("kubectl create -f {0} --save-config".format(yaml_file), False)

#def build_resource(command):
#    if check_kube_resource("kubectl get -f {0}".format(yaml_file)):
#        utils.write_line("Resource {0} already exists, skipping".format(yaml_file))
#    else:
#        utils.execute_command("kubectl create -f {0} --save-config".format(yaml_file), False)


def build_ns(path, namespace):
    utils.write_line("Building namespace")
    check_and_cleanup_file(path, "namespace.yaml")

    with open("{0}/{1}.yaml".format(path, namespace), "w") as ns_yaml:
        ns_yaml.write("kind: Namespace\n")
        ns_yaml.write("apiVersion: v1\n")
        ns_yaml.write("metadata:\n")
        ns_yaml.write("  name: {0}\n".format(namespace))
        ns_yaml.write("  labels:\n")
        ns_yaml.write("    name: {0}\n".format(namespace))

    yaml_file = path + "/" + namespace + ".yaml"
    build_resource_with_yaml(yaml_file)


def deploy_crd():
    utils.write_line("Deploying CRD")
    build_resource_with_yaml("./resources/cbao/{0}/crd.yaml".format(version))


def deploy_operator_role(namespace):
    utils.write_line("Deploying Couchbase Autonmous Operator Role")
    build_resource_with_yaml("./resources/cbao/{0}/operator-role.yaml --namespace {1}".format(version, namespace))


def deploy_operator_sa(namespace):
    utils.write_line("Deploying Couchbase Autonmous Operator Service Account")
    build_resource_with_yaml("./resources/cbao/{0}/operator-service-account.yaml --namespace {1}".format(version, namespace))


def build_operator_role_binding(path, namespace):
    utils.write_line("Building operator role binding")
    check_and_cleanup_file(path, "operator-role-binding.yaml")

    with open("{0}/operator-role-binding.yaml".format(path), "w") as orb_yaml:
        orb_yaml.write("apiVersion: rbac.authorization.k8s.io/v1\n")
        orb_yaml.write("kind: RoleBinding\n")
        orb_yaml.write("metadata:\n")
        orb_yaml.write("  creationTimestamp: null\n")
        orb_yaml.write("  name: couchbase-operator\n")
        orb_yaml.write("roleRef:\n")
        orb_yaml.write("  apiGroup: rbac.authorization.k8s.io\n")
        orb_yaml.write("  kind: Role\n")
        orb_yaml.write("  name: couchbase-operator\n")
        orb_yaml.write("subjects:\n")
        orb_yaml.write("- kind: ServiceAccount\n")
        orb_yaml.write("  name: couchbase-operator\n")
        orb_yaml.write("  namespace: {0}\n".format(namespace))

    yaml_file = path + "/operator-role-binding.yaml"
    build_resource_with_yaml("{0} --namespace {1}".format(yaml_file, namespace))


def deploy_operator(namespace):
    utils.write_line("Deploying Couchbase Autonmous Operator")
    build_resource_with_yaml("./resources/cbao/{0}/operator-deployment.yaml --namespace {1}".format(version, namespace))


def deploy_secret(namespace):
    utils.write_line("Deploying Couchbase Administrator Password")
    build_resource_with_yaml("./resources/cbao/{0}/secret.yaml --namespace {1}".format(version, namespace))


def check_limts(server):
    ret_val = False
    if int(server.pod.limits['cpu']) > 0:
        ret_val = True

    if int(server.pod.limits['memory']) > 0:
        ret_val = True

    if int(server.pod.limits['storage']) > 0:
        ret_val = True

    return ret_val


def check_requests(server):
    ret_val = False
    if int(server.pod.requests['cpu']) > 0:
        ret_val = True

    if int(server.pod.requests['memory']) > 0:
        ret_val = True

    if int(server.pod.requests['storage']) > 0:
        ret_val = True

    return ret_val


def check_volume_mount(server):
    ret_val = False
    if server.pod.volume_mount['default'] != "":
        ret_val = True

    if server.pod.volume_mount['data'] != "":
        ret_val = True

    if server.pod.volume_mount['index'] != "":
        ret_val = True

    for itr in range(0,len(server.pod.volume_mount['analytics'])-1):
        if server.pod.volume_mount['analytics'][itr] != "":
            ret_val = True

    return ret_val


def check_pod(server):
    ret_val = False

    if check_limts(server):
        ret_val = True

    if check_requests(server):
        ret_val = True

    if len(server.pod.nodeselector) >= 1:
        ret_val = True

    if check_volume_mount(server):
        ret_val = True

    return ret_val


def build_cb_cluster(path, cbcluster_config):
    utils.write_line("Deploying Couchbase Cluster")

    check_and_cleanup_file(path, "couchbase-cluster.yaml")
    with open("{0}/couchbase-cluster.yaml".format(path), "w") as cb_yaml:
        #General Info
        cb_yaml.write("apiVersion: couchbase.com/v1\n")
        cb_yaml.write("kind: CouchbaseCluster\n")
        cb_yaml.write("metadata:\n")
        cb_yaml.write("  name: {0}\n".format(cbcluster_config.clustername))
        cb_yaml.write("  namespace: {0}\n".format(cbcluster_config.namespace))
        cb_yaml.write("spec:\n")
        cb_yaml.write("  baseImage: couchbase/server\n")
        cb_yaml.write("  version: enterprise-{0}\n".format(cbcluster_config.version))
        cb_yaml.write("  paused: false\n")
        if cbcluster_config.antiaffinity:
            cb_yaml.write("  antiAffinity: true\n")
        else:
            cb_yaml.write("  antiAffinity: false\n")

        #TODO - TLS Section
        if cbcluster_config.tls or cbcluster_config.expose_features['admin'] or \
            cbcluster_config.expose_features['xdcr'] or cbcluster_config.expose_features['client'] or \
                cbcluster_config.external_dns:
            cb_yaml.write("  tls:\n")
            cb_yaml.write("    static:\n")
            cb_yaml.write("      member:\n")
            cb_yaml.write("        serverSecret: couchbase-server-tls\n")
            cb_yaml.write("      operatorSecret: couchbase-operator-tls\n")

        cb_yaml.write("  authSecret: cb-example-auth\n")

        #Admin Services
        if cbcluster_config.expose_admin_console:
            cb_yaml.write("  exposeAdminConsole: true\n")
            cb_yaml.write("  adminConsoleServiceType: LoadBalancer\n")
            cb_yaml.write("  adminConsoleServices:\n")
            if cbcluster_config.expose_admin_svcs == "data":
                cb_yaml.write("    - data\n")
            if cbcluster_config.expose_admin_svcs == "index":
                cb_yaml.write("    - index\n")
            if cbcluster_config.expose_admin_svcs == "query":
                cb_yaml.write("    - query\n")
            if cbcluster_config.expose_admin_svcs == "search":
                cb_yaml.write("    - search\n")
            if cbcluster_config.expose_admin_svcs == "eventing":
                cb_yaml.write("    - eventing\n")
            if cbcluster_config.expose_admin_svcs == "analytics":
                cb_yaml.write("    - analytics\n")
        else:
            cb_yaml.write("  exposeAdminConsole: false\n")

        #Exposed Features
        if cbcluster_config.expose_features['admin'] or cbcluster_config.expose_features['xdcr'] or \
            cbcluster_config.expose_features['client']:
            cb_yaml.write("  exposedFeatures:\n")
            for itr in cbcluster_config.expose_features:
                if cbcluster_config.expose_features[itr]:
                    cb_yaml.write("    - {}\n".format(itr))
            cb_yaml.write("  exposedFeatureServiceType: LoadBalancer\n")

        if cbcluster_config.disable_bucket_management:
            cb_yaml.write("  disableBucketManagement: true\n")
        else:
            cb_yaml.write("  disableBucketManagement: false\n")

        #DNS
        cb_yaml.write("  dns:\n")
        cb_yaml.write("    domain: {}\n".format(cbcluster_config.dns))

        #Cluster
        cb_yaml.write("  cluster:\n")
        for itr in cbcluster_config.cluster:
            cb_yaml.write("    {0}: {1}\n".format(itr, cbcluster_config.cluster[itr]))

        #Buckets
        cb_yaml.write("  buckets:\n")
        if not cbcluster_config.disable_bucket_management and len(cbcluster_config.buckets) < 1:
            utils.write_error("Bucket management is enabled and 0 buckets defined")
            return
        else:
            for itr in cbcluster_config.buckets:
                bucket = cbcluster_config.buckets[itr]

                cb_yaml.write("    - name: {}\n".format(bucket.name))
                cb_yaml.write("      type: {}\n".format(bucket.type))
                cb_yaml.write("      memoryQuota: {}\n".format(bucket.memoryQuota))
                cb_yaml.write("      replicas: {}\n".format(bucket.replicas))
                cb_yaml.write("      ioPriority: {}\n".format(bucket.ioPriority))
                cb_yaml.write("      evictionPolicy: {}\n".format(bucket.evictionPolicy))
                cb_yaml.write("      conflictResolution: {}\n".format(bucket.conflictResolution))
                cb_yaml.write("      enableFlush: {}\n".format(bucket.enableFlush))
                cb_yaml.write("      enableIndexReplica: false\n")
                cb_yaml.write("      compressionMode: passive\n")

        #Servers
        if len(cbcluster_config.servers) < 1:
            utils.write_error("At least one server must be configured")
            return
        else:
            vct_string = ""
            vct_map = {}
            cb_yaml.write("  servers:\n")
            for itr in cbcluster_config.servers:
                server = cbcluster_config.servers[itr]
                cb_yaml.write("    - size: {}\n".format(server.size))
                cb_yaml.write("      name: {}\n".format(server.name))
                cb_yaml.write("      services:\n")
                for svc_itr in server.services:
                    if server.services[svc_itr] == "1":
                        cb_yaml.write("        - {}\n".format(svc_itr))

                #server.pod
                if check_pod(server):
                    cb_yaml.write("      pod:\n")

                    if check_requests(server) or check_limts(server):
                        cb_yaml.write("        resources:\n")
                        if check_limts(server):
                            cb_yaml.write("          limits:\n")
                            if int(server.pod.limits['cpu']) > 0:
                                cb_yaml.write("            cpu: \"{}\"\n".format(server.pod.limits['cpu']))
                            if int(server.pod.limits['memory']) > 0:
                                cb_yaml.write("            memory: \"{0}{1}\"\n".format(
                                    server.pod.limits['memory'], server.pod.limits['memory_size']
                                ))
                            #if int(server.pod.limits['storage']) > 0:
                            #    cb_yaml.write("            storage: \"{0}{1}\"\n".format(
                            #        server.pod.limits['storage'], server.pod.limits['storage_size']
                            #    ))
                        if check_requests(server):
                            cb_yaml.write("          requests:\n")
                            if int(server.pod.requests['cpu']) > 0:
                                cb_yaml.write("            cpu: \"{}\"\n".format(server.pod.requests['cpu']))
                            if int(server.pod.requests['memory']) > 0:
                                cb_yaml.write("            memory: \"{0}{1}\"\n".format(
                                    server.pod.requests['memory'], server.pod.requests['memory_size']
                                ))
                            #if int(server.pod.requests['storage']) > 0:
                            #    cb_yaml.write("            storage: \"{0}{1}\"\n".format(
                            #        server.pod.requests['storage'], server.pod.requests['storage_size']
                            #    ))

                    if len(server.pod.nodeselector) >= 1:
                        cb_yaml.write("        nodeSelector:\n")
                        for itr in server.pod.nodeselector:
                            cb_yaml.write("          {0}: {1}\n".format(itr, server.pod.nodeselector[itr]))

                    #Volume Mounts
                    #TODO - Review Volume Mounts (Possible timeout issue)
                    if check_volume_mount(server):
                        cb_yaml.write("        volumeMounts:\n")
                        if server.pod.volume_mount['default'] != "":
                            cb_yaml.write("          default: {0}\n".format(server.pod.volume_mount['default']))
                        #if server.pod.volume_mount['data'] != "":
                        #    cb_yaml.write("          data:  {0}\n".format(server.pod.volume_mount['data']))
                        #if server.pod.volume_mount['index'] != "":
                        #    cb_yaml.write("          index: {0}\n".format(server.pod.volume_mount['index']))

                        #vm_analytics = "          analytics:\n"
                        #for itr in server.pod.volume_mount['analytics']:
                        #    if itr != "":
                        #        vm_analytics = vm_analytics + "            - {}\n".format(itr)

                        #if vm_analytics != "          analytics:\n":
                        #    cb_yaml.write(vm_analytics)

                    if len(cbcluster_config.vct) >= 1:
                        if len(vct_string) < 1:
                            vct_string = vct_string + "  volumeClaimTemplates:\n"
                        for itr in cbcluster_config.vct:
                            tmp_vct = cbcluster_config.vct[itr]
                            if tmp_vct.name not in vct_map:
                                vct_map[tmp_vct.name] = "Added"
                                vct_string = vct_string + "    - metadata:\n"
                                vct_string = vct_string + "        name: {}\n".format(tmp_vct.name)
                                vct_string = vct_string + "      spec:\n"
                                vct_string = vct_string + "        storageClassName: \"{}\"\n".format(tmp_vct.storage_class)
                                vct_string = vct_string + "        resources:\n"
                                vct_string = vct_string + "          requests:\n"
                                vct_string = vct_string + "            storage: \"{0}{1}\"\n".format(tmp_vct.size, tmp_vct.size_type)

            #After all the servers are added to the yaml configure the VCT once
            if len(vct_string) > 1:
                cb_yaml.write(vct_string)


def build_custom_pod(path, cbcluster_config, name, image):
    utils.write_line("Deploying Application Pods")

    check_and_cleanup_file(path, "app-pod.yaml")
    with open("{0}/app-pod.yaml".format(path), "w") as app_pod:
        app_pod.write("apiVersion: apps/v1\n")
        app_pod.write("kind: Deployment\n")
        app_pod.write("metadata:\n")
        app_pod.write("  name: {}\n".format(name))
        app_pod.write("spec:\n")
        app_pod.write("  selector:\n")
        app_pod.write("    matchLabels:\n")
        app_pod.write("      app: {}\n".format(name))
        app_pod.write("  template:\n")
        app_pod.write("    metadata:\n")
        app_pod.write("      labels:\n")
        app_pod.write("        app: {}\n".format(name))
        app_pod.write("    spec:\n")
        app_pod.write("      containers:\n")
        app_pod.write("      - name: {}\n".format(name))
        app_pod.write("        image: {}\n".format(image))
        app_pod.write("        imagePullPolicy: Always\n")

def build_sgw_config(path, cbcluster_config, is_import):
    utils.write_line("Deploying SGW")

    check_and_cleanup_file(path, "sgw-config.json")
    with open("{0}/sgw-config.json".format(path), "w") as sgw_config:
        sgw_config.write("{\n")
        sgw_config.write("  \"logging\": {\n")
        sgw_config.write("    \"log_file_path\": \"/var/tmp/sglogs\",\n")
        sgw_config.write("    \"console\": {\n")
        sgw_config.write("      \"enabled\": true,\n")
        sgw_config.write("      \"log_level\": \"info\",\n")
        sgw_config.write("      \"log_keys\": [\"*\"]\n")
        sgw_config.write("    }\n")
        sgw_config.write("  },\n")
        sgw_config.write("  \"databases\": {\n")
        sgw_config.write("    \"db\": {\n")
        sgw_config.write("      \"server\": \"{0}-0000.{0}.{1}.svc:8091\",\n".format(cbcluster_config.clustername,
                                                                                     cbcluster_config.namespace))
        sgw_config.write("      \"bucket\": \"{0}\",\n".format(list(cbcluster_config.buckets)[0]))
        sgw_config.write("      \"username\": \"Administrator\",\n")
        sgw_config.write("      \"password\": \"password\",\n")
        sgw_config.write("      \"users\": { \"GUEST\": { \"disabled\": false, \"admin_channels\": [\"*\"] } },\n")
        sgw_config.write("      \"allow_conflicts\": false,\n")
        sgw_config.write("      \"revs_limit\": 20,\n")

        if is_import:
            sgw_config.write("      \"enable_shared_bucket_access\": true,\n")
            sgw_config.write("      \"import_docs\": true\n")
        else:
            sgw_config.write("      \"enable_shared_bucket_access\": true\n")

        sgw_config.write("    }\n")
        sgw_config.write("  }\n")
        sgw_config.write("}\n")


def check_cluster_running(cbcluster_config):
    utils.write_line("Checking couchbasecluster status")
    counter = "0"
    ret_val = True
    #command = kubectl get pods testcluster-0000 --namespace testns | tail -1 | tr -s [:blank:] | cut -d' ' -f2
    for itr in cbcluster_config.servers:
        server = cbcluster_config.servers[itr]
        if server.size >= 1:
            for i in range(0, int(server.size)):

                my_attempts = 1
                run = True
                ready = False

                while my_attempts <= cbcluster_config.attempts and run:
                    utils.write_line("Checking pod status...")
                    result = utils.execute_command_with_return("kubectl get pods {0}-{1} --namespace {2} | tail -1 | tr -s [:blank:] | cut -d' ' -f2".format(
                    cbcluster_config.clustername, counter.zfill(4), cbcluster_config.namespace
                    ), False, False, True)[0]

                    utils.write_line("Got result {}".format(result))
                    if result == "1/1":
                        run = False
                        ready = True
                    else:
                        time.sleep(cbcluster_config.wait_sec)

                if not ready:
                    ret_val = False
                    return ret_val
                else:
                    counter = str(int(counter)+1)

    return ret_val


def setup_tls(cb_config):
    #Pulled from earlier work on testing internal CA and couchbasesummit
    #TODO - Convert to code generation and not external project
    utils.write_line("Generating TLS certificate")

    if os.path.exists("./work/{0}/easy-rsa".format(cb_config.name)):
        utils.execute_command("rm -rf ./work/{0}/easy-rsa".format(cb_config.name), False)
    utils.execute_command("git clone https://github.com/OpenVPN/easy-rsa ./work/{0}/easy-rsa".format(cb_config.name), False)

    os.environ['EASYRSA_PKI'] = "./work/{0}/easy-rsa/easyrsa3/pki".format(cb_config.name)
    utils.write_line("EASYRSA_PKI set to : {}".format(os.environ['EASYRSA_PKI']))

    utils.execute_command("sh ./work/{0}/easy-rsa/easyrsa3/easyrsa init-pki".format(cb_config.name), False)

    utils.execute_command("sh ./work/{0}/easy-rsa/easyrsa3/easyrsa build-ca nopass < ./resources/cbao/{1}/couchbase_tls.txt".format(
        cb_config.name, version), False)

    san_string = "--subject-alt-name=\"DNS:*.{1}.{2}.svc,DNS:*.{2}.svc,DNS:*.{1}.{3}\"".format(
        cb_config.name, cb_config.get_cbcluster_config().clustername,
        cb_config.get_cbcluster_config().namespace, cb_config.get_cbcluster_config().dns
    )

    utils.execute_command(
        "sh ./work/{0}/easy-rsa/easyrsa3/easyrsa {1} build-server-full couchbase-server nopass".format(cb_config.name,
                                                                                                       san_string),
        False)

    utils.execute_command(
        "openssl rsa -in ./work/{0}/easy-rsa/easyrsa3/pki/private/couchbase-server.key -out ./work/{0}/easy-rsa/easyrsa3/pki/private/pkey.key.der -outform DER".format(cb_config.name), False)

    utils.execute_command(
        "openssl rsa -in ./work/{0}/easy-rsa/easyrsa3/pki/private/pkey.key.der -inform DER -out ./work/{0}/easy-rsa/easyrsa3/pki/private/pkey.key -outform PEM".format(cb_config.name), False)

    utils.execute_command(
        "cp -p ./work/{0}/easy-rsa/easyrsa3/pki/issued/couchbase-server.crt ./work/{0}/easy-rsa/easyrsa3/pki/issued/chain.pem".format(cb_config.name), False)

    utils.execute_command(
        "cp -p ./work/{0}/easy-rsa/easyrsa3/pki/issued/couchbase-server.crt ./work/{0}/easy-rsa/easyrsa3/pki/issued/tls-cert-file".format(cb_config.name), False)

    utils.execute_command(
        "cp -p ./work/{0}/easy-rsa/easyrsa3/pki/private/pkey.key ./work/{0}/easy-rsa/easyrsa3/pki/private/tls-private-key-file".format(cb_config.name), False)

    PRIVATE_PATH = "./work/{0}/easy-rsa/easyrsa3/pki/private".format(cb_config.name)
    ISSUED_PATH = "./work/{0}/easy-rsa/easyrsa3/pki/issued".format(cb_config.name)

    utils.execute_command(
        "kubectl create secret generic couchbase-server-tls --from-file {0} --from-file {1} --namespace {2}".format(
            PRIVATE_PATH + "/pkey.key", ISSUED_PATH + "/chain.pem", cb_config.get_cbcluster_config().namespace), False)

    utils.execute_command(
        "kubectl create secret generic couchbase-operator-admission --from-file {0} --from-file {1} --namespace {2}".format(
            ISSUED_PATH + "/tls-cert-file", PRIVATE_PATH + "/tls-private-key-file", cb_config.get_cbcluster_config().namespace), False)

    utils.execute_command("kubectl create secret generic couchbase-operator-tls --from-file {0} --namespace {1}".format(
        "./work/{0}/easy-rsa/easyrsa3/pki/ca.crt".format(cb_config.name), cb_config.get_cbcluster_config().namespace), False)
