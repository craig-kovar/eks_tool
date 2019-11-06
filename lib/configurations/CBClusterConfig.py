

class CBClusterConfig:

    def __init__(self, name):
        self.namespace = "testns"
        self.clustername = name
        self.version = "6.0.3"
        self.version_loc = 0
        self.antiaffinity = False
        self.disable_bucket_management = False
        self.tls = False
        self.expose_admin_console = True
        self.expose_admin_svcs = 'data'
        self.expose_admin_svc_loc = 0
        self.expose_features = {'admin': 0, 'xdcr': 0, 'client': 0}
        self.external_dns = False
        self.dns = "se-couchbasedemos.com"
        self.idx_loc = 0
        self.cluster = {'dataServiceMemoryQuota': "256", 'indexServiceMemoryQuota': "256",
                        'searchServiceMemoryQuota': "256", 'eventingServiceMemoryQuota': "256",
                        'analyticsServiceMemoryQuota': "1024", 'indexStorageSetting': "plasma",
                        'autoFailoverTimeout': "30", "autoFailoverMaxCount": "1",
                        'autoFailoverOnDataDiskIssues': 'true', 'autoFailoverOnDataDiskIssuesTimePeriod': "120",
                        'autoFailoverServerGroup': "false"}
        self.buckets = {}
        self.servers = {}
        self.vct = {}
        self.sgw = 0
        self.sgw_conf = None
        self.app = 0
        self.couchmart = 0
        self.attempts = 15
        self.wait_sec = 60

    def __str__(self):
        ret_string = "{\n"
        ret_string = ret_string + " namespace: {0}\n".format(self.namespace)
        ret_string = ret_string + " cluster_name: {0}\n".format(self.clustername)
        ret_string = ret_string + " version: {0}\n".format(self.version)
        ret_string = ret_string + " antiAffinity: {0}\n".format(self.antiaffinity)
        ret_string = ret_string + " disable_bucket_management: {0}\n".format(self.disable_bucket_management)
        ret_string = ret_string + " expose_admin_console: {0}\n".format(self.expose_admin_console)
        ret_string = ret_string + " expose_admin_services: {0}\n".format(self.expose_admin_svcs)
        ret_string = ret_string + " expose_features: {0}\n".format(self.expose_features)
        ret_string = ret_string + " dns: {0}\n".format(self.dns)
        ret_string = ret_string + " sgw_config: {0}\n".format(self.sgw_conf)
        ret_string = ret_string + " cluster:\n"
        ret_string = ret_string + "  {\n"
        for key in self.cluster.keys():
            ret_string = ret_string + "    {0}: {1}\n".format(key, self.cluster[key])
        ret_string = ret_string + "  }\n"
        ret_string = ret_string + " buckets:\n"
        ret_string = ret_string + "  {\n"
        for key in self.buckets.keys():
            ret_string = ret_string + "    {0}: {1}\n".format(key, self.buckets[key])
        ret_string = ret_string + "  }\n"
        ret_string = ret_string + " servers:\n"
        ret_string = ret_string + "  {\n"
        for key in self.servers.keys():
            ret_string = ret_string + "    {0}: {1}\n".format(key, self.servers[key])
        ret_string = ret_string + "  }\n"
        ret_string = ret_string + "}\n"

        return ret_string

    def add_bucket(self, bucket):
        if bucket is not None:
            self.buckets[bucket.name] = bucket

    def del_bucket(self, name):
        try:
            del self.buckets[name]
        except KeyError:
            pass

    def add_server(self, server):
        if server is not None:
            self.servers[server.name] = server

    def del_server(self, name):
        try:
            del self.servers[name]
        except KeyError:
            pass

class CBClusterBucket:

    def __init__(self):
        self.name = None
        self.type = "couchbase"
        self.memoryQuota = "256"
        self.replicas = "1"
        self.ioPriority = "low"
        self.evictionPolicy = "value-eviction"
        self.conflictResolution = "seqno"
        self.enableFlush = "false"
        self.enableIndexReplica = "false"
        self.compressionMode = "passive"

    def __str__(self):
        ret_str = "name: {0} -> type: {1}; quota: {2}; replicas: {3}; ioPriority: {4}; evictionPolicy: {5}; conflictResolution: {6}; enableFlush: {7}".format(
            self.name, self.type, self.memoryQuota, self.replicas, self.ioPriority, self.evictionPolicy, self.conflictResolution, self.enableFlush
        )
        return ret_str

class CBClusterPod:

    def __init__(self):
        self.limits = {'cpu': "0", 'memory': "0", 'memory_size': "Gi", 'storage': "0", 'storage_size': "Gi"}
        self.requests = {'cpu': "0", 'memory': "0", 'memory_size': "Gi", 'storage': "0", 'storage_size': "Gi"}
        self.nodeselector = {}
        self.volume_mount = {
            'default' : "",
            'data': "",
            'index': "",
            'analytics': ["", "", "", "", "", ""]
        }

    def __str__(self):
        return "limits: {0}; requests: {1}; node_selector: {2}; volume_mounts: {3}".format(
            self.limits, self.requests, self.nodeselector, self.volume_mount
        )

    def del_nodeselector(self, name):
        try:
            del self.nodeselector[name]
        except KeyError:
            pass

class CBClusterServer:

    def __init__(self):
        self.name = None
        self.size = "1"
        self.services = {
            'data': "0",
            'index': "0",
            'query': "0",
            'search': "0",
            'eventing': "0",
            'analytics': "0"
        }
        self.pod = CBClusterPod()

    def __str__(self):
        return "name: {0}; size: {1}: services: {2};\n\tpod: {3}".format(
            self.name, self.size, self.services, self.pod
        )


class CBVct:

    def __init__(self):
        self.name = None
        self.storage_class = "gp2"
        self.size = "0"
        self.size_type = "Gi"

    def __str__(self):
        return "name: {0}; storage_class: {1}; size: {2}{3}".format(self.name,
                                                                    self.storage_class,
                                                                    self.size,
                                                                    self.size_type)