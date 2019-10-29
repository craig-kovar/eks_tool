

class CBClusterConfig:

    def __init__(self, name):
        self.namespace = "testns"
        self.clustername = name
        self.version = "6.0.1"
        self.antiaffinity = False
        self.disable_bucket_management = False
        self.expose_admin_console = False
        self.expose_admin_svcs = {}
        self.expose_features = {}
        self.dns = "se-couchbasedemos.com"
        self.cluster = {'dataServiceMemoryQuota': "256", 'indexServiceMemoryQuota': "256",
                        'searchServiceMemoryQuota': "256", 'eventingServiceMemoryQuota': "256",
                        'analyticsServiceMemoryQuota': "1024", 'indexStorageSetting': "plasma",
                        'autoFailoverTimeout': "30", "autoFailoverMaxCount": "1",
                        'autoFailoverOnDataDiskIssues': 'true', 'autoFailoverOnDataDiskIssuesTimePeriod': "120",
                        'autoFailoverServerGroup': "false"}
        self.buckets = {}
        self.servers = {'test': CBClusterServer()}
        self.vct = {}


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


class CBClusterBucket:

    def __init__(self):
        self.name = None
        self.type = "couchbase"
        self.memoryQuota = "1024"
        self.replicas = "1"
        self.ioPriority = "low"
        self.evictionPolicy = "value-eviction"
        self.conflictResolution = "seqno"
        self.enableFlush = "true"
        self.enableIndexReplica = "false"
        self.compressionMode = "passive"

    def __str__(self):
        ret_str = "name: {0} -> type: {1}; quota: {2}; replicas: {3}; ioPriority: {4}; evictionPolicy: {5}; conflictResolution: {6}; enableFlush: {7}".format(
            self.name, self.type, self.memoryQuota, self.replicas, self.ioPriority, self.evictionPolicy, self.conflictResolution, self.enableFlush
        )
        return ret_str

class CBClusterPod:

    def __init__(self):
        self.limits = {}
        self.requests = {}
        self.nodeselector = {}
        self.volume_mount = {
            'default' : None,
            'data': None,
            'index': None,
            'analytics': []
        }

    def __str__(self):
        return "limits: {0}; requests: {1}; node_selector: {2}; volume_mounts: {3}".format(
            self.limits, self.requests, self.nodeselector, self.volume_mount
        )

class CBClusterServer:

    def __init__(self):
        self.name = None
        self.size = "1"
        self.services = {
            'data': "disabled",
            'index': "disabled",
            'query': "disabled",
            'search': "disabled",
            'eventing': "disabled",
            'analytics': "disabled"
        }
        self.pod = CBClusterPod()

    def __str__(self):
        return "name: {0}; size: {1}: services: {2};\n\tpod: {3}".format(
            self.name, self.size, self.services, self.pod
        )
