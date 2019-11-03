from lib.configurations.EKSConfiguration import EKSConfiguration
from lib.configurations.CBClusterConfig import CBClusterConfig

class CBConfig:

    def __init__(self, name):
        self.name = name
        self.eks_config = EKSConfiguration(name)
        self.cbcluster_config = CBClusterConfig(name)

    def __str__(self):
        divider = "------------------------------------------\n"
        return divider + str(self.eks_config) + "<--------------->\n " + str(self.cbcluster_config) + divider

    def get_eks_config(self):
        return self.eks_config

    def get_cbcluster_config(self):
        return self.cbcluster_config
