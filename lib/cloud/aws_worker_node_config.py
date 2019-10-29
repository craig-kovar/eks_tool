import lib.utils.ekstool_utils as utils


class aws_worker_node_config:

    def __init__(self, name):
        self.name = name
        self.group_name = name + "-eks-nodes"
        self.group_min = 0
        self.group_max = 0
        self.group_desired = 0
        self.instance_type = "m4.4xlarge"
        self.ami = "unknown"
        self.volume_size = 20
        self.labels = {}

    def __repr__(self):
        return "name: {0}, group_name: {1}, group_size (min/max/desired): [{2},{3},{4}], instance: {5}, ami: {6}, volume size: {7}, labels: {8}".format(
            self.name, self.group_name, str(self.group_min), str(self.group_max),
            str(self.group_desired), self.instance_type, self.ami, self.volume_size, self.labels)

    def __str__(self):
        return "name: {0}, group_name: {1}, group_size (min/max/desired): [{2},{3},{4}], instance: {5}, ami: {6}, volume size: {7}, labels: {8}".format(
            self.name, self.group_name, str(self.group_min), str(self.group_max),
            str(self.group_desired), self.instance_type, self.ami, self.volume_size, self.labels)

    def get_name(self):
        return self.name

    def set_name(self, name):
        self.name = name

    def get_group_name(self):
        return self.group_name

    def set_group_name(self, group_name):
        self.group_name = group_name

    def get_group_min(self):
        return self.group_min

    def set_group_min(self, group_min):
        try:
            self.group_min = int(group_min)
        except ValueError:
            utils.write_warn("Invalid value, min not set")

    def get_group_max(self):
        return self.group_max

    def set_group_max(self, group_max):
        try:
            self.group_max = int(group_max)
        except ValueError:
            utils.write_warn("Invalid value, max not set")

    def get_group_desired(self):
        return self.group_desired

    def set_group_desired(self, group_desired):
        try:
            if (self.group_min <= int(group_desired)) and (self.group_max >= int(group_desired)):
                self.group_desired = int(group_desired)
            else:
                utils.write_warn("Desired state does not fall between min and max, desired size not set")
        except ValueError:
            utils.write_warn("Invalid value, desired size not set")

    def get_instance_type(self):
        return self.instance_type

    def set_instance_type(self, instance_type):
        self.instance_type = instance_type

    def get_ami(self):
        return self.ami

    def set_ami(self, ami):
        self.ami = ami

    def get_volume_size(self):
        return self.volume_size

    def set_volume_size(self, volume_size):
        self.volume_size = volume_size

    def add_label(self, key, value):
        self.labels[key] = value

    def get_labels(self):
        return self.labels
