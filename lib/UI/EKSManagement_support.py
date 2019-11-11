#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# Support module generated by PAGE version 4.25.1
#  in conjunction with Tcl version 8.6
#    Oct 18, 2019 04:35:50 PM CDT  platform: Darwin

import sys

try:
    import Tkinter as tk
except ImportError:
    import tkinter as tk

try:
    import ttk
    py3 = False
except ImportError:
    import tkinter.ttk as ttk
    py3 = True

from lib.UI.popup import PopupWindow as dialog
from lib.UI.WrkNode import WrkNodeTop as WrkNode
import lib.cloud.ICloudUtils as cloud
import lib.utils.ekstool_utils as utils
import time


def set_Tk_var():
    global vpc_name
    vpc_name = tk.StringVar()
    global config_name
    config_name = tk.StringVar()
    global eks_name
    eks_name = tk.StringVar()


def destroy_window():
    # Function which closes the window.
    global top_level
    top_level.destroy()
    top_level = None


def set_config_name(new_name):
    global config_name
    config_name=new_name


def update_work_node_display():
    eks_config = w.cb_config.get_eks_config()
    w.Scrolledlistbox_Nodes.delete(0, 'end')
    worker_nodes = eks_config.get_work_nodes()
    for itr in worker_nodes:
        item = worker_nodes[itr]
        w.Scrolledlistbox_Nodes.insert('end',
                                       "Name: {0}; Instance: {1}; Min: {2}; Max: {3}; Desired: {4}; Disk: {5}; Labels: {6}".format(
                                           item.get_name(), item.get_instance_type(), item.get_group_min(),
                                           item.get_group_max(), item.get_group_desired(),
                                           item.get_volume_size(), item.get_labels()))


def add_node():
    #print('EKSManagement_support.add_node')
    #sys.stdout.flush()
    eks_config = w.cb_config.get_eks_config()
    wrk_node = WrkNode(root, None).show()
    eks_config.add_worker_node(wrk_node)
    update_work_node_display()


def delete_node():
    #print('EKSManagement_support.delete_node')
    #sys.stdout.flush()
    eks_config = w.cb_config.get_eks_config()
    try:
        wrk_name = w.Scrolledlistbox_Nodes.get(w.Scrolledlistbox_Nodes.curselection(), w.Scrolledlistbox_Nodes.curselection())[0]
        name = wrk_name.split(";")[0].split(" ")[1]
        eks_config.del_worker_node(name)
        update_work_node_display()
    except tk.TclError:
        pass


def edit_node():
    #print('EKSManagement_support.edit_node')
    #sys.stdout.flush()
    eks_config = w.cb_config.get_eks_config()
    try:
        wrk_name = w.Scrolledlistbox_Nodes.get(w.Scrolledlistbox_Nodes.curselection(), w.Scrolledlistbox_Nodes.curselection())[0]
        name = wrk_name.split(";")[0].split(" ")[1]
        wrk_node = eks_config.get_work_node(name)
        upd_wrk_node = WrkNode(root, wrk_node).show()
        eks_config.add_worker_node(upd_wrk_node)
        update_work_node_display()
        eks_config.print_worker_nodes()
    except tk.TclError:
        pass


def build_cluster():
    #print('EKSManagement_support.build_cluster')
    #sys.stdout.flush()
    eks_config = w.cb_config.get_eks_config()
    eks_config.set_name(w.TEntry_Config.get())
    eks_config.set_vpc_name(w.TEntry_VPC.get())
    eks_config.set_eks_cluster_name(w.TEntry_EKS.get())

    #utils.write_line("Building Configuration:: str(eks_config))

    utils.write_line("Building VPC")
    cloud.build_vpc(eks_config.get_vpc_stack_name(), eks_config.get_attempts(), eks_config.get_wait_sec())

    utils.write_line("Building EKS Cluster")
    cloud.build_kube_cluster(eks_config.get_eks_cluster_name(), eks_config.get_attempts(),
                             eks_config.get_wait_sec(), eks_config.get_arn())

    utils.write_line("Connecting to Kubernetes Cluster")
    cloud.connect_to_eks_cluster(eks_config.get_eks_cluster_name())

    utils.write_line("Building Worker Nodes")

    wrk_nodes = eks_config.get_work_nodes()
    for inst in wrk_nodes:
        cloud.build_work_nodes(wrk_nodes[inst], eks_config.get_eks_cluster_name(),
                               eks_config.get_attempts(), eks_config.get_wait_sec(), eks_config.get_name())

    utils.write_line("Applying auth map")
    cloud.apply_auth_map(eks_config.get_name())

    utils.write_line("Validating Nodes are ready")
    if cloud.validate_nodes_ready(eks_config.get_attempts(), eks_config.get_wait_sec()):
        utils.write_line("Applying labels")
        for inst in wrk_nodes:
            cloud.apply_labels(wrk_nodes[inst])
    else:
        utils.write_error("Worker nodes not ready")
        utils.on_error("Worker nodes not ready")

    utils.write_line("Linking Node Groups")
    cloud.link_node_groups(w.cb_config)

    utils.write_line("Build of Kubernetes Cluster is complete")


def connect_vpc():
    print('EKSManagement_support.connect_vpc')
    sys.stdout.flush()


def delete_cluster():
    #print('EKSManagement_support.delete_cluster')
    #sys.stdout.flush()
    eks_config = w.cb_config.get_eks_config()
    eks_config.set_name(w.TEntry_Config.get())
    eks_config.set_vpc_name(w.TEntry_VPC.get())
    eks_config.set_eks_cluster_name(w.TEntry_EKS.get())

    cloud.unlink_node_groups(w.cb_config)
    time.sleep(2)

    worker_nodes = w.cb_config.get_eks_config().get_work_nodes()
    for inst in worker_nodes:
        cloud.detach_externaldns_policy(worker_nodes[inst].name)
        cloud.delete_worker_node(worker_nodes[inst].get_name(), w.cb_config.get_eks_config().get_attempts(),
                                 w.cb_config.get_eks_config().get_wait_sec())
        time.sleep(2)

    cloud.delete_eks_cluster(w.cb_config.get_eks_config().get_eks_cluster_name(), w.cb_config.get_eks_config().get_attempts(),
                             w.cb_config.get_eks_config().get_wait_sec())
    time.sleep(2)

    cloud.remove_elb(w.cb_config.get_eks_config().vpc_stack_name)

    time.sleep(2)

    cloud.delete_vpc_stack(w.cb_config.get_eks_config().get_vpc_stack_name(),
                           w.cb_config.get_eks_config().get_attempts(),
                           w.cb_config.get_eks_config().get_wait_sec())


def return_cluster(cb_config):
    #print('EKSManagement_support.return_cluster')
    #sys.stdout.flush()
    import lib.UI.MainScreen as MainScreen
    destroy_window()
    MainScreen.vp_start_gui(cb_config)


def switch_profile():
    #print('EKSManagement_support.switch_profile')
    #sys.stdout.flush()
    new_profile = dialog(root, "Enter a new profile").show()
    if len(new_profile) >= 1:
        cloud.switch_profile(new_profile)
        update_names(w)


def switch_region():
    #print('EKSManagement_support.switch_region')
    #sys.stdout.flush()
    new_region = dialog(root, "Enter a new region").show()
    if len(new_region) >= 1:
        cloud.switch_region(new_region)
        update_names(w)


def init(top, gui, *args, **kwargs):
    global w, top_level, root
    w = gui
    top_level = top
    root = top


def append_text(line):
    w.Scrolledtext_Console.insert('end', line)
    w.Scrolledtext_Console.text.see(tk.END)


def update_names(top_lvl_eks):
    if top_lvl_eks.cb_config is not None:
        top_lvl_eks.TEntry_Config.delete(0, 'end')
        top_lvl_eks.TEntry_Config.insert(0, top_lvl_eks.cb_config.eks_config.get_name())
        top_lvl_eks.TEntry_VPC.delete(0, 'end')
        top_lvl_eks.TEntry_VPC.insert(0, "VPC-{}".format(top_lvl_eks.cb_config.eks_config.get_name()))
        top_lvl_eks.TEntry_EKS.delete(0, 'end')
        top_lvl_eks.TEntry_EKS.insert(0, "CLUSTER-{}".format(top_lvl_eks.cb_config.eks_config.get_name()))
        top_lvl_eks.Label_User['text']="User: {}".format(cloud.get_user().replace("\"", ""))
        top_lvl_eks.Label_Region['text']="Region: {}".format(cloud.get_current_region())
        top_lvl_eks.Label_VPC['text']="VPC: {}".format(cloud.get_vpc())


def update_names_and_config(top_lvl_eks):
    if top_lvl_eks.cb_config is not None:
        name = top_lvl_eks.TEntry_Config.get()
        if name is not None:
            top_lvl_eks.cb_config.eks_config.set_name(name)
            top_lvl_eks.TEntry_Config.delete(0, 'end')
            top_lvl_eks.TEntry_Config.insert(0, name)
            top_lvl_eks.TEntry_VPC.delete(0, 'end')
            top_lvl_eks.TEntry_VPC.insert(0, "VPC-{}".format(name))
            top_lvl_eks.TEntry_EKS.delete(0, 'end')
            top_lvl_eks.TEntry_EKS.insert(0, "CLUSTER-{}".format(name))
            top_lvl_eks.Label_User['text']="User: {}".format(cloud.get_user().replace("\"", ""))
            top_lvl_eks.Label_Region['text']="Region: {}".format(cloud.get_current_region())
            top_lvl_eks.Label_VPC['text'] = "VPC: {}".format(cloud.get_vpc())
            top_lvl_eks.cb_config.name = name


if __name__ == '__main__':
    import lib.UI.EKSManagement as EKSManagement
    EKSManagement.vp_start_gui()




