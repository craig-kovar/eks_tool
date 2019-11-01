#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# GUI module generated by PAGE version 4.25.1
#  in conjunction with Tcl version 8.6
#    Oct 18, 2019 04:34:38 PM CDT  platform: Darwin

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

import lib.UI.EKSManagement_support as EKSManagement_support
import lib.utils.ekstool_utils as utils

def vp_start_gui(cb_config):
    '''Starting point when module is the main routine.'''
    global val, w, root
    root = tk.Tk()
    EKSManagement_support.set_Tk_var()
    top = ToplevelEKS (root, cb_config)
    EKSManagement_support.init(root, top)
    root.mainloop()

w = None
def create_ToplevelEKS(root, *args, **kwargs):
    '''Starting point when module is imported by another program.'''
    global w, w_win, rt
    rt = root
    w = tk.Toplevel (root)
    EKSManagement_support.set_Tk_var()
    top = ToplevelEKS (w)
    EKSManagement_support.init(w, top, *args, **kwargs)
    return (w, top)

def destroy_ToplevelEKS():
    global w
    w.destroy()
    w = None

class ToplevelEKS:
    def __init__(self, top=None, cb_config=None):
        self.cb_config = cb_config

        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''
        _bgcolor = '#d9d9d9'  # X11 color: 'gray85'
        _fgcolor = '#000000'  # X11 color: 'black'
        _compcolor = '#d9d9d9' # X11 color: 'gray85'
        _ana1color = '#d9d9d9' # X11 color: 'gray85'
        _ana2color = '#ececec' # Closest X11 color: 'gray92'
        self.style = ttk.Style()
        if sys.platform == "win32":
            self.style.theme_use('winnative')
        self.style.configure('.',background=_bgcolor)
        self.style.configure('.',foreground=_fgcolor)
        self.style.configure('.',font="TkDefaultFont")
        self.style.map('.',background=
            [('selected', _compcolor), ('active',_ana2color)])

        top.geometry("969x791+-1523+216")
        top.title("EKS Management Console")
        top.configure(background="#d9d9d9")
        top.configure(highlightbackground="#d9d9d9")
        top.configure(highlightcolor="black")

        self.Labelframe_Console = tk.LabelFrame(top)
        self.Labelframe_Console.place(relx=0.01, rely=0.632, relheight=0.36
                , relwidth=0.98)
        self.Labelframe_Console.configure(relief='groove')
        self.Labelframe_Console.configure(foreground="black")
        self.Labelframe_Console.configure(text='''Command Output''')
        self.Labelframe_Console.configure(background="#ffffff")
        self.Labelframe_Console.configure(highlightbackground="#d9d9d9")
        self.Labelframe_Console.configure(highlightcolor="black")

        self.Scrolledtext_Console = ScrolledText(self.Labelframe_Console)
        self.Scrolledtext_Console.place(relx=0.011, rely=0.07, relheight=0.898, relwidth = 0.977, bordermode = 'ignore')
        self.Scrolledtext_Console.configure(background="white")
        self.Scrolledtext_Console.configure(font="TkTextFont")
        self.Scrolledtext_Console.configure(foreground="black")
        self.Scrolledtext_Console.configure(highlightbackground="#d9d9d9")
        self.Scrolledtext_Console.configure(highlightcolor="black")
        self.Scrolledtext_Console.configure(insertbackground="black")
        self.Scrolledtext_Console.configure(insertborderwidth="3")
        self.Scrolledtext_Console.configure(selectbackground="#c4c4c4")
        self.Scrolledtext_Console.configure(selectforeground="black")
        self.Scrolledtext_Console.configure(wrap="none")

        self.TSeparator1 = ttk.Separator(top)
        self.TSeparator1.place(relx=0.0, rely=0.126, relwidth=1.001)

        self.Label_User = tk.Label(top)
        self.Label_User.place(relx=0.021, rely=0.013, height=22, width=481)
        self.Label_User.configure(activebackground="#f9f9f9")
        self.Label_User.configure(activeforeground="black")
        self.Label_User.configure(anchor='w')
        self.Label_User.configure(background="#d9d9d9")
        self.Label_User.configure(foreground="#000000")
        self.Label_User.configure(highlightbackground="#d9d9d9")
        self.Label_User.configure(highlightcolor="black")
        self.Label_User.configure(text='''User:''')

        self.Label_Region = tk.Label(top)
        self.Label_Region.place(relx=0.021, rely=0.038, height=22, width=481)
        self.Label_Region.configure(activebackground="#f9f9f9")
        self.Label_Region.configure(activeforeground="black")
        self.Label_Region.configure(anchor='w')
        self.Label_Region.configure(background="#d9d9d9")
        self.Label_Region.configure(foreground="#000000")
        self.Label_Region.configure(highlightbackground="#d9d9d9")
        self.Label_Region.configure(highlightcolor="black")
        self.Label_Region.configure(text='''Region:''')

        self.Label_VPC = tk.Label(top)
        self.Label_VPC.place(relx=0.021, rely=0.063, height=22, width=481)
        self.Label_VPC.configure(activebackground="#f9f9f9")
        self.Label_VPC.configure(activeforeground="black")
        self.Label_VPC.configure(anchor='w')
        self.Label_VPC.configure(background="#d9d9d9")
        self.Label_VPC.configure(foreground="#000000")
        self.Label_VPC.configure(highlightbackground="#d9d9d9")
        self.Label_VPC.configure(highlightcolor="black")
        self.Label_VPC.configure(text='''VPC:''')

        self.TButton_Profile = ttk.Button(top)
        self.TButton_Profile.place(relx=0.795, rely=0.013, height=24, width=137)
        self.TButton_Profile.configure(command=EKSManagement_support.switch_profile)
        self.TButton_Profile.configure(takefocus="")
        self.TButton_Profile.configure(text='''Switch Profile''')

        self.TButton_Region = ttk.Button(top)
        self.TButton_Region.place(relx=0.795, rely=0.051, height=24, width=137)
        self.TButton_Region.configure(command=EKSManagement_support.switch_region)
        self.TButton_Region.configure(text='''Switch Region''')

        self.Label_VPC_Name = tk.Label(top)
        self.Label_VPC_Name.place(relx=0.021, rely=0.202, height=22, width=111)
        self.Label_VPC_Name.configure(activebackground="#f9f9f9")
        self.Label_VPC_Name.configure(activeforeground="black")
        self.Label_VPC_Name.configure(anchor='w')
        self.Label_VPC_Name.configure(background="#d9d9d9")
        self.Label_VPC_Name.configure(foreground="#000000")
        self.Label_VPC_Name.configure(highlightbackground="#d9d9d9")
        self.Label_VPC_Name.configure(highlightcolor="black")
        self.Label_VPC_Name.configure(text='''VPC Name:''')

        self.TEntry_VPC = ttk.Entry(top)
        self.TEntry_VPC.place(relx=0.144, rely=0.202, relheight=0.033
                , relwidth=0.341)
        self.TEntry_VPC.configure(textvariable=EKSManagement_support.vpc_name)
        self.TEntry_VPC.configure(takefocus="")
        self.TEntry_VPC.configure(cursor="ibeam")

        self.Label_Config_Name = tk.Label(top)
        self.Label_Config_Name.place(relx=0.021, rely=0.152, height=22
                , width=111)
        self.Label_Config_Name.configure(activebackground="#f9f9f9")
        self.Label_Config_Name.configure(activeforeground="black")
        self.Label_Config_Name.configure(anchor='w')
        self.Label_Config_Name.configure(background="#d9d9d9")
        self.Label_Config_Name.configure(foreground="#000000")
        self.Label_Config_Name.configure(highlightbackground="#d9d9d9")
        self.Label_Config_Name.configure(highlightcolor="black")
        self.Label_Config_Name.configure(text='''Config Name:''')

        self.TButton_Connect_VPC = ttk.Button(top)
        self.TButton_Connect_VPC.place(relx=0.795, rely=0.088, height=24
                , width=137)
        self.TButton_Connect_VPC.configure(command=EKSManagement_support.connect_vpc)
        self.TButton_Connect_VPC.configure(text='''Connect to VPC''')

        self.Label_EKS_Name = tk.Label(top)
        self.Label_EKS_Name.place(relx=0.021, rely=0.253, height=22, width=111)
        self.Label_EKS_Name.configure(activebackground="#f9f9f9")
        self.Label_EKS_Name.configure(activeforeground="black")
        self.Label_EKS_Name.configure(anchor='w')
        self.Label_EKS_Name.configure(background="#d9d9d9")
        self.Label_EKS_Name.configure(foreground="#000000")
        self.Label_EKS_Name.configure(highlightbackground="#d9d9d9")
        self.Label_EKS_Name.configure(highlightcolor="black")
        self.Label_EKS_Name.configure(text='''EKS Name:''')

        self.TEntry_EKS = ttk.Entry(top)
        self.TEntry_EKS.place(relx=0.144, rely=0.253, relheight=0.033
                , relwidth=0.341)
        self.TEntry_EKS.configure(textvariable=EKSManagement_support.eks_name)
        self.TEntry_EKS.configure(takefocus="")
        self.TEntry_EKS.configure(cursor="ibeam")

        self.Labelframe_Wrk_Nodes = tk.LabelFrame(top)
        self.Labelframe_Wrk_Nodes.place(relx=0.021, rely=0.303, relheight=0.247
                , relwidth=0.774)
        self.Labelframe_Wrk_Nodes.configure(relief='groove')
        self.Labelframe_Wrk_Nodes.configure(foreground="black")
        self.Labelframe_Wrk_Nodes.configure(text='''Worker Nodes''')
        self.Labelframe_Wrk_Nodes.configure(background="#d9d9d9")
        self.Labelframe_Wrk_Nodes.configure(highlightbackground="#d9d9d9")
        self.Labelframe_Wrk_Nodes.configure(highlightcolor="black")

        self.Scrolledlistbox_Nodes = ScrolledListBox(self.Labelframe_Wrk_Nodes)
        self.Scrolledlistbox_Nodes.place(relx=0.013, rely=0.103, relheight=0.841
                , relwidth=0.976, bordermode='ignore')
        self.Scrolledlistbox_Nodes.configure(background="white")
        self.Scrolledlistbox_Nodes.configure(font="TkFixedFont")
        self.Scrolledlistbox_Nodes.configure(foreground="black")
        self.Scrolledlistbox_Nodes.configure(highlightbackground="#d9d9d9")
        self.Scrolledlistbox_Nodes.configure(highlightcolor="#d9d9d9")
        self.Scrolledlistbox_Nodes.configure(selectbackground="#c4c4c4")
        self.Scrolledlistbox_Nodes.configure(selectforeground="black")
        worker_nodes = self.cb_config.get_eks_config().get_work_nodes()
        for itr in worker_nodes:
            item = worker_nodes[itr]
            if item is not None:
                self.Scrolledlistbox_Nodes.insert('end',
                                           "Name: {0}; Instance: {1}; Min: {2}; Max: {3}; Desired: {4}; Disk: {5}; Labels: {6}".format(
                                               item.get_name(), item.get_instance_type(), item.get_group_min(),
                                               item.get_group_max(), item.get_group_desired(),
                                               item.get_volume_size(), item.get_labels()))


        self.TButton_Add_Node = ttk.Button(top)
        self.TButton_Add_Node.place(relx=0.805, rely=0.341, height=24, width=177)

        self.TButton_Add_Node.configure(command=EKSManagement_support.add_node)
        self.TButton_Add_Node.configure(takefocus="")
        self.TButton_Add_Node.configure(text='''Add Worker Nodes''')

        self.TButton_Edit_Node = ttk.Button(top)
        self.TButton_Edit_Node.place(relx=0.805, rely=0.379, height=24
                , width=177)
        self.TButton_Edit_Node.configure(command=EKSManagement_support.edit_node)
        self.TButton_Edit_Node.configure(takefocus="")
        self.TButton_Edit_Node.configure(text='''Edit Worker Nodes''')

        self.TButton_Delete_Node = ttk.Button(top)
        self.TButton_Delete_Node.place(relx=0.805, rely=0.417, height=24
                , width=177)
        self.TButton_Delete_Node.configure(command=EKSManagement_support.delete_node)
        self.TButton_Delete_Node.configure(takefocus="")
        self.TButton_Delete_Node.configure(text='''Delete Worker Nodes''')

        self.TButton_Build = ttk.Button(top)
        self.TButton_Build.place(relx=0.495, rely=0.569, height=34, width=127)
        self.TButton_Build.configure(command=EKSManagement_support.build_cluster)
        self.TButton_Build.configure(takefocus="")
        self.TButton_Build.configure(text='''Build Cluster''')

        self.TButton_Delete = ttk.Button(top)
        self.TButton_Delete.place(relx=0.65, rely=0.569, height=34, width=127)
        self.TButton_Delete.configure(command=EKSManagement_support.delete_cluster)
        self.TButton_Delete.configure(takefocus="")
        self.TButton_Delete.configure(text='''Delete Cluster''')

        self.TButton_Return = ttk.Button(top)
        self.TButton_Return.place(relx=0.805, rely=0.569, height=34, width=167)
        self.TButton_Return.configure(command=lambda: EKSManagement_support.return_cluster(cb_config))
        self.TButton_Return.configure(takefocus="")
        self.TButton_Return.configure(text='''Return to Main Menu''')

        self.TEntry_Config = ttk.Entry(top)
        self.TEntry_Config.place(relx=0.144, rely=0.152, relheight=0.033
                , relwidth=0.341)
        self.TEntry_Config.configure(textvariable=EKSManagement_support.config_name)
        #self.TEntry_Config.configure(validate="focusout")
        #self.TEntry_Config.configure(validatecommand=lambda: update_names_and_config(self))
        self.TEntry_Config.bind("<FocusOut>", lambda e: EKSManagement_support.update_names_and_config(self))
        self.TEntry_Config.configure(takefocus="")
        self.TEntry_Config.configure(cursor="ibeam")

        utils.set_scroll(self.Scrolledtext_Console)
        EKSManagement_support.update_names(self)


# The following code is added to facilitate the Scrolled widgets you specified.
class AutoScroll(object):
    '''Configure the scrollbars for a widget.'''

    def __init__(self, master):
        #  Rozen. Added the try-except clauses so that this class
        #  could be used for scrolled entry widget for which vertical
        #  scrolling is not supported. 5/7/14.
        try:
            vsb = ttk.Scrollbar(master, orient='vertical', command=self.yview)
        except:
            pass
        hsb = ttk.Scrollbar(master, orient='horizontal', command=self.xview)

        #self.configure(yscrollcommand=_autoscroll(vsb),
        #    xscrollcommand=_autoscroll(hsb))
        try:
            self.configure(yscrollcommand=self._autoscroll(vsb))
        except:
            pass
        self.configure(xscrollcommand=self._autoscroll(hsb))

        self.grid(column=0, row=0, sticky='nsew')
        try:
            vsb.grid(column=1, row=0, sticky='ns')
        except:
            pass
        hsb.grid(column=0, row=1, sticky='ew')

        master.grid_columnconfigure(0, weight=1)
        master.grid_rowconfigure(0, weight=1)

        # Copy geometry methods of master  (taken from ScrolledText.py)
        if py3:
            methods = tk.Pack.__dict__.keys() | tk.Grid.__dict__.keys() \
                  | tk.Place.__dict__.keys()
        else:
            methods = tk.Pack.__dict__.keys() + tk.Grid.__dict__.keys() \
                  + tk.Place.__dict__.keys()

        for meth in methods:
            if meth[0] != '_' and meth not in ('config', 'configure'):
                setattr(self, meth, getattr(master, meth))

    @staticmethod
    def _autoscroll(sbar):
        '''Hide and show scrollbar as needed.'''
        def wrapped(first, last):
            first, last = float(first), float(last)
            if first <= 0 and last >= 1:
                sbar.grid_remove()
            else:
                sbar.grid()
            sbar.set(first, last)
        return wrapped

    def __str__(self):
        return str(self.master)

def _create_container(func):
    '''Creates a ttk Frame with a given master, and use this new frame to
    place the scrollbars and the widget.'''
    def wrapped(cls, master, **kw):
        container = ttk.Frame(master)
        container.bind('<Enter>', lambda e: _bound_to_mousewheel(e, container))
        container.bind('<Leave>', lambda e: _unbound_to_mousewheel(e, container))
        return func(cls, container, **kw)
    return wrapped

class ScrolledText(AutoScroll, tk.Text):
    '''A standard Tkinter Text widget with scrollbars that will
    automatically show/hide as needed.'''
    @_create_container
    def __init__(self, master, **kw):
        tk.Text.__init__(self, master, **kw)
        AutoScroll.__init__(self, master)

class ScrolledListBox(AutoScroll, tk.Listbox):
    '''A standard Tkinter Listbox widget with scrollbars that will
    automatically show/hide as needed.'''
    @_create_container
    def __init__(self, master, **kw):
        tk.Listbox.__init__(self, master, **kw)
        AutoScroll.__init__(self, master)
    def size_(self):
        sz = tk.Listbox.size(self)
        return sz

import platform
def _bound_to_mousewheel(event, widget):
    child = widget.winfo_children()[0]
    if platform.system() == 'Windows' or platform.system() == 'Darwin':
        child.bind_all('<MouseWheel>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Shift-MouseWheel>', lambda e: _on_shiftmouse(e, child))
    else:
        child.bind_all('<Button-4>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Button-5>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Shift-Button-4>', lambda e: _on_shiftmouse(e, child))
        child.bind_all('<Shift-Button-5>', lambda e: _on_shiftmouse(e, child))

def _unbound_to_mousewheel(event, widget):
    if platform.system() == 'Windows' or platform.system() == 'Darwin':
        widget.unbind_all('<MouseWheel>')
        widget.unbind_all('<Shift-MouseWheel>')
    else:
        widget.unbind_all('<Button-4>')
        widget.unbind_all('<Button-5>')
        widget.unbind_all('<Shift-Button-4>')
        widget.unbind_all('<Shift-Button-5>')

def _on_mousewheel(event, widget):
    if platform.system() == 'Windows':
        widget.yview_scroll(-1*int(event.delta/120),'units')
    elif platform.system() == 'Darwin':
        widget.yview_scroll(-1*int(event.delta),'units')
    else:
        if event.num == 4:
            widget.yview_scroll(-1, 'units')
        elif event.num == 5:
            widget.yview_scroll(1, 'units')

def _on_shiftmouse(event, widget):
    if platform.system() == 'Windows':
        widget.xview_scroll(-1*int(event.delta/120), 'units')
    elif platform.system() == 'Darwin':
        widget.xview_scroll(-1*int(event.delta), 'units')
    else:
        if event.num == 4:
            widget.xview_scroll(-1, 'units')
        elif event.num == 5:
            widget.xview_scroll(1, 'units')

if __name__ == '__main__':
    vp_start_gui()





