#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# GUI module generated by PAGE version 4.25.1
#  in conjunction with Tcl version 8.6
#    Oct 18, 2019 08:33:50 AM CDT  platform: Darwin

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

import lib.UI.MainScreen_support
#from functools import partial

def vp_start_gui(cb_config):
    '''Starting point when module is the main routine.'''
    global val, w, root
    root = tk.Tk()
    top = Toplevel1 (root, cb_config)
    lib.UI.MainScreen_support.init(root, top)
    try:
        root.mainloop()
    except UnicodeDecodeError:
        pass

w = None
def create_Toplevel1(root, *args, **kwargs):
    '''Starting point when module is imported by another program.'''
    global w, w_win, rt
    rt = root
    w = tk.Toplevel (root)
    top = Toplevel1 (w)
    lib.UI.MainScreen_support.init(w, top, *args, **kwargs)
    return (w, top)

def destroy_Toplevel1():
    global w
    w.destroy()
    w = None

class Toplevel1:
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

        top.geometry("941x634+-1477+320")
        top.title("Couchbase EKS Manager")
        top.configure(background="#d9d9d9")
        top.configure(highlightbackground="#d9d9d9")
        top.configure(highlightcolor="black")

        self.Labelframe1 = tk.LabelFrame(top)
        self.Labelframe1.place(relx=0.17, rely=0.095, relheight=0.797
                , relwidth=0.648)
        self.Labelframe1.configure(relief='groove')
        self.Labelframe1.configure(foreground="black")
        self.Labelframe1.configure(text='''Management Options''')
        self.Labelframe1.configure(background="#d9d9d9")
        self.Labelframe1.configure(highlightbackground="#d9d9d9")
        self.Labelframe1.configure(highlightcolor="black")

        self.TButton1 = ttk.Button(self.Labelframe1)
        self.TButton1.place(relx=0.23, rely=0.108, height=54, width=317
                , bordermode='ignore')
        #self.TButton1.configure(command=partial(lib.UI.MainScreen_support.launch_eks, eks_config))
        self.TButton1.configure(command=lambda: lib.UI.MainScreen_support.launch_eks(self.cb_config))
        self.TButton1.configure(takefocus="")
        self.TButton1.configure(text='''Manage EKS Cluster''')

        self.TButton_K8S = ttk.Button(self.Labelframe1)
        self.TButton_K8S.place(relx=0.23, rely=0.267, height=54, width=317
                , bordermode='ignore')
        self.TButton_K8S.configure(command=lambda: lib.UI.MainScreen_support.launch_kube(self.cb_config))
        self.TButton_K8S.configure(takefocus="")
        self.TButton_K8S.configure(text='''Manage K8S Cluster''')

        self.TButton_Save = ttk.Button(self.Labelframe1)
        self.TButton_Save.place(relx=0.23, rely=0.426, height=54, width=317
                                , bordermode='ignore')
        self.TButton_Save.configure(command=lambda: lib.UI.MainScreen_support.save(self.cb_config))
        self.TButton_Save.configure(takefocus="")
        self.TButton_Save.configure(text='''Save Configuration''')

        self.TButton_Load = ttk.Button(self.Labelframe1)
        self.TButton_Load.place(relx=0.23, rely=0.585, height=54, width=317
                                , bordermode='ignore')
        self.TButton_Load.configure(command=lambda: lib.UI.MainScreen_support.load(self.cb_config))
        self.TButton_Load.configure(takefocus="")
        self.TButton_Load.configure(text='''Load Configuration''')

        self.TButton_Quit = ttk.Button(self.Labelframe1)
        self.TButton_Quit.place(relx=0.23, rely=0.744, height=54, width=317
                , bordermode='ignore')
        self.TButton_Quit.configure(command=lib.UI.MainScreen_support.quit)
        self.TButton_Quit.configure(takefocus="")
        self.TButton_Quit.configure(text='''Quit''')

if __name__ == '__main__':
    vp_start_gui()





