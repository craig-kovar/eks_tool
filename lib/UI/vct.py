#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# GUI module generated by PAGE version 4.25.1
#  in conjunction with Tcl version 8.6
#    Nov 01, 2019 11:33:58 AM CDT  platform: Darwin

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

from lib.configurations.CBClusterConfig import CBVct

class Toplevel_VCT:
    def __init__(self, master, cbcluster_config, storage_class, vct):
        self.master = master
        top = self.top = tk.Toplevel(master)

        self.cbcluster_config = cbcluster_config
        self.storage_class = storage_class

        if vct is None:
            self.vct = CBVct()
            self.disable_name = False
        else:
            self.vct = vct
            self.disable_name = True

        self.sizetype = ['Ki', 'Mi', 'Gi']
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

        top.geometry("312x265+-1379+301")
        top.title("Volume Claim Template")
        top.configure(background="#d9d9d9")

        self.Label_Name = tk.Label(top)
        self.Label_Name.place(relx=0.064, rely=0.113, height=22, width=81)
        self.Label_Name.configure(anchor='w')
        self.Label_Name.configure(background="#d9d9d9")
        self.Label_Name.configure(foreground="#000000")
        self.Label_Name.configure(text='''Name''')

        self.TEntry_Name = ttk.Entry(top)
        self.TEntry_Name.place(relx=0.288, rely=0.094, relheight=0.098
                , relwidth=0.609)
        self.TEntry_Name.configure(takefocus="")
        self.TEntry_Name.configure(cursor="ibeam")
        self.TEntry_Name.insert(0, str(self.vct.name))
        if self.disable_name:
            self.TEntry_Name['state'] = 'disabled'

        self.Label_Storage_Class = tk.Label(top)
        self.Label_Storage_Class.place(relx=0.064, rely=0.264, height=22
                , width=101)
        self.Label_Storage_Class.configure(activebackground="#f9f9f9")
        self.Label_Storage_Class.configure(activeforeground="black")
        self.Label_Storage_Class.configure(anchor='w')
        self.Label_Storage_Class.configure(background="#d9d9d9")
        self.Label_Storage_Class.configure(foreground="#000000")
        self.Label_Storage_Class.configure(highlightbackground="#d9d9d9")
        self.Label_Storage_Class.configure(highlightcolor="black")
        self.Label_Storage_Class.configure(text='''Storage Class''')

        self.sc_cbox = tk.StringVar()
        self.sc_cbox.set(self.vct.storage_class)
        self.TCombobox_SC = ttk.Combobox(top)
        self.TCombobox_SC.place(relx=0.417, rely=0.245, relheight=0.102
                , relwidth=0.468)
        self.TCombobox_SC.configure(textvariable=self.sc_cbox)
        self.TCombobox_SC.configure(takefocus="")
        self.TCombobox_SC.configure(values=self.storage_class)
        #self.TCombobox_SC.current(0)

        #self.menubar = tk.Menu(top,font="TkMenuFont",bg=_bgcolor,fg=_fgcolor)
        #top.configure(menu = self.menubar)

        self.Label_Size = tk.Label(top)
        self.Label_Size.place(relx=0.064, rely=0.415, height=22, width=41)
        self.Label_Size.configure(activebackground="#f9f9f9")
        self.Label_Size.configure(activeforeground="black")
        self.Label_Size.configure(anchor='w')
        self.Label_Size.configure(background="#d9d9d9")
        self.Label_Size.configure(foreground="#000000")
        self.Label_Size.configure(highlightbackground="#d9d9d9")
        self.Label_Size.configure(highlightcolor="black")
        self.Label_Size.configure(text='''Size''')

        self.TEntry_Size = ttk.Entry(top)
        self.TEntry_Size.place(relx=0.192, rely=0.415, relheight=0.098
                , relwidth=0.256)
        self.TEntry_Size.configure(takefocus="")
        self.TEntry_Size.configure(cursor="ibeam")
        self.TEntry_Size.insert(0, self.vct.size)

        self.size_cbox = tk.StringVar()
        self.size_cbox.set(self.vct.size_type)
        self.TCombobox_SizeType = ttk.Combobox(top)
        self.TCombobox_SizeType.place(relx=0.513, rely=0.415, relheight=0.102
                , relwidth=0.308)
        self.TCombobox_SizeType.configure(textvariable=self.size_cbox)
        self.TCombobox_SizeType.configure(takefocus="")
        self.TCombobox_SizeType.configure(values=self.sizetype)
        #self.size_cbox.set("Gi")

        self.TButton_OK = ttk.Button(top)
        self.TButton_OK.place(relx=0.353, rely=0.717, height=24, width=87)
        self.TButton_OK.configure(command=lambda: self.on_ok())
        self.TButton_OK.configure(takefocus="")
        self.TButton_OK.configure(text='''OK''')

        self.TButton_Cancel = ttk.Button(top)
        self.TButton_Cancel.place(relx=0.673, rely=0.717, height=24, width=87)
        self.TButton_Cancel.configure(command=lambda: self.on_cancel())
        self.TButton_Cancel.configure(takefocus="")
        self.TButton_Cancel.configure(text='''Cancel''')

    def cleanup(self):
        self.top.destroy()

    def show(self):
        self.top.wait_window()
        #return self.server

    def on_ok(self):
        self.vct.name = self.TEntry_Name.get()
        self.vct.storage_class = self.sc_cbox.get()
        self.vct.size = self.TEntry_Size.get()
        self.vct.size_type = self.size_cbox.get()

        self.cbcluster_config.vct[self.vct.name] = self.vct
        self.cleanup()

    def on_cancel(self):
        self.cleanup()

