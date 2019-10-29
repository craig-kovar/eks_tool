import subprocess
import sys
import time
import os
import json

try:
    import Tkinter as tk
except ImportError:
    import tkinter as tk


divider = "---------------------------------------------------------"
mode = "console"
scroll = None


def set_mode(myMode):
    global mode
    mode = myMode

def set_scroll(scrolltext):
    global scroll
    scroll = scrolltext

def on_error(command, retval):
    write_line("Error detected:: ")
    write_line("command: {}".format(command))
    write_line("retval: {}".format(retval))
    if mode == "console":
        sys.exit(retval)


def execute_command(command, ignore_error):
    write_line(divider)
    write_line("Executing command : {}".format(command))
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        write_line(line)
    retval = p.wait()

    if retval != 0 and ignore_error == False:
        on_error(command, retval)


def execute_command_with_status(command, ignore_error, status_command, status, attempts, wait_sec):
    write_line(divider)
    write_line("Running {}".format(command))

    execute_command(command, ignore_error)

    write_line("Checking completion status...")
    for x in range(attempts):
        write_line("Checking attempt #{}".format(x))
        p = subprocess.Popen(status_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            spaces = line.split()
            write_line("Status :: {}".format(spaces[0]))
            try:
                if spaces[0].decode('ascii') == status:
                    return 0
            except AttributeError:
                if spaces[0].decode('ascii') == status:
                    return 0

            retval = p.wait()
            time.sleep(wait_sec)

    on_error(command, retval)


def execute_command_with_return(command, ignore_error, print_output, print_command):
    results = []
    if print_command:
        write_line(divider)
        write_line("Executing command : {}".format(command))

    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        if print_output:
            write_line(line)

        try:
            line = line.decode('ascii')
        except AttributeError:
            pass

        results.append(line.strip())

    retval = p.wait()

    if retval != 0 and ignore_error == False:
        on_error(command, retval)
    else:
        return results


def parse_results(results):
    retVal = {}
    item = 0
    start = False
    jsonString = ""
    objDepth = 0
    for line in results:
        obj = line.strip()
        if obj == "{":
            start = True
            objDepth += 1
            jsonString += obj
        if (obj != "}" and obj != "}," and obj != "{") and start:
            jsonString += obj
        if obj == "}" or obj == "},":
            jsonString += obj
            objDepth -= 1
            if objDepth == 0:
                item += 1
                start = False
                if jsonString.endswith(","):
                    jsonString = jsonString[:-1]
                retVal[str(item)] = json.loads(jsonString)
                jsonString = ""

    return retVal


def prompt_input(prompt):
    if sys.version_info[0] == 2:
        return raw_input(prompt)
    elif sys.version_info[0] == 3:
        return input(prompt)


def prompt_input_default(prompt, default):
    if sys.version_info[0] == 2:
        retVal = raw_input(prompt)
    elif sys.version_info[0] == 3:
        retVal = input(prompt)

    if len(retVal.strip()) >= 1:
        return retVal
    else:
        return default


def write_line(line):
    try:
        line = line.decode('ascii')
        line = line.replace('"', '')
    except AttributeError:
        pass
    except TypeError:
        pass

    if mode == "console":
        print(str(line))
    elif scroll is not None:
        scroll.insert('end', line+"\n")
        scroll.see(tk.END)
        scroll.update()


def write_warn(line):
    try:
        line = line.decode('ascii')
        line = line.replace('"', '')
    except AttributeError:
        pass
    except TypeError:
        pass

    if mode == "console":
        print(str(line))
    elif scroll is not None:
        scroll.insert('end', "[WARN] " + line + "\n")
        scroll.see(tk.END)
        scroll.update()


def write_error(line):
    try:
        line = line.decode('ascii')
        line = line.replace('"', '')
    except AttributeError:
        pass
    except TypeError:
        pass

    if mode == "console":
        print(str(line))
    elif scroll is not None:
        scroll.insert('end', "[ERROR] " + line + "\n")
        scroll.see(tk.END)
        scroll.update()

def check_wrk_dir(config_name):
    if not os.path.exists("./work/"+config_name):
        os.makedirs("./work/"+config_name)