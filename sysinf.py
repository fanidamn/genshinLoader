import sys, inspect, time, os, re, subprocess, string, win32service
from random import choice
from ctypes import *

w_char = string.ascii_letters
w_digits = string.digits

script = os.path.abspath(os.path.dirname(__file__))
print(script)
proc_name = "genshinimpact.exe"
upload_path = os.path.join(script, "upload.dat")
dll_path = "null"
start_time, end_time = 0, 0

struct = "%d.%m.%y %H:%M:%S"
Architecture = (sys.maxsize > 2 ** 32 and 64) or 32

def alloc(pid, dll_path):
    l = windll.kernel32.OpenProcess(983040 | 1048576 | 4095, False, pid)
    a = windll.kernel32.VirtualAllocEx(l, 0, len(dll_path), 4096 | 8192, 4)
    w = windll.kernel32.WriteProcessMemory(l, a, dll_path, len(dll_path), byref(c_int(0)))
    c = windll.kernel32.CreateRemoteThread(l, None, 0, windll.kernel32.GetProcAddress(windll.kernel32.GetModuleHandleA('kernel32.dll'), 'LoadLibraryA'), a, 0, byref(c_ulong(0)))
    print("Successfully loaded!")

def retrieve_name(var):
    callers_local_vars = inspect.currentframe().f_back.f_locals.items()
    return [var_name for var_name, var_val in callers_local_vars if var_val is var]

def isAdmin():
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        is_admin = windll.shell32.IsUserAnAdmin() != 0
    return is_admin

def giveError(err):
    sysbit = f"[{time.strftime(struct)}] 32bit cannot use a process injection!"
    dllErr = f"[{time.strftime(struct)}] Dll path error, please check and rerun injector!"
    notfound = f"[{time.strftime(struct)}] GenshinImpact.exe process not found!"
    notadmin = f"[{time.strftime(struct)}] A injector will be run as admin."
    dllRuntimeError = f"[{time.strftime(struct)}] A dll path isn't loaded, try again later or contact with admin @crryx."

    errs = { sysbit, dllErr, notfound, notadmin, dllRuntimeError }
    for i in errs:
        if err == retrieve_name(i)[0]:
            print(i)
            sys.exit(0)

if Architecture == 32:
    giveError("sysbit")

if not isAdmin():
    giveError("notadmin")

def thread(location):
    try:
        promptCommand = subprocess.check_output('tasklist /fo csv /fi "imagename eq genshinimpact.exe"', shell=True, universal_newlines=True)
        if "genshinimpact.exe" in promptCommand.lower():
            print("Wait AntiCheat service was closed. [manually bypass]")
            while True:
                dm = subprocess.check_output('sc.exe queryex mhyprot2', shell=True, universal_newlines=True)
                print(dm)
                if "mhyprot2" in str(dm):
                    time.sleep(2)
                else:
                    print("AntiCheat successfully closed.")
                    break
            pidMatched = re.findall(r'(\d+)', promptCommand.lower())[0]
            pid = int(pidMatched)
            print('pID was founded!')
            if location == "null":
                giveError("dllRuntimeError")
            print("Injection started...")
            alloc(int(pid), str(location))
        else:
            giveError("notfound")

    except Exception as E:
        print(E)
        giveError("notfound")

def write(d):
    with open(upload_path, "w") as q:
        n = ''.join([choice(w_char + w_digits) for i in range(8)])
        os.rename(os.path.join(script, d), os.path.join(script, f"{n}.dll"))
        dll_path = os.path.join(script, f"{n}.dll")
        q.write(f"{n}.dll")
        q.flush()
        q.close()
        thread(dll_path)

with open(upload_path, "r") as q:
    d = q.read()
    write(d)
    q.close()
