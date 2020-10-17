import tkinter
from tkinter import Frame, Tk, Button, filedialog, END, SE
from pythonping import ping
import requests
import time
from zeroconf import ServiceBrowser, Zeroconf
import os
import re


class MyListener:

    names_list = []

    @staticmethod
    def remove_service(zeroconf, taio_cruz, name):
        print("Service %s removed" % (name,))

    def add_service(self, zeroconf, taio_cruz, name):
        info = zeroconf.get_service_info(taio_cruz, name)
        if name[:9] == Dict.select_cam:
            self.names_list.append(name)

    def update_service(self, zeroconf, taio_cruz, name):
        pass


class Application(Frame):
    choose_file = None
    UI_Check = False

    @staticmethod
    def callback(selection):
        Dict.select_cam = selection

    def create_widgets(self):  # make buttons and text boxes
        if not Application.UI_Check:
            self.QUIT = Button(height=2, width=10)  # exit program
            self.QUIT["text"] = "QUIT"
            self.QUIT["fg"] = "red"
            self.QUIT["command"] = self.quit

            self.QUIT.place(relx=1, rely=1, x=-5, y=-5, anchor=SE)

            self.file_select = Button(height=1, width=10)  # choose firmware file to upload, file type restrictions possibly?
            self.file_select["text"] = "Select File"
            self.file_select["command"] = lambda: Dict.choose_file(Dict)

            self.file_select.place(relx=0, rely=0, x=30, y=20)

            self.upload_file = Button(height=1, width=10)  # take file send to address
            self.upload_file["text"] = "Upload"
            self.upload_file["command"] = lambda: Dict.scan_net(Dict)

            self.upload_file.place(relx=0, rely=0, x=30, y=50)

            Application.T1 = tkinter.Text(root, height=1, width=115)  # file path readout
            Application.T1.place(relx=0, rely=0, x=125, y=22)
            Application.T2 = tkinter.Text(root, height=1, width=60)  # firmware update progression readout
            Application.T2.place(relx=0, rely=0, x=125, y=52)
            Application.T2.insert(tkinter.END, "")
            self.cam_list = tkinter.StringVar()
            self.cam_list.set(None)
            Application.S1 = tkinter.OptionMenu(root, self.cam_list, "24M8.29IP", "28M2.16IP", command=self.callback)
            Application.S1.place(relx=0, rely=0, x=30, y=80)

            self.UI_Check = True

    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.create_widgets()


class Dict:

    s = requests.Session()
    mac_ip_dict = {}
    select_cam = None
    mac_check = []
    names = []
    PARSE_MAC = r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})"

    def get_file(self, ip_addr):  # (ip_addr: STR, log_file_path: RAW)
        log_file_path = r'C:\Users\cjohnson\desktop\debug.txt'
        command = "arp.exe -a " + ip_addr + " > " + log_file_path
        os.system('cmd /c' + command)
        mac = self.parse_file(log_file_path, self.PARSE_MAC)
        self.mac_ip_dict[ip_addr] = mac

    @staticmethod
    def parse_file(log_file_path, REGEX):
        with open(log_file_path, "r") as file:
            for line in file:
                for match in re.finditer(REGEX, line, re.S):
                    macaddress = match.group()
                    mac = (macaddress.replace('-', "").replace(':',"")).upper()
                    return mac

    def scan_net(self):

        Application.T2.delete(1.0, tkinter.END)
        Application.T2.insert(tkinter.END, "Scanning zeroconf devices...")
        zeroconf = Zeroconf()
        listener = MyListener()
        browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
        time.sleep(5)

        Application.T2.delete(1.0, tkinter.END)
        Application.T2.insert(tkinter.END, "Retrieving IP addresses")
        for octet in range(2, 10):  # future: add IP range min-max to UI, scan across that range
            ADDR = "192.168.0." + str(octet)
            self.get_file(self, ADDR)

        self.cross_ref(self)

    def cross_ref(self):
        print("referencing zeroconf list")
        for value in MyListener.names_list:
            new_val = value[10:22]
            print(new_val)
            self.names.append(new_val)

        MyListener.names_list = []

        for key, addr in self.mac_ip_dict.items():
            if addr in self.names:
                print(key)
                self.mac_check.append(key)
        self.mac_ip_dict = {}
        self.names = []
        print(self.mac_ip_dict)
        for IPaddr in self.mac_check:
            self.address(self, IPaddr)
        self.mac_check = []

    def pingtest(self):  # Sees if camera is on or not by pinging it repeatedly, I don't like this.
        for address in Dict.mac_check:
            res = ping(address, timeout=1, count=1, verbose=False)

            res_str = str(res)
            x = len('Reply from ' + address)

            if (res_str[:x] == 'Reply from ' + address):
                res_str = str(ping(address, verbose=False))
                return True
            else:
                return False

    def login(self):
        # encoded password
        API_KEY = "n6teCDYVftNBwOG8hE5G1q4JdWI+af0/4nvXXutnU7EhPiAwvh/YxyplQajU5mkJipGzFTPfN2AGhCS3dZVxUg=="

        # data to be sent to the login screen
        data1 = {
            'app': 'set',
            'method': 'login',
            'hidden_pwd': API_KEY,
            'user': "admin",
            'login_dt': '2020-08-27',
            'login_tm': '11%3A00%3A01',
        }

        # send request to URL with parameters/form data
        r1 = self.s.post(url=self.API_ENDPOINT1, data=data1)
        self.T2.delete(1.0, tkinter.END)
        self.T2.insert(tkinter.END, "Login Successful")

    def applySettings(self):  # sends firmware file as text in request
        files = {'fimage': (
            'FTN-H1_v1.1.1.140.img.encrypt', open(self.file_path_string, 'rb'), 'application/octet-stream',
            {'Expires': '0'})}

        r2 = self.s.post(url=self.API_ENDPOINT2, files=files)
        self.T2.delete(1.0, tkinter.END)
        self.T2.insert(tkinter.END, "Update Successful. Do not power off camera.")

    def choose_file(self):
        root = tkinter.Toplevel()
        root.withdraw()

        app.T2.delete(1.0, tkinter.END)
        app.T2.insert(tkinter.END, "Selecting File")
        file_path = filedialog.askopenfilename()

        self.file_path_string = str(file_path)
        if (self.file_path_string):
            Application.T1.delete(1.0, tkinter.END)
            Application.T1.insert(tkinter.END,
                           self.file_path_string)  # future: print only file name and not entire path to UI, check for changes in text box
            Application.T2.delete(1.0, tkinter.END)
            Application.T2.insert(tkinter.END, "File Selected")

    def address(self, address):  # assign API endpoints to address, and call them
        cam_total = 0

        Application.T2.delete(1.0, tkinter.END)
        Application.T2.insert(tkinter.END, "Assigning endpoints")
        self.API_ENDPOINT1 = 'http://' + address + '/'
        self.API_ENDPOINT2 = 'http://' + address + '/setup/system/update.php'
        Application.T2.delete(1.0, tkinter.END)
        Application.T2.insert(tkinter.END, "Endpoints assigned, logging in")
        self.login(self)
        Application.T2.delete(1.0, tkinter.END)
        Application.T2.insert(tkinter.END, "Applying Update")
        self.applySettings(self)


if __name__ == '__main__':
    root = Tk(className=' IP Camera Firmware Uploader Tool')
    root.geometry("1200x200")
    app = Application(master=root)
    app.mainloop()
    root.destroy()
