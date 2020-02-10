import re
import os
import sys
import time
import json
import ctypes
import urllib3
import requests
import threading
import tkinter as tk
from tkinter import ttk
from pythonping import ping
from tkinter import filedialog
from datetime import datetime as dt
from bs4 import BeautifulSoup as bs
import tkinter.scrolledtext as tkst



urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def abuse_result(ip):   #Queries www.abuseiddb.com API
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
    'ipAddress': ip,
    'maxAgeInDays': '30'
    }
    headers = {
    'Accept': 'application/json',
    'Key': 'e5f391da7bcb1c68bce3bdac7c5602a311d0d59d018e2858d01ef401ba490757bae75ab999fa1d3e'
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring, verify=False)
    decodedResponse = json.loads(response.text)
    return decodedResponse['data']['totalReports']


def prettify_time(time):    #Converts time to a more readable format
    time = dt.strptime(time, '%Y-%m-%dT%H:%M')
    pretty_time = dt.strftime(time, '%m/%d/%Y %I:%M %p')
    return pretty_time


def invalid_file(): #Invalid file alert
    ctypes.windll.user32.MessageBoxW(None, "Invalid file selected. This must be the KaseyaLogOn_AfterHours report downloaded as XML.", "Invalid File", 0)
    text_box.config(state='disabled')
    text_box.tag_config('invalid', foreground='orangered3')
    label.config(fg="orangered3", bg='Black')
    label.config(text='Invalid File.')
    time.sleep(2)
    label.config(text=' ')



def post_to_textfield(location, title, tag=None):   #Posts passed data into the scrollable text field
    if tag == None:
        text_box.insert(tk.INSERT, f'{title} {location}\n') 
    else:
        text_box.insert(tk.INSERT, f'{title} {location}\n', tag)
        text_box.tag_config(tag, foreground='orangered3')


def geo_locate(ip): #Queries the freegeoip.com API 
    locator_site = requests.get(f'https://freegeoip.app/xml/{ip}', verify=False)
    soup = bs(locator_site.content, 'html.parser')
    country = soup.find('countryname')
    state = soup.find('regionname')

    if 'United States' not in country:
        post_to_textfield(country.get_text(), 'Country:', 'ip')
    else:
        post_to_textfield(country.get_text(), 'Country:')

    if 'California' not in state:
        if len(state) != 0:
            post_to_textfield(state.get_text(), 'State:', 'name')
        else:
            post_to_textfield('None Listed', 'State:', 'name')
    else:
        post_to_textfield(state.get_text(), 'State:')

    text_box.insert(tk.INSERT, f'\n')


def center(win):    #Function to center the window on the display
    """
    centers a tkinter window
    :param win: the root or Toplevel window to center
    """
    win.update_idletasks()
    width = win.winfo_width()
    frm_width = win.winfo_rootx() - win.winfo_x()
    win_width = width + 2 * frm_width
    height = win.winfo_height()
    titlebar_height = win.winfo_rooty() - win.winfo_y()
    win_height = height + titlebar_height + frm_width
    x = win.winfo_screenwidth() // 2 - win_width // 2
    y = win.winfo_screenheight() // 2 - win_height // 2
    win.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    win.deiconify()


def file_parse(event=None):
    #try:
        text_box.config(state='normal')
        text_box.delete('1.0', tk.END)
        filename = filedialog.askopenfilename()
        if 'xml' not in filename:
            invalid_file()
            return
        soup = bs(open(f'{filename}'), 'lxml')
        admin = soup.find_all('adminname')
        if len(admin) <=0:
            invalid_file()
            return
        conn_test = ping('8.8.8.8')
        if conn_test.success() == False:
            ctypes.windll.user32.MessageBoxW(None, "Unable to connect to APIs. Check internet connection and try again.", "Connection Failure", 0)
            label.config(fg="orangered3", bg='Black')
            label.config(text='Connection Failure.')
            return
        label.config(fg="SeaGreen", bg='Black')
        label.config(text="Compiling results...")
        for memb in admin:
            ip_data = memb.find_all('details')
            for i in ip_data:
                if re.match(r'(?=Logged in)', i['textbox5']):
                    times = re.match(r'\d{4}-\d{2}-\w{5}:\d{2}', i['textbox6'])
                    text_box.insert(tk.INSERT, f'Username: {memb["adminname1"]}\n')
                    text_box.insert(tk.INSERT, f'Logon Time: {prettify_time(times[0])}\n')
                    ipd = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', i['textbox5'])[0]
                    text_box.insert(tk.INSERT, f'IP Address: {ipd}\n')
                    if abuse_result(ipd) == 0:
                        text_box.insert(tk.INSERT, 'Abuse Reports(abuseipdb.com): Negative\n')
                    else:
                        text_box.insert(tk.INSERT, f'Abuse Reports: Positive ({abuse_result(ipd)} reports found on abuseipdb.com)\n')
                    geo_locate(ipd)
        text_box.config(state='disabled')
        label.config(text='Finished.')
        time.sleep(4)
        label.config(text='')
        return
    #except:
    #   print('Failure')


def start_submit_thread():
    global submit_thread
    submit_thread = threading.Thread(target=file_parse)
    submit_thread.daemon = True
    submit_thread.start()
    root.after(20, check_submit_thread)


def check_submit_thread():
    if submit_thread.is_alive():
        root.after(20, check_submit_thread)


root = tk.Tk()
frame1 = tk.Frame(
    master = root,
    bg = '#000000'
)
frame1.pack(fill='both', expand='yes')
text_box = tkst.ScrolledText(
    master = frame1,
    wrap   = tk.WORD,
    width  = 20,
    height = 30
)
label = tk.Label(frame1, text='', font='Helvetica 12 bold')
label.config(fg="SeaGreen", bg='Black')
label.pack(side='top')
root.geometry('540x600')
root.title('GeoIP Tool')
root.tk.call('wm', 'iconphoto', root._w, tk.PhotoImage(file=f'{os.getcwd()}\\arrow.png'))
style = ttk.Style() 
style.configure('TButton', font=('calibri', 15, 'bold'), borderwidth='4', relief='flat') 
button = ttk.Button(frame1, text='Open Report XML', style='TButton', command=start_submit_thread)
button.pack()
center(root)
text_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
text_box.insert(tk.INSERT, 'Open the downloaded XML report to see the geo-ip information.')
text_box.config(bg='gray85')
root.mainloop()

