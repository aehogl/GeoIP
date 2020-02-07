import re
import os
import time
import requests
import threading
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from bs4 import BeautifulSoup as bs
import tkinter.scrolledtext as tkst
from datetime import datetime as dt


def prettify_time(time):
    time = dt.strptime(time, '%Y-%m-%dT%H:%M')
    pretty_time = dt.strftime(time, '%m/%d/%Y %I:%M %p')
    return pretty_time


def invalid_file():
    text_box.insert(tk.INSERT, f'Invalid file selected. This must be the KaseyaLogOn_AfterHours report downloaded as XML.', 'invalid')
    text_box.config(state='disabled')
    text_box.tag_config('invalid', foreground='orangered3')
    label.config(fg="orangered3", bg='Black')
    label.config(text='Invalid File')
    time.sleep(2)
    label.config(text=' ')


def post_to_textfield(location, title, tag=None):
    if tag == None:
        text_box.insert(tk.INSERT, f'{title} {location}\n') 
    else:
        text_box.insert(tk.INSERT, f'{title} {location}\n', tag)
        text_box.tag_config(tag, foreground='orangered3')


def geo_locate(ip):
    locator_site = requests.get(f'https://freegeoip.app/xml/{ip}')
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


def file_parse(event=None):
    try:
        text_box.config(state='normal')
        text_box.delete('1.0', tk.END)
        filename = filedialog.askopenfilename()
        label.config(fg="SeaGreen", bg='Black')
        label.config(text="Compiling results...")
        if 'xml' not in filename:
            invalid_file()
            return
        soup = bs(open(f'{filename}'), 'lxml')
        admin = soup.find_all('adminname')
        if len(admin) <=0:
            invalid_file()
            return
        for memb in admin:
            ip_data = memb.find_all('details')
            for i in ip_data:
                if re.match(r'(?=Logged in)', i['textbox5']):
                    times = re.match(r'\d{4}-\d{2}-\w{5}:\d{2}', i['textbox6'])
                    text_box.insert(tk.INSERT, f'Username: {memb["adminname1"]}\n')
                    text_box.insert(tk.INSERT, f'Logon Time: {prettify_time(times[0])}\n')
                    ipd = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', i['textbox5'])[0]
                    text_box.insert(tk.INSERT, f'IP Address: {ipd}\n')
                    geo_locate(ipd)
        text_box.config(state='disabled')
        label.config(text='Finished.')
        time.sleep(4)
        label.config(text='')
        return
    except:
       print('Failure')


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
label = tk.Label(frame1, text='')
label.config(fg="SeaGreen", bg='Black')
label.pack(side='top')
root.geometry('400x600')
root.title('GeoIP Tool')
root.tk.call('wm', 'iconphoto', root._w, tk.PhotoImage(file=f'{os.getcwd()}\\arrow.png'))

style = ttk.Style() 
style.configure('TButton', font=('calibri', 15, 'bold'), borderwidth='4', relief='flat') 

button = ttk.Button(frame1, text='Open Report XML', style='TButton', command=start_submit_thread)
button.pack()
text_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
text_box.insert(tk.INSERT, 'Open the downloaded XML report to see the geo-ip information.')
text_box.config(bg='gray70')
root.mainloop()

