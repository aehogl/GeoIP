import re
import requests
from bs4 import BeautifulSoup as bs
import tkinter as tk
from tkinter import filedialog
import tkinter.scrolledtext as tkst

def geo_locate(ip):
    locator_site = requests.get(f'https://freegeoip.app/xml/{ip}')
    zoup = bs(locator_site.content, 'html.parser')
    country = zoup.find('countryname')
    state = zoup.find('regionname')

    if 'United States' not in country:
        editArea.insert(tk.INSERT, f'Country: {country.gettext()}\n', 'ip')
        editArea.tag_config('ip', foreground='red')
    else:
        editArea.insert(tk.INSERT, f'Country: {country.get_text()}\n') 

    if 'California' not in state:
        editArea.insert(tk.INSERT, f'State: {state.get_text()}\n', 'state')
        editArea.tag_config('state', foreground='red')
    else:
        editArea.insert(tk.INSERT, f'State: {state.get_text()}\n')

    editArea.insert(tk.INSERT, f'\n')

def UploadAction(event=None):
    try:
        editArea.delete('1.0', tk.END)
        filename = filedialog.askopenfilename()
        if 'xml' not in filename:
            editArea.insert(tk.INSERT, f'Invalid file selected. This must be the KaseyaLogOn_AfterHours report downloaded as XML.', 'invalid')
            editArea.tag_config('invalid', foreground='red')
            return
        soup = bs(open(f'{filename}'), 'lxml')
        admin = soup.find_all('adminname')
        if len(admin) <=0:
            editArea.insert(tk.INSERT, f'Invalid file selected. This must be the KaseyaLogOn_AfterHours report downloaded as XML.', 'invalid')
            editArea.tag_config('invalid', foreground='red')
            return
        for memb in admin:
            ip_data = memb.find_all('details')
            editArea.insert(tk.INSERT, f'Username: {memb["adminname1"]}\n')
            for i in ip_data:
                if re.match(r'(?=Logged in)', i['textbox5']):
                    ipd = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', i['textbox5'])[0]
                    editArea.insert(tk.INSERT, f'IP Address: {ipd}\n')
                    geo_locate(ipd)
        return
    except:
        print('Failure')


root = tk.Tk()
frame1 = tk.Frame(
    master = root,
    bg = '#000000'
)
frame1.pack(fill='both', expand='yes')
editArea = tkst.ScrolledText(
    master = frame1,
    wrap   = tk.WORD,
    width  = 20,
    height = 30
)
root.geometry('400x400')
root.title('Geo IP Tool')
button = tk.Button(frame1, text='Open Report XML', command=UploadAction)
button.pack()
editArea.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
editArea.insert(tk.INSERT, 'Open the downloaded XML report to see the geo-ip information.')
root.mainloop()