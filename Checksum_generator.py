import hashlib

try:
    import pyperclip
except:
    print("Install Pyperclip using \"pip install pyperclip\" ")
else:
    pass        

from tkinter import *
from tkinter import ttk
from tkinter import filedialog
import tkinter.messagebox as msg
from PIL import ImageTk,Image
import webbrowser

def copmd5():
    pyperclip.copy(md5.get())
def copblk2():
    pyperclip.copy(blake2.get())
def copsha256():
    pyperclip.copy(sha256.get())
def copsha512():
    pyperclip.copy(sha512.get())    

def browsefile_checker():
    cfilename.set(filedialog.askopenfilename(title="Select a File",filetypes=(("Text Files","*.txt"),)))
    ttk.Label(l3,text="filename: ",background="black",foreground="green").grid(row=2,column=2)
    ttk.Label(l3,textvariabl=cfilename,background="black",foreground="green").grid(row=2,column=3,sticky='W',columnspan=3)

def browsefile():
    filename.set(filedialog.askopenfilename(title="Select a File",filetypes=(("Text Files","*.txt"),)))
    ttk.Label(l1,text="filename: ",background="black",foreground="green").grid(row=2,column=2)
    ttk.Label(l1,textvariable=filename,background="black",foreground="green").grid(row=2,column=3,sticky='W',columnspan=3)

def check2():
    if(cfilename.get()==""):
        msg.showerror("Status","Select a File!!")
    else:
        if(hashprovided.get()==""):
            msg.showerror("Status","Enter Hash Provided!!")
        else:
            file=open(cfilename.get(),"r")
            message=file.read().encode()
            file.close()
            if(hashalgo.get()=="md5"):
                hashgen.set(hashlib.md5(message).hexdigest())
            elif(hashalgo.get()=="sha256"):
                hashgen.set(hashlib.sha256(message).hexdigest())
            elif(hashalgo.get()=="sha512"):
                hashgen.set(hashlib.sha512(message).hexdigest()) 
            elif(hashalgo.get()=="blake2"):
                hashgen.set(hashlib.blake2s(message).hexdigest())     
            ttk.Label(l3,text="Hash Generated: ",background="black",foreground="green").grid(row=8,column=2)  
            ttk.Label(l3,textvariable=hashgen,background="black",foreground="green").grid(row=8,column=3)
            if(hashprovided.get()==hashgen.get()):
                hash_matched_unmatched.set("Hash Matched")
                l.configure(fg="green")
            else:  
                hash_matched_unmatched.set("Hash Does Not Matches")
                l.configure(fg="red")
            
         


def gen2():
    if(filename.get()==""):
        msg.showerror("Status","Select a File!!")
    else:
        file=open(filename.get())
        message=file.read().encode()
        file.close()
        md5.set(hashlib.md5(message).hexdigest())
        sha256.set(hashlib.sha256(message).hexdigest())
        sha512.set(hashlib.sha512(message).hexdigest())
        blake2.set(hashlib.blake2s(message).hexdigest())
        
def about():
    global r4
    r4=Toplevel(root)
    r4.title("About this")
    r4.resizable(False,False)
    r4.iconbitmap("icon.ico")
    mf4=ttk.Frame(r4,padding='3 3 12 12')
    mf4.pack(fill="both",expand="yes")
    mf4.rowconfigure(0,weight=1)
    mf4.columnconfigure(0,weight=1)
    l=ttk.Label(mf4,background="black")
    l.pack(fill="both",expand="yes")
    ttk.Label(l,text="Created By: Hrithik Raj",foreground="green",background="black",font=("Arial Black",16)).grid(row=2,column=0,columnspan=2)
    img=ImageTk.PhotoImage(Image.open("icon.ico"))
    imglbl=ttk.Label(l,background="#004080",image=img)
    imglbl.photo=img
    imglbl.grid(row=4,column=0,rowspan=3)
    ttk.Label(l,text="Checksum Checker and Generator",foreground="green",background="black",font=("Calibri",16)).grid(row=4,column=1)
    ttk.Label(l,text="Version : v1.0.0",foreground="green",background="black",font=("Calibri",16)).grid(row=5,column=1)
    ttk.Separator(l,orient="horizontal").grid(row=6,column=0,columnspan=3,sticky="ew")
    ttk.Label(l,text="Email : hrithikraj137@gmail.com",foreground="green",background="black",font=("Calibri",14)).grid(row=7,column=1)
    glbl=ttk.Label(l,text="Github : https://github.com/Cyborg117",foreground="green",background="black",font=("Calibri",14),cursor="hand1")
    glbl.grid(row=9,column=1)
    glbl.bind('<1>',lambda e: webbrowser.open("https://github.com/Cyborg117"))
    for child in l.winfo_children():
        child.grid_configure(pady=10)

def checker():
    global r3,mf3,l,l3
    r3=Toplevel(root)
    r3.title("Checker")
    r3.resizable(False,False)
    r3.iconbitmap("icon.ico")
    mf3=ttk.Frame(r3,padding='3 3 12 12')
    mf3.grid(row=0,column=0,sticky=('N E W S'))
    mf3.rowconfigure(0,weight=1)
    mf3.columnconfigure(0,weight=1)

    hashprovided.set("")
    hash_matched_unmatched.set("")

    l3=ttk.Label(mf3,background="black")
    l3.pack(fill="both",expand="yes")

    Button(l3,text="Browse",background="black",foreground="green",command=browsefile_checker).grid(row=4,column=2,columnspan=3)
    ttk.Label(l3,text="Hash Provided: ",background="black",foreground="green").grid(row=6,column=2)
    ttk.Entry(l3,textvariable=hashprovided,width=30).grid(row=6,column=3)
    l=Label(l3, textvariable=hash_matched_unmatched,bg="black",fg="green", font=("calibri", 11))
    l.grid(row=14,column=3)
    ttk.Label(l3,text="Algorithm: ",background="black",foreground="green").grid(row=10,column=2)
    algo=ttk.Combobox(l3,textvariable=hashalgo,background="black",foreground="black")
    algo.grid(row=10,column=3)
    algo['values']=('md5','sha256','sha512','blake2')
    algo.configure(state='readonly')
    Button(l3,text="Check",background="black",foreground="green",command=check2).grid(row=12,column=2)

    for child in l3.winfo_children():
        child.grid_configure(padx=10,pady=10)
    
def generator():
    global r2,mf2,l1
    r2=Toplevel(root)
    r2.title("Generator")
    r2.resizable(False,False)
    r2.iconbitmap("icon.ico")
    mf2=ttk.Frame(r2,padding='3 3 12 12')
    mf2.grid(row=0,column=0,sticky=('N E W S'))
    mf2.rowconfigure(0,weight=1)
    mf2.columnconfigure(0,weight=1)

    md5.set("")
    sha256.set("")
    sha512.set("")
    blake2.set("")
    
    l1=ttk.Label(mf2,background="black")
    l1.pack(fill="both",expand="yes")

    Button(l1,text="Browse",background="black",foreground="green",command=browsefile).grid(row=4,column=4,columnspan=3)
    Button(l1,text="Generate",background="black",foreground="green",command=gen2).grid(row=6,column=2)
    ttk.Label(l1,text="MD5: ",background="black",foreground="green").grid(row=8,column=2)
    ttk.Label(l1,text="BLAKE2: ",background="black",foreground="green").grid(row=9,column=2)
    ttk.Label(l1,text="SHA256: ",background="black",foreground="green").grid(row=10,column=2)
    ttk.Label(l1,text="SHA512",background="black",foreground="green").grid(row=11,column=2)
    ttk.Label(l1,textvariable=md5,background="black",foreground="green").grid(row=8,column=3,sticky='W')
    ttk.Label(l1,textvariable=blake2,background="black",foreground="green").grid(row=9,column=3,sticky='W')
    ttk.Label(l1,textvariable=sha256,background="black",foreground="green").grid(row=10,column=3,sticky='W')
    ttk.Label(l1,textvariable=sha512,background="black",foreground="green").grid(row=11,column=3,columnspan=3)
    Button(l1,text="copy",background="black",foreground="green",command=copmd5).grid(row=8,column=4)
    Button(l1,text="copy",background="black",foreground="green",command=copblk2).grid(row=9,column=4)
    Button(l1,text="copy",background="black",foreground="green",command=copsha256).grid(row=10,column=4)
    Button(l1,text="copy",background="black",foreground="green",command=copsha512).grid(row=11,column=6)
    for child in l1.winfo_children():
        child.grid_configure(padx=10,pady=10)
   
root=Tk()
root.title("Checksum generator")
root.resizable(False,False)
root.iconbitmap("icon.ico")
mainframe = ttk.Frame(root, padding="3 3 12 12")
mainframe.grid(column=0, row=0, sticky=('N, W, E, S'))
mainframe.columnconfigure(0, weight=1)
mainframe.rowconfigure(0, weight=1)

l1=ttk.Label(mainframe,background="black")
l1.pack(fill="both",expand="yes")

filename=StringVar()
cfilename=StringVar()
md5=StringVar()
sha256=StringVar()
sha512=StringVar()
blake2=StringVar()
hashprovided=StringVar()
hashalgo=StringVar()
hashgen=StringVar()
hash_matched_unmatched=StringVar()

hashalgo.set("md5")
hash_matched_unmatched.set("")

ttk.Label(l1,text="Checksum Checker or Generator",width=30,background="black",foreground="green",font=("Arial Bold",13)).grid(row=2,column=2)
Button(l1,text="Checker",background="black",foreground="green",command=checker).grid(row=10,column=2,ipadx=10,ipady=5)
Button(l1,text="Generator",background="black",foreground="green",command=generator).grid(row=14,column=2,ipadx=10,ipady=5)
Button(l1,text="About",background="black",foreground="green",command=about).grid(row=18,column=2,ipadx=10,ipady=5)


for child in l1.winfo_children():
    child.grid_configure(padx=10,pady=10)

root.mainloop()
