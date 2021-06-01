import hashlib
from tkinter import *
from tkinter import ttk
from tkinter import filedialog
import tkinter.messagebox as msg
from PIL import ImageTk,Image
import webbrowser
try:
    import pyperclip
except:
    msg.showerror("Status","pyperclip not installed \ninstall using \"pip install pyperclip\" ")
    quit()
else:
    pass        

class algorithms():     # All algorithms encapsulated in a class for simple usage
    fname=""
    def __init__(self,fname1):
        self.fname=fname1
    
    def md5algo(self):
        md5val=hashlib.md5()
        with open(self.fname,'rb') as file:
            while True:
                message=file.read(BUF_SIZE)       #Get data in 64Kb Chunks to avoid Load on Memory
                if not message:
                    break
                md5val.update(message)            #Update the value of checksum with every chunk
        return md5val.hexdigest()    
    
    def sha256algo(self):
        sha256val=hashlib.sha256()
        with open(self.fname,'rb') as file:
            while True:
                message=file.read(BUF_SIZE)
                if not message:
                    break
                sha256val.update(message) 
        return sha256val.hexdigest()  

    def sha512algo(self):
        sha512val=hashlib.sha512()
        with open(self.fname,'rb') as file:
            while True:
                message=file.read(BUF_SIZE)
                if not message:
                    break
                sha512val.update(message) 
        return sha512val.hexdigest()     

    def blake2algo(self):
        blake2val=hashlib.blake2s()
        with open(self.fname,'rb') as file:
            while True:
                message=file.read(BUF_SIZE)
                if not message:
                    break
                blake2val.update(message) 
        return blake2val.hexdigest()
    
    def sha224algo(self):
        sha224val=hashlib.sha224()
        with open(self.fname,'rb') as file:
            while True:
                message=file.read(BUF_SIZE)
                if not message:
                    break
                sha224val.update(message) 
        return sha224val.hexdigest()

    def sha384algo(self):
        sha384val=hashlib.sha384()
        with open(self.fname,'rb') as file:
            while True:
                message=file.read(BUF_SIZE)
                if not message:
                    break
                sha384val.update(message) 
        return sha384val.hexdigest()  

    def sha3_224algo(self):
        sha3_224val=hashlib.sha3_224()
        with open(self.fname,'rb') as file:
            while True:
                message=file.read(BUF_SIZE)
                if not message:
                    break
                sha3_224val.update(message) 
        return sha3_224val.hexdigest()   

    def sha3_256algo(self):
        sha3_256val=hashlib.sha3_256()
        with open(self.fname,'rb') as file:
            while True:
                message=file.read(BUF_SIZE)
                if not message:
                    break
                sha3_256val.update(message) 
        return sha3_256val.hexdigest()

    def sha3_512algo(self):
        sha3_512val=hashlib.sha3_512()
        with open(self.fname,'rb') as file:
            while True:
                message=file.read(BUF_SIZE)
                if not message:
                    break
                sha3_512val.update(message) 
        return sha3_512val.hexdigest()

    def sha3_384algo(self):
        sha3_384val=hashlib.sha3_384()
        with open(self.fname,'rb') as file:
            while True:
                message=file.read(BUF_SIZE)
                if not message:
                    break
                sha3_384val.update(message) 
        return sha3_384val.hexdigest()                                          


def copmd5():
    pyperclip.copy(md5.get())
def copblk2():
    pyperclip.copy(blake2.get())
def copsha256():
    pyperclip.copy(sha256.get())
def copsha512():
    pyperclip.copy(sha512.get())
def copsha224():
    pyperclip.copy(sha224.get())
def copsha384():
    pyperclip.copy(sha384.get())
def copsha3_224():
    pyperclip.copy(sha3_224.get())
def copsha3_256():
    pyperclip.copy(sha3_256.get())
def copsha3_384():
    pyperclip.copy(sha3_384.get())
def copsha3_512():
    pyperclip.copy(sha3_512.get())            

def browsefile_checker():
    cfilename.set(filedialog.askopenfilename(title="Select a File",filetypes=(("All Files","*.*"),)))
    ttk.Label(l3,text="filename: ",background="black",foreground="green").grid(row=2,column=2)
    ttk.Label(l3,textvariabl=cfilename,background="black",foreground="green").grid(row=2,column=3,sticky='W',columnspan=3)

def browsefile():
    filename.set(filedialog.askopenfilename(title="Select a File",filetypes=(("All Files","*.*"),)))
    ttk.Label(l1,text="filename: ",background="black",foreground="green").grid(row=2,column=2)
    ttk.Label(l1,textvariable=filename,background="black",foreground="green").grid(row=2,column=3,sticky='W',columnspan=3)

def check2():
    if(cfilename.get()==""):
        msg.showerror("Status","Select a File!!")
    else:
        if(hashprovided.get()==""):
            msg.showerror("Status","Enter Hash Provided!!")
        else:
            algoinst=algorithms(cfilename.get())
            if(hashalgo.get()=="md5"):
                hashgen.set(algoinst.md5algo())
            elif(hashalgo.get()=="sha256"):
                hashgen.set(algoinst.sha256algo())
            elif(hashalgo.get()=="sha512"):
                hashgen.set(algoinst.sha512algo()) 
            elif(hashalgo.get()=="blake2"):
                hashgen.set(algoinst.blake2algo()) 
            elif(hashalgo.get()=="sha224"):
                hashgen.set(algoinst.sha224algo())
            elif(hashalgo.get()=="sha384"):
                hashgen.set(algoinst.sha384algo()) 
            elif(hashalgo.get()=="sha3_224"):
                hashgen.set(algoinst.sha3_224algo())
            elif(hashalgo.get()=="sha3_256"):
                hashgen.set(algoinst.sha3_256algo())
            elif(hashalgo.get()=="sha3_384"):
                hashgen.set(algoinst.sha3_384algo()) 
            elif(hashalgo.get()=="sha3_512"):
                hashgen.set(algoinst.sha3_512algo())            
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
        algoinst=algorithms(filename.get())
        md5.set(algoinst.md5algo())
        sha256.set(algoinst.sha256algo())
        sha512.set(algoinst.sha512algo())
        blake2.set(algoinst.blake2algo())
        sha224.set(algoinst.sha224algo())
        sha384.set(algoinst.sha384algo())
        sha3_224.set(algoinst.sha3_224algo())
        sha3_256.set(algoinst.sha3_256algo())
        sha3_384.set(algoinst.sha3_384algo())
        sha3_512.set(algoinst.sha3_512algo())
        
def features():
    global r4
    r5=Toplevel(root)
    r5.title("What's New")
    r5.resizable(False,False)
    r5.iconbitmap("icon.ico")
    mf5=ttk.Frame(r5,padding='3 3 12 12')
    mf5.pack(fill="both",expand="yes")
    mf5.rowconfigure(0,weight=1)
    mf5.columnconfigure(0,weight=1)
    l=ttk.Label(mf5,background="black")
    l.pack(fill="both",expand="yes")
    ttk.Label(l,text="v1.0.0",foreground="green",background="black",font=("Arial black",16)).grid(row=2,column=0)
    ttk.Separator(l,orient="horizontal").grid(row=3,column=0,columnspan=5,sticky="ew")
    ttk.Label(l,text="1. Compare or Generate Checksum",foreground="green",background="black",font=("Calibri",16)).grid(row=5,column=0)
    ttk.Label(l,text="2. Support all Text files (*.txt) ",foreground="green",background="black",font=("Calibri",16)).grid(row=6,column=0)
    ttk.Label(l,text="3. Hashing Algorithms: Md5, SHA256, SHA512, Blake2s",foreground="green",background="black",font=("Calibri",16)).grid(row=7,column=0)

    ttk.Label(l,text="v2.0.0",foreground="green",background="black",font=("Arial black",16)).grid(row=9,column=0)
    ttk.Separator(l,orient="horizontal").grid(row=10,column=0,columnspan=5,sticky="ew")
    ttk.Label(l,text="1. Compare or Generate Checksum",foreground="green",background="black",font=("Calibri",16)).grid(row=12,column=0)
    ttk.Label(l,text="2. Support all File Types (*.*) ",foreground="green",background="black",font=("Calibri",16)).grid(row=13,column=0)
    ttk.Label(l,text="\n   3. Added a Mechanism To read binary data for very Big files ",foreground="green",background="black",font=("Calibri",16)).grid(row=14,column=0)
    ttk.Label(l,text=" in 64Kb Chunks So as to not Overload the Memory ",foreground="green",background="black",font=("Calibri",16)).grid(row=15,column=0)
    ttk.Label(l,text="\n4. Hashing ALgorithms: Md5, SHA256, SHA512, Blake2s ",foreground="green",background="black",font=("Calibri",16)).grid(row=17,column=0)
    ttk.Label(l,text="                             SHA224, SHA384, SHA3_224, SHA3_256 ",foreground="green",background="black",font=("Calibri",16)).grid(row=18,column=0)
    ttk.Label(l,text="                        SHA3_384, SHA3_512 ",foreground="green",background="black",font=("Calibri",16)).grid(row=19,column=0)
    

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
    ttk.Label(l,text="Version : v2.0.0",foreground="green",background="black",font=("Calibri",16)).grid(row=5,column=1)
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

    cfilename.set("")
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
    algo['values']=('md5','sha224','sha256','sha384','sha512','blake2','sha3_224','sha3_256','sha3_384','sha3_512')
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
    sha224.set("")
    sha384.set("")
    sha3_224.set("")
    sha3_256.set("")
    sha3_384.set("")
    sha3_512.set("")
    filename.set("")
    
    l1=ttk.Label(mf2,background="black")
    l1.pack(fill="both",expand="yes")

    Button(l1,text="Browse",background="black",foreground="green",command=browsefile).grid(row=4,column=4,columnspan=3)
    Button(l1,text="Generate",background="black",foreground="green",command=gen2).grid(row=6,column=2)
    ttk.Label(l1,text="MD5: ",background="black",foreground="green").grid(row=8,column=2)
    ttk.Label(l1,text="BLAKE2: ",background="black",foreground="green").grid(row=9,column=2)
    ttk.Label(l1,text="SHA256: ",background="black",foreground="green").grid(row=10,column=2)
    ttk.Label(l1,text="SHA512",background="black",foreground="green").grid(row=11,column=2)
    ttk.Label(l1,text="SHA224: ",background="black",foreground="green").grid(row=12,column=2)
    ttk.Label(l1,text="SHA384: ",background="black",foreground="green").grid(row=13,column=2)
    ttk.Label(l1,text="SHA3_224: ",background="black",foreground="green").grid(row=14,column=2)
    ttk.Label(l1,text="SHA3_256",background="black",foreground="green").grid(row=15,column=2)
    ttk.Label(l1,text="SHA3_384: ",background="black",foreground="green").grid(row=16,column=2)
    ttk.Label(l1,text="SHA3_512",background="black",foreground="green").grid(row=17,column=2)

    ttk.Label(l1,textvariable=md5,background="black",foreground="green").grid(row=8,column=3,sticky='W')
    ttk.Label(l1,textvariable=blake2,background="black",foreground="green").grid(row=9,column=3,sticky='W')
    ttk.Label(l1,textvariable=sha256,background="black",foreground="green").grid(row=10,column=3,sticky='W')
    ttk.Label(l1,textvariable=sha512,background="black",foreground="green").grid(row=11,column=3,columnspan=3)
    ttk.Label(l1,textvariable=sha224,background="black",foreground="green").grid(row=12,column=3,sticky='W')
    ttk.Label(l1,textvariable=sha384,background="black",foreground="green").grid(row=13,column=3,sticky='W')
    ttk.Label(l1,textvariable=sha3_224,background="black",foreground="green").grid(row=14,column=3,sticky='W')
    ttk.Label(l1,textvariable=sha3_256,background="black",foreground="green").grid(row=15,column=3)
    ttk.Label(l1,textvariable=sha3_384,background="black",foreground="green").grid(row=16,column=3,sticky='W')
    ttk.Label(l1,textvariable=sha3_512,background="black",foreground="green").grid(row=17,column=3,columnspan=3)

    Button(l1,text="copy",background="black",foreground="green",command=copmd5).grid(row=8,column=4)
    Button(l1,text="copy",background="black",foreground="green",command=copblk2).grid(row=9,column=4)
    Button(l1,text="copy",background="black",foreground="green",command=copsha256).grid(row=10,column=4)
    Button(l1,text="copy",background="black",foreground="green",command=copsha512).grid(row=11,column=6)
    Button(l1,text="copy",background="black",foreground="green",command=copsha224).grid(row=12,column=4)
    Button(l1,text="copy",background="black",foreground="green",command=copsha384).grid(row=13,column=4)
    Button(l1,text="copy",background="black",foreground="green",command=copsha3_224).grid(row=14,column=4)
    Button(l1,text="copy",background="black",foreground="green",command=copsha3_256).grid(row=15,column=4)
    Button(l1,text="copy",background="black",foreground="green",command=copsha3_384).grid(row=16,column=4)
    Button(l1,text="copy",background="black",foreground="green",command=copsha3_512).grid(row=17,column=6)
    for child in l1.winfo_children():
        child.grid_configure(padx=10,pady=10)
   
root=Tk()
root.title("Checksum-Util v2.0.0")
root.resizable(False,False)
root.iconbitmap("icon.ico")
mainframe = ttk.Frame(root, padding="3 3 12 12")
mainframe.grid(column=0, row=0, sticky=('N, W, E, S'))
mainframe.columnconfigure(0, weight=1)
mainframe.rowconfigure(0, weight=1)

l1=ttk.Label(mainframe,background="black")
l1.pack(fill="both",expand="yes")

BUF_SIZE=65536            #Buffer Size = 64Kb for very big files
filename=StringVar()
cfilename=StringVar()
md5=StringVar()
sha256=StringVar()
sha512=StringVar()
blake2=StringVar()
sha224=StringVar()
sha384=StringVar()
sha3_224=StringVar()
sha3_256=StringVar()
sha3_384=StringVar()
sha3_512=StringVar()
hashprovided=StringVar()
hashalgo=StringVar()
hashgen=StringVar()
hash_matched_unmatched=StringVar()

hashalgo.set("md5")
hash_matched_unmatched.set("")

ttk.Label(l1,text="Checksum Checker and Generator",width=30,background="black",foreground="green",font=("Arial Bold",13)).grid(row=2,column=1,columnspan=5,sticky='e')
Button(l1,text="Checker",background="black",foreground="green",command=checker).grid(row=10,column=2,ipadx=10,ipady=5)
Button(l1,text="Generator",background="black",foreground="green",command=generator).grid(row=14,column=2,ipadx=10,ipady=5)
Button(l1,text="About",background="black",foreground="green",command=about).grid(row=18,column=1,ipadx=10,ipady=5)
Button(l1,text="What's New",background="black",foreground="green",command=features).grid(row=18,column=3,ipadx=5,ipady=5)


for child in l1.winfo_children():
    child.grid_configure(pady=10)

root.mainloop()
