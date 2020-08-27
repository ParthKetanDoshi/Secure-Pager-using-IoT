from tkinter import *
from tkinter import messagebox
from tkinter.font import Font
import tkinter as tk
import requests
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

BLOCK_SIZE = 16
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

HEIGHT = 411
WIDTH = 600

root = tk.Tk()

root.title("Secure Pager Receiver")

canvas = tk.Canvas(root, height=HEIGHT, width=WIDTH)
canvas.pack()

msg = StringVar()
encryptedmessage = StringVar()

background_image = tk.PhotoImage(file='receiver.png')
canvas.create_image(0,0,image=background_image,anchor=NW)

p="Password Set Succesfully!"

def secure():
    pas = entryMessage.get("1.0","end-1c")
    if(pas != p and pas != ""):
        global password
        password = str(pas)
        entryMessage.delete("1.0",END)
        entryMessage.insert(END,p)
    else:
        entryMessage.delete("1.0",END)

def decrypt(enc, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))

frameMessage = tk.Frame(root, bg='#58fcff')
frameMessage.place(relx=0.5, rely=0.1, relwidth=0.85, relheight=0.58, anchor='n')

myfont = Font(family="Game Over",size=75)
entryMessage = tk.Text(frameMessage, font=myfont, bg='#58fcff', bd=0, highlightthickness=0)
entryMessage.place(relwidth=1, relheight=1)

warning = tk.PhotoImage(file='warning.png')

frameWarning = tk.Frame(root, bg='#444444')
frameWarning.place(relx=0.15, rely=0.755, relwidth=0.1, relheight=0.18, anchor='n')

btnWarning = tk.Button(frameWarning, image=warning, bg='#444444', bd=0, highlightthickness=0, activebackground='#444444', command=secure)
btnWarning.place(relx=0, relheight=1, relwidth=1)

s="Message Received Succesfully!"

def receiveMsg():
    message = requests.get("https://sec-pag.firebaseio.com/conversation/message/dispatch.json").json()
    display = entryMessage.get("1.0","end-1c")
    decryptedmessage = str(decrypt(message,password))
    m = decryptedmessage[2 : len(encryptedmessage.get())-1]
    if(display == ""):
        entryMessage.delete("1.0",END)
        entryMessage.insert(END,m)
    elif(display == m):
        entryMessage.delete("1.0",END)
        entryMessage.insert(END,s)
    else:
        entryMessage.delete("1.0",END)

send = tk.PhotoImage(file='receive.png')

frameSend = tk.Frame(root, bg='#444444')
frameSend.place(relx=0.87, rely=0.755, relwidth=0.1, relheight=0.18, anchor='n')

btnSend = tk.Button(frameSend, image=send, bg='#444444', bd=0, highlightthickness=0, activebackground='#444444', command=receiveMsg)
btnSend.place(relx=0, relheight=1, relwidth=1)

root.mainloop()
