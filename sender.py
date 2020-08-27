from tkinter import *
from tkinter import messagebox
from tkinter.font import Font
import tkinter as tk
from firebase import firebase
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

firebase = firebase.FirebaseApplication('https://sec-pag.firebaseio.com/',None)

HEIGHT = 411
WIDTH = 600

root = tk.Tk()

root.title("Secure Pager Sender")

canvas = tk.Canvas(root, height=HEIGHT, width=WIDTH)
canvas.pack()

msg = StringVar()
encryptedmessage = StringVar()

background_image = tk.PhotoImage(file='sender.png')
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

def encrypt(raw, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw)
    global iv
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))

frameMessage = tk.Frame(root, bg='#95c9a3')
frameMessage.place(relx=0.5, rely=0.1, relwidth=0.85, relheight=0.58, anchor='n')

myfont = Font(family="Game Over",size=75)
entryMessage = tk.Text(frameMessage, font=myfont, bg='#95c9a3', bd=0, highlightthickness=0)
entryMessage.place(relwidth=1, relheight=1)

warning = tk.PhotoImage(file='warning.png')

frameWarning = tk.Frame(root, bg='#444444')
frameWarning.place(relx=0.15, rely=0.755, relwidth=0.1, relheight=0.18, anchor='n')

btnWarning = tk.Button(frameWarning, image=warning, bg='#444444', bd=0, highlightthickness=0, activebackground='#444444', command=secure)
btnWarning.place(relx=0, relheight=1, relwidth=1)

s="Message Sent Succesfully!"

def sendMsg():
    message = entryMessage.get("1.0","end-1c")
    encryptedmessage = str(encrypt(message,password))
    enc = encryptedmessage[2 : len(encryptedmessage)-1]
    if(message != s and message != ""):
        firebase.put('/conversation/','/message/',{"dispatch":enc})
        entryMessage.delete("1.0",END)
        entryMessage.insert(END,s)
    else:
        entryMessage.delete("1.0",END)

send = tk.PhotoImage(file='send.png')

frameSend = tk.Frame(root, bg='#444444')
frameSend.place(relx=0.86, rely=0.755, relwidth=0.1, relheight=0.18, anchor='n')

btnSend = tk.Button(frameSend, image=send, bg='#444444', bd=0, highlightthickness=0, activebackground='#444444', command=sendMsg)
btnSend.place(relx=0, relheight=1, relwidth=1)

root.mainloop()
