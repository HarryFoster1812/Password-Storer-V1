############ Imports ############
from passlib.hash import pbkdf2_sha256
from cryptography.fernet import Fernet

import os
import json
from tkinter import *
from tkinter import messagebox
from tkinter import scrolledtext

############ Global variables ############

encryptedpass = []
decryptedpass = []
emails = []
usernames = []
sites = []

############ Files ############

acc_username_arry_dir = 'Account details\\accountusernames.json'
acc_password_arry_dir = 'Account details\\accountpasswords.json'
accountfiles = [acc_username_arry_dir, acc_password_arry_dir]

############ OOP BABY ############

class Encryptor():
    def gen_key(self):
        key = Fernet.generate_key()
        return key

    def write_key(self, key):
        global username
        with open(f'Data\\{username}\\my_key.key', 'wb') as myfile:
            myfile.write(key)

    def load_key(self):
        global username
        with open(f'Data\\{username}\\my_key.key', 'rb') as myfile:
            key = myfile.read()
            return key

    def encrypt(self, key, message):
        f = Fernet(key)
        encrypted = f.encrypt(bytes(message, encoding = 'utf-8'))
        return encrypted.decode('utf-8')

    def decrypt(self, key, message):
        f = Fernet(key)
        decrypted = f.decrypt(bytes(message, encoding = 'utf-8'))
        return decrypted.decode('utf-8')

encryptor = Encryptor() # Creating a global instance

############ Back end (nerd stuff) ############
def loginfunc(userusername, root, userpass):
    global userinput, account_usernames, account_passwords
    userinput = userusername
    if userusername in account_usernames:
        index = account_usernames.index(userusername)
        verifypass = account_passwords[index]
        validate(verifypass, root, userpass)

def account_signup(username1, root, password):
    global account_usernames, account_passwords, username
    if username1 in account_usernames:
        messagebox.showwarning('Invalid username','The username you have entered is already taken!')
    else:
        username = username1
        account_usernames.append(username)
        hashedpass = hashpass(password)
        account_passwords.append(hashedpass)
        write_account()
        root.destroy()
        createdir()

def uservalid():
    load()
    obtain_key()
    menu()

def createdir():
    global username, key
    newdir = f"Data\\{username}"
    os.mkdir(newdir)
    write()
    key = encryptor.gen_key()
    encryptor.write_key(key)
    uservalid()

def write():
    files = [f'Data\\{username}\\pass.json', f'Data\\{username}\\email.json', f'Data\\{username}\\username.json', f'Data\\{username}\\sites.json']
    for file in files:
        with open(file, 'w') as jsonfile:

            if file == files[0]:
                json.dump(encryptedpass, jsonfile)

            elif file == files[1]:
                 json.dump(emails, jsonfile)

            elif file == files[2]:
                json.dump(usernames, jsonfile)
            
            else:
                json.dump(sites, jsonfile)

def write_account():
    global accountfiles
    for file in accountfiles:
        with open(file, 'w') as jsonfile:
            if file == accountfiles[0]:
                json.dump(account_usernames, jsonfile)
            else:
                json.dump(account_passwords, jsonfile)

def load_account():
    global account_usernames, account_passwords
    for file in accountfiles:
        with open(file, 'r') as jsonfile:
            if file == accountfiles[0]:
                account_usernames = json.load(jsonfile)
            else:
                account_passwords = json.load(jsonfile)

def load():
    global encryptedpass, emails, usernames, sites, username
    files = [f'Data\\{username}\\pass.json', f'Data\\{username}\\email.json', f'Data\\{username}\\username.json', f'Data\\{username}\\sites.json']
    for i in range(len(files)):
        with open(files[i], 'r') as jsonfile:
            file = files[i]
            if file == files[0]:
                encryptedpass = json.load(jsonfile)

            elif file == files[1]:
                emails = json.load(jsonfile)

            elif file == files[2]:
                usernames = json.load(jsonfile)

            elif file == files[3]:
                sites = json.load(jsonfile)

def setoptionnew():
    global option
    option = 'new'

def setoptionremove():
    global option
    option = 'remove'

def setoptionedit():
    global option
    option = 'edit'

def add(info, widgets):
    global sites, usernames, emails, decryptedpass
    for i in range(len(info)):
        if i == 0:
            sites.append(info[0])
        elif i == 1:
            usernames.append(info[1])
        elif i == 2:
            emails.append(info[2])
        else:
            decryptedpass.append(info[3])

    for widget in widgets:
        widget.delete(0, 'end')
    obtain_output()

def remove(entrysite):
    try:
        if entrysite in sites:
            index = sites.index(entrysite)
            sites.remove(sites[index])
            emails.remove(emails[index])
            usernames.remove(usernames[index])
            decryptedpass.remove(decryptedpass[index])
            obtain_output()
    except Exception as e:
        messagebox.showerror('ERROR',f'Could not find item, {e}')

def change(userinput, choice):
    global sites, usernames, emails, decryptedpass, index
    usernames[index] = userinput if choice == 'Username' else usernames[index]
    decryptedpass[index] = userinput if choice == 'Password' else decryptedpass[index]
    emails[index] = userinput if choice == 'Email' else emails[index]
    sites[index] = userinput if choice == 'Site' else sites[index]
    obtain_output()
    remove_add()

def get_edit_index(site):
    global sites, index
    try:
        if site in sites:
            index = sites.index(site)
    except:
        messagebox.showerror('ERROR',"Couldn't find site")

def on_close(root):
    global key
    key = encryptor.gen_key()
    encryptor.write_key(key)
    encryptedpass.clear()
    for item in decryptedpass:
        encrypted_item = encryptor.encrypt(key, item)
        encryptedpass.append(encrypted_item)
    write()
    root.destroy()

def obtain_key():
    global key
    key = encryptor.load_key()
    for item in encryptedpass:
        decrypted_item = encryptor.decrypt(key, item)
        decryptedpass.append(decrypted_item)

def hashpass(password):
    return pbkdf2_sha256.hash(password)

def validate(user, root, userpass):
    global masterpass, userinput, username
    if pbkdf2_sha256.verify(userpass, user):
        username = userinput
        masterpass = userpass
        root.destroy()
        uservalid()
    else:
        messagebox.showwarning('Wrong password','The password you have entered is incorrect!')

############ Front end (trash) ############

def obtain_output():
    global sites, usernames, decryptedpass, emails, scroll_lbl, outputframe, outputdata
    outputdata.destroy()

    outputdata = Frame(outputframe)
    outputdata.pack()
    scroll_lbl = scrolledtext.ScrolledText(outputdata)
    data = ''
    for i in range(len(emails)):
        if i == 0:
            data = sites[i].ljust(20, ' ')+usernames[i].ljust(17, ' ')+emails[i].ljust(20, ' ')+decryptedpass[i].rjust(20, ' ')

        else:
            data = data+'\n'+sites[i].ljust(20, ' ')+usernames[i].ljust(17, ' ')+emails[i].ljust(20, ' ')+decryptedpass[i].rjust(20, ' ')
    scroll_lbl.insert(INSERT, data)
    scroll_lbl.configure(state='disabled')
    scroll_lbl.pack()

def remove_add():
    global new_entityframe, option, root, insidenewentity, editoption, editframe
    insidenewentity.destroy()
    insidenewentity = Frame(new_entityframe)
    insidenewentity.pack()

    if option == 'new':
        entity = Label(insidenewentity, text='Add Entity', font=('Courier', 18))
        site_lbl = Label(insidenewentity, text="Site: ", font=('Courier', 14))
        name_lbl = Label(insidenewentity, text='Name: ', font=('Courier', 14))
        email_lbl = Label(insidenewentity, text='Email: ', font=('Courier', 14))
        pass_lbl = Label(insidenewentity, text='Password: ', font=('Courier', 14))
        site_entry = Entry(insidenewentity, font=('Courier', 14))
        name_entry = Entry(insidenewentity, font=('Courier', 14))
        email_entry = Entry(insidenewentity, font=('Courier', 14))
        password_entry = Entry(insidenewentity, show='*', font=('Courier', 14))
        View = Button(insidenewentity, text="V", command = lambda: editentry(password_entry))
        submit_entry = Button(insidenewentity, text='Add Email', font=('Courier', 14), command = lambda: add([site_entry.get(), name_entry.get(), email_entry.get(), password_entry.get()], [site_entry, name_entry, email_entry, password_entry]))
        entity.grid(columnspan=4, row=0)

        site_lbl.grid(row=1, sticky=E, padx=3)
        name_lbl.grid(row=2, sticky=E, padx=3)
        email_lbl.grid(row=3, sticky=E, padx=3)
        pass_lbl.grid(row=4, sticky=E, padx=3)

        site_entry.grid(columnspan=3,row=1, column=1, padx=2, pady=2, sticky=W)
        name_entry.grid(columnspan=3, row=2, column=1, padx=2, pady=2, sticky=W)
        email_entry.grid(columnspan=3, row=3, column=1, padx=2, pady=2, sticky=W)
        password_entry.grid(columnspan=3, row=4, column=1, padx=2, pady=2, sticky=W)
        View.grid(row = 4 , column = 5)

        submit_entry.grid(columnspan=4, row=5,pady=6)

    elif option == 'remove':
        entity_label = Label(insidenewentity, text='Remove Entity', font=('Courier', 18)).grid(row=0,columnspan=4)
        site_label = Label(insidenewentity, text="Site: ", font=('Courier', 14)).grid(row=1, column=1)
        site = Entry(insidenewentity, font=('Courier', 14))
        site.grid(row=1, column=2)
        submit = Button(insidenewentity, text='Remove', font=('Courier', 14), command = lambda: remove(site.get())).grid(columnspan=4, row=5,pady=6)

    else:
        editoption = StringVar(insidenewentity)
        var = IntVar()
        choices = {'Site', 'Username', 'Email', 'Password'}
        Label(insidenewentity, text='Edit Entity', font=('Courier', 18)).grid(row=0,columnspan=4)

        Label(insidenewentity, text="Which site do you want to edit:", font=('Courier', 14)).grid(row=1, column=1)
        edit_site_entry = Entry(insidenewentity, font=('Courier', 14))
        edit_site_entry.grid(row=1, column=2)
        search = Button(insidenewentity, text='Search', font=('Courier', 14), command = lambda: (var.set(1), get_edit_index(edit_site_entry.get())))
        search.grid(columnspan=4, row=2,pady=4)
        search.wait_variable(var)
        searchoption = OptionMenu(insidenewentity, editoption, *choices)
        Label(insidenewentity, text="What would you like to edit:", font=('Courier', 14)).grid(row=3, columnspan=4)
        searchoption.grid(row=4, columnspan=4, pady=5)
        editframe = Frame(insidenewentity)
        editframe.grid(row=6, columnspan=4)
        Button(insidenewentity, text='Submit', font=('Courier', 14), command = lambda: editselection(editoption.get())).grid(columnspan=4, row=5,pady=4)

def editselection(choice):
    global insidenewentity, editframe
    editframe.destroy()
    editframe = Frame(insidenewentity)
    editframe.grid(row=6, columnspan=4)
    Label(editframe, text=f"{choice}:", font = ('Courier', 14)).grid(row=0, column=1, pady=6)
    userinput = Entry(editframe, font = ('Courier', 14))
    userinput.grid(row=0, column=2, pady=6)
    Button(editframe, text='Change', font=('Courier', 14), command = lambda: change(userinput.get(), choice)).grid(columnspan=4, row=1,pady=4)

def signup(root):
    global loginframe, showit
    showit = True
    loginframe.destroy()
    loginframe = Frame(root)
    loginframe.pack()
    Label(loginframe, text='Signup', font=('Courier', 18)).grid(columnspan = 4, row=0)
    Label(loginframe, text="Username:").grid(row=1, column=1)
    Label(loginframe, text="Password:").grid(row=2, column=1)
    accountusername = Entry(loginframe)
    accountusername.grid(row=1, column=2)
    accountpassword = Entry(loginframe, show="*")
    accountpassword.grid(row=2, column=2)
    Button(loginframe, text="V", command = lambda: editentry(accountpassword)).grid(row = 2 , column = 3)
    Button(loginframe, text="Sign Up", command = lambda: account_signup(accountusername.get(), root, accountpassword.get())).grid(columnspan = 4, row=3)

def login():
    global showit, loginframe
    showit = True
    root = Tk()
    loginframe = Frame(root)
    loginframe.pack()
    Label(loginframe, text='Login', font=('Courier', 18)).grid(columnspan = 4, row=0)
    usersusername = Entry(loginframe)
    usersusername.grid(columnspan=2, row=1)
    userpass = Entry(loginframe, show="*")
    userpass.grid(columnspan = 2, row=2)
    Button(loginframe, text="V", command = lambda: editentry(userpass)).grid(row = 2 , column = 3)
    Button(loginframe, text="Submit", command = lambda: loginfunc(usersusername.get(), root, userpass.get())).grid(columnspan = 4, row=3)
    Button(loginframe, text="Sign up", command = lambda: signup(root)).grid(columnspan = 4, row=4, pady=6)
    root.mainloop()

def editentry(userpass):
    global showit
    if showit:
        showit = False
        userpass.config(show="")
    else:
        showit = True
        userpass.config(show="*")

def menu():
    global root, outputframe, new_entityframe, scroll_lbl, option, root, insidenewentity, outputdata
    option = 'new'
    root = Tk()
    root.title("Password Storer")

    buttonframe = Frame(root)
    buttonframe.pack()
    new = Button(buttonframe, text = 'New', font = ('Courier', 14), command = lambda: (setoptionnew(), remove_add()))
    new.grid(row = 0, column = 1)
    remove = Button(buttonframe, text = 'Remove', font = ('Courier', 14), command = lambda: (setoptionremove(), remove_add()))
    remove.grid(row = 0, column = 2)
    editbutton = Button(buttonframe, text = 'Edit', font = ('Courier', 14), command = lambda: (setoptionedit(), remove_add()))
    editbutton.grid(row = 0, column = 3)
    new_entityframe = Frame(root)
    new_entityframe.pack()
    insidenewentity = Frame(new_entityframe)
    insidenewentity.pack()

    outputframe = Frame(root, pady=4)
    outputframe.pack()
    Label(outputframe, text='Site'.ljust(16, ' ')+'Username'.ljust(16, ' ')+'Email'.ljust(16, ' ')+'Password'.rjust(16, ' '), font=('Courier', 14)).pack()
    outputdata = Frame(outputframe)
    outputdata.pack()
    obtain_output()

    quitbtn = Button(root, text='Quit', font = ('Courier', 14), command = lambda: (on_close(root)))
    quitbtn.pack()
    root.mainloop()

load_account()
login()