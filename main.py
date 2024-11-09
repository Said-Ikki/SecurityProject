# This is a sample Python script.
import msvcrt
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

import os
import sys
import rsa

import cryptography
from cryptography.fernet import Fernet
from getpass import getpass

import pyautogui

import requests
import socket

def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')

    print(Fernet.generate_key())
    key = b'5i5davgtM7BIRKNfxRXzaIt6AvFRajleCV7gDpEz11Q='
    fernet = Fernet(key)

    create_new_account_button_name = 'Create a New Account'
    login_button_name = 'Login'

    isLoginOrNewAccount = pyautogui.confirm('Would you like to create a new account or log into a previous account??',
                          buttons=[create_new_account_button_name, login_button_name])
    print(isLoginOrNewAccount)

    if isLoginOrNewAccount == create_new_account_button_name:
        new_username = pyautogui.password('Enter username: ')
        new_password = pyautogui.password('Enter password: ')

        encUsername = fernet.encrypt(new_username.encode())
        encPassword = fernet.encrypt(new_password.encode())

        try:
            os.mkdir("F:\\Top Secret Artifact\\Login Files")
        except FileExistsError:
            pass

        f = open( str("F:\\Top Secret Artifact\\Login Files\\user_info.txt") , "w")
        f.write( str(encUsername.decode()) )
        f.write( "\n" + str(encPassword.decode()  ) )
        f.close()

    if isLoginOrNewAccount == login_button_name:
        entered_username = pyautogui.password('Enter username: ')
        entered_password = pyautogui.password('Enter password: ')

        # open the sample file used
        #file = open('user_info.txt')
        try:
            file = open("F:\\Top Secret Artifact\\Login Files\\user_info.txt")
            # read the content of the file opened
            content = file.readlines()

            #print("unencoded: " + content[0])
            actual_username = fernet.decrypt(content[0]).decode()
            actual_password = fernet.decrypt(content[1]).decode()

            isUsernameMatch = (actual_username == entered_username)
            isPasswordMatch = (actual_password == entered_password)

            print("-------------------")
            if isUsernameMatch and isPasswordMatch:
                print('Login successful!')
                hostname = socket.gethostname()
                ip_address = socket.gethostbyname(hostname)
                #sending_key = b'8F1F2787abOWcBkoS3CjPcpj-j9BJsUmITdP0lqopos='
                #sendingFernet = Fernet(sending_key)
                #encryptedIP = sendingFernet.encrypt(ip_address.encode())
                #print(requests.post(url="http://192.168.250.63:5000/validate", data=encryptedIP.decode()))
                print(requests.post(url="http://192.168.250.63:5000/validate", data=ip_address))
            else:
                print('Login failed')
            print("-------------------")
        except FileNotFoundError:
            print('Please Insert Your Ultra-Secret Super-Duper Mega-USB before proceeding')

        #print(actual_username, actual_password)


    message = "hello there"
    encMessage = fernet.encrypt(message.encode())
    decMessage = fernet.decrypt(encMessage).decode()
    print(message)
    print(encMessage)
    print(decMessage)

    print( os.path.isfile("C:\\Windows\\System32\\notepad.exe") )
    print( os.path.isfile( "F:\\Top Secret Artifact\\optimal.png" ) )

    f = open("demofile3.txt", "w")
    f.write("Woops! I have deleted the content!")
    f.close()

    # open and read the file after the overwriting:
    f = open("demofile3.txt", "r")
    print(f.read())

    #key = input("Enter the Password")
    key = pyautogui.password('Enter password: ')
    if key != "key":
        print("Wrong Password")
        sys.exit()

    drives = {"C", "D", "E", "F", "G"}

    hasFile = False
    for drive in drives:
        isMainDrive   = os.path.isfile(drive + ":\\Windows\\System32\\notepad.exe"   )
        isUSBwithFile = os.path.isfile(drive + ":\\Top Secret Artifact\\optimal.png" )
        if isMainDrive == False and isUSBwithFile == True:
            print("Access Granted: Drive " + drive)
            hasFile = True
        #elif isMainDrive:
        #    print("Drive " + drive + " is a main drive")
        #elif isUSBwithFile == False:
        #    print("Drive " + drive + " does not contain the file")
    if not hasFile:
        print("Access Denied: You Forgot Your External Device")



# See PyCharm help at https://www.jetbrains.com/help/pycharm/
