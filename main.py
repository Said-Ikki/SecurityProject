import os
import sys
import rsa
import json

import cryptography
from cryptography.fernet import Fernet
from getpass import getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import pyautogui

import requests
import socket

drive = "F" # default driver for testing
drives = ["D", "E", "F", "G"] # potential USB drives
def create_keys(): # creates the private and public keys
    private_key = RSA.generate(4096) # create private
    public_key = private_key.publickey() # create public based on private
    f = open('privatekey.pem', 'wb') # save private key
    f.write(private_key.exportKey('PEM'))
    f.close()
    f = open('publickey.pem', 'wb') # save public key
    f.write(public_key.exportKey('PEM'))
    f.close()

def write_user_info(driver, encUsername, encPassword): # write encrypted unser info to files
    try:
        os.mkdir(driver + ":\\Top Secret Artifact\\Login Files") # check if this file is ok to write to
        f = open(str(driver + ":\\Top Secret Artifact\\Login Files\\user_info_1.txt"), "wb") #write the username to file 1
        f.write(encUsername)
        f.close()
        f = open(str(driver + ":\\Top Secret Artifact\\Login Files\\user_info_2.txt"), "wb") # write the password to file 2
        f.write(encPassword)
        f.close()
        return True
    except FileNotFoundError: # if driver is bad
        return False # say no op was performed
    except FileExistsError: # if a user info already exists
        print("Info Already Exists! Rewriting") # rewrite it
        f = open(str(driver + ":\\Top Secret Artifact\\Login Files\\user_info_1.txt"), "wb")
        f.write(encUsername)
        f.close()
        f = open(str(driver + ":\\Top Secret Artifact\\Login Files\\user_info_2.txt"), "wb")
        f.write(encPassword)
        f.close()
        return True

def read_user_info(): # get user info from files
    isDriveWork = False # flag for figuring out if a USB is inserted
    for d in drives: # check all predifined drives
        if isDriveWork: # if one is already found
            break # end
        # check if file is there
        isDriveWork = os.path.isfile(d + ":\\Top Secret Artifact\\Login Files\\user_info_1.txt")
        if isDriveWork: # if it is
            driver = d # thats the drive we take info from
            break # end loop
    if not isDriveWork: # if no drives work
        raise FileNotFoundError # no USB is inserted

    # read information from file
    file = open(driver + ":\\Top Secret Artifact\\Login Files\\user_info_1.txt", "rb")
    content1 = file.read()
    file.close()

    file = open(driver + ":\\Top Secret Artifact\\Login Files\\user_info_2.txt", "rb")
    content2 = file.read()
    file.close()
    return content1, content2


# Press the green button in the gutter to run the script.
if __name__ == '__main__':

    # read keys in folder
    private_key = RSA.importKey(open('privatekey.pem').read())
    public_key = RSA.importKey(open('publickey.pem').read())

    cipher = PKCS1_OAEP.new(public_key) # create encryptor

    # variables for button names
    # when the buttons are chosen, the string is returned so it makes for easy comparisons
    create_new_account_button_name = 'Create a New Account'
    login_button_name = 'Login'

    # will the user login or register?
    isLoginOrNewAccount = pyautogui.confirm('Would you like to create a new account or log into a previous account??',
                                            buttons=[create_new_account_button_name, login_button_name])
    print(isLoginOrNewAccount)


    if isLoginOrNewAccount == create_new_account_button_name: # if register
        new_username = pyautogui.password('Enter username: ') # get username
        new_password = pyautogui.password('Enter password: ') # and password
        # hidden ofc

        encUsername = cipher.encrypt(new_username.encode()) # encrypt both
        encPassword = cipher.encrypt(new_password.encode())

        # save it somewhere
        for d in drives: # save it in all drives
            didWrite = write_user_info(d, encUsername, encPassword)
        if didWrite == False: # if it wasn't able to save, it was because no USB was inserted
            print("Failed to save information. Please Insert Your Ultra-Secret Super-Duper Mega-USB before proceeding ")
        elif didWrite == True: # otherwise, its good
            print("Successfully Saved Information")

        #try:
         #   os.mkdir(drive + ":\\Top Secret Artifact\\Login Files")
        #except FileExistsError:
         #   pass

        #f = open(str(drive + ":\\Top Secret Artifact\\Login Files\\user_info_1.txt"), "wb")
        #f.write(encUsername)
        #f.close()
        #f = open(str(drive + ":\\Top Secret Artifact\\Login Files\\user_info_2.txt"), "wb")
        #f.write(encPassword)
        #f.close()

    if isLoginOrNewAccount == login_button_name: # if they want to login
        entered_username = pyautogui.password('Enter username: ') # get username
        entered_password = pyautogui.password('Enter password: ') # and password
        #  hidden ofc

        try:
            #file = open(drive + ":\\Top Secret Artifact\\Login Files\\user_info_1.txt", "rb")
            #content1 = file.read()
            #file.close()

            #file = open(drive + ":\\Top Secret Artifact\\Login Files\\user_info_2.txt", "rb")
            #content2 = file.read()
            #file.close()

            content1, content2 = read_user_info() # get info

            cipher = PKCS1_OAEP.new(private_key) # get decryptor

            actual_username = cipher.decrypt(content1).decode() # decrypt and decode
            actual_password = cipher.decrypt(content2).decode() # to process it later

            isUsernameMatch = (actual_username == entered_username) # does the input
            isPasswordMatch = (actual_password == entered_password) # match with whats saved

            print("-------------------")
            if isUsernameMatch and isPasswordMatch: # if it is
                print('Login successful!')
                hostname = socket.gethostname() # get hostname
                ip_address = socket.gethostbyname(hostname) # to get IP

                public_sender = RSA.importKey(open('public.pem').read()) # use different encryptor provided by server
                cipher = PKCS1_OAEP.new(public_sender) # get server encryptor
                msg = cipher.encrypt(ip_address.encode()) # encrypt IP address as msg
                msg2 = cipher.encrypt( "127.0.0.1".encode() )
                # this github has all files squished together
                # ideally this code only has access to the public key for the server
                # so it can only encrypt, reducing vulnerability

                print("...Checking Status...") # send msg
                print(requests.post(url="http://172.26.16.1:5000/validate", data=msg).json)
                print(requests.post(url="http://172.26.16.1:5000/validate", data=msg2).json)
            else: # if the info doesnt match
                print('Login failed') # login failed
            print("-------------------")
        except FileNotFoundError: # only if USB not entered
            print('Please Insert Your Ultra-Secret Super-Duper Mega-USB before proceeding')

