# This is a sample Python script.
import msvcrt
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

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

# Press the green button in the gutter to run the script.
if __name__ == '__main__':

    #    private_key = RSA.generate(4096)
    #   public_key = private_key.publickey()
    #  f = open('privatekey.pem', 'wb')
    # f.write(private_key.exportKey('PEM'))
    # f.close()
    #    f = open('publickey.pem', 'wb')
    #   f.write(public_key.exportKey('PEM'))
    #  f.close()

    private_key = RSA.importKey(open('privatekey.pem').read())
    public_key = RSA.importKey(open('publickey.pem').read())

    cipher = PKCS1_OAEP.new(public_key)

    create_new_account_button_name = 'Create a New Account'
    login_button_name = 'Login'

    isLoginOrNewAccount = pyautogui.confirm('Would you like to create a new account or log into a previous account??',
                                            buttons=[create_new_account_button_name, login_button_name])
    print(isLoginOrNewAccount)
    drive = "F"

    if isLoginOrNewAccount == create_new_account_button_name:
        new_username = pyautogui.password('Enter username: ')
        new_password = pyautogui.password('Enter password: ')

        encUsername = cipher.encrypt(new_username.encode())
        encPassword = cipher.encrypt(new_password.encode())

        try:
            os.mkdir(drive + ":\\Top Secret Artifact\\Login Files")
        except FileExistsError:
            pass

        f = open(str(drive + ":\\Top Secret Artifact\\Login Files\\user_info_1.txt"), "wb")
        f.write(encUsername)
        f.close()
        f = open(str(drive + ":\\Top Secret Artifact\\Login Files\\user_info_2.txt"), "wb")
        f.write(encPassword)
        f.close()

    if isLoginOrNewAccount == login_button_name:
        entered_username = pyautogui.password('Enter username: ')
        entered_password = pyautogui.password('Enter password: ')

        try:
            file = open(drive + ":\\Top Secret Artifact\\Login Files\\user_info_1.txt", "rb")
            content1 = file.read()
            file.close()

            file = open(drive + ":\\Top Secret Artifact\\Login Files\\user_info_2.txt", "rb")
            content2 = file.read()
            file.close()

            cipher = PKCS1_OAEP.new(private_key)

            actual_username = cipher.decrypt(content1).decode()
            actual_password = cipher.decrypt(content2).decode()

            isUsernameMatch = (actual_username == entered_username)
            isPasswordMatch = (actual_password == entered_password)

            print("-------------------")
            if isUsernameMatch and isPasswordMatch:
                print('Login successful!')
                hostname = socket.gethostname()
                ip_address = socket.gethostbyname(hostname)

                public_sender = RSA.importKey(open('public.pem').read())
                cipher = PKCS1_OAEP.new(public_sender)
                msg = cipher.encrypt(ip_address.encode())

                print("...Checking Status...")
                print(requests.post(url="http://192.168.250.63:5000/validate", data=msg).json)
            else:
                print('Login failed')
            print("-------------------")
        except FileNotFoundError:
            print('Please Insert Your Ultra-Secret Super-Duper Mega-USB before proceeding')

