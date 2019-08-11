#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Apr  2 11:05:06 2019

@author: apurvakatti
"""

import socket
import math

r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
r.connect(("192.168.122.57", 31337))


validity="Invalid"
string=""
stringBlock=""

def tokenize(x):
    #print(x)
    x = x.split('\n') 
    y=x[0].split('\\n')
    
    length = y[0][-2:]
    
    IV = x[1].split("'")[1]
    IV = bytes.fromhex(IV)
    
    cipher = y[1][0:-1]
    cipher=bytes.fromhex(cipher)
    return (length,IV,cipher)


def findTheMessage(m,cipher,IV):
    return chr(int(m,16) ^ int(cipher[-17:-16].hex(),16) ^ int(IV[-1:].hex(),16))
 
length_old=0    
for count in range(17):
    message=bytes.fromhex("00"*count).hex()
    if(count==0):
        r.send("-E".encode())
    else:
        r.send(("-e "+message).encode())
        
    length, IV, cipher=tokenize(str(r.recv(1024).decode()))
    
    if(count>0 and length_old !=length):
        #print("The padding is:",(count-1))
        break
    length_old=length

padding=count

r.send("-E".encode())
length, IV, cipher=tokenize(str(r.recv(1024).decode()))
block_size=math.ceil(((int(length)-padding)-16)/16)

if (padding < 16):
    prefix = bytes.fromhex("00"*padding).hex()
    #print(len(prefix))
    #block_size=math.ceil((((int(length)+len(prefix/2))-padding)-16)/16)
    
else:
    prefix=""
    
    
print("Please Wait...")
#print("The block size is",block_size)

block=0
while(block<block_size):
    validity="Invalid"
    #print("Checking the first bytes Validity")
    while(validity=="Invalid"):
        if (padding <16):
            r.send(("-e "+prefix).encode())
            #print(("-e "+message).encode())
        else:
            r.send("-E".encode())
            #print("sent empty string")
           # Encryption of the secret message
        length,IV,cipher=tokenize(str(r.recv(1024).decode()))
        
        modified_cipher = cipher[:len(cipher)-16] + cipher[(16*block):(16*(block+1))]
        #print("The modified cipher is", modified_cipher.hex())
       
        r.send(("-v "+modified_cipher.hex()+" "+IV.hex()).encode())
        validity = r.recv(1024).decode()
    validity="Invalid"
    
    m=hex(15)
    
    if(block==0):
        stringBlock=findTheMessage(m,cipher,IV)+stringBlock
    else:
        temp=cipher[(16*(block-1)):(16*block)]
        #print(len(temp),temp.hex())
        
        stringBlock=findTheMessage(m,cipher,temp)+stringBlock
    
    #print(stringBlock)
    
    count=1
    while(count<16):
            
        message=bytes.fromhex("00"*count).hex()
        
        while(validity=="Invalid"):
            r.send(("-e "+prefix+message).encode())    # Encryption of the secret message
            length_new, IV_new, cipher_new=tokenize(str(r.recv(1024).decode()))
           
            modified_cipher = cipher[:len(cipher)-16] + cipher_new[(16*block):(16*(block+1))]
            r.send(("-v "+modified_cipher.hex()+" "+IV.hex()).encode())
            validity = r.recv(1024).decode()
        validity="Invalid"
        
        m=hex(15)
        
        if(block==0):
            stringBlock=findTheMessage(m,cipher,IV_new)+stringBlock
        else:
            temp=cipher_new[(16*(block-1)):(16*block)]
            #print(len(temp),temp.hex())
            stringBlock=findTheMessage(m,cipher,temp)+stringBlock
        
        #print(stringBlock)
        
        count+=1
    #print("Block Done")
    print("The",(block+1),"block of message is",stringBlock)
    string+=stringBlock
    stringBlock=""
    
    block+=1

if(padding<16):
    print("The Secret Message is:",string[(padding-1):])
else:
    print("The Secret Message is:",string)
    
    


