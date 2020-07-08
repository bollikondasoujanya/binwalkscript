#! /usr/bin/python
#This script extract the multiple firmware's and gives the output only spesified details 
#those are No of files in given folder,Filename,Image type,FIlesystem,Entropy,Endianes

import os

import binwalk

import sys 

import fpdf


dir_name = "/home/cdac/zipfiles"   #path for input directory(zip/bin..files)

ext_dir = "/home/cdac/extract_dir" #path for output dirctory(extracted files)

onlyfiles = next(os.walk(dir_name))[2] #dir_name is your directory path as string

print ("No of files:%d" %(len(onlyfiles)))

os.chdir(dir_name)

for files in os.listdir(dir_name):#get the list of files

    print ("Filename:%s" %(files))

    for module in binwalk.scan(files, "-y","kernel",signature=True,quiet=True):

        for entry in module.results:
            
            print("\tImage type  : %s "% (entry.description))

    for module in binwalk.scan(files ,"-y","filesystem",signature=True,quiet=True):

        for entry in module.results:

            print("\tFilesystem  : %s "%(entry.description))

            break;
#print "\tif entropy value is: > 0.9 firmware encrypted "
#print "\tif entropy value is: < 0.9 firmware compressed"

    for module in binwalk.scan(files,"-E",save=True,directory=ext_dir,signature=True,extract=True,quiet=True):

        for entry in module.results:

            print("\t Entropy     :  %s "%(entry.description))

            break;
        
    for module in binwalk.scan(files, "-y", "endian",signature=True, quiet=True):

        for entry in module.results:

            print("\t Endianess   :%s" %(entry.description))

            break;

   
