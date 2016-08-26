#!/usr/bin/env python

# By Jhonathan Davi A.K.A jh00nbr_ / Team RTFM - Red Team Freakin' Maniacs - rtfm-ctf.org
# Writeup - Intercepted Conversations Pt.1 - IceCTF 2016

hids_codes = {"0x04":"a","0x05":"b","0x06":"c","0x07":"d","0x08":"e","0x09":"f","0x0A":"g","0x0B":"h","0x0C":"i","0x0D":"j","0x0E":"k","0x0F":"l","0x10":"m","0x11":"n","0x12":"o","0x13":"p","0x14":"q","0x15":"r","0x16":"s","0x17":"t","0x18":"u","0x19":"v","0x1A":"w","0x1B":"x","0x1C":"y","0x1D":"z","0x1E":"1","0x1F":"2","0x20":"3","0x21":"4","0x22":"5","0x23":"6","0x24":"7","0x25":"8","0x26":"9","0x27":"0","0x36":",","0x33":":","0x28":"\n","0x2C":" ","0x2D":"_","0x2E":"=","0x2F":"{","0x30":"}"}
layout_dvorak = { 'q':"'", 'w':',', 'e':'.', 'r':'p', 't':'y', 'y':'f', 'u':'g', 'i':'c', 'o':'r', 'p':'l', '_':'_', ':':'S','[':'/', '{':'{', '}':'}' ,']':'=','a':'a', 's':'o', 'd':'e', 'f':'u', 'g':'i', 'h':'d', 'j':'h', 'k':'t', 'l':'n', ';':'s', "'":'-','z':';', 'x':'q', 'c':'j', 'v':'k', 'b':'x', 'n':'b', 'm':'m', ',':'w', '.':'v', '.':'z',' ':' ','Q':"'", 'W':',', 'E':'.', 'R':'P', 'T':'Y', 'Y':'F', 'U':'G', 'I':'C', 'O':'R', 'P':'L','A':'A', 'S':'O', 'D':'E', 'F':'U', 'G':'I', 'H':'D', 'J':'H', 'K':'T', 'L':'N', ';':'S', "'":'-','Z':';', 'X':'Q', 'C':'J', 'V':'K', 'B':'X', 'N':'B', 'M':'M','0':'0','1':'1','2':'2','3':'3','4':'4','5':'5','6':'6','7':'7','7':'7','8':'8','9':'9'}

# 02 = Shift 
# 20 = Shift 

flag = []

with open("usb_hid.dat","r") as files:
	for linhas in files.readlines():
                usb_key = linhas.split()[0]
                inicio = usb_key[0:2]
                usb_key_code = "0x"+usb_key[4:6].upper()
                if usb_key_code in hids_codes:
                    if inicio.startswith('02'): # Verifica se no comeco Foi usado o shift '02' 0200360000000000
                        print hids_codes[usb_key_code].upper(),
                        flag.append(hids_codes[usb_key_code].upper())
                    elif inicio.startswith('20'):
                        print hids_codes[usb_key_code].upper(),
                        flag.append(hids_codes[usb_key_code].upper())
                    else:
                        print hids_codes[usb_key_code],
                        flag.append(hids_codes[usb_key_code].upper())
                        
for flag in flag:
   print layout_dvorak[flag],
