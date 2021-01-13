import argparse
import socket
import time
import select
import struct
import sys
import binascii
import automator
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto.Util.Padding import unpad
from Crypto import Random
from Crypto.Util.Padding import pad
from encrypted_package_pb2 import EncryptedPackage, PlaintextAndMAC, IM

def receiveMessages(clientSocket, conKey, authKey):
    dataLength_packed = clientSocket.recv(4, socket.MSG_WAITALL)
    dataLength= struct.unpack('!L',dataLength_packed)[0]
    protobuf = clientSocket.recv(dataLength, socket.MSG_WAITALL)
    package = EncryptedPackage()
    package.ParseFromString(protobuf) 
    cipher = AES.new(conKey, AES.MODE_CBC, iv=package.iv) 
    serialPlain =  unpad( cipher.decrypt(package.encryptedMessage), AES.block_size )
        
    plaintextAndMacPackage = PlaintextAndMAC()
    plaintextAndMacPackage.ParseFromString(serialPlain)
    serialIM = unpad(plaintextAndMacPackage.paddedPlaintext,AES.block_size)
    im = IM()
    im.ParseFromString(serialIM)
    automator.decrypted_IM(im)

    macCheck = HMAC.new(authKey,digestmod=SHA256)
    macCheck.update(serialIM)
    try: 
        macCheck.verify(plaintextAndMacPackage.mac)
        automator.hmac_verification_passed()
        return im.message, im.nickname
    except:
        automator.hmac_verification_failed()
        print("HMAC failed to verify")

def main():
    parser = argparse.ArgumentParser()
    
    parser.add_argument('-p', dest='port', help='port number', required=True, type=int)
    parser.add_argument('-s', dest='servername', help='name of the server', required=True)
    parser.add_argument('-n', dest='nickname', help='your nickname', required=True)
    parser.add_argument('-c', dest='con_key',help='confidentiality', required=True  )
    parser.add_argument('-a', dest='auth_key',help='authenticity', required=True)

    args = parser.parse_args()
 
    cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        cs.connect( (args.servername, args.port) )

    except:
        exit(1)

  
    user_authKey = SHA256.new(data=args.auth_key.encode('utf-8')).digest()
    user_conKey = SHA256.new(data=args.con_key.encode('utf-8')).digest() 

    read_handles = [sys.stdin, cs]

    while True: 
        readyReadSockets, _, _ = select.select(read_handles, [], [])

        if cs in readyReadSockets:
            #message = receiveMessages(cs, user_conKey, user_authKey)    
            #print("%s: %s" % (message[0], message[1]))

            dataLength_packed = cs.recv(4, socket.MSG_WAITALL)
            dataLength= struct.unpack('!L',dataLength_packed)[0]
            protobuf = cs.recv(dataLength, socket.MSG_WAITALL)
            package = EncryptedPackage()
            package.ParseFromString(protobuf) 
            cipher = AES.new(user_conKey, AES.MODE_CBC, iv=package.iv) 
            serialPlain =  unpad(cipher.decrypt(package.encryptedMessage), AES.block_size )
        
            plaintextAndMacPackage = PlaintextAndMAC()
            plaintextAndMacPackage.ParseFromString(serialPlain)
            serialIM = unpad(plaintextAndMacPackage.paddedPlaintext,AES.block_size)
            im = IM()
            im.ParseFromString(serialIM)
            automator.decrypted_IM(im)

            macTest = HMAC.new(user_authKey,digestmod=SHA256)
            macTest.update(serialIM)
            try: 
                macTest.verify(plaintextAndMacPackage.mac)
                automator.hmac_verification_passed()
                print("%s: %s" % (im.nickname, im.message))

            except ValueError as e:
                automator.hmac_verification_failed()
                print("Message not authenticated.")


        if sys.stdin in readyReadSockets:

            iv = Random.get_random_bytes(AES.block_size) 

            user_input = input()
            if str(user_input).lower() == "exit": 
                cs.close()
                exit(0)

            im = IM ()
            im.nickname = args.nickname 
            im.message = user_input
            serialIM = im.SerializeToString()  

            
            plaintext = PlaintextAndMAC()
            plaintext.paddedPlaintext = pad(serialIM,AES.block_size)
            temp = HMAC.new(user_authKey,digestmod=SHA256) 
            temp.update(serialIM)
            plaintext.mac = temp.digest()
            serialPlain = plaintext.SerializeToString()

           
            encrypted_package = EncryptedPackage()
            encrypted_package.iv = iv
            cipher = AES.new(user_conKey, AES.MODE_CBC, iv=iv)
            encrypted_package.encryptedMessage = cipher.encrypt(pad(serialPlain,AES.block_size)) 
            serialEncryptPackage= encrypted_package.SerializeToString()

 
            dataLength= len(serialEncryptPackage)
            cs.send(struct.pack('!L', dataLength)) 
            cs.send(serialEncryptPackage) 

if __name__ == '__main__': 
    main()
