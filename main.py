import base64
import os
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

class Cipher:
    def __init__(self):
        self.profile = os.path.basename(os.path.expanduser("~"))
        self.output_dire = f"{os.path.expanduser('~')}/Pythcryption"
        if not os.path.exists(self.output_dire):
            os.mkdir(self.output_dire)
    
        self.key_directory = f"/media/{self.profile}/7406-CC77/.key/"

    def writeKey(self,key,keyname):
        key_path = self.key_directory+keyname+".key"
        with open(key_path,'wb') as k:
            k.write(key)
        print("!!! Key written to the keydrive !!!")

    def hashKey(self,keyname):
        hashed_string = hashlib.sha256(keyname.encode()).hexdigest()
        return hashed_string

    def encrypt(self,key):
        input_file = input("Enter the path of the file with extention : ")
        output_file = f'{os.path.expanduser("~")}/Pythcryption/{input_file.split(".")[0].split("/")[-1]}'
        counter = 2

        while os.path.exists(output_file+".encrypted"):
            output_file += f'{counter}'

        output_file_path = f'{output_file}.encrypted'

        with open(input_file, 'rb') as f:
            data = f.read()  # Read the bytes of the input file

        fernet = Fernet(key)
        keyhash = self.hashKey(os.path.splitext(os.path.basename(output_file_path))[0])
        encrypted = fernet.encrypt(data)+f"@@{keyhash}".encode()

        with open(output_file_path, 'wb') as f:
            f.write(encrypted)  # Write the encrypted bytes to the output file

        self.writeKey(key,keyhash)

        # Note: You can delete input_file here if you want
        os.remove(input_file)

        print("!!! Data Encrypted !!!")
        print("!!! Input File Deleted !!!")

    def decrypt(self):
        files_encrypted = os.listdir(self.output_dire)
        print("Choose the encrypted file\n")
        for i in range(len(files_encrypted)):
            print(f'{i+1}. {files_encrypted[i]}')

        file = int(input(">>> "))
        if file in range(len(files_encrypted)) and file != 0:
            print("Invalid File Number")


        input_file = self.output_dire+"/"+files_encrypted[file-1]
        

        with open(input_file, 'rb') as f:
            data = f.read()  # Read the bytes of the encrypted file

        if not os.path.exists(self.key_directory):
            print("!!! Key drive not found !!!")
            key = self.getkey()
        else:
            keyname =  data.split(b'@@')[1]
            key_path = self.key_directory+keyname.decode()+".key"
            with open(key_path,"rb") as k:
                key = k.read()

        
        fernet = Fernet(key)
        try:
            decrypted = fernet.decrypt(data.split(b'@@')[0])

            print("\n\n",decrypted.decode(),"\n\n")
            save = input("\nSave to File ? (y/n): ")
            if save == "y":
                output_path = input("Enter the ouptut path (./.. linux conventions)\n>>> ")
                output_file = output_path+"/"+os.path.splitext(os.path.basename(input_file))[0]+".txt"
                with open(output_file, 'wb') as f:
                    f.write(decrypted)  # Write the decrypted bytes to the output file
                print("!!! Data Saved To File !!!")             
            else:
                print("!!! Data Decrypted !!!")
        
        except InvalidToken as e:
            print("!!! Wrong Key !!!")



    def getkey(self):
        password_provided = input("Enter the key : ")  # This is input in the form of a string
        password = password_provided.encode()  # Convert to type bytes
        salt = input("Enter the salt : ").encode()  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
        return key

    def run(self):            
            choice = int(input("Choose\n1. Encrypt\n2. Decrypt\n>>> "))
            if choice == 1:
                if not os.path.exists(self.key_directory):
                    print("!!! Plug in the KeyDrive!!!")
                else:
                    print("!!! KeyDrive Found !!!")
                    key = self.getkey()
                    self.encrypt(key)
            elif choice == 2:
                self.decrypt()
            else :
                print("!!! Invalid Choice !!!")

l = Cipher()
l.run()
