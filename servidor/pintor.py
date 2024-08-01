# -*- coding: utf-8 -*-
"""
Created on Tue Nov 28 08:48:24 2023

@author: diego
"""


from ecdsa import SigningKey, NIST521p
from ecdsa import VerifyingKey, BadSignatureError
from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import requests
import hashlib
import json
import sqlite3


# Función para descifrar datos con AES-GCM
def decrypt_aes_gcm(key, ciphertext, nonce, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()


def lista():
    # conexion=sqlite3.connect("bd1.db")
    # cursor=conexion.execute("select ID,cliente_id from pedidos")
    # for fila in cursor:
    #     print(fila)
        
    selector = input("selecciona el id del pedido: ")
    
    cursor=conexion.execute("select * from pedidos where ID = " + selector)
    fila=cursor.fetchone()
    # print(fila[1])
    # print(bytes.fromhex(fila[1]))
    json_decrypt = decrypt_aes_gcm(b64decode(fila[5]), bytes.fromhex(fila[1]), bytes.fromhex(fila[2]), bytes.fromhex(fila[3]))
    # print(photo_decrypt['photo'])
    # Leer la imagen como bytes
    with open("imagen_decrypt_pedido_" + selector + ".jpg", "wb") as f:
        f.write(b64decode(json.loads(json_decrypt)['photo']))
        # image_data = b64encode(image_file.read()).decode('utf-8')
    
    verifyn_signature(str(fila[6]), json_decrypt.encode('utf-8'), bytes.fromhex(fila[4]))
    conexion.close()
    
    return selector
    

def verifyn_signature(id,json_signature,sig):
    conexion=sqlite3.connect("bd1.db")
    cursor=conexion.execute("select llave_publica from clientes where id = " + id)
    # for fila in cursor:
        # print(fila)
    
    # cursor=conexion.execute("select * from pedidos where ID = " + selector)
    fila=cursor.fetchone()
    
    conexion.close()
    
    vk = VerifyingKey.from_pem(fila[0])
    try:
        vk.verify(sig, json_signature)
        print ("Esta correcta la firma")
    except BadSignatureError:
        print ("Te jugaron chueco mano")
        

def derivar_clave_pbkdf2(password, salt, key_length=32, iterations=100000):
    # Derivar una clave usando PBKDF2
    clave_derivada = PBKDF2(password, salt, dkLen=key_length, count=iterations)
    return clave_derivada

# 

def cifrar_aes(mensaje, password):
    salt = get_random_bytes(16)  # Generar un salt aleatorio
    clave_aes = derivar_clave_pbkdf2(password, salt)
    iv = get_random_bytes(AES.block_size)  # IV aleatorio
    cifrador = AES.new(clave_aes, AES.MODE_CFB, iv)
    texto_cifrado = cifrador.encrypt(mensaje)
    print(b64encode(salt).decode('utf-8'))
    print(b64encode(iv).decode('utf-8'))
    print(b64encode(texto_cifrado).decode('utf-8'))
    datos_cifrados_concatenados = b64encode(salt).decode('utf-8') + \
                                  b64encode(iv).decode('utf-8') + \
                                  b64encode(texto_cifrado).decode('utf-8')
    return datos_cifrados_concatenados

def descifrar_aes(datos_cifrados, password):
    # Separar los datos cifrados concatenados
    salt, iv, texto_cifrado = map(b64decode, (datos_cifrados[:24], datos_cifrados[24:48], datos_cifrados[48:]))
    clave_aes = PBKDF2(password, salt, dkLen=32, count=100000)
    cifrador = AES.new(clave_aes, AES.MODE_CFB, iv)
    texto_descifrado = cifrador.decrypt(texto_cifrado)

    return texto_descifrado.decode('utf-8')

def llaves_ecdsa(usuario,contraseña):
    # Generar par de claves
    key = RSA.generate(2048)
    public_key = key.publickey()
    
    
    llavepc = cifrar_aes(key.exportKey('PEM'),contraseña)

    
    # Enviar datos cifrados, firma y clave pública al servidor
    payload = {
        "usuario": 'ROOT',
        "contraseña_hash": (hashlib.sha256(contraseña.encode()).digest()).hex(), # SHA256.new(contraseña),
        "llave_publica": b64encode(public_key.export_key('PEM')).decode('utf-8'),
        "llave_privada_cifrada": llavepc
    }
    
    url = "http://127.0.0.1:8080/api/submit_user"

    response = requests.post(url, json=payload)
    # Manejar la respuesta del servidor según tus necesidades
    print("Respuesta del servidor:", response.text)

    

# Función para generar una clave AES aleatoria
def generate_aes_key():
    return get_random_bytes(32)  # Clave de 256 bits

# Función para cifrar datos con AES-GCM
def encrypt_aes_gcm(key, plaintext):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return ciphertext, cipher.nonce, tag

# Función para firmar datos con ECDSA
def sign_ecdsa(data,NOMBRE):
    with open("private_key_of_" + NOMBRE + ".pem") as f:
        sk = SigningKey.from_pem(f.read())
    sig = sk.sign(data)
    return sig

def post_dat_Imag(ciphertext, nonce, tag, status_id):
    conexion=sqlite3.connect("bd1.db")
  
    conexion.execute("UPDATE status_table SET status=?, pedido_terminado=?, nonce=?, tag=?  WHERE ID = ?",(1,
                                                                                                         ciphertext.hex(),
                                                                                                         nonce.hex(),
                                                                                                         tag.hex(),
                                                                                                         status_id
                                                                                                         ))
    conexion.commit() 
    conexion.close()  


def cifrar_clave_rsa(clave_publica, mensaje):
    cipher_rsa = PKCS1_OAEP.new(clave_publica)
    cifrado = cipher_rsa.encrypt(mensaje)
    return cifrado

def descifrar_clave_rsa(clave_privada, cifrado):
    cipher_rsa = PKCS1_OAEP.new(clave_privada)
    mensaje_descifrado = cipher_rsa.decrypt(cifrado)
    return mensaje_descifrado

def pedirContraseña():
    contraseña = input("Contraseña |")
    # registrate(usuario, SHA256(contraseña))
    llaves_ecdsa(usuario,contraseña)
    
# def pedido():
#     conexion=sqlite3.connect("bd1.db")
#     cursor=conexion.execute("select ID,cliente_id from pedidos")
#     for fila in cursor:
#         print(fila)
#     selector = input("selecciona el id del pedido: ")
#     cursor=conexion.execute("select * from pedidos where ID = " + selector)
#     fila=cursor.fetchone()
    
#     json_decrypt = decrypt_aes_gcm(b64decode(fila[5]), bytes.fromhex(fila[1]), bytes.fromhex(fila[2]), bytes.fromhex(fila[3]))
#     with open("imagen_decrypt_pedido_" + selector + ".jpg", "wb") as f:
#         f.write(b64decode(json.loads(json_decrypt)['photo']))
#         # image_data = b64encode(image_file.read()).decode('utf-8')
    
#     verifyn_signature(str(fila[6]), json_decrypt.encode('utf-8'), bytes.fromhex(fila[4]))
#     conexion.close()
    
#     return selector
    


# Ejemplo de uso
if __name__ == "__main__":
    
    usuario = 'ROOT'
    
    pedirContraseña()
    contraseña = None
    
    while(1):
        # tabla = input('Tabla: ')
        
        select = int(input("Que quiere hacer?\n1)Recuperar Status\n2)Descifrar\n3)Subir pedido"))
        # if(select == 1):
            
            # manito=lista()
            
            # # Ruta de la foto que se enviará al servidor
            # photo_path = "fotoTerminada.jpg"
            # # submit_photo(photo_path)
            
            # # Leer la imagen como bytes
            # with open(photo_path, "rb") as image_file:
            #     image_data = b64encode(image_file.read()).decode('utf-8')
                
            # pedido = {
            #         "photo": image_data
            #     }
            # json_data = json.dumps(pedido)
            
            # conexion=sqlite3.connect("bd1.db")
            # cursor=conexion.execute("select aes_key, status_id from pedidos where id="+ manito)
            
            # private_key=cursor.fetchone()
            # conexion.close()
            
            # # Cifrar la imagen temrinada
            # ciphertext, nonce, tag = encrypt_aes_gcm(b64decode(private_key[0]), json_data)
            # post_dat_Imag(ciphertext, nonce, tag, private_key[1])
            
        if(select == 1):
            
            print('revisar estado de pedidos')
            payload = {
                "usuario": usuario
            }
            
            url = "http://127.0.0.1:8080/api/recuperar_status"
        
            response = requests.post(url, json=payload)
        
            # Manejar la respuesta del servidor según tus necesidades
            print("\n", json.loads(response.text)['key'])
            
        elif(select == 2):
            
            conexion=sqlite3.connect("bd1.db")
            
            cursor=conexion.execute("select llave_privada_cifrada from clientes where usuario = 'ROOT' ")
            fila=cursor.fetchone()
            
            llavepintor= fila[0]
            contraseña = input("Contraseña |")
            llavepintorDesc=descifrar_aes(llavepintor, contraseña)
            pintorRSA=RSA.import_key(llavepintorDesc)
            print(pintorRSA)
            
            
            # cursor=conexion.execute("select ID,cliente_id from pedidos")
            # for fila in cursor:
            #     print(fila)
            
            payload = {
                "usuario": usuario
            }
            
            url = "http://127.0.0.1:8080/api/recuperar_status"
        
            response = requests.post(url, json=payload)
        
            # Manejar la respuesta del servidor según tus necesidades
            print("\n", json.loads(response.text)['key'])
            selector = input("selecciona el id del pedido: ")
            cursor=conexion.execute("select * from pedidos where ID = " + selector)
            fila=cursor.fetchone()
            
            llave=json.loads(fila[5])
            KeyAesPintor= b64decode(llave["key_pintor"])
            print(KeyAesPintor)
            llaveAesGCM=descifrar_clave_rsa(pintorRSA, KeyAesPintor)
            print(llaveAesGCM)
            
            json_decrypt = decrypt_aes_gcm(llaveAesGCM, bytes.fromhex(fila[1]), bytes.fromhex(fila[2]), bytes.fromhex(fila[3]))
            # print(photo_decrypt['photo'])
            # Leer la imagen como bytes
            with open("imagen_decrypt_pedido_" + selector + ".jpg", "wb") as f:
                f.write(b64decode(json.loads(json_decrypt)['photo']))
                # image_data = b64encode(image_file.read()).decode('utf-8')
            
            verifyn_signature(str(fila[6]), json_decrypt.encode('utf-8'), bytes.fromhex(fila[4]))
            conexion.close()
        elif(select == 3):
            payload = {
                "usuario": usuario
            }
            
            url = "http://127.0.0.1:8080/api/recuperar_status"
        
            response = requests.post(url, json=payload)
        
            # Manejar la respuesta del servidor según tus necesidades
            print("\n", json.loads(response.text)['key'])
            selector = input("selecciona el id del pedido que quieres subir: ")
            # manito=lista()
            
            # Ruta de la foto que se enviará al servidor
            photo_path = "fotoTerminada.jpg"
            # submit_photo(photo_path)
            
            # Leer la imagen como bytes
            with open(photo_path, "rb") as image_file:
                image_data = b64encode(image_file.read()).decode('utf-8')
                
            pedido = {
                    "photo": image_data
                }
            json_data = json.dumps(pedido)
            
            conexion=sqlite3.connect("bd1.db")
            cursor=conexion.execute("select * from pedidos where ID = " + selector)
            fila=cursor.fetchone()
            
            llave=json.loads(fila[5])
            KeyAesPintor= b64decode(llave["key_pintor"])
            print(KeyAesPintor)
            llaveAesGCM=descifrar_clave_rsa(pintorRSA, KeyAesPintor)
            print(llaveAesGCM)
            
            # private_key=cursor.fetchone()
            conexion.close()
            
            # Cifrar la imagen temrinada
            ciphertext, nonce, tag = encrypt_aes_gcm(llaveAesGCM, json_data)
            post_dat_Imag(ciphertext, nonce, tag, selector)
       
        
