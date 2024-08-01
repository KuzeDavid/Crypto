# -*- coding: utf-8 -*-
"""
Created on Mon Nov 20 16:42:44 2023

@author: David
"""

from ecdsa import SigningKey, NIST521p
from ecdsa import VerifyingKey, BadSignatureError
from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

import secrets
import requests
import json
from ecdsa import ECDH
import hashlib
import sqlite3
from io import BytesIO
import tkinter as tk
from pathlib import Path
from tkinter import filedialog
import sys


#################################################3
#  CLASE PARA MANTENER SEGURA LA CONTRASEÑA
##################################################
class SecureContext:
    def __enter__(self):
        # En este método puedes realizar configuraciones seguras
        # o inicializar variables necesarias para tu contexto seguro.
        print("--------------------- contexto seguro")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # En este método puedes realizar limpieza o acciones seguras
        # cuando salgas del contexto, por ejemplo, eliminar la contraseña.
        print("--------------------- contexto seguro")
        



############################################################################################################################
#  FUNCIONES OCUPADAS PARA INICIAR SESION
############################################################################################################################

def llaves_ecdsa(usuario,contraseña):
    sk = SigningKey.generate(curve=NIST521p)
    vk = sk.verifying_key

    llavepc = cifrar_aes(sk.to_string(),contraseña)
    # print(llavepc)
    # print(b64encode(llavepc).decode('utf-8'))
    
    # Enviar datos cifrados, firma y clave pública al servidor
    payload = {
        "usuario": usuario,
        "contraseña_hash": (hashlib.sha256(contraseña.encode()).digest()).hex(), # SHA256.new(contraseña),
        "llave_publica": b64encode(vk.to_pem()).decode('utf-8'),
        "llave_privada_cifrada": llavepc
    }
    
    url = "http://127.0.0.1:8080/api/submit_user"

    response = requests.post(url, json=payload)
    # Manejar la respuesta del servidor según tus necesidades
    print("Respuesta del servidor:", response.text)


def cifrar_aes(mensaje, password):
    salt = get_random_bytes(16)  # Generar un salt aleatorio
    clave_aes = derivar_clave_pbkdf2(password, salt)
    iv = get_random_bytes(AES.block_size)  # IV aleatorio
    cifrador = AES.new(clave_aes, AES.MODE_CFB, iv)
    texto_cifrado = cifrador.encrypt(mensaje)
    # print(b64encode(salt).decode('utf-8'))
    # print(b64encode(iv).decode('utf-8'))
    # print(b64encode(texto_cifrado).decode('utf-8'))
    datos_cifrados_concatenados = b64encode(salt).decode('utf-8') + \
                                  b64encode(iv).decode('utf-8') + \
                                  b64encode(texto_cifrado).decode('utf-8')
    return datos_cifrados_concatenados


############################################################################################################################




############################################################################################################################
#  FUNCIONES OCUPADAS PARA CONFIRMAR SESION
############################################################################################################################

def confirmar_usuario(usuario,contraseña):
    # sk = SigningKey.generate(curve=NIST521p)
    # vk = sk.verifying_key
    
    
    contraseña_hasheada = (hashlib.sha256(contraseña.encode()).digest()).hex()
    payload = {
        "usuario": usuario
    }
    
    url = "http://127.0.0.1:8080/api/regresar_user"

    response = requests.post(url, json=payload)
    # response['llave']
    # print(response.text)
    data = json.loads(response.text)
    
    hash_contraseña = data['hash']
    # print(hash_contraseña[0])
    # print(contraseña_hasheada)
    
    if contraseña_hasheada == hash_contraseña[0]:
        return 1
    else: return 0

# Función para pedir la llave del pintor al servidor
def pedir_Llave(NOMBRE,llave):
    url = "http://127.0.0.1:8080/api/recuperar_llave"
    
    # Puedes modificar headers según sea necesario
    headers = {"Content-Type": "application/json"}
    
    # Datos que enviarás en la solicitud (usuario y tipo de llave)
    data = {
        "usuario": NOMBRE,  # Ajusta el nombre del pintor
        "llave": llave  # Pide la llave pública del pintor
    }
    
    
    
    # Realizar la solicitud HTTP al servidor
    response = requests.post(url, json=data, headers=headers)    
    
    if response.status_code == 200:
        # La solicitud fue exitosa
        llave_pintor = response.json()["key"]
        return llave_pintor
    else:
        # La solicitud falló, manejar el error según sea necesario
        print(f"Error al obtener la llave del pintor. Código de estado: {response.status_code}")
        return None
############################################################################################################################



def descifrar_aes(datos_cifrados, password):
    # Separar los datos cifrados concatenados
    salt, iv, texto_cifrado = map(b64decode, (datos_cifrados[:24], datos_cifrados[24:48], datos_cifrados[48:]))
    clave_aes = PBKDF2(password, salt, dkLen=32, count=100000)
    cifrador = AES.new(clave_aes, AES.MODE_CFB, iv)
    texto_descifrado = cifrador.decrypt(texto_cifrado)

    return texto_descifrado


############################################################################################################################
#  FUNCIONES PARA CREAR LAS LLAVES DEL AES CON DH
############################################################################################################################

# Función para generar una clave AES aleatoria
def generate_aes_key(NOMBRE):
    # return get_random_bytes(32)  # Clave de 256 bits
    # Enviar datos cifrados, firma y clave pública al servidor
    ecdh = ECDH(curve=NIST521p)
    ecdh.generate_private_key()
    local_public_key = ecdh.get_public_key()
    
    payload = {
        "public_key": b64encode(local_public_key.to_pem()).decode('utf-8')
    }
    
    url = "http://127.0.0.1:8080/api/ecdh"

    response = requests.post(url, json=payload)
    # response['llave']
    # print(response.text)
    data = json.loads(response.text)
    
    remote_public_key = b64decode(data['llave'])
    ecdh.load_received_public_key_pem(remote_public_key)
    password = ecdh.generate_sharedsecret_bytes()
    # print(data['ID'])
    
    return b64encode(hashlib.sha256(password).digest()), str(data['ID'])

# Función para cifrar datos con AES-GCM
def encrypt_aes_gcm(key, plaintext):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return ciphertext, cipher.nonce, tag

# Función para descifrar datos con AES-GCM
def decrypt_aes_gcm(key, ciphertext, nonce, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# Función para firmar datos con ECDSA
def sign_ecdsa(data,NOMBRE):
    skc = pedir_Llave(NOMBRE, "priv")
    print(skc[0])
    with SecureContext():
        # contrasena = "mi_contrasena_segura"
        # enviar_contrasena(contrasena)
        contraseña = input("Contraseña |")
        sk_s = descifrar_aes(skc[0], contraseña)
        contraseña = None
    sk = SigningKey.from_string(sk_s, curve=NIST521p)
    # with open("private_key_of_" + NOMBRE + ".pem") as f:
    #     sk = SigningKey.from_pem(f.read())
    sig = sk.sign(data)
    return sig

def derivar_clave_pbkdf2(password, salt, key_length=32, iterations=100000):
    # Derivar una clave usando PBKDF2
    clave_derivada = PBKDF2(password, salt, dkLen=key_length, count=iterations)
    return clave_derivada


def cifrar_clave_rsa(clave_publica, mensaje):
    cipher_rsa = PKCS1_OAEP.new(clave_publica)
    cifrado = cipher_rsa.encrypt(mensaje)
    return cifrado

def descifrar_clave_rsa(clave_privada, cifrado):
    cipher_rsa = PKCS1_OAEP.new(clave_privada)
    mensaje_descifrado = cipher_rsa.decrypt(cifrado)
    return mensaje_descifrado.decode("utf-8")


  
    
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
        

def registrate(usuario,contraseña):
    cuenta = {
            "usuario":usuario,
            "contraseña":contraseña
        }
    
    url = "http://127.0.0.1:8080/api/registrar_usuario"

    response = requests.post(url, json=cuenta)
    # Manejar la respuesta del servidor según tus necesidades
    print("Respuesta del servidor:", response.text)
           
# Ejemplo de uso
if __name__ == "__main__":
    
    while(1):
        
        select = int(input("Que quiere hacer?\n1)Registrarte\n2)Iniciar Sesion\n"))
        
        if(select == 1):
            usuario = input("Usuario | ")
            with SecureContext():
                # contrasena = "mi_contrasena_segura"
                # enviar_contrasena(contrasena)
                contraseña = input("Contraseña |")
                # registrate(usuario, SHA256(contraseña))
                llaves_ecdsa(usuario,contraseña)
                contraseña = None
            
        elif(select == 2):
            usuario = input("Usuario | ")
            with SecureContext():
                # contrasena = "mi_contrasena_segura"
                # enviar_contrasena(contrasena)
                contraseña = input("Contraseña |")
                # registrate(usuario, SHA256(contraseña))
                desicion = confirmar_usuario(usuario,contraseña)
                contraseña = None
            
            if desicion == 1:
                while(1):
                    select = int(input("Que quiere hacer?\n1)Crear Pedido\n2)Revisar estado de tus pedidos\n3)Cerrar sesion"))
                    if select == 1:
                        print('crear pedido')
                        # Generar clave AES para la sesión
                        aes_key = secrets.token_bytes(16)
                        
                        # wait = input('Presiona enter para continuar')
                        ventana = tk.Tk()
                        photo_path = filedialog.askopenfilename(initialdir=Path(sys.executable).parent)
                        ventana.destroy()
                        # Ruta de la foto que se enviará al servidor
                        # photo_path = "foto.jpg"
                        # submit_photo(photo_path)
                        
                        # Leer la imagen como bytes
                        with open(photo_path, "rb") as image_file:
                            image_data = b64encode(image_file.read()).decode('utf-8')
                    
                        # Datos del cliente
                        client_data = "Datos confidenciales del cliente"
                        
                        pedido = {
                                "photo": image_data,
                                "data": client_data
                            }
                        
                        json_data = json.dumps(pedido)
                        
                        signature = sign_ecdsa(json_data.encode('utf-8'),usuario)
                    
                        # Cifrar con AES-GCM
                        ciphertext, nonce, tag = encrypt_aes_gcm(aes_key, json_data)
                    
                        # Generar par de claves ECDSA
                        # client_private_key = ECC.generate(curve='P-256')
                        # client_public_key = client_private_key.public_key()
                    
                        # # Firmar los datos con ECDSA
                        # signature = sign_ecdsa(client_private_key, client_data)
                    
                        # Enviar datos cifrados, firma y clave pública al servidor
                        with SecureContext():
                            # contrasena = "mi_contrasena_segura"
                            # enviar_contrasena(contrasena)
                            contraseña = input("Contraseña |")
                            
                            # Llave del pintor
                            llave_pintor = b64decode(pedir_Llave("ROOT","pub"))
                            print(llave_pintor)
                            # print(BytesIO(llave_pintor))
                            # print(b64decode(llave_pintor.encode('utf-8')))
                            aes_llaves_cifradas = {
                                    "key_cliente": cifrar_aes(aes_key,contraseña),
                                    "key_pintor": b64encode(cifrar_clave_rsa(RSA.import_key(llave_pintor),aes_key)).decode('utf-8')
                                }
                            
                            # Asegúrate de manejar el caso en el que la llave del pintor sea None
                            if llave_pintor is not None:
                             contraseña = None

                        payload = {
                            "ciphertext": ciphertext.hex(),
                            "nonce": nonce.hex(),
                            "tag": tag.hex(),
                            "signature": signature.hex(),
                            "aes_key":json.dumps(aes_llaves_cifradas),
                            "name": usuario
                        }
                        
                        url = "http://127.0.0.1:8080/api/submit_order"
                    
                        response = requests.post(url, json=payload)
                    
                        # Manejar la respuesta del servidor según tus necesidades
                        print("Respuesta del servidor:", response.text)
                    elif select == 2:
                        print('revisar estado de pedidos')
                        payload = {
                            "usuario": usuario
                        }
                        
                        url = "http://127.0.0.1:8080/api/recuperar_status"
                    
                        response = requests.post(url, json=payload)
                    
                        # Manejar la respuesta del servidor según tus necesidades
                        print("\n", json.loads(response.text)['key'])
                        selector = input("selecciona el id del pedido que quieres descargar (si el pedido no esta terminado, no podras descargarlo): ")
                        
                        payload = {
                            "usuario": usuario,
                            "ID":selector
                        }
                        
                        url = "http://127.0.0.1:8080/api/descargar_datos"
                    
                        response = requests.post(url, json=payload)
                        pedidossss = json.loads(response.text)
                        # print("\n", bytes.fromhex(pedidossss['pedido']))
                        # print("\n", bytes.fromhex(pedidossss['nonce']))
                        # print("\n", bytes.fromhex(pedidossss['tag']))
                        
                        llave=json.loads(pedidossss['aes_key'])
                        print(llave["key_cliente"])
                        KeyAesPcliente= b64decode(llave["key_cliente"])
                        print(KeyAesPcliente)
                        contraseña = input("Contraseña |")
                        llaveAesGCM=descifrar_aes(llave["key_cliente"],contraseña)
                        print(llaveAesGCM)
                        
                        json_decrypt = decrypt_aes_gcm(llaveAesGCM,bytes.fromhex(pedidossss['pedido']),bytes.fromhex(pedidossss['nonce']),bytes.fromhex(pedidossss['tag']))
                        with open("imagen_decrypt_pedido_" + selector + ".jpg", "wb") as f:
                            f.write(b64decode(json.loads(json_decrypt)['photo']))
                    elif select == 3:
                        print('cerrar sesion')
                        break
                    else:
                        print('No le sabes chavo')
                    #Pedimos nombre
                    # NOMBRE = input('Nombre: ')
                    
                    # Generamos llaves ECDSA
                    
                    
                    # NOMBRE = input("Usuario | ")
                    # wait = input('Presiona enter para continuar')
                    
                # else:
                #     print("no le sabes chavo, intentalo de nuevo")
            else:
                print("No le sabes chavo")
            
            
        
        
        
