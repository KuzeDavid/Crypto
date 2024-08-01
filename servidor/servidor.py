# -*- coding: utf-8 -*-
"""
Created on Mon Nov 20 16:37:47 2023

@author: David
SERVIDOR
"""
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from flask import Flask, request, jsonify
import os
import json
import sqlite3
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from ecdsa import SigningKey, NIST521p
from ecdsa import VerifyingKey, BadSignatureError
from base64 import b64encode, b64decode
from ecdsa import ECDH
import hashlib
# import mysql.connector


conexion=sqlite3.connect("bd1.db")
try:
    conexion.execute("""
                        CREATE TABLE if not exists clientes (
                            ID INTEGER PRIMARY KEY AUTOINCREMENT,
                            usuario VARCHAR(255),
                            contraseña_hash VARCHAR(255),
                            llave_publica VARCHAR(1000),
                            llave_privada_cifrada VARCHAR(1000)
                        )
                    """)
                    
    conexion.execute("""
                        CREATE TABLE if not exists pedidos (
                            ID INTEGER PRIMARY KEY AUTOINCREMENT,
                            pedido_cifrado VARCHAR(255),
                            nonce VARCHAR(255),
                            tag VARCHAR(255),
                            signature VARCHAR(255),
                            aes_key VARCHAR(255),
                            cliente_id INT,
                            status_id INT,
                            FOREIGN KEY (cliente_id) REFERENCES clientes(id),
                            FOREIGN KEY (status_id) REFERENCES status(id)
                        )
                    """)
    conexion.execute("""
                        CREATE TABLE if not exists status_table (
                            ID INTEGER PRIMARY KEY AUTOINCREMENT,
                            status INT,
                            pedido_terminado VARCHAR(255),
                            nonce VARCHAR(255),
                            tag VARCHAR(255)
                        )
                    """)
                    
    print("se creo las tablas articulos")
except sqlite3.OperationalError:
    print("La tabla articulos ya existe") 
    

conexion.commit() 
conexion.close()
    
app = Flask(__name__)


############################################################################################################################
# INICIAR SESION
############################################################################################################################
@app.route('/api/submit_user', methods=['POST'])
def submit_user():
    conexion=sqlite3.connect("bd1.db")
    # print("entreeee")
    # Obtener datos del cuerpo de la solicitud en formato JSON
    data = request.json
    
    # print( b64decode(data['llave_publica']))
    cursor = conexion.execute("select usuario from clientes where usuario = ?",(data['usuario'],))
    user = cursor.fetchone()
    if not user:
        conexion.execute("insert into clientes(usuario,contraseña_hash,llave_publica,llave_privada_cifrada) values (?,?,?,?)", 
                                        (
                                            data['usuario'],
                                            data['contraseña_hash'],
                                            b64decode(data['llave_publica']),
                                            data['llave_privada_cifrada']
                                        )
                         )
        conexion.commit()
        conexion.close()
        return jsonify({"message": "archivos de usuario recibida y guardada correctamente"})
    
    # # Verificar si se recibió un archivo de imagen
    # if 'publick_key' not in requ['publick_key']

    # # Guardar la foto en el directorio del programa
    # save_path = os.path.join(os.path.dirname(__file__), "./servidor/")
    
    # if not os.path.exists(save_path):
    #     os.makedirs(save_path)

    # file_path = os.path.join(save_path, photo.filename)
    # photo.save(file_path)est.files:
    #     return jsonify({"error": "No se recibió ninguna llave publica"})

    # public_key = request.files

    return jsonify({"error": "Usuario ya encontrado"})

########################################################## ##################################################################


############################################################################################################################
# CONFIRMAR SESION
############################################################################################################################
@app.route('/api/regresar_user', methods=['POST'])
def regresar_user():
    conexion=sqlite3.connect("bd1.db")
    # print("entreeee")
    # Obtener datos del cuerpo de la solicitud en formato JSON
    data = request.json
    
    # print( b64decode(data['llave_publica']))
    cursor = conexion.execute("select contraseña_hash from clientes where usuario = ?",(data['usuario'],))
    user = cursor.fetchone()
        

    return jsonify({"hash": user})


############################################################################################################################

############################################################################################################################
# REGRESAR LLAVE
############################################################################################################################
@app.route('/api/recuperar_llave', methods=['POST'])
def recuperar_llave():
    #json = {"usuario": usuario,
    #        "llave": priv/pub}
    conexion=sqlite3.connect("bd1.db")
    # print(entreeee")
    # Obtener datos del cuerpo de la solicitud en formato JSON
    data = request.json
    
    if data['llave'] == 'priv':
        llave = 'llave_privada_cifrada'
    else:
        llave = 'llave_publica'
    # print( b64decode(data['llave_publica']))
    cursor = conexion.execute("select " + llave + " from clientes where usuario = ?",(data['usuario'],))
    user = cursor.fetchone()
        
    if data['llave'] == 'priv':
        return jsonify({"key": user})
    else:
        return jsonify({"key": b64encode(user[0]).decode('utf-8')})
    


############################################################################################################################

############################################################################################################################
# REGRESAR LLAVE
############################################################################################################################
@app.route('/api/recuperar_status', methods=['POST'])
def recuperar_status():
    #json = {"usuario": usuario,
    #        "llave": priv/pub}
    conexion=sqlite3.connect("bd1.db")
    # print(entreeee")
    # Obtener datos del cuerpo de la solicitud en formato JSON
    data = request.json
    
    if data['usuario'] == 'ROOT':
        llave = 'c.usuario'
    else:
        llave = "'" + str(data['usuario']) + "'"
    # print( b64decode(data['llave_publica']))
    print(llave)
    cursor = conexion.execute("select c.usuario, p.ID, st.status from pedidos as p INNER JOIN clientes as c ON p.cliente_id = c.ID INNER JOIN status_table as st ON p.status_id = st.ID where c.usuario = " + llave)
    # print(cursor)
    texto = ''
    for fila in cursor:
        if fila[2] == 0:
            texto = texto + 'Usuario: ' + fila[0] + ' | ID pedido: ' + str(fila[1]) + ' | status: En proceso\n' #print(fila)
        else:
            texto = texto + 'Usuario: ' + fila[0] + ' | ID pedido: ' + str(fila[1]) + ' | status: Terminado\n' 
    return jsonify({"key": texto})
    


############################################################################################################################



@app.route('/api/enviar_datos_cifrados', methods=['POST'])
def enviar_datos_cifrados(data):
    conexion=sqlite3.connect("bd1.db")
    cursor=conexion.execute("select ID from clientes where usuario = '" + data['name'] + "'")
    fila=cursor.fetchone()
    
    # conexion.execute("insert into pedidos(pedido_cifrado,nonce,tag,signature,cliente_id) values (?,?,?,?,?) WHERE ID = " + data['ID'], (
    #         data['ciphertext'],
    #         data['nonce'],
    #         data['tag'],
    #         data['signature'],
    #         # data['aes_key'],
    #         int(fila[0])
    #         )
    #     )
    conexion.execute("INSERT INTO status_table (status) values (?)",(0,))
    
    cursor=conexion.execute("select seq from sqlite_sequence where name = 'status_table'")
    fila_ID_status=cursor.fetchone()
    print(fila_ID_status)
    
    conexion.execute("INSERT INTO pedidos (pedido_cifrado, nonce, tag, signature, aes_key, cliente_id, status_id) values (?,?,?,?,?,?,?)", (
        data['ciphertext'],
        data['nonce'],
        data['tag'],
        data['signature'],
        data['aes_key'],
        int(fila[0]),
        fila_ID_status[0]
    ))

    conexion.commit() 
    conexion.close()         
    
@app.route('/api/descargar_datos', methods=['POST'])
def descargar_datos():
    conexion=sqlite3.connect("bd1.db")
    # print("entreeee")
    # Obtener datos del cuerpo de la solicitud en formato JSON
    data = request.json
    
    # print( b64decode(data['llave_publica']))
    cursor = conexion.execute("select st.*, p.aes_key from pedidos as p INNER JOIN clientes as c ON p.cliente_id = c.ID INNER JOIN status_table as st ON p.status_id = st.ID where c.usuario = '" +  data['usuario'] + "' AND st.status = 1 AND p.ID = " + data['ID'])
        # "select * from status_table where usuario = ? AND ",(data['usuario'],))
    fila=cursor.fetchone()
    conexion.commit()
    conexion.close()
    # print(fila[2])
    # print(fila[3])
    # print(fila[4])
    print(fila[5])
    return jsonify({ "pedido": fila[2],
                    "nonce": fila[3],
                    "tag": fila[4],
                    "aes_key": fila[5]
        }
        )
    
    # # Verificar si se recibió un archivo de imagen
    # if 'publick_key' not in requ['publick_key']

    # # Guardar la foto en el directorio del programa
    # save_path = os.path.join(os.path.dirname(__file__), "./servidor/")
    
    # if not os.path.exists(save_path):
    #     os.makedirs(save_path)

    # file_path = os.path.join(save_path, photo.filename)
    # photo.save(file_path)est.files:
    #     return jsonify({"error": "No se recibió ninguna llave publica"})

    # public_key = request.files

    return jsonify({"error": "Usuario ya encontrado"})


    

@app.route('/api/submit_order', methods=['POST'])
def submit_order():
    # Obtener datos del cuerpo de la solicitud en formato JSON
    data = request.json

    # Guardar los datos en un archivo JSON en el directorio del programa
    save_path = os.path.join(os.path.dirname(__file__), "data_received.json")

    with open(save_path, "a") as json_file:
        json.dump(data, json_file, indent=4)

    enviar_datos_cifrados(data)
    
    # Simplemente devuelve una respuesta de prueba
    return jsonify({"message": "Datos recibidos correctamente"})



@app.route('/api/submit_photo', methods=['POST'])
def submit_photo():
    # Verificar si se recibió un archivo de imagen
    if 'photo' not in request.files:
        return jsonify({"error": "No se recibió ninguna foto"})

    photo = request.files['photo']

    # Guardar la foto en el directorio del programa
    save_path = os.path.join(os.path.dirname(__file__), "./servidor/")
    
    if not os.path.exists(save_path):
        os.makedirs(save_path)

    file_path = os.path.join(save_path, photo.filename)
    photo.save(file_path)
    # print("siiiiiiiiii")
    return jsonify({"message": "Foto recibida y guardada correctamente"})

@app.route('/api/receive_order', methods=['POST'])
def receive_order():
    # Obtener datos del cuerpo de la solicitud en formato JSON
    data = request.json

    # Verificar que se proporcionó el ID del usuario
    if 'ID' not in data:
        return jsonify({"error": "Falta el ID del usuario en la solicitud"})

    user_id = int(data['ID'])

    # Buscar el cliente en la base de datos
    conexion = sqlite3.connect("bd1.db")
    cursor = conexion.execute("SELECT ID, Nombre, llave_publica FROM clientes WHERE ID=?", (user_id,))
    user = cursor.fetchone()

    if not user:
        conexion.close()
        return jsonify({"error": "Usuario no encontrado"})

    # Resto del código para procesar la orden aquí...

    # Por ejemplo, puedes imprimir el ID y el nombre del usuario
    print(f"Recibida orden para el usuario ID={user[0]}, Nombre={user[1]}")

    # Resto del código para procesar la orden aquí...

    conexion.close()

    # Devuelve una respuesta de prueba
    return jsonify({"message": "Orden recibida correctamente para el usuario", "user_id": user_id})

    

@app.route('/api/ecdh', methods=['POST'])
def ecdh():
    data = request.json
    conexion=sqlite3.connect("bd1.db")
        
    ecdh = ECDH(curve=NIST521p)
    ecdh.generate_private_key()
    local_public_key = ecdh.get_public_key()
    
    remote_public_key = b64decode(data['public_key'])
    # print(remote_public_key)
    ecdh.load_received_public_key_pem(remote_public_key)
    password = ecdh.generate_sharedsecret_bytes()
    # print(secret)
    
    # print(b64encode(hashlib.sha256(password).digest()))
    
    conexion.execute("INSERT INTO pedidos (aes_key) VALUES (?)", (
        b64encode(hashlib.sha256(password).digest()),
        ))
    
        
    cursor=conexion.execute("select seq from sqlite_sequence where name = 'pedidos'")
    fila_ID=cursor.fetchone()
    # print(fila_ID)
        
    conexion.commit() 
    conexion.close() 
    return jsonify(
                        {
                            "llave": b64encode(local_public_key.to_pem()).decode('utf-8'),
                            "ID": str(fila_ID[0])
                         }
                   )


    

# Ejemplo de uso
if __name__ == "__main__":
    
    app.run(host='127.0.0.1', port=8080, debug=True)
     


