from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes

def descifraPasos1y3(emisor, KET, t_cifrado, t_mac, t_nonce):
    """ Descifra el mensaje del paso 1/3, y devuelve los campos"""
    # Descifro los datos con AES GCM
    datos_descifrado_ET = funciones_aes.descifrarAES_GCM(KET, t_nonce, t_cifrado, t_mac)

    # Decodifica el contenido: Alice, Na
    json_ET = datos_descifrado_ET.decode("utf-8" ,"ignore")
    print(emisor + "->T (descifrado): " + json_ET)
    msg_ET = json.loads(json_ET)

    # Extraigo el contenido, y lo devuelvo
    t_emisor, t_ne = msg_ET
    t_ne = bytearray.fromhex(t_ne)
    return t_emisor, t_ne

def cifraPasos2y4(receptor, KET, K1, K2, t_ne):
    """ Cifra el mensaje del  paso 2/4, y devuelve el cifrado """
    # Codifica el contenido (los campos binarios en una cadena) y contruyo el mensaje JSON
    msg_TE = []
    msg_TE.append(K1.hex())
    msg_TE.append(K2.hex())
    msg_TE.append(t_ne.hex())
    json_ET = json.dumps(msg_TE)
    print("T->" + receptor + " (descifrado): " + json_ET)

    # Cifra los datos con AES GCM
    aes_engine = funciones_aes.iniciarAES_GCM(KET)
    t_cifrado, t_mac, t_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_ET.encode("utf-8"))

    return t_cifrado, t_mac, t_nonce


# Crear Clave KAT, guardar a fichero
KAT = funciones_aes.crear_AESKey()
FAT = open("KAT.bin", "wb")
FAT.write(KAT)
FAT.close()
 
# Crear Clave KBT, guardar a fichero
KBT = funciones_aes.crear_AESKey()
FBT = open("KBT.bin", "wb")
FBT.write(KBT)
FBT.close()

# Crear el socket de escucha de Bob (5551)
print("Esperando a Bob...")
socket_Bob = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket_Bob.escuchar()

# Crea la respuesta para B y A: K1 y K2
K1 = funciones_aes.crear_AESKey()
K2 = funciones_aes.crear_AESKey()

# Paso 1) B->T: KBT(Bob, Nb) en AES-GCM
cifrado = socket_Bob.recibir()
cifrado_mac = socket_Bob.recibir()
cifrado_nonce = socket_Bob.recibir()
_, t_nb = descifraPasos1y3("B", KBT, cifrado, cifrado_mac, cifrado_nonce)

# Paso 2) T->B: KBT(K1, K2, Nb) en AES-GCM
cifrado, cifrado_mac, cifrado_nonce = cifraPasos2y4("B", KBT, K1, K2, t_nb)
socket_Bob.enviar(cifrado)
socket_Bob.enviar(cifrado_mac)
socket_Bob.enviar(cifrado_nonce)

# Crear el socket de escucha de Alice (5550)
print("Esperando a Alice...")
socket_Alice = SOCKET_SIMPLE_TCP('127.0.0.1', 5550)
socket_Alice.escuchar()

# Paso 3) A->T: KAT(Alice, Na) en AES-GCM
cifrado = socket_Alice.recibir()
cifrado_mac = socket_Alice.recibir()
cifrado_nonce = socket_Alice.recibir()
_, t_na = descifraPasos1y3("A", KAT, cifrado, cifrado_mac, cifrado_nonce)

# Paso 4) T->A: KAT(K1, K2, Na) en AES-GCM
cifrado, cifrado_mac, cifrado_nonce = cifraPasos2y4("A", KAT, K1, K2, t_na)
socket_Alice.enviar(cifrado)
socket_Alice.enviar(cifrado_mac)
socket_Alice.enviar(cifrado_nonce)

# T termina su trabajo :-)
socket_Alice.cerrar()
socket_Bob.cerrar()