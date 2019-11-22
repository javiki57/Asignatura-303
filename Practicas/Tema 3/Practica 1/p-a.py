from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

def cifraPaso1(emisor, receptor, KET, E, t_ne):
    """ Cifra el mensaje del paso 1, y devuelve el cifrado """
    # Codifica el contenido (los campos binarios en una cadena) y contruyo el mensaje JSON
    msg_TE = []
    msg_TE.append(E)
    msg_TE.append(t_ne.hex())
    json_ET = json.dumps(msg_TE)
    print(emisor + "->" + receptor + " (descifrado): " + json_ET)

    # Cifra los datos con AES GCM
    aes_engine = funciones_aes.iniciarAES_GCM(KET)
    t_cifrado, t_mac, t_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_ET.encode("utf-8"))

    return t_cifrado, t_mac, t_nonce

def descifraPaso2(receptor, emisor, KET, t_cifrado, t_mac, t_nonce):
    """ Descifra el mensaje del paso 2, y devuelve los campos"""
    # Descifro los datos con AES GCM
    datos_descifrado_ET = funciones_aes.descifrarAES_GCM(KET, t_nonce, t_cifrado, t_mac)

    # Decodifica el contenido: K1, K2, Nb
    json_ET = datos_descifrado_ET.decode("utf-8" ,"ignore")
    print(emisor + "->" + receptor +" (descifrado): " + json_ET)
    msg_ET = json.loads(json_ET)

    # Extraigo el contenido, y lo devuelvo
    t_k1, t_k2, t_ne = msg_ET
    t_k1 = bytearray.fromhex(t_k1)
    t_k2 = bytearray.fromhex(t_k2)
    t_ne = bytearray.fromhex(t_ne)
    return t_k1, t_k2, t_ne

# Lee clave KAT
KAT = open("KAT.bin", "rb").read()

# Crear el socket de conexion con T (5550)
print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5550)
socket.conectar()

# Paso 1) A->T: KAT(Alice, Na) en AES-GCM
t_n_origen = get_random_bytes(16)
cifrado, cifrado_mac, cifrado_nonce = cifraPaso1("A", "T", KAT, "Alice", t_n_origen)
socket.enviar(cifrado)
socket.enviar(cifrado_mac)
socket.enviar(cifrado_nonce)

# Paso 2) T->A: KAT(K1, K2, Na) en AES-GCM
cifrado = socket.recibir()
cifrado_mac = socket.recibir()
cifrado_nonce = socket.recibir()
socket.cerrar()
k1, k2, t_n_destino = descifraPaso2("A", "T", KAT, cifrado, cifrado_mac, cifrado_nonce)

# Compara que el nonce sea el mismo en el origen y la respuesta
if (t_n_origen != t_n_destino):
    print("T->B: El nonce es incorrecto")
    sys.exit()

# Conexion con Bob
print("Conectandose con Bob...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket.conectar()

# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
mensaje = "Nombre"
print("A->B (descifrado): " + mensaje)
mensaje = mensaje.encode("utf-8")

aes_engine = funciones_aes.iniciarAES_CTR(k1)
cifrado, cifrado_nonce = funciones_aes.cifrarAES_CTR(aes_engine, mensaje)
hash_engine = HMAC.new(bytes(k2), digestmod=SHA256)
hash_engine.update(mensaje)
cifrado_hmac = hash_engine.digest()
socket.enviar(cifrado)
socket.enviar(cifrado_hmac)
socket.enviar(cifrado_nonce)

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
cifrado = socket.recibir()
cifrado_hmac = socket.recibir()
cifrado_nonce = socket.recibir()
mensaje = funciones_aes.descifrarAES_CTR(k1, cifrado_nonce, cifrado)
print("B->A (descifrado): " + mensaje.decode("utf-8", "ignore"))

hash_engine = HMAC.new(bytes(k2), digestmod=SHA256)
hash_engine.update(mensaje)
try:
    hash_engine.verify(cifrado_hmac)
except ValueError:
    print("B->A: Mensaje erroneo")
    sys.exit()

# Termina la comunicacion
socket.cerrar()
