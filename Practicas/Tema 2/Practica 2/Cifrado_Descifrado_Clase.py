from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Util import Counter

class DES_CIPHER:
    BLOCK_SIZE_DES = 8
    def __init__(self, key):
        """Inicializa las variables locales"""
        self.key = key

    def cifrar(self, cadena, IV):
        """Cifra el parametro cadena (de tipo String), y devuelve el texto cifrado binario"""
        datos = cadena.encode("utf-8")
        cipher = DES.new(self.key, DES.MODE_CBC, IV)
        return cipher.encrypt(pad(datos,type(self).BLOCK_SIZE_DES))

    def descifrar(self, datos, IV):
        """Cifra el parametro datos (de tipo binario), y devuelve la cadena en claro de tipo String"""
        cipher = DES.new(self.key, DES.MODE_CBC, IV)
        return unpad(cipher.decrypt(datos), type(self).BLOCK_SIZE_DES).decode("utf-8", "ignore")

class AES_CIPHER:
    BLOCK_SIZE_AES = 16
    def __init__(self, key):
        """Inicializa las variables locales"""
        self.key = key

    def cifrar(self, cadena, IV):
        """Cifra el parametro cadena (de tipo String), y devuelve el texto cifrado binario"""
        datos = cadena.encode("utf-8")
        cipher = AES.new(self.key, AES.MODE_CBC, IV)
        return cipher.encrypt(pad(datos,type(self).BLOCK_SIZE_AES))

    def descifrar(self, datos, IV):
        """Cifra el parametro datos (de tipo binario), y devuelve la cadena en claro de tipo String"""
        cipher = AES.new(self.key, AES.MODE_CBC, IV)
        return unpad(cipher.decrypt(datos), type(self).BLOCK_SIZE_AES).decode("utf-8", "ignore")

# Cifrado y Descifrado con DES
##############################
print("")
print("Cifrado y Descifrado con DES")
print("----------------------------")
key_8 = get_random_bytes(8) # Clave aleatoria de 64 bits
IV_8 = get_random_bytes(8)  # IV aleatorio de 64 bits
datos_DES = "Hola Mundo con DES en modo CBC"
print(datos_DES)
des_engine = DES_CIPHER(key_8)
cifrado_DES = des_engine.cifrar(datos_DES, IV_8)
print(cifrado_DES)
descifrado_DES = des_engine.descifrar(cifrado_DES, IV_8)
print(descifrado_DES)

# Cifrado y Descifrado con AES
##############################
print("")
print("Cifrado y Descifrado con AES")
print("----------------------------")
key_16 = get_random_bytes(16) # Clave aleatoria de 128 bits
IV_16 = get_random_bytes(16)  # IV aleatorio de 128 bits
datos_AES = "Hola amigos de la seguridad"
print(datos_AES)
aes_engine = AES_CIPHER(key_16)
cifrado_AES = aes_engine.cifrar(datos_AES, IV_16)
print(cifrado_AES)
descifrado_AES = aes_engine.descifrar(cifrado_AES, IV_16)
print(descifrado_AES)

datos_AES = "Hola amigas de la seguridad"
print(datos_AES)
aes_engine = AES_CIPHER(key_16)
cifrado_AES = aes_engine.cifrar(datos_AES, IV_16)
print(cifrado_AES)
descifrado_AES = aes_engine.descifrar(cifrado_AES, IV_16)
print(descifrado_AES)

# Cifrado y Descifrado con AES - Modos
######################################
print("")
print("Cifrado y Descifrado con AES - Modo ECB")
print("---------------------------------------")
key_16 = get_random_bytes(16) # Clave aleatoria de 128 bits
datos = "Hola Amigos de Seguridad"
print(datos)
aes_cifrado = AES.new(key_16, AES.MODE_ECB)
datos_cifrado = aes_cifrado.encrypt(pad(datos.encode("utf-8"),16))
print(datos_cifrado)
aes_descifrado = AES.new(key_16, AES.MODE_ECB)
datos_claro = unpad(aes_descifrado.decrypt(datos_cifrado),16).decode("utf-8", "ignore")
print(datos_claro)

print("")
print("Cifrado y Descifrado con AES - Modo CTR")
print("---------------------------------------")
key_16 = get_random_bytes(16)  # Clave aleatoria de 128 bits
nonce_16 = get_random_bytes(8) # nonce aleatorio de 64 bits
                                 # --64 nonce--|--64 contador--
ctr_16 = 0                     # contador, empezando desde 0
datos = "Hola Amigos de Seguridad"
print(datos)
aes_cifrado = AES.new(key_16, AES.MODE_CTR, nonce = nonce_16, initial_value = ctr_16)
datos_cifrado = aes_cifrado.encrypt(datos.encode("utf-8"))
print(datos_cifrado)
aes_descifrado = AES.new(key_16, AES.MODE_CTR, nonce = nonce_16, initial_value = ctr_16)
datos_claro = aes_descifrado.decrypt(datos_cifrado).decode("utf-8", "ignore")
print(datos_claro)

print("")
print("Cifrado y Descifrado con AES - Modo OFB")
print("---------------------------------------")
key_16 = get_random_bytes(16) # Clave aleatoria de 128 bits
IV_16 = get_random_bytes(16)  # IV aleatorio de 128 bits
datos = "Hola Amigos de Seguridad"
print(datos)
aes_cifrado = AES.new(key_16, AES.MODE_OFB, IV_16)
datos_cifrado = aes_cifrado.encrypt(datos.encode("utf-8"))
print(datos_cifrado)
aes_descifrado = AES.new(key_16, AES.MODE_OFB, IV_16)
datos_claro = aes_descifrado.decrypt(datos_cifrado).decode("utf-8", "ignore")
print(datos_claro)

print("")
print("Cifrado y Descifrado con AES - Modo CFB")
print("---------------------------------------")
key_16 = get_random_bytes(16) # Clave aleatoria de 128 bits
IV_16 = get_random_bytes(16)  # IV aleatorio de 128 bits
datos = "Hola Amigos de Seguridad"
print(datos)
aes_cifrado = AES.new(key_16, AES.MODE_CFB, IV_16)
datos_cifrado = aes_cifrado.encrypt(datos.encode("utf-8"))
print(datos_cifrado)
aes_descifrado = AES.new(key_16, AES.MODE_CFB, IV_16)
datos_claro = aes_descifrado.decrypt(datos_cifrado).decode("utf-8", "ignore")
print(datos_claro)


print("")
print("Cifrado y Descifrado con AES - Modo GCM")
print("---------------------------------------")
key_16 = get_random_bytes(16)   # Clave aleatoria de 128 bits
nonce_16 = get_random_bytes(16) # Nonce aleatorio de 128 bits
mac_size = 16                   # Usaremos una MAC de 16 bytes / 128 bits
datos = "Hola Amigos de Seguridad"
print(datos)
aes_cifrado = AES.new(key_16, AES.MODE_GCM, nonce = nonce_16, mac_len = mac_size)
datos_cifrado, mac_cifrado = aes_cifrado.encrypt_and_digest(datos.encode("utf-8"))
print(datos_cifrado)
try:
    aes_descifrado = AES.new(key_16, AES.MODE_GCM, nonce = nonce_16)
    datos_claro = aes_descifrado.decrypt_and_verify(datos_cifrado, mac_cifrado).decode("utf-8", "ignore")
    print(datos_claro)
except (ValueError, KeyError) as e:
    print("Error en el descifrado de AES GCM")