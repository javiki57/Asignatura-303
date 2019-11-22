from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

def crear_ECCKey():
    key = ECC.generate(curve='P-256')

    return key

def guardar_ECCKey_Privada(fichero, key, password):
    key_cifrada = key.export_key(passphrase=password, format = "DER", use_pkcs8=True, protection="PBKDF2WithHMAC-SHA1AndAES128-CBC")
    file_out = open(fichero, "wb")
    file_out.write(key_cifrada)
    file_out.close()

def cargar_ECCKey_Privada(fichero, password):
    key_cifrada = open(fichero, "rb").read()
    key = ECC.import_key(key_cifrada, passphrase=password)

    return key

def guardar_ECCKey_Publica(fichero, key):
    key_pub = key.public_key().export_key(format = "DER")
    file_out = open(fichero, "wb")
    file_out.write(key_pub)
    file_out.close()

def cargar_ECCKey_Publica(fichero):
    keyFile = open(fichero, "rb").read()
    key_pub = ECC.import_key(keyFile)

    return key_pub

def firmarECC_DSS(texto, key_private):
    h = SHA256.new(texto.encode("utf-8")) 
    signer = DSS.new(key_private, 'fips-186-3')
    signature = signer.sign(h)

    return signature

def comprobarECC_DSS(texto, firma, key_public):
    h = SHA256.new(texto.encode("utf-8"))
    print(h.hexdigest())
    verifier = DSS.new(key_public, 'fips-186-3')
    try:
        verifier.verify(h, firma)
        return True
    except (ValueError, TypeError):
        return False

# Main
# Crear clave ECC
# y guardar en ficheros la clave privada (protegida) y publica
cadena = "Hola amigos de la seguridad"
password = "password"
fichero_privado = "ecc_key.der"
fichero_publico = "ecc_key.pub"
key = crear_ECCKey()
guardar_ECCKey_Privada(fichero_privado, key, password)
guardar_ECCKey_Publica(fichero_publico, key)

# Cargar la clave RSA privada del fichero, y muestra ambas en pantalla
# (La estructura de la clave privada tambien guarda la clave publica)
key = cargar_ECCKey_Privada(fichero_privado, password)
print(key.public_key().export_key(format = "PEM"))
print(key.export_key(format = "PEM"))

# Firmar y comprobar con DSS
firma = firmarECC_DSS(cadena, key)

keypub = cargar_ECCKey_Publica(fichero_publico)
if comprobarECC_DSS(cadena, firma, keypub):
    print("La firma es valida")
else:
    print("La firma es invalida")