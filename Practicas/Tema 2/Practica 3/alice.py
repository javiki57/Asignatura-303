import funciones_rsa

password_alice = "alice"
fichero_alice = "rsa_alice"
fichero_bob = "rsa_bob"

# Cargar la clave privada de Alice y la clave pública de Bob. 
key_alice = funciones_rsa.cargar_RSAKey_Privada(fichero_alice + ".pem", password_alice)
key_bob = funciones_rsa.cargar_RSAKey_Publica(fichero_bob + ".pub")

# Cifrar el texto “Hola amigos de la seguridad” utilizando la clave de Bob.
cadena = "Hola amigos de la seguridad"
cifrado = funciones_rsa.cifrarRSA_OAEP(cadena, key_bob)
print("CIFRADO: " + cifrado.hex())

# Firmar el texto “Hola amigos de la seguridad” utilizando la clave de Alice.
firma = funciones_rsa.firmarRSA_PSS(cadena, key_alice)
print("FIRMA: " + firma.hex())

# Guardar en unos ficheros el texto cifrado y la firma digital. 
file_cifra = open("cifrado.bin", "wb")
file_cifra.write(cifrado)
file_cifra.close()

file_firma = open("firma.bin", "wb")
file_firma.write(firma)
file_firma.close()
