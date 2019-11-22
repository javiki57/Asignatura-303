import funciones_rsa

password_bob = "bob"
fichero_alice = "rsa_alice"
fichero_bob = "rsa_bob"

# Cargar la clave privada de Bob y la clave pública de Alice
key_bob = funciones_rsa.cargar_RSAKey_Privada(fichero_bob + ".pem", password_bob)
key_alice = funciones_rsa.cargar_RSAKey_Publica(fichero_alice + ".pub")

# Cargar el texto cifrado y la firma digital.
cifrado = open("cifrado.bin", "rb").read()
firma = open("firma.bin", "rb").read()
print("CIFRADO: " + cifrado.hex())
print("FIRMA: " + firma.hex())

# Descifrar el texto cifrado y mostrarlo por pantalla.
descifrado = funciones_rsa.descifrarRSA_OAEP(cifrado, key_bob)
print("TEXTO EN CLARO: " + descifrado)

# Comprobar la validez de la firma digital.
if funciones_rsa.comprobarRSA_PSS(descifrado, firma, key_alice):
    print("La firma es valida. El mensaje proviene de Alice.")
else:
    print("La firma es INVALIDA. El mensaje NO proviene de Alice.")
