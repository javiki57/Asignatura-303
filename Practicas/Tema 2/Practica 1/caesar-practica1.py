def cifradoCesarAlfabetoInglesMAY(cadena):
    """Devuelve un cifrado Cesar tradicional (+3)"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a cifrar
        ordenClaro = ord(cadena[i])
        ordenCifrado = 0
        # Cambia el caracter a cifrar
        if (ordenClaro >= 65 and ordenClaro <= 90):
            ordenCifrado = (((ordenClaro - 65) + 3) % 26) + 65
        # Añade el caracter cifrado al resultado
        resultado = resultado + chr(ordenCifrado)
        i = i + 1
    # devuelve el resultado
    return resultado

def cifradoCesarAlfabetoIngles(cadena):
    """Devuelve un cifrado Cesar tradicional (+3)"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a cifrar
        ordenClaro = ord(cadena[i])
        ordenCifrado = 0
        # Cambia el caracter a cifrar
        if (ordenClaro >= 65 and ordenClaro <= 90):
            ordenCifrado = (((ordenClaro - 65) + 3) % 26) + 65
        if (ordenClaro >= 97 and ordenClaro <= 122):
            ordenCifrado = (((ordenClaro - 97) + 3) % 26) + 97
        # Añade el caracter cifrado al resultado
        resultado = resultado + chr(ordenCifrado)
        i = i + 1
    # devuelve el resultado
    return resultado

def descifradoCesarAlfabetoInglesMAY(cadena):
    """Devuelve un cifrado Cesar tradicional (+3)"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "descifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a descifrar
        ordenClaro = ord(cadena[i])
        ordenCifrado = 0
        # Cambia el caracter a descifrar
        if (ordenClaro >= 65 and ordenClaro <= 90):
            ordenCifrado = (((ordenClaro - 65) - 3) % 26) + 65
        # Añade el caracter descifrado al resultado
        resultado = resultado + chr(ordenCifrado)
        i = i + 1
    # devuelve el resultado
    return resultado

def descifradoCesarAlfabetoIngles(cadena):
    """Devuelve un cifrado Cesar tradicional (+3)"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "descifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a descifrar
        ordenClaro = ord(cadena[i])
        ordenCifrado = 0
        # Cambia el caracter a descifrar
        if (ordenClaro >= 65 and ordenClaro <= 90):
            ordenCifrado = (((ordenClaro - 65) - 3) % 26) + 65
        if (ordenClaro >= 97 and ordenClaro <= 122):
            ordenCifrado = (((ordenClaro - 97) - 3) % 26) + 97
        # Añade el caracter descifrado al resultado
        resultado = resultado + chr(ordenCifrado)
        i = i + 1
    # devuelve el resultado
    return resultado

def cifradoMonoalfabeticoInglesMAY(claro, secreto):
    """Devuelve un cifrado monoalfabetico, donde A suma +1 y Z suma +26"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    idxClaro = 0
    idxSecreto = 0
    while idxClaro < len(claro):
        # Recoge el caracter a cifrar y el caracter que cifra
        ordenClaro = ord(claro[idxClaro])
        ordenSecreto = ord(secreto[idxSecreto])
        # Cambia el caracter a cifrar
        if (ordenClaro >= 65 and ordenClaro <= 90) and (ordenSecreto >= 65 and ordenSecreto <= 90):
            ordenCifrado = (((ordenClaro - 65) + (ordenSecreto - 65 + 1)) % 26) + 65
        # Añade el caracter cifrado al resultado
        resultado = resultado + chr(ordenCifrado)
        idxClaro = idxClaro + 1
        idxSecreto = (idxSecreto + 1) % len(secreto)
    # devuelve el resultado
    return resultado

def descifradoMonoalfabeticoInglesMAY(cifrado, secreto):
    """Devuelve un cifrado monoalfabetico, donde A suma +1 y Z suma +26 (ver enunciado)"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "descifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    idxCifrado = 0
    idxSecreto = 0
    while idxCifrado < len(cifrado):
        # Recoge el caracter a descifrar y el caracter que descifra
        ordenCifrado = ord(cifrado[idxCifrado])
        ordenSecreto = ord(secreto[idxSecreto])
        # Cambia el caracter a descifrar
        if (ordenCifrado >= 65 and ordenCifrado <= 90) and (ordenSecreto >= 65 and ordenSecreto <= 90):
            ordenCifrado = (((ordenCifrado - 65) - (ordenSecreto - 65 + 1)) % 26) + 65
        # Añade el caracter descifrado al resultado
        resultado = resultado + chr(ordenCifrado)
        idxCifrado = idxCifrado + 1
        idxSecreto = (idxSecreto + 1) % len(secreto)
    # devuelve el resultado
    return resultado

claroCESARMAY = 'VENI VIDI VINCI AURIA'
print(claroCESARMAY)
cifradoCESARMAY = cifradoCesarAlfabetoInglesMAY(claroCESARMAY) 
print(cifradoCESARMAY)

claroCESAR = 'VENI vidi VINCI auria'
print(claroCESAR)
cifradoCESAR = cifradoCesarAlfabetoIngles(claroCESAR) 
print(cifradoCESAR)
print(descifradoCesarAlfabetoIngles(cifradoCESAR))

claroMONO = 'HOLAAMIGOS'
print(claroMONO)
cifradoMONO = cifradoMonoalfabeticoInglesMAY(claroMONO,'CIFRA') 
print(cifradoMONO)
print(descifradoMonoalfabeticoInglesMAY(cifradoMONO,'CIFRA'))