# cesarsimple.py
import sys

def cesar_cipher(texto, desplazamiento):
    resultado = ""

    for char in texto:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            resultado += chr((ord(char) - base + desplazamiento) % 26 + base)
        else:
            resultado += char

    return resultado

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: py cesarsimple.py <texto> <desplazamiento>")
        sys.exit(1)

    texto = sys.argv[1]
    try:
        desplazamiento = int(sys.argv[2])
    except ValueError:
        print("El desplazamiento debe ser un número entero.")
        sys.exit(1)

    print(cesar_cipher(texto, desplazamiento))
