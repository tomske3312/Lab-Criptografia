# -*- coding: utf-8 -*-

# Importamos las capas y funciones necesarias de Scapy y el módulo sys
from scapy.all import rdpcap, ICMP, IP, Raw 
import sys

def extraer_mensaje_pcap_filtrado(pcap_file, ip_destino_filtro="8.8.8.8"):
    """
    Extrae los caracteres en la posición 0x20 (decimal 32) del payload 
    de los paquetes ICMP echo request (tipo 8) ENVIADOS a una IP específica 
    en un archivo PCAP.
    """
    try:
        # Leemos todos los paquetes del archivo PCAP
        paquetes = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"Error: El archivo '{pcap_file}' no fue encontrado.")
        sys.exit(1)
    except Exception as e:
        # Capturamos otros posibles errores al leer el PCAP
        print(f"Error al leer el archivo PCAP '{pcap_file}': {e}")
        sys.exit(1)
        
    mensaje_cifrado = ""
    contador_paquetes_procesados = 0
    
    # Iteramos sobre cada paquete leído
    for pkt in paquetes:
        # 1. Verificamos si el paquete tiene capa IP y capa ICMP
        if IP in pkt and ICMP in pkt:
            # 2. Verificamos si la IP de destino es la que buscamos (8.8.8.8)
            #    Y si el tipo de ICMP es 8 (echo request)
            if pkt[IP].dst == ip_destino_filtro and pkt[ICMP].type == 8:
                # 3. Verificamos si existe una capa de datos Raw (payload)
                if Raw in pkt:
                    payload = pkt[Raw].load
                    # 4. Verificamos si el payload tiene longitud suficiente (mayor a 0x20)
                    if len(payload) > 0x20: 
                        # 5. Extraemos el byte en la posición 0x20 (el byte número 33)
                        byte_objetivo = payload[0x20:0x21] # Tomamos un slice para mantenerlo como bytes
                        
                        # 6. Intentamos decodificar el byte a carácter (UTF-8 o Latin-1)
                        try:
                            caracter = byte_objetivo.decode('utf-8')
                        except UnicodeDecodeError:
                            try:
                               caracter = byte_objetivo.decode('latin-1') 
                            except Exception:
                                # Si no se puede decodificar, lo omitimos y continuamos
                                # print(f"Advertencia: No se pudo decodificar el byte en la posición 0x20 del paquete {pkt.summary()}.")
                                continue 
                        
                        # 7. Añadimos el carácter al mensaje cifrado
                        mensaje_cifrado += caracter
                        contador_paquetes_procesados += 1
                        
    if contador_paquetes_procesados == 0:
        print(f"Advertencia: No se encontraron paquetes ICMP tipo 8 enviados a {ip_destino_filtro} con payload de longitud suficiente (> 0x20).")
    elif not mensaje_cifrado:
         print(f"Advertencia: Se procesaron {contador_paquetes_procesados} paquetes, pero no se pudo construir un mensaje (posibles problemas de decodificación).")
        
    return mensaje_cifrado, contador_paquetes_procesados

def descifrar_cesar(texto_cifrado, desplazamiento):
    """
    Descifra un texto que fue cifrado con el cifrado César, probando un desplazamiento específico.
    Considera tanto mayúsculas como minúsculas. Los caracteres no alfabéticos se mantienen.
    """
    resultado = ""
    
    for char in texto_cifrado:
        if 'a' <= char <= 'z':
            base = ord('a')
            # Aplicamos la fórmula de descifrado César para minúsculas
            resultado += chr((ord(char) - base - desplazamiento) % 26 + base)
        elif 'A' <= char <= 'Z':
            base = ord('A')
            # Aplicamos la fórmula de descifrado César para mayúsculas
            resultado += chr((ord(char) - base - desplazamiento) % 26 + base)
        else:
            # Si no es una letra, la añadimos tal cual
            resultado += char
            
    return resultado

# --- Bloque Principal de Ejecución ---
if __name__ == "__main__":
    # Verificamos que se pase el nombre del archivo como argumento
    if len(sys.argv) != 2:
        print(f"Uso: python {sys.argv[0]} <archivo.pcap>")
        print(f"Ejemplo: python {sys.argv[0]} mensaje_cifrado_enviado.pcap")
        sys.exit(1)
    
    archivo_pcap = sys.argv[1]
    ip_objetivo = "8.8.8.8" # IP de destino a filtrar
    
    print(f"[*] Leyendo el archivo PCAP: {archivo_pcap}")
    print(f"[*] Filtrando paquetes ICMP tipo 8 enviados a: {ip_objetivo}")
    print(f"[*] Extrayendo carácter de la posición 0x20 (byte 33) del payload.")
    
    # 1. Extraer el mensaje cifrado del archivo PCAP usando la función filtrada
    mensaje_cifrado, num_paquetes = extraer_mensaje_pcap_filtrado(archivo_pcap, ip_objetivo)
    
    # Si no se extrajo mensaje, terminar ejecución. La función ya imprime advertencias.
    if not mensaje_cifrado:
         print("[!] No se pudo extraer un mensaje cifrado con los filtros aplicados.")
         sys.exit(1)
         
    print(f"\n[*] Se procesaron {num_paquetes} paquetes que cumplieron los criterios.")
    print(f"[*] Mensaje cifrado reconstruido:")
    print(f"'{mensaje_cifrado}'")
    
    print("\n[*] Aplicando los 26 posibles desplazamientos del cifrado César:")
    print("-" * 60)
    
    # 2. Intentar todos los desplazamientos posibles (0 a 25) y mostrar los resultados
    for d in range(26):
        mensaje_descifrado = descifrar_cesar(mensaje_cifrado, d)
        # Imprimimos cada resultado posible del descifrado César
        print(f"Desplazamiento {d:2d}: {mensaje_descifrado}")
        
    print("-" * 60)
    print("[*] Proceso completado. Revisa los 26 resultados para encontrar el mensaje original.")