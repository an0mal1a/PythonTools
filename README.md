# Python Tools

Este repositorio contiene varios scripts para realizar tareas relacionadas con la detección de hosts, cambio de dirección MAC, análisis de tráfico, y manipulación de paquetes de red. Además, incluye algunos ejemplos de herramientas de malware como un keylogger y un simple stealer.

## Descripción

Este proyecto contiene una variedad de herramientas para realizar tareas de análisis de red y, en algunos casos, de inyección de código en redes y aplicaciones. A continuación se describen las funcionalidades de cada carpeta y sus scripts:

### HostDetector

Se incluye un detector de hosts utilizando dos métodos diferentes:
- **ARP** (Address Resolution Protocol): Utiliza `scapy` para escanear la red y detectar dispositivos conectados.
- **ICMP** (Internet Control Message Protocol): Realiza pings para identificar hosts activos en la red.

### MacChanger

Script para cambiar la dirección MAC de una interfaz de red en sistemas Linux. Permite restaurar la MAC previamente guardada en un archivo. Si se cambian dos interfaces, no se pierde la información de ninguna.

**Requisitos**: Requiere acceso a comandos del sistema operativo y permisos de superusuario.

### Malwares

1. **KeyLogger**: Un keylogger simple que captura las teclas presionadas y las envía por correo electrónico cada ciertos segundos. (Mejorable).
   
2. **SimpleStealer**: Un "stealer" simple que descarga el script `firefox_decrypt.py` desde GitHub y lo importa como módulo. Este stealer puede ser compilado con `pyinstaller` para ser ejecutado sin necesidad de tener Python instalado.
   
   **Lógica de compilación**:

   ```python
   if getattr(sys, "frozen", False):
       base_path = sys._MEIPASS
   else:
       base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", 'SimpleStealer'))

   stealer_path = os.path.join(base_path, "SimpleStealer", "stealer.py") 
    ```
   
3. C&C (Command & Control): Un simple servidor y cliente C&C. El servidor ejecuta comandos en la máquina víctima y devuelve los resultados. Si el comando es "firefox", importa y ejecuta el stealer.

4. ForwardShell: Permite una shell interactiva mediante el comando mkfifo con tuberías. Ideal para mantener la comunicación persistente y simular una shell real.

### PortScanner

Un escáner de puertos básico pero rápido en Python que permite escanear puertos en una red y determinar si están abiertos.

#### Sniffers

1. dnsSniffer: Utiliza scapy para esnifar tráfico DNS. Requiere el script spoofarp para interceptar el tráfico.

2. HTTPS-Sniffer: Utiliza mitmdump para esnifar tráfico HTTPS. Se necesita instalar un certificado en la ruta de confianza de la máquina víctima para descifrar el tráfico.

3. HTTPSniffer: Similar al anterior, pero esnifa tráfico HTTP. Requiere spoofarp para redirigir el tráfico hacia nuestra máquina.

4. IMGSniffer: Un script para mitmdump que descarga las imágenes visitadas por el cliente, tanto HTTP como HTTPS.

### Spoofers

1. ARPSpoofer: Utiliza scapy para envenenar el tráfico ARP entre el router y la víctima. Esto hace que la víctima crea que nuestra máquina es el router.

2. DNSpoofer: Funciona junto con arpspoof para redirigir el tráfico DNS de la víctima a un dominio o IP controlada.

3. TrafficHijack: Similar a DNSpoofer, pero permite interceptar y modificar paquetes, inyectando código JavaScript o modificando las respuestas de servidores.

## Requisitos

Cada carpeta contiene un archivo requirements.txt con las dependencias necesarias para ejecutar los scripts. Algunas dependencias comunes son:

- scapy 
- mitmproxy 
- pyinstaller

Puedes instalar las dependencias con el siguiente comando:

```PowerShell
pip install -r requirements.txt
```

## Compilación de Scripts con PyInstaller

Para compilar los scripts de malware, como `SimpleStealer`, puedes usar `pyinstaller` para crear un ejecutable independiente de Python. Asegúrate de modificar el código como se explicó antes para que el script funcione correctamente al ser compilado.

### Uso de los Scripts
1. HostDetector: Ejecuta el script correspondiente (ARP o ICMP) para detectar hosts activos en la red. 
2. MacChanger: Ejecuta machanger.py con permisos de superusuario para cambiar la dirección MAC de una interfaz. 
3. Malwares: Ejecuta los scripts para probar las herramientas de malware, pero recuerda que estas herramientas deben ser usadas con fines educativos y en un entorno controlado. 
4. PortScanner: Ejecuta portscanner.py con los parámetros correspondientes para escanear los puertos de una máquina objetivo. 
5. Sniffers: Ejecuta los sniffers para capturar tráfico de red. Ten en cuenta que algunos requieren privilegios de administrador y el uso de spoofarp. 
6. Spoofers: Ejecuta los scripts de spoofing para manipular el tráfico de la red. Asegúrate de usar estos scripts de manera ética.
