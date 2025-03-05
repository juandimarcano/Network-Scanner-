import nmap
import netifaces
import ipaddress
from termcolor import colored

def obtener_ip() -> str:
    """Obtiene la IP y máscara de red de la interfaz activa"""
    try:
        interfaces = netifaces.interfaces()
        for interfaz in interfaces:
            if interfaz.startswith('lo'):
                continue  # Ignorar localhost
            
            direcciones = netifaces.ifaddresses(interfaz)
            if netifaces.AF_INET in direcciones:
                for direccion in direcciones[netifaces.AF_INET]:
                    ip = direccion.get('addr')
                    mascara = direccion.get('netmask')
                    if ip and mascara:
                        prefix = ipaddress.IPv4Network(f'0.0.0.0/{mascara}', strict=False).prefixlen
                        return f"{ip}/{prefix}"
        return None
    except Exception as e:
        print(colored(f"Error obteniendo IP: {e}", 'red'))
        return None

def calcular_rango(ip_red: str) -> tuple:
    """Calcula información de la red"""
    try:
        red = ipaddress.IPv4Network(ip_red, strict=False)
        return red.network_address, red.broadcast_address
    except ValueError as e:
        print(colored(f"Error en formato de red: {e}", 'red'))
        return None, None

def escanear_red(ip: str) -> list:
    """Escanea dispositivos en la red usando nmap"""
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=ip, arguments="-T4 -F --host-timeout 15s")
        return scanner.all_hosts()
    except nmap.PortScannerError as e:
        print(colored(f"Error de escaneo: {e}", 'red'))
        return []

def mostrar_resultados(ip_red: str, red: str, broadcast: str, hosts: list):
    """Muestra los resultados formateados"""
    print(colored("\n[+] Información de red", 'cyan', attrs=['bold']))
    print(f"• Rango CIDR: {colored(ip_red, 'yellow')}")
    print(f"• Dirección de red: {colored(red, 'yellow')}")
    print(f"• Broadcast: {colored(broadcast, 'yellow')}")
    
    print(colored("\n[+] Dispositivos detectados", 'cyan', attrs=['bold']))
    for i, host in enumerate(hosts, 1):
        print(f"{colored(f'{i}.', 'green')} {host}")

def main():
    """Función principal"""
    ip_red = obtener_ip()
    
    if not ip_red:
        print(colored("No se detectó conexión de red activa", 'red'))
        return
    
    red, broadcast = calcular_rango(ip_red)
    
    if red and broadcast:
        hosts = escanear_red(ip_red)
        mostrar_resultados(ip_red, red, broadcast, hosts)

if __name__ == "__main__":
    main()
