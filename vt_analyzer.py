import json
import requests
import time
import csv
import ipaddress
import os

# Reemplaza con tu clave API real de VirusTotal
API_KEY = 'SU API KEY'
# Por seguridad borre la mia 
HEADERS = {'x-apikey': API_KEY}

def es_ip(valor):
    """Verifica si una cadena corresponde a una dirección IPv4 o IPv6."""
    try:
        ipaddress.ip_address(valor)
        return True
    except ValueError:
        return False

def obtener_lista_analisis(datos):
    """Extrae una lista de tuplas (indicador, tipo) tanto si el JSON es diccionario como si es lista."""
    lista_analisis = []
    if isinstance(datos, dict):
        lista_analisis = [(ip, 'ip') for ip in datos.get('ips', [])] + \
                         [(dom, 'dominio') for dom in datos.get('dominios', [])]
    elif isinstance(datos, list):
        for item in datos:
            indicador = item.get('Address') if isinstance(item, dict) else str(item)
            if indicador:
                tipo = 'ip' if es_ip(indicador) else 'dominio'
                lista_analisis.append((indicador, tipo))
    return lista_analisis

def consultar_vt(indicador, tipo):
    """Consulta la API de VirusTotal dependiendo si es IP o Dominio."""
    if tipo == 'ip':
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicador}"
    elif tipo == 'dominio':
        url = f"https://www.virustotal.com/api/v3/domains/{indicador}"
    else:
        return None

    try:
        response = requests.get(url, headers=HEADERS, timeout=20)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return {
                'Indicador': indicador,
                'Tipo': tipo.upper(),
                'Maliciosos': stats.get('malicious', 0),
                'Sospechosos': stats.get('suspicious', 0),
                'Inofensivos': stats.get('harmless', 0)
            }
        elif response.status_code == 429:
            print(f"[-] Límite de API excedido al consultar {indicador}.")
            return None
        else:
            print(f"[-] Error {response.status_code} al consultar {indicador}.")
            return None
    except Exception as e:
        print(f"[-] Error de red con {indicador}: {e}")
        return None

def guardar_csv(resultados, ruta_csv):
    """Guarda los resultados obtenidos en el archivo CSV."""
    claves_csv = ['Indicador', 'Tipo', 'Maliciosos', 'Sospechosos', 'Inofensivos']
    with open(ruta_csv, 'w', newline='', encoding='utf-8') as archivo_csv:
        escritor = csv.DictWriter(archivo_csv, fieldnames=claves_csv)
        escritor.writeheader()
        escritor.writerows(resultados)

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    ruta_json = os.path.join(base_dir, 'indicadores.json')
    ruta_csv = os.path.join(base_dir, 'reporte_seguridad.csv')

    print("[*] Leyendo archivo JSON...")
    try:
        with open(ruta_json, 'r', encoding='utf-8') as archivo_json:
            datos = json.load(archivo_json)
    except FileNotFoundError:
        print("[-] No se encontró el archivo indicadores.json")
        return

    resultados = []
    
    # Consolidar todos los indicadores en una lista con su tipo
    lista_analisis = obtener_lista_analisis(datos)

    total = len(lista_analisis)
    print(f"[*] Se encontraron {total} indicadores para analizar.\n")

    try:
        for index, (indicador, tipo) in enumerate(lista_analisis):
            print(f"[{index + 1}/{total}] Analizando {tipo}: {indicador}...")
            resultado = consultar_vt(indicador, tipo)
            
            if resultado:
                resultados.append(resultado)
                guardar_csv(resultados, ruta_csv)
                if resultado['Maliciosos'] > 0:
                    print(f"    ! ALERTA: {resultado['Maliciosos']} motores lo detectaron como malicioso.")
            
            # Respetar límite de la API gratuita (4 requests / min)
            if index < total - 1:
                time.sleep(15)
    except KeyboardInterrupt:
        print("\n[!] Ejecución interrumpida por el usuario. Guardando resultados parciales...")

    # Generar reporte en CSV
    if resultados:
        print("\n[*] Generando informe reporte_seguridad.csv...")
        guardar_csv(resultados, ruta_csv)
        print("[+] Informe generado con éxito.")

if __name__ == "__main__":
    main()
