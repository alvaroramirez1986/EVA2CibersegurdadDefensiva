#!/usr/bin/env python3
"""
alvaro.py - Consulta interactiva de direcciones IP (y dominios) en VirusTotal API v3.
Permite ingresar una o varias direcciones por teclado, realizar búsquedas sucesivas
y preguntar al usuario si desea salir del programa.
"""

import ipaddress
import re
import time
import requests

# Reemplaza con tu clave API real de VirusTotal
API_KEY = '948b24a9cf710c97ba110ee485b71a291b2f66fdb23487abf72a6e0e89452189'
HEADERS = {'x-apikey': API_KEY}


def es_ip(valor):
    """Verifica si una cadena corresponde a una dirección IPv4 o IPv6."""
    try:
        ipaddress.ip_address(valor)
        return True
    except ValueError:
        return False


def procesar_entrada(entrada_usuario):
    """Separa una o varias direcciones ingresadas por comas, espacios o punto y coma."""
    elementos = [item.strip() for item in re.split(r'[,\s;]+', entrada_usuario) if item.strip()]
    lista_unica = []
    for elem in elementos:
        if elem not in lista_unica:
            lista_unica.append(elem)
    return lista_unica


def consultar_vt(indicador):
    """Consulta la API de VirusTotal para la dirección IP o dominio ingresado."""
    tipo = 'ip' if es_ip(indicador) else 'dominio'
    if tipo == 'ip':
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicador}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{indicador}"

    try:
        response = requests.get(url, headers=HEADERS, timeout=20)
        if response.status_code == 200:
            atributos = response.json()['data']['attributes']
            stats = atributos.get('last_analysis_stats', {})
            resultados_motores = atributos.get('last_analysis_results', {})

            alertas_motores = [
                f"{motor} ({info.get('result', info.get('category'))})"
                for motor, info in resultados_motores.items()
                if info.get('category') in ('malicious', 'suspicious')
            ]

            return {
                'Indicador': indicador,
                'Tipo': tipo.upper(),
                'Pais': atributos.get('country', 'N/A'),
                'Propietario': atributos.get('as_owner', 'N/A'),
                'Maliciosos': stats.get('malicious', 0),
                'Sospechosos': stats.get('suspicious', 0),
                'Inofensivos': stats.get('harmless', 0),
                'Alertas': alertas_motores
            }
        elif response.status_code == 404:
            print(f"[-] No se encontraron registros en VirusTotal para: {indicador}")
            return None
        elif response.status_code == 429:
            print(f"[-] Límite de API excedido al consultar: {indicador}")
            return None
        else:
            print(f"[-] Error HTTP {response.status_code} al consultar: {indicador}")
            return None
    except Exception as e:
        print(f"[-] Error de red al consultar {indicador}: {e}")
        return None


def mostrar_resultado(resultado):
    """Muestra en pantalla el resultado y las alertas de la dirección consultada."""
    tiene_alerta = resultado['Maliciosos'] > 0 or resultado['Sospechosos'] > 0
    estado = "! CON ALERTAS !" if tiene_alerta else "LIMPIO (Sin alertas)"

    print("\n" + "=" * 70)
    print(f" [{resultado['Tipo']}] {resultado['Indicador']}  -->  {estado}")
    print("=" * 70)
    print(f"  País / Red          : {resultado['Pais']} ({resultado['Propietario']})")
    print(f"  Motores Maliciosos  : {resultado['Maliciosos']}")
    print(f"  Motores Sospechosos : {resultado['Sospechosos']}")
    print(f"  Motores Inofensivos : {resultado['Inofensivos']}")

    if resultado['Alertas']:
        print("  Detalle de Alertas  :")
        for alerta in resultado['Alertas']:
            print(f"    - {alerta}")
    print("=" * 70)


def main():
    print("=" * 70)
    print("   ANALIZADOR INTERACTIVO DE DIRECCIONES IP - VIRUSTOTAL (alvaro.py)")
    print("=" * 70)

    while True:
        try:
            entrada = input(
                "\n[?] Ingresa una o varias direcciones IP (separadas por coma o espacio): "
            ).strip()

            if not entrada:
                print("[!] No ingresaste ninguna dirección. Intenta nuevamente.")
                continue

            direcciones = procesar_entrada(entrada)
            total = len(direcciones)
            print(f"\n[*] Consultando {total} dirección(es) en VirusTotal...")

            for idx, direccion in enumerate(direcciones):
                resultado = consultar_vt(direccion)
                if resultado:
                    mostrar_resultado(resultado)

                # Si se ingresaron más de 4 IPs de una vez, respetar límite de API gratuita
                if idx < total - 1 and total > 4:
                    print("[*] Esperando 15 segundos por límite de la API gratuita...")
                    time.sleep(15)

            salir = input("\n[?] ¿Deseas salir del programa? (s/n): ").strip().lower()
            if salir in ('s', 'si', 'sí', 'y', 'yes'):
                print("\n[+] Saliendo del programa. ¡Hasta luego!")
                break

        except KeyboardInterrupt:
            print("\n\n[+] Saliendo del programa. ¡Hasta luego!")
            break


if __name__ == "__main__":
    main()
