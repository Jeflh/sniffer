from scapy.all import *


def leer_archivo(modo):
    datos_hex = ""
    datos_bits = ""
    try:
        archivo = open("paquete.pcap", "rb")
        byte = archivo.read(1)
        cont = 0
        while byte:
            cont += 1
            
            if cont > 40:
                aux_hex = str("{:02X}".format(ord(byte)))
                aux_bit = str(format(ord(byte), '08b'))
                datos_hex += aux_hex
                datos_bits += aux_bit
                
            byte = archivo.read(1)
        archivo.close()

        if modo == 1:
            return datos_hex
        elif modo == 2:          
            return datos_bits

    except IOError:
        print("Error al abrir el archivo, es posible que no exista")


def captura():
    paquete = sniff(count=1)
    wrpcap("paquete.pcap", paquete)


def ethernet():
    datos_hex = leer_archivo(1)
    dir_mac_origen = ""
    dir_mac_destino = ""

    for i in range(0, 12, 2):
        dir_mac_destino += datos_hex[i:i + 2] + ":"

    for i in range(12, 24, 2):
        dir_mac_origen += datos_hex[i:i + 2] + ":"

    dir_mac_origen = dir_mac_origen[:-1]
    dir_mac_destino = dir_mac_destino[:-1]

    codigo = datos_hex[24:28]

    print("============================================")
    print("\t\t\t\tPaquete Ethernet")
    print("============================================")
    print("Dirección MAC de destino:", dir_mac_destino)
    print("Dirección MAC de origen:", dir_mac_origen)

    if codigo == "0800":
        tipo = "IPv4"
        print("Tipo de código:", codigo, "[" + tipo + "]")
        ipv4()

    elif codigo == "0806":
        tipo = "ARP"
        print("Tipo de código:", codigo, "[" + tipo + "]")
        arp_rarp()

    elif codigo == "8035":
        tipo = "RARP"
        print("Tipo de código:", codigo, "[" + tipo + "]")
        arp_rarp()

    elif codigo == "86DD":
        tipo = "IPv6"
        print("Tipo de código:", codigo, "[" + tipo + "]")
        ipv6()


def ipv4():
    datos_bits = leer_archivo(2)
    ver_ip = int(datos_bits[112:116], 2)
    tam_cabe = int(datos_bits[116:120], 2)
    bit_02 = datos_bits[120:123]
    bit_3 = datos_bits[124]
    bit_4 = datos_bits[125]
    bit_5 = datos_bits[126]
    long_total = int(datos_bits[128:144], 2)
    identificador = int(datos_bits[144:160], 2)
    flags = datos_bits[160:163]
    flag_bit_0 = flags[0]
    flag_bit_1 = flags[1]
    flag_bit_2 = flags[2]
    pos_fragmento = int(datos_bits[163:176], 2)
    tiempo_vida = int(datos_bits[176:184], 2)
    bits_proto = int(datos_bits[184:192], 2)

    ip_origen_1 = str(int(datos_bits[208:216], 2))
    ip_origen_2 = str(int(datos_bits[216:224], 2))
    ip_origen_3 = str(int(datos_bits[224:232], 2))
    ip_origen_4 = str(int(datos_bits[232:240], 2))

    ip_destino_1 = str(int(datos_bits[240:248], 2))
    ip_destino_2 = str(int(datos_bits[248:256], 2))
    ip_destino_3 = str(int(datos_bits[256:264], 2))
    ip_destino_4 = str(int(datos_bits[264:272], 2))

    # Prioridad
    prioridad = ""
    if bit_02 == "000":
        prioridad = "De rutina"
    elif bit_02 == "001":
        prioridad = "Prioritario"
    elif bit_02 == "010":
        prioridad = "Inmediato"
    elif bit_02 == "011":
        prioridad = "Relámpago"
    elif bit_02 == "100":
        prioridad = "Invalidación relámpago"
    elif bit_02 == "101":
        prioridad = "Procesando llamada crítica y de emergencia"
    elif bit_02 == "110":
        prioridad = "Control de trabajo de internet"
    elif bit_02 == "111":
        prioridad = "Control de red"

    # Desglose de bits
    if bit_3 == "0":
        retardo = "Normal"
    else:
        retardo = "Bajo"
    if bit_4 == "0":
        rendimiento = "Normal"
    else:
        rendimiento = "Alto"
    if bit_5 == "0":
        fiabilidad = "Normal"
    else:
        fiabilidad = "Alto"

    # Flags
    flag_0 = ""
    if flag_bit_0 == "0":
        flag_0 = "Reservado"
    if flag_bit_1 == "0":
        flag_1 = "Divisible"
    else:
        flag_1 = "No divisible"
    if flag_bit_2 == "0":
        flag_2 = "Último fragmento"
    else:
        flag_2 = "Fragmento intermedio"

    # Protocolo
    protocolo = ""
    if bits_proto == 1:
        protocolo = "ICMPv4"
    elif bits_proto == 6:
        protocolo = "TCP"
    elif bits_proto == 17:
        protocolo = "UDP"
    elif bits_proto == 58:
        protocolo = "ICMPv6"
    elif bits_proto == 118:
        protocolo = "STP"
    elif bits_proto == 121:
        protocolo = "SMP"

    suma_veri = hex(int(datos_bits[192:208], 2)).split("x")
    suma_veri = suma_veri[1].upper()
    ip_origen = ip_origen_1 + "." + ip_origen_2 + "." + ip_origen_3 + "." + ip_origen_4
    ip_destino = ip_destino_1 + "." + ip_destino_2 + "." + ip_destino_3 + "." + ip_destino_4

    datos_proto = datos_bits[272:]

    print("\n============================================")
    print("\t\t\t\tPaquete IPv4")
    print("============================================")
    print("Versión:", ver_ip)
    print("Tamaño cabecera:", tam_cabe, "palabras")
    print("\n\t-Tipo de servicio-")
    print("Prioridad:", prioridad)
    print("Retardo:", retardo)
    print("Rendimiento:", rendimiento)
    print("Fiabilidad:", fiabilidad)
    print("\nLongitud total:", long_total, "Octetos")
    print("Identificador:", identificador)
    print("\nFlags:", flags)
    print("Bit 0:", "[" + flag_bit_0 + "]", flag_0)
    print("Bit 1:", "[" + flag_bit_1 + "]", flag_1)
    print("Bit 2:", "[" + flag_bit_2 + "]", flag_2)
    print("\nPosición de fragmento:", pos_fragmento)
    print("Tiempo de vida:", tiempo_vida)
    print("Protocolo:", protocolo)
    print("Checksum:", suma_veri[0:2] + ":" + suma_veri[2:4])
    print("\nDirección IP de origen:", ip_origen)
    print("Dirección IP de destino:", ip_destino)

    if protocolo == "ICMPv4":
        icmpv4(datos_proto)
    elif protocolo == "TCP":
        tcp(datos_proto)
    elif protocolo == "UDP":
        udp(datos_proto)
    elif protocolo == "ICMPv6":
        pass
    elif protocolo == "STP":
        pass
    elif protocolo == "SMP":
        pass


def icmpv4(datos):
    print("\n============================================")
    print("\t\t\t\tPaquete ICMPv4")
    print("============================================")

    tipo = int(datos[0:8], 2)
    print("Tipo:", end=" ")

    if tipo == 0:
        print("Echo Reply (respuesta de eco)")
    elif tipo == 3:
        print("Destination Unreachable (destino inaccesible)")
    elif tipo == 4:
        print("Source Quench (disminución del tráfico desde el origen)")
    elif tipo == 5:
        print("Redirect (redireccionar - cambio de ruta)")
    elif tipo == 8:
        print("Echo (solicitud de eco)")
    elif tipo == 11:
        print("Time Exceeded (tiempo excedido para un datagrama)")
    elif tipo == 12:
        print("Parameter Problem (problema de parámetros")
    elif tipo == 13:
        print("Timestamp (solicitud de marca de tiempo)")
    elif tipo == 14:
        print("Timestamp Reply (respuesta de marca de tiempo)")
    elif tipo == 15:
        print("Information Request (solicitud de información) -Obsoleto")
    elif tipo == 16:
        print("Information Reply (respuesta de información) - Obsoleto")
    elif tipo == 17:
        print("Address mask (solicitud de máscara de dirección)")
    elif tipo == 18:
        print("Address mask Reply (respuesta de máscara de dirección)")

    codigo = int(datos[8:16], 2)
    print("Código:", end=" ")

    if codigo == 0:
        print("No se puede llegar a la red")
    elif codigo == 1:
        print("No se puede llegar al host o aplicación de destino")
    elif codigo == 2:
        print("El destino no dispone del protocolo solicitado")
    elif codigo == 3:
        print("No se puede llegar al puerto destino o la aplicación destino no está libre")
    elif codigo == 4:
        print("Se necesita aplicar fragmentación, pero el flag correspondiente indica lo contrario")
    elif codigo == 5:
        print("La ruta de origen no es correcta")
    elif codigo == 6:
        print("No se conoce la red destino")
    elif codigo == 7:
        print("No se conoce el host destino")
    elif codigo == 8:
        print("El host origen está aislado")
    elif codigo == 9:
        print("La comunicación con la red destino está prohibida por razones administrativas")
    elif codigo == 10:
        print("La comunicación con el host destino está prohibida por razones administrativas")
    elif codigo == 11:
        print("No se puede llegar a la red destino debido al Tipo de servicio")
    elif codigo == 12:
        print("No se puede llegar al host destino debido al Tipo de servicio ")

    suma_veri_icmp = datos[16:32]
    suma_veri_icmp = hex(int(suma_veri_icmp, 2)).split("x")
    suma_veri_icmp = suma_veri_icmp[1].upper()
    print("Checksum:", suma_veri_icmp[0:2] + ":" + suma_veri_icmp[2:4])

    datos_hex = hex(int(datos[32:], 2)).split("x")

    if len(str(datos_hex[1])) % 2 != 0:
        datos_hex = datos_hex[0] + datos_hex[1]
    else:
        datos_hex = datos_hex[1]

    datos_hex = datos_hex.upper()
    datos_hex_s = ""

    for i in range(0, len(str(datos_hex)), 2):
        j = i + 2
        datos_hex_s += str(datos_hex[i:j]) + " "

    datos_hex_s = datos_hex_s[:-1]

    print("Datos:", datos_hex_s)


def arp_rarp():
    datos_hex = leer_archivo(1)

    # Tipo de hardware
    tipo_hard = int(datos_hex[28:32], 16)
    nombre_hardware = ""
    if tipo_hard == 1:
        nombre_hardware = "Ethernet (10 Mb)"
    elif tipo_hard == 6:
        nombre_hardware = "IEE 802 Networks"
    elif tipo_hard == 7:
        nombre_hardware = "ARCNET"
    elif tipo_hard == 15:
        nombre_hardware = "Frame Relay"
    elif tipo_hard == 16:
        nombre_hardware = "Asynchronous Transfer Mode (ATM)"
    elif tipo_hard == 17:
        nombre_hardware = "HDLC"
    elif tipo_hard == 18:
        nombre_hardware = "Fibre Channel"
    elif tipo_hard == 19:
        nombre_hardware = "Asynchronous Transfer Mode (ATM)"
    elif tipo_hard == 20:
        nombre_hardware = "Serial Line"

    # Tipo de protocolo
    tipo_proto = datos_hex[32:36]
    tipo_proto = tipo_proto.upper()  # En caso de mayúsculas

    tipo = ""
    if tipo_proto == "0800":
        tipo = "IPv4"
    elif tipo_proto == "0806":
        tipo = "ARP"
    elif tipo_proto == "8035":
        tipo = "RARP"
    elif tipo_proto == "86DD":
        tipo = "IPv6"

    # Longitud de la dirección hardware y protocolo
    long_hard = int(datos_hex[36:38], 16)
    long_proto = int(datos_hex[38:40], 16)

    # Código de operación
    codigo_op = int(datos_hex[40:44], 16)
    datagrama = ""
    if codigo_op == 1:
        datagrama = "(1) Solicitud ARP"
    elif codigo_op == 2:
        datagrama = "(2)Respuesta ARP"
    elif codigo_op == 3:
        datagrama = "(3)Solicitud RARP"
    elif codigo_op == 4:
        datagrama = "(4)Respuesta RARP"
    elif codigo_op == 5:
        datagrama = "(5)Solicitud DRARP"
    elif codigo_op == 6:
        datagrama = "(6) Respuesta DRARP"
    elif codigo_op == 7:
        datagrama = "(7) Error DRARP"
    elif codigo_op == 8:
        datagrama = "(8) Solicitud InARP"
    elif codigo_op == 9:
        datagrama = "(9) Respuesta InARP"

    # Dirección MAC del emisor
    dir_mac_emisor = str(datos_hex[44:46])
    dir_mac_emisor += ":" + str(datos_hex[46:48])
    dir_mac_emisor += ":" + str(datos_hex[48:50])
    dir_mac_emisor += ":" + str(datos_hex[50:52])
    dir_mac_emisor += ":" + str(datos_hex[52:54])
    dir_mac_emisor += ":" + str(datos_hex[54:56])
    # Dirección IP del emisor
    dir_ip_emisor = str(int(datos_hex[56:58], 16))
    dir_ip_emisor += "." + str(int(datos_hex[58:60], 16))
    dir_ip_emisor += "." + str(int(datos_hex[60:62], 16))
    dir_ip_emisor += "." + str(int(datos_hex[62:64], 16))

    # Dirección MAC del receptor
    dir_mac_receptor = str(datos_hex[64:66])
    dir_mac_receptor += ":" + str(datos_hex[66:68])
    dir_mac_receptor += ":" + str(datos_hex[68:70])
    dir_mac_receptor += ":" + str(datos_hex[70:72])
    dir_mac_receptor += ":" + str(datos_hex[72:74])
    dir_mac_receptor += ":" + str(datos_hex[74:76])
    # Dirección IP del receptor
    dir_ip_receptor = str(int(datos_hex[76:78], 16))
    dir_ip_receptor += "." + str(int(datos_hex[78:80], 16))
    dir_ip_receptor += "." + str(int(datos_hex[80:82], 16))
    dir_ip_receptor += "." + str(int(datos_hex[82:84], 16))

    print("\n============================================")
    print("\t\t\t\tPaquete ARP/RARP")
    print("============================================")
    print("Tipo de hardware:", nombre_hardware)
    print("Tipo de protocolo:", tipo)
    print("Longitud de dirección de hardware:", long_hard)
    print("Longitud de dirección de protocolo:", long_proto)
    print("Código de operación:", datagrama)
    print("Dirección de hardware del emisor:", dir_mac_emisor)
    print("Dirección de protocolo del emisor:", dir_ip_emisor)
    print("Dirección de hardware del receptor:", dir_mac_receptor)
    print("Dirección de protocolo del receptor:", dir_ip_receptor)


def ipv6():
    datos_bits = leer_archivo(2)
    ver_ip = int(datos_bits[112:116], 2)

    # Clase de tráfico
    clase_trafico = datos_bits[116:119]
    bit_retardo = datos_bits[119:120]
    bit_rendimiento = datos_bits[120:121]
    bit_fiabilidad = datos_bits[121:122]
    # bit_6y7 = datos_bits[123:124]

    prioridad = ""
    if clase_trafico == "000":
        prioridad = "De rutina"
    elif clase_trafico == "001":
        prioridad = "Prioritario"
    elif clase_trafico == "010":
        prioridad = "Inmediato"
    elif clase_trafico == "011":
        prioridad = "Relámpago"
    elif clase_trafico == "100":
        prioridad = "Invalidación relámpago"
    elif clase_trafico == "101":
        prioridad = "Procesando llamada crítica y de emergencia"
    elif clase_trafico == "110":
        prioridad = "Control de trabajo de internet"
    elif clase_trafico == "111":
        prioridad = "Control de red"

    # Desglose de bits
    if bit_retardo == "0":
        retardo = "Normal"
    else:
        retardo = "Bajo"

    if bit_rendimiento == "0":
        rendimiento = "Normal"
    else:
        rendimiento = "Alto"

    if bit_fiabilidad == "0":
        fiabilidad = "Normal"
    else:
        fiabilidad = "Alto"

    # Etiqueta de flujo
    etiqueta = int(datos_bits[124:144], 2)

    # Tamaño de datos
    tam_datos = int(datos_bits[144:160], 2)

    # Encabezado siguiente
    encabezado = int(datos_bits[160:168], 2)
    sig = ""
    if encabezado == 1:
        sig = "ICMPv4"
    elif encabezado == 6:
        sig = "TCP"
    elif encabezado == 17:
        sig = "UDP"
    elif encabezado == 58:
        sig = "ICMPv6"
    elif encabezado == 118:
        sig = "STP"
    elif encabezado == 121:
        sig = "SMP"

    # Límite de salto
    limite_salto = int(datos_bits[168:176], 2)

    # Dirección de origen
    dir_origen = hex(int(datos_bits[176:304], 2)).split("x")
    dir_origen = dir_origen[1].upper()
    str(dir_origen)
    dir_origen_s = ""
    for i in range(0, 32, 4):
        dir_origen_s += dir_origen[i:i + 4] + ":"

    dir_origen_s = dir_origen_s[:-1]

    # Dirección de destino
    dir_destino = hex(int(datos_bits[304:432], 2)).split("x")
    dir_destino = dir_destino[1].upper()
    str(dir_destino)
    dir_destino_s = ""
    for i in range(0, 32, 4):
        dir_destino_s += dir_destino[i:i + 4] + ":"

    dir_destino_s = dir_destino_s[:-1]

    datos_proto = datos_bits[432:]

    print("\n============================================")
    print("\t\t\t\tPaquete IPv6")
    print("============================================")
    print("Versión:", ver_ip)
    print("Clase de tráfico:", prioridad)
    print("Retardo:", retardo)
    print("Rendimiento:", rendimiento)
    print("Fiabilidad:", fiabilidad)
    print("Etiqueta de flujo:", etiqueta)
    print("Tamaño de datos:", tam_datos, "Octetos")
    print("Encabezado siguiente:", sig)
    print("Límite de salto:", limite_salto)
    print("Dirección de origen:", dir_origen_s)
    print("Dirección de destino:", dir_destino_s)

    # Siguiente protocolo
    if sig == "ICMPv4":
        icmpv4(datos_proto)
    elif sig == "TCP":
        tcp(datos_proto)
    elif sig == "UDP":
        udp(datos_proto)
    elif sig == "ICMPv6":
        icmpv6(datos_proto)
    elif sig == "STP":
        pass
    elif sig == "SMP":
        pass


def icmpv6(datos):
    print("\n============================================")
    print("\t\t\t\tPaquete ICMPv6")
    print("============================================")

    tipo = int(datos[0:8], 2)
    codigo = int(datos[8:16], 2)
    mensaje = ""

    if tipo == 1:
        if codigo == 0:
            mensaje = "[0] No existe ruta destino"
        elif codigo == 1:
            mensaje = "[1] Comunicación con el destino administrativamente prohibida"
        elif codigo == 2:
            mensaje = "[2] No asignado"
        elif codigo == 3:
            mensaje = "[3] Dirección inalcanzable"

        print("[1] Mensaje de destino inalcanzable")
        print(mensaje)

    elif tipo == 2:
        if codigo == 0:
            print("[0] Mensaje de paquete demasiado grande")

    elif tipo == 3:
        if codigo == 0:
            mensaje = "[0] El límite del salto excedido"
        if codigo == 1:
            mensaje = "[1] Tiempo de reensamble de fragmento excedido"

        print("[3] Time Exceeded Message")
        print(mensaje)

    elif tipo == 4:
        if codigo == 0:
            mensaje = "[0] El campo del encabezado erróneo encontró"
        elif codigo == 1:
            mensaje = "[1] El tipo siguiente desconocido del encabezado encontró"
        elif codigo == 2:
            mensaje = "[2] Opción desconocida del IPv6 encontrada"

        print("[4] Mensaje de problema de parámetro")
        print(mensaje)

    elif tipo == 128:
        if codigo == 0:
            print("[0] Mensaje del pedido de eco")

    elif tipo == 129:
        if codigo == 0:
            print("[0] Mensaje de respuesta de eco")

    elif tipo == 133:
        if codigo == 0:
            print("[0] Mensaje de solicitud del router")

    elif tipo == 134:
        if codigo == 0:
            print("[0] Mensaje de anuncio del router")

    elif tipo == 135:
        if codigo == 0:
            print("[0] Mensaje de solicitud vecino")

    elif tipo == 136:
        if codigo == 0:
            print("[0] Mensaje de anuncio de vecino")

    elif tipo == 137:
        if codigo == 0:
            print("[0] Reoriente el mensaje")

    suma_veri_icmp = datos[16:32]
    suma_veri_icmp = hex(int(suma_veri_icmp, 2)).split("x")
    suma_veri_icmp = suma_veri_icmp[1].upper()
    print("Checksum:", suma_veri_icmp[0:2] + ":" + suma_veri_icmp[2:4])

    # Datos

    datos_s = hex(int(datos[32:], 2)).split("x")
    datos_s = datos_s[1].upper()
    str(datos_s)
    datos_imp = ""

    for i in range(0, len(datos_s), 2):
        datos_imp += datos[i:i + 2] + " "

    print("Datos:", datos_imp)


def tcp(datos):
    puerto_origen = int(datos[0:16], 2)
    puerto_destino = int(datos[16:32], 2)

    tipo_origen = ""
    if 0 <= puerto_origen <= 1023:
        tipo_origen = "Puerto bien conocido"
    elif 1024 <= puerto_origen <= 49151:
        tipo_origen = "Puerto registrado"
    elif 49152 <= puerto_origen <= 65535:
        tipo_origen = "Puerto dinámico o privado"

    tipo_destino = ""
    if 0 <= puerto_destino <= 1023:
        tipo_destino = "Puerto bien conocido"
    elif 1024 <= puerto_destino <= 49151:
        tipo_destino = "Puerto registrado"
    elif 49152 <= puerto_destino <= 65535:
        tipo_destino = "Puerto dinámico o privado"

    servicio = ""
    if puerto_destino == 20:
        servicio = "FTP"
    elif puerto_destino == 21:
        servicio = "FTP"
    elif puerto_destino == 22:
        servicio = "SSH"
    elif puerto_destino == 23:
        servicio = "TELNET"
    elif puerto_destino == 25:
        servicio = "SMTP"
    elif puerto_destino == 53:
        servicio = "DNS"
    elif puerto_destino == 67:
        servicio = "DHCP"
    elif puerto_destino == 68:
        servicio = "DHCP"
    elif puerto_destino == 69:
        servicio = "TFTP"
    elif puerto_destino == 80:
        servicio = "HTTP"
    elif puerto_destino == 110:
        servicio = "POP3"
    elif puerto_destino == 143:
        servicio = "IMAP"
    elif puerto_destino == 443:
        servicio = "HTTPS"
    elif puerto_destino == 993:
        servicio = "IMAP SSL"
    elif puerto_destino == 995:
        servicio = "POP SSL"

    num_sec = int(datos[32:64], 2)
    num_acuse = int(datos[64:96], 2)
    long_cabecera = int(datos[96:100], 2)
    # reservado = datos[100:103]

    # Banderas de comunicación de TCP
    flags = datos[103:112]
    ns = flags[0]
    cwr = flags[1]
    ece = flags[2]
    urg = flags[3]
    ack = flags[4]
    psh = flags[5]
    rst = flags[6]
    syn = flags[7]
    fin = flags[8]

    tam_ventana = int(datos[112:128], 2)

    suma_veri = datos[128:144]
    suma_veri = hex(int(suma_veri, 2)).split("x")
    suma_veri = suma_veri[1].upper()

    punt_urg = int(datos[144:160], 2)

    resto = datos[64:]
    continuar_dns = False
    print("\n============================================")
    print("\t\t\t\tProtocolo TCP")
    print("============================================")
    print("Puerto de origen:", puerto_origen, "-", tipo_origen)
    print("Puerto de destino:", puerto_destino, "-", tipo_destino)
    if servicio != "":
        print("Servicio:", servicio)
        if servicio == "DNS":
            continuar_dns = True
    print("Número de secuencia:", num_sec)
    print("Número de acuse de recibo:", num_acuse)
    print("Longitud de cabecera:", long_cabecera, "palabras")
    print("\nBanderas de comunicación de TCP")
    print("\tNS:", ns)
    print("\tCWR:", cwr)
    print("\tECE:", ece)
    print("\tURG:", urg)
    print("\tACK:", ack)
    print("\tPSH:", psh)
    print("\tRST:", rst)
    print("\tSYN:", syn)
    print("\tFIN:", fin)
    print("\nTamaño de ventana:", tam_ventana, "Bytes")
    print("Checksum:", suma_veri[0:2] + ":" + suma_veri[2:4])
    if urg == 1:
        print("Puntero urgente:", punt_urg)

    if continuar_dns:
        dns(resto)


def udp(datos):
    puerto_origen = int(datos[0:16], 2)
    puerto_destino = int(datos[16:32], 2)

    tipo_origen = ""
    if 0 <= puerto_origen <= 1023:
        tipo_origen = "Puerto bien conocido"
    elif 1024 <= puerto_origen <= 49151:
        tipo_origen = "Puerto registrado"
    elif 49152 <= puerto_origen <= 65535:
        tipo_origen = "Puerto dinámico o privado"

    tipo_destino = ""
    if 0 <= puerto_destino <= 1023:
        tipo_destino = "Puerto bien conocido"
    elif 1024 <= puerto_destino <= 49151:
        tipo_destino = "Puerto registrado"
    elif 49152 <= puerto_destino <= 65535:
        tipo_destino = "Puerto dinámico o privado"

    servicio = ""
    if puerto_destino == 20:
        servicio = "FTP"
    elif puerto_destino == 21:
        servicio = "FTP"
    elif puerto_destino == 22:
        servicio = "SSH"
    elif puerto_destino == 23:
        servicio = "TELNET"
    elif puerto_destino == 25:
        servicio = "SMTP"
    elif puerto_destino == 53:
        servicio = "DNS"
    elif puerto_destino == 67:
        servicio = "DHCP"
    elif puerto_destino == 68:
        servicio = "DHCP"
    elif puerto_destino == 69:
        servicio = "TFTP"
    elif puerto_destino == 80:
        servicio = "HTTP"
    elif puerto_destino == 110:
        servicio = "POP3"
    elif puerto_destino == 143:
        servicio = "IMAP"
    elif puerto_destino == 443:
        servicio = "HTTPS"
    elif puerto_destino == 993:
        servicio = "IMAP SSL"
    elif puerto_destino == 995:
        servicio = "POP SSL"

    longitud_total = int(datos[32:48], 2)

    suma_veri = datos[48:64]
    suma_veri = hex(int(suma_veri, 2)).split("x")
    suma_veri = suma_veri[1].upper()

    resto = datos[64:]

    # datos_s = hex(int(datos[64:], 2)).split("x")
    # datos_s = datos_s[1].upper()
    # str(datos_s)
    # datos_imp = ""
    #
    # for i in range(0, len(datos_s), 2):
    #     datos_imp += datos_s[i:i + 2] + " "
    continuar_dns = False
    print("\n============================================")
    print("\t\t\t\tProtocolo UDP")
    print("============================================")
    print("Puerto de origen:", puerto_origen, "-", tipo_origen)
    print("Puerto de destino:", puerto_destino, "-", tipo_destino)
    if servicio != "":
        print("Servicio:", servicio)
        if servicio == "DNS":
            continuar_dns = True
    print("Longitud total:", longitud_total, "Bytes")
    print("Checksum:", suma_veri[0:2] + ":" + suma_veri[2:4])

    if continuar_dns:
        dns(resto)


def dns(datos):
    id_dns = datos[0:16]
    id_dns = hex(int(id_dns, 2)).split("x")
    id_dns = id_dns[1].upper()

    band = datos[16:32]

    qr = int(band[0])
    if qr == 0:
        qr = "0 - Consulta"
    elif qr == 1:
        qr = "1 - Respuesta"

    op_code = int(band[1:4], 2)
    if op_code == 0:
        op_code = "0 - Consulta estándar (QUERY)"
    elif op_code == 1:
        op_code = "1 - Consulta inversa (IQUERY)"
    elif op_code == 2:
        op_code = "2 - Solicitud del estado del servidor (STATUS)"

    aa = int(band[5])
    tc = int(band[6])
    rd = int(band[7])
    ra = int(band[8])
    z = int(band[9:12])
    r_code = int(band[12:16])

    qd_count = int(datos[32:48])
    an_count = int(datos[48:64])
    ns_count = int(datos[64:80])
    ar_count = int(datos[80:96])

    print("\n============================================")
    print("\t\t\t\tProtocolo DNS")
    print("============================================")
    print("ID:", id_dns)
    print("\nBanderas")
    print("\tQR:", qr)
    print("\tOP code:", op_code)
    print("\tAA:", aa)
    print("\tTC:", tc)
    print("\tRD:", rd)
    print("\tRA:", ra)
    print("\tZ:", z)
    print("\tR code:", r_code)
    print("\nContadores")
    print(f"\tQD count: {qd_count} entradas")
    print(f"\tAN count: {an_count} RRs")
    print(f"\tNS count: {ns_count} RRs")
    print(f"\tAR count: {ar_count} RRs")

    nd = datos[96:]

    if qd_count == 0:
        print("\n\t\tNo hay preguntas")

    aum = 0

    for i in range(qd_count):
        print(f"\n\t\t\tPregunta {i + 1}\n")
        nombre_encontrado = False
        sig = True
        aum = 8
        nombre = ""
        while not nombre_encontrado:

            if sig:
                aux = int(nd[:8], 2)
            else:
                aux = 0

            if aux == 0:
                break

            for j in range(aux):
                nd = nd[8:]
                aum += 8
                if nd != "":
                    nombre += chr(int(nd[:8], 2))

                if j == aux - 1:
                    nd = nd[8:]
                    aum += 8
                    nombre += "."
                    sig = True

        k = 96 + aum

        tipo = int(datos[k:k + 16], 2)
        if tipo == 1:
            tipo_n = "A"
        elif tipo == 5:
            tipo_n = "CNAME"
        elif tipo == 13:
            tipo_n = "HINFO"
        elif tipo == 15:
            tipo_n = "MX"
        elif tipo == 22 or tipo == 23:
            tipo_n = "NS"
        else:
            tipo_n = "Sin definir"

        clase = int(datos[k + 16:k + 32], 2)
        if clase == 1:
            clase_n = "IN"
        elif clase == 3:
            clase_n = "CH"
        else:
            clase_n = "Sin definir"

        print(f"Nombre de dominio: {nombre[:-1]}")
        print(f"Tipo: {tipo} - {tipo_n}")
        print(f"Clase: {clase} - {clase_n}")

    if an_count == 0:
        print("\n\t\tNo hay respuestas")

    else:
        puntero = hex(int(datos[96+aum:96+aum+16], 2)).split("x")
        puntero = puntero[1].upper()
        print(puntero)
        nd = datos[96+aum+16:]

    for i in range(an_count):

        print(f"\n\t\t\tRespuesta {i + 1}\n")
        nombre_encontrado = False
        sig = True
        aum2 = 8
        nombre = ""
        while not nombre_encontrado:

            if sig:
                aux = int(nd[:8], 2)
            else:
                aux = 0

            if aux == 0:
                break

            for j in range(aux):
                nd = nd[8:]
                aum2 += 8
                if nd != "":
                    nombre += chr(int(nd[:8], 2))

                if j == aux - 1:
                    nd = nd[8:]
                    aum2 += 8
                    nombre += "."
                    sig = True

        k = 96 + aum + aum2

        tipo = int(datos[k:k + 16], 2)
        if tipo == 1:
            tipo_n = "A"
        elif tipo == 5:
            tipo_n = "CNAME"
        elif tipo == 13:
            tipo_n = "HINFO"
        elif tipo == 15:
            tipo_n = "MX"
        elif tipo == 22 or tipo == 23:
            tipo_n = "NS"
        else:
            tipo_n = "Sin definir"

        clase = int(datos[k + 16:k + 32], 2)
        if clase == 1:
            clase_n = "IN"
        elif clase == 3:
            clase_n = "CH"
        else:
            clase_n = "Sin definir"

        tiempo_vida = int(datos[k+32:k+64], 2)
        long_datos = int(datos[k+64:k+80], 2)

        r_data = datos[k+80:k+(long_datos*8)]

        aux = "0b"
        aux += r_data
        aux = int(aux, 2)
        aux = aux.to_bytes((aux.bit_length() + 7) // 8, 'big').decode()

        print(f"Nombre de dominio: {nombre[:-1]}")
        print(f"Tipo: {tipo} - {tipo_n}")
        print(f"Clase: {clase} - {clase_n}")
        print(f"Tiempo de vida: {tiempo_vida}")
        print(f"Longitud de datos: {long_datos}")
        print("RDATA: ")

        if tipo == 1:
            print(
                f'Dirección IP: {int(r_data[0:8], 2)}.{int(r_data[8:16]), 2}.{int(r_data[16:24], 2)}'
                f'.{int(r_data[24:32]), 2}')

        elif tipo == 5:
            print("Nombre del dominio: " + nombre[:-1])
        elif tipo == 15:
            print("MX:", aux)
        elif tipo == 22 or tipo == 23:
            print("NS:", aux)
        else:
            print("SOA:", aux)


if __name__ == '__main__':
    while True:
        captura()
        ethernet()
        print("\n============================================")
        input("Pulse enter para mostrar el siguiente paquete...")
