# Importa as variáveis compartilhadas e o lock para sincronização de threads
from data import log_lock, packet_logs, packet_stats

# Importa as funções para carregar e aplicar regras do firewall
from regras import load_rules, apply_rules, get_rules

# Importa as funções principais da biblioteca Scapy para captura e manipulação de pacotes
from scapy.all import sniff, IP, TCP, UDP

# Importa a biblioteca time para registrar timestamps
import time

#############################
# CARREGAMENTO INICIAL DAS REGRAS DO FIREWALL
#############################

# Carrega as regras do firewall a partir do arquivo rules.json ao iniciar
load_rules()

#############################
# FUNÇÃO PARA PROCESSAR PACOTES
#############################

def packet_handler(packet):
    """
    Processa um pacote capturado, aplica as regras do firewall e registra o resultado nos logs.

    Args:
        packet: O pacote capturado pela Scapy.
    """
    # Aplica as regras do firewall ao pacote capturado usando as regras mais recentes
    action, rule = apply_rules(packet)

    #############################
    # DETERMINAÇÃO DA DIREÇÃO DO PACOTE
    #############################

    # Verifica se o pacote contém o protocolo IP
    if IP in packet:
        # Determina se o pacote foi enviado ou recebido com base no endereço IP de origem
        if packet[IP].src.startswith(("192.168.", "10.", "172.16.", "172.31.")):
            direction = "sent"  # Pacote enviado pela LAN (rede local)
        else:
            direction = "received"  # Pacote recebido pela WAN (rede externa)
    else:
        direction = None  # Caso o pacote não contenha IP, a direção é indefinida

    #############################
    # ATUALIZAÇÃO DAS ESTATÍSTICAS DE PACOTES
    #############################

    # Usa o log_lock para garantir que a atualização das estatísticas seja thread-safe
    with log_lock:
        if direction == "sent":
            packet_stats["sent"] += 1  # Incrementa o contador de pacotes enviados
        elif direction == "received":
            packet_stats["received"] += 1  # Incrementa o contador de pacotes recebidos

    #############################
    # CRIAÇÃO DE UMA ENTRADA DE LOG
    #############################

    # Cria uma entrada de log com as informações do pacote capturado
    log_entry = {
        "timestamp": time.time(),  # Marca o timestamp atual (em segundos desde a época Unix)
        "src_ip": packet[IP].src if IP in packet else None,  # Endereço IP de origem
        "dst_ip": packet[IP].dst if IP in packet else None,  # Endereço IP de destino
        "protocol": packet[IP].proto if IP in packet else None,  # Protocolo (TCP, UDP, etc.)
        "src_port": packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None),  # Porta de origem
        "dst_port": packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None),  # Porta de destino
        "action": action,  # Ação aplicada ao pacote ("allowed" ou "blocked")
        "direction": direction,  # Direção do pacote ("sent" ou "received")
        "rule": rule  # Adiciona a regra que causou a ação (None se permitido)
    }

    #############################
    # ADIÇÃO DO LOG À LISTA COMPARTILHADA
    #############################

    # Usa o log_lock para garantir que a adição ao log seja thread-safe
    with log_lock:
        packet_logs.append(log_entry)  # Adiciona a entrada de log à lista compartilhada

#############################
# FUNÇÃO PARA CAPTURAR PACOTES
#############################

def sniff_packets():
    """
    Captura pacotes de rede em tempo real e os processa usando a função packet_handler.
    """
    # Usa a função sniff da biblioteca Scapy para capturar pacotes
    # - filter="ip": Captura apenas pacotes IP
    # - prn=packet_handler: Chama a função packet_handler para processar cada pacote capturado
    # - store=0: Não armazena os pacotes capturados na memória (apenas processa em tempo real)
    sniff(filter="ip", prn=packet_handler, store=0)