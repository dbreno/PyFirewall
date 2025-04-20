# Importa a biblioteca JSON para manipular o arquivo de regras (rules.json)
import json

# Importa as camadas IP, TCP e UDP da biblioteca Scapy para verificar pacotes
from scapy.all import IP, TCP, UDP

# Importa as variáveis compartilhadas para logs e sincronização
from data import log_lock, packet_logs

# Cria um lock para sincronizar o acesso às regras
import threading
rules_lock = threading.Lock()

# Variável global para armazenar as regras carregadas
_rules = []

# Função para carregar as regras do firewall a partir do arquivo rules.json
def load_rules():
    """
    Carrega as regras do firewall de um arquivo JSON e atualiza a variável global _rules.

    Returns:
        list: Uma lista de regras, onde cada regra é um dicionário contendo
              os critérios de bloqueio ou permissão.
    """
    global _rules
    try:
        with open("rules.json", "r") as f:
            with rules_lock:
                _rules = json.load(f)
        return _rules
    except Exception as e:
        print(f"Erro ao carregar regras: {e}")
        return _rules

# Função para obter as regras atuais
def get_rules():
    """
    Retorna as regras atualmente carregadas.

    Returns:
        list: Lista de regras carregadas.
    """
    with rules_lock:
        return _rules

# Função para salvar as regras no arquivo rules.json
def save_rules(rules):
    """
    Salva as regras no arquivo rules.json e atualiza a variável global _rules.

    Args:
        rules: Lista de regras a ser salva.
    """
    global _rules
    try:
        with open("rules.json", "w") as f:
            json.dump(rules, f, indent=4)
        with rules_lock:
            _rules = rules
    except Exception as e:
        print(f"Erro ao salvar regras: {e}")

# Função para aplicar as regras do firewall a um pacote capturado
def apply_rules(packet, rules=None):
    """
    Aplica as regras do firewall a um pacote capturado.

    Args:
        packet: O pacote capturado pela Scapy.
        rules: Lista de regras a serem aplicadas. Se None, usa as regras carregadas.

    Returns:
        tuple: Um par (action, rule), onde:
               - action (str): "blocked" se o pacote for bloqueado, "allowed" caso contrário.
               - rule (dict): A regra que causou o bloqueio, ou None se permitido.
    """
    if rules is None:
        rules = get_rules()

    # Itera sobre todas as regras
    for rule in rules:
        # Verifica se a ação da regra é "block" (bloquear)
        if rule["action"] == "block":
            # Flag para verificar se todos os critérios da regra são atendidos
            match = True

            # Verifica o IP de origem, se especificado na regra
            if "src_ip" in rule:
                if not (IP in packet and packet[IP].src == rule["src_ip"]):
                    match = False

            # Verifica o IP de destino, se especificado na regra
            if "dst_ip" in rule:
                if not (IP in packet and packet[IP].dst == rule["dst_ip"]):
                    match = False

            # Verifica o protocolo, se especificado na regra
            if "protocol" in rule:
                # Mapeia o nome do protocolo para o número (ex.: "tcp" -> 6)
                protocol_map = {"tcp": 6, "udp": 17, "icmp": 1}
                expected_proto = protocol_map.get(rule["protocol"].lower(), None)
                if not (IP in packet and expected_proto is not None and packet[IP].proto == expected_proto):
                    match = False

            # Verifica a porta de origem, se especificada na regra
            if "src_port" in rule:
                src_port = None
                if TCP in packet:
                    src_port = packet[TCP].sport
                elif UDP in packet:
                    src_port = packet[UDP].sport
                if src_port is None or src_port != int(rule["src_port"]):
                    match = False

            # Verifica a porta de destino, se especificada na regra
            if "dst_port" in rule:
                dst_port = None
                if TCP in packet:
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    dst_port = packet[UDP].dport
                if dst_port is None or dst_port != int(rule["dst_port"]):
                    match = False

            # Se todos os critérios da regra forem atendidos, bloqueia o pacote
            if match:
                return "blocked", rule

    # Se nenhuma regra bloquear o pacote, ele é permitido
    return "allowed", None