# Importa a biblioteca threading para gerenciar sincronização entre threads
import threading

# Cria um lock (trava) para garantir que apenas uma thread acesse os logs por vez
log_lock = threading.Lock()

# Lista compartilhada para armazenar os logs dos pacotes capturados
packet_logs = []

# Variáveis compartilhadas para rastrear pacotes enviados, recebidos e perdidos
packet_stats = {
    "sent": 0,  # Total de pacotes enviados
    "received": 0,  # Total de pacotes recebidos
    "lost": 0  # Total de pacotes perdidos
}
"""
packet_stats:
    - Um dicionário que armazena estatísticas sobre os pacotes capturados.
    - "sent": Total de pacotes enviados pela rede local.
    - "received": Total de pacotes recebidos pela rede local.
    - "lost": Total de pacotes perdidos (enviados sem resposta).
"""