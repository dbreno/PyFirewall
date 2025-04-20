# Importa variáveis compartilhadas e o lock para sincronização de threads
from data import log_lock, packet_logs, packet_stats

# Importa a biblioteca Streamlit para criar a interface gráfica
import streamlit as st

# Importa pandas para manipulação de dados em formato tabular
import pandas as pd

# Importa plotly.express para criar gráficos interativos
import plotly.express as px

# Importa plotly.graph_objects para criar gráficos de linha (tráfego ao longo do tempo)
import plotly.graph_objects as go

# Importa threading para gerenciar threads no programa
import threading

# Importa a função sniff_packets para capturar pacotes de rede
from main import sniff_packets

# Importa time para controlar o intervalo de atualização
import time

# Importa datetime para manipulação de timestamps
from datetime import datetime, timedelta

# Importa pytz para manipulação de fusos horários
import pytz

# Importa funções para gerenciar regras
from regras import get_rules, save_rules

#############################
# INICIALIZAÇÃO DO SESSION_STATE
#############################

# Verifica se a thread de captura já foi iniciada no session_state
if "sniffing_thread_started" not in st.session_state:
    st.session_state["sniffing_thread_started"] = False

# Verifica se o estado de captura já foi definido no session_state
if "capture_state" not in st.session_state:
    st.session_state["capture_state"] = "running"

# Verifica se o contador de iterações já foi definido no session_state
if "iteration" not in st.session_state:
    st.session_state["iteration"] = 0

# Verifica se o último gráfico já foi armazenado no session_state
if "last_chart" not in st.session_state:
    st.session_state["last_chart"] = None

# Verifica se a última tabela já foi armazenada no session_state
if "last_table" not in st.session_state:
    st.session_state["last_table"] = None

# Verifica se o botão de exportação foi clicado
if "export_clicked" not in st.session_state:
    st.session_state["export_clicked"] = False

# Verifica o timestamp de quando o botão de exportação foi clicado
if "export_timestamp" not in st.session_state:
    st.session_state["export_timestamp"] = None

# Verifica se há dados de exportação para download
if "export_data" not in st.session_state:
    st.session_state["export_data"] = None

# Persiste o estado do filtro de pacotes bloqueados
if "show_blocked_only" not in st.session_state:
    st.session_state["show_blocked_only"] = False

# Persiste o critério de ordenação
if "sort_by" not in st.session_state:
    st.session_state["sort_by"] = "timestamp"

# Persiste a direção da ordenação
if "sort_order" not in st.session_state:
    st.session_state["sort_order"] = "Ascendente"

# Persiste os filtros de pesquisa por IP e protocolo
if "search_src_ip" not in st.session_state:
    st.session_state["search_src_ip"] = ""
if "search_dst_ip" not in st.session_state:
    st.session_state["search_dst_ip"] = ""
if "search_protocol" not in st.session_state:
    st.session_state["search_protocol"] = ""

# Persiste o intervalo de tempo do gráfico de tráfego
if "traffic_interval" not in st.session_state:
    st.session_state["traffic_interval"] = "10s"

# Persiste o filtro de tempo
if "time_filter" not in st.session_state:
    st.session_state["time_filter"] = "Todos"

# Dados para exportação filtrada
if "export_filtered_data" not in st.session_state:
    st.session_state["export_filtered_data"] = None
if "export_filtered_clicked" not in st.session_state:
    st.session_state["export_filtered_clicked"] = False
if "export_filtered_timestamp" not in st.session_state:
    st.session_state["export_filtered_timestamp"] = None

# Notificações de pacotes suspeitos
if "notifications" not in st.session_state:
    st.session_state["notifications"] = []
if "last_notification_check" not in st.session_state:
    st.session_state["last_notification_check"] = 0

# Índice do pacote selecionado para visualização detalhada
if "selected_packet_index" not in st.session_state:
    st.session_state["selected_packet_index"] = 0

# Flag para controlar a exibição dos detalhes
if "show_details" not in st.session_state:
    st.session_state["show_details"] = False

# Estado para o CRUD de regras
if "rule_form_action" not in st.session_state:
    st.session_state["rule_form_action"] = "add"
if "rule_form_index" not in st.session_state:
    st.session_state["rule_form_index"] = None

# Dicionário para armazenar os valores do formulário de regras
if "rule_form_values" not in st.session_state:
    st.session_state["rule_form_values"] = {
        "action": "block",
        "protocol": "",
        "src_ip": "",
        "dst_ip": "",
        "src_port": "",
        "dst_port": ""
    }

#############################
# FUNÇÕES AUXILIARES
#############################

# Função para alternar o estado de captura (entre "running" e "paused")
def toggle_capture():
    """
    Alterna o estado de captura entre 'running' e 'paused'.
    """
    st.session_state["capture_state"] = (
        "paused" if st.session_state["capture_state"] == "running" else "running"
    )

# Função para alternar o estado do botão de exportação (logs completos)
def toggle_export():
    """
    Alterna o estado do botão de exportação para indicar que foi clicado.
    """
    st.session_state["export_clicked"] = True
    st.session_state["export_timestamp"] = time.time()
    with log_lock:
        logs = packet_logs.copy()
    if logs:
        df_logs = pd.DataFrame(logs)
        csv = df_logs.to_csv(index=False)
        st.session_state["export_data"] = csv
    else:
        st.session_state["export_data"] = None

# Função para exportar o DataFrame filtrado
def toggle_export_filtered(filtered_df):
    """
    Exporta o DataFrame filtrado como CSV.
    """
    st.session_state["export_filtered_clicked"] = True
    st.session_state["export_filtered_timestamp"] = time.time()
    if not filtered_df.empty:
        csv = filtered_df.to_csv(index=False)
        st.session_state["export_filtered_data"] = csv
    else:
        st.session_state["export_filtered_data"] = None

# Função que inicia a thread de captura de pacotes (apenas uma vez)
def start_sniffing_thread():
    """
    Inicia a thread de captura de pacotes, garantindo que ela seja iniciada apenas uma vez.
    """
    if not st.session_state["sniffing_thread_started"]:
        sniffing_thread = threading.Thread(target=sniff_packets, daemon=True)
        sniffing_thread.start()
        st.session_state["sniffing_thread_started"] = True

# Função para atualizar os dados manualmente
def update_data():
    """
    Atualiza os dados do dashboard manualmente, incrementando a iteração.
    """
    st.session_state["iteration"] += 1

# Função para limpar os filtros de pesquisa
def clear_filters():
    """
    Limpa os filtros de pesquisa, redefinindo os campos para vazio.
    """
    st.session_state["search_src_ip"] = ""
    st.session_state["search_dst_ip"] = ""
    st.session_state["search_protocol"] = ""
    st.session_state["time_filter"] = "Todos"

# Função para verificar notificações de pacotes suspeitos
def check_notifications(df, last_check):
    """
    Verifica se há pacotes bloqueados ou picos de tráfego desde a última verificação.
    """
    notifications = []
    
    # Filtra pacotes desde a última verificação
    new_packets = df[df["timestamp"] > last_check]
    
    # Verifica pacotes bloqueados
    blocked_packets = new_packets[new_packets["action"] == "blocked"]
    if not blocked_packets.empty:
        for _, packet in blocked_packets.iterrows():
            timestamp = pd.to_datetime(packet["timestamp"], unit="s").tz_localize('UTC').tz_convert('America/Sao_Paulo').strftime("%H:%M:%S")
            notifications.append(f"🚨 Pacote bloqueado às {timestamp}: {packet['src_ip']} -> {packet['dst_ip']}")
    
    # Verifica picos de tráfego (ex.: mais de 50 pacotes em 10 segundos)
    if not new_packets.empty:
        time_window = 10
        time_bins = new_packets["timestamp"].apply(lambda x: int(x // time_window) * time_window)
        traffic_counts = time_bins.value_counts()
        for time_bin, count in traffic_counts.items():
            if count > 50:
                timestamp = pd.to_datetime(time_bin, unit="s").tz_localize('UTC').tz_convert('America/Sao_Paulo').strftime("%H:%M:%S")
                notifications.append(f"📈 Pico de tráfego às {timestamp}: {count} pacotes em 10s")
    
    # Atualiza a última verificação
    if not new_packets.empty:
        st.session_state["last_notification_check"] = new_packets["timestamp"].max()
    
    return notifications

# Função para atualizar o índice do pacote selecionado
def update_selected_packet_index():
    """
    Atualiza o índice do pacote selecionado no session_state com base no valor do number_input.
    """
    st.session_state["selected_packet_index"] = st.session_state["packet_index_input"]

# Funções para o CRUD de regras
def add_rule(new_rule):
    """
    Adiciona uma nova regra à lista de regras e atualiza o rules.json.
    """
    rules = get_rules()
    rules.append(new_rule)
    save_rules(rules)
    st.success("✅ Regra adicionada com sucesso!")

def update_rule(index, updated_rule):
    """
    Atualiza uma regra existente na lista de regras e atualiza o rules.json.
    """
    rules = get_rules()
    if 0 <= index < len(rules):
        rules[index] = updated_rule
        save_rules(rules)
        st.success("✅ Regra atualizada com sucesso!")
    else:
        st.error("❌ Índice inválido!")

def delete_rule(index):
    """
    Remove uma regra da lista de regras e atualiza o rules.json.
    """
    rules = get_rules()
    if 0 <= index < len(rules):
        deleted_rule = rules.pop(index)
        save_rules(rules)
        st.success(f"✅ Regra removida: {deleted_rule}")
    else:
        st.error("❌ Índice inválido!")

def reset_rule_form():
    """
    Reseta os valores do formulário de regras para o estado inicial.
    """
    st.session_state["rule_form_action"] = "add"
    st.session_state["rule_form_index"] = None
    st.session_state["rule_form_values"] = {
        "action": "block",
        "protocol": "",
        "src_ip": "",
        "dst_ip": "",
        "src_port": "",
        "dst_port": ""
    }

def prepare_edit_rule(index):
    """
    Prepara o formulário para editar uma regra existente.
    """
    rules = get_rules()
    if 0 <= index < len(rules):
        selected_rule = rules[index]
        st.session_state["rule_form_action"] = "edit"
        st.session_state["rule_form_index"] = index
        st.session_state["rule_form_values"] = {
            "action": selected_rule.get("action", "block"),
            "protocol": selected_rule.get("protocol", ""),
            "src_ip": selected_rule.get("src_ip", ""),
            "dst_ip": selected_rule.get("dst_ip", ""),
            "src_port": str(selected_rule.get("src_port", "")) if selected_rule.get("src_port") else "",
            "dst_port": str(selected_rule.get("dst_port", "")) if selected_rule.get("dst_port") else ""
        }

#############################
# FUNÇÃO PRINCIPAL DO DASHBOARD
#############################

def display_dashboard():
    """
    Exibe o painel de tráfego de rede na interface gráfica.
    Mostra métricas, gráficos e tabelas baseados nos pacotes capturados.
    Atualiza os dados sob demanda, permitindo interatividade nos filtros.
    """
    # Título do painel
    st.header("Painel de Tráfego de Rede")

    # Define a cor do botão "Pausar/Retomar Captura" com base no estado
    button_label = "Pausar Captura" if st.session_state["capture_state"] == "running" else "Retomar Captura"

    # CSS para alinhar verticalmente os botões e evitar quebras de linha
    st.markdown("""
        <style>
        .button-container {
            display: flex;
            align-items: center;
        }
        .stButton > button {
            white-space: nowrap;
        }
        </style>
    """, unsafe_allow_html=True)

    # Botões alinhados na mesma linha: "Exportar Logs como CSV", "Atualizar Dados" e "Pausar/Retomar Captura"
    col_left, col_middle, col_right = st.columns([2, 2, 1])

    with col_left:
        # Botão para exportar logs completos como CSV
        if st.button("Exportar Logs como CSV", key="export_button", help="Clique para exportar os logs completos em formato CSV"):
            toggle_export()
        if st.session_state["export_data"] is not None:
            st.download_button(
                label="Baixar Logs Completos",
                data=st.session_state["export_data"],
                file_name="firewall_logs.csv",
                mime="text/csv",
                key="download_button"
            )

    with col_middle:
        # Botão para atualizar os dados manualmente
        st.button("Atualizar Dados", key="update_button", on_click=update_data, help="Clique para atualizar as métricas, gráficos e tabela")

    with col_right:
        # Botão que alterna o estado de captura
        st.button(button_label, key="pause_button", on_click=toggle_capture)

    # Mensagem de sucesso para exportação de logs completos
    if st.session_state["export_data"] is not None:
        st.success("✅ Logs completos exportados com sucesso! Clique no botão acima para baixar.")

    # Reseta o estado de exportação após 5 segundos
    if st.session_state["export_timestamp"] is not None:
        current_time = time.time()
        if current_time - st.session_state["export_timestamp"] >= 5:
            st.session_state["export_clicked"] = False
            st.session_state["export_data"] = None
            st.session_state["export_timestamp"] = None

    # Inicia a thread de captura de pacotes (caso ainda não tenha sido iniciada)
    start_sniffing_thread()

    # Se a captura estiver pausada, exibe uma mensagem e não atualiza os dados
    if st.session_state["capture_state"] == "paused":
        st.warning("⚠️ Captura de pacotes pausada. Retome a captura para atualizar os dados.")
        return

    #############################
    # LINK PARA CONTROLE DE BLOQUEIO REAL
    #############################

    st.subheader("Controle de Bloqueio Real")
    st.markdown("Gerencie o bloqueio real de pacotes em uma página separada para evitar interferências no dashboard.")
    st.markdown("[Acessar Controle de Bloqueio Real](http://localhost:8000)")

    #############################
    # GERENCIAMENTO DE REGRAS (CRUD)
    #############################

    st.subheader("Gerenciamento de Regras do Firewall")

    # Exibe a lista de regras atuais com botões de ação
    rules = get_rules()
    if rules:
        rules_df = pd.DataFrame(rules)
        rules_df["Ações"] = [f"Editar | Deletar" for _ in range(len(rules))]
        st.dataframe(rules_df, key="rules_table", use_container_width=True)

        # Adiciona botões de ação para cada regra
        for index, rule in enumerate(rules):
            col_edit, col_delete = st.columns(2)
            with col_edit:
                if st.button(f"Editar Regra {index}", key=f"edit_rule_{index}"):
                    prepare_edit_rule(index)
                    st.rerun()
            with col_delete:
                if st.button(f"Deletar Regra {index}", key=f"delete_rule_{index}"):
                    delete_rule(index)
                    reset_rule_form()
                    st.rerun()
    else:
        st.info("ℹ️ Nenhuma regra encontrada.")

    # Formulário para adicionar ou editar uma regra
    st.subheader("Adicionar/Editar Regra")
    form_values = st.session_state["rule_form_values"]

    with st.form(key="rule_form"):
        action = st.selectbox(
            "Ação",
            options=["block", "allow"],
            index=0 if form_values["action"] == "block" else 1
        )
        protocol = st.text_input(
            "Protocolo (ex.: tcp, udp, icmp)",
            value=form_values["protocol"],
            placeholder="Deixe vazio para qualquer protocolo"
        )
        src_ip = st.text_input(
            "IP de Origem",
            value=form_values["src_ip"],
            placeholder="Ex.: 192.168.0.100 (deixe vazio para qualquer IP)"
        )
        dst_ip = st.text_input(
            "IP de Destino",
            value=form_values["dst_ip"],
            placeholder="Ex.: 8.8.8.8 (deixe vazio para qualquer IP)"
        )
        src_port = st.text_input(
            "Porta de Origem",
            value=form_values["src_port"],
            placeholder="Ex.: 12345 (deixe vazio para qualquer porta)"
        )
        dst_port = st.text_input(
            "Porta de Destino",
            value=form_values["dst_port"],
            placeholder="Ex.: 80 (deixe vazio para qualquer porta)"
        )

        col_submit, col_cancel = st.columns(2)
        with col_submit:
            submit_button = st.form_submit_button(label="Salvar Regra")
        with col_cancel:
            if st.session_state["rule_form_action"] == "edit":
                cancel_button = st.form_submit_button(label="Cancelar Edição")
            else:
                cancel_button = False

        if submit_button:
            # Cria a nova regra como um dicionário
            new_rule = {"action": action}
            if protocol:
                new_rule["protocol"] = protocol.lower()
            if src_ip:
                new_rule["src_ip"] = src_ip
            if dst_ip:
                new_rule["dst_ip"] = dst_ip
            if src_port:
                try:
                    new_rule["src_port"] = int(src_port)
                except ValueError:
                    st.error("❌ Porta de origem deve ser um número inteiro!")
                    st.stop()
            if dst_port:
                try:
                    new_rule["dst_port"] = int(dst_port)
                except ValueError:
                    st.error("❌ Porta de destino deve ser um número inteiro!")
                    st.stop()

            # Adiciona ou atualiza a regra
            if st.session_state["rule_form_action"] == "add":
                add_rule(new_rule)
            else:
                update_rule(st.session_state["rule_form_index"], new_rule)

            # Reseta o formulário
            reset_rule_form()
            st.rerun()

        if cancel_button:
            reset_rule_form()
            st.rerun()

    #############################
    # PROCESSAMENTO DOS DADOS
    #############################

    # Copia os logs e estatísticas de forma thread-safe
    with log_lock:
        logs = packet_logs.copy()
        stats = packet_stats.copy()

    # Converte os logs em um DataFrame do pandas
    df = pd.DataFrame(logs)

    # Verifica notificações de pacotes suspeitos
    if not df.empty:
        new_notifications = check_notifications(df, st.session_state["last_notification_check"])
        st.session_state["notifications"].extend(new_notifications)

    # Exibe notificações
    if st.session_state["notifications"]:
        st.subheader("Notificações")
        for notification in st.session_state["notifications"][-5:]:
            st.markdown(notification)
        # Botão para limpar notificações
        if st.button("Limpar Notificações", key="clear_notifications"):
            st.session_state["notifications"] = []

    #############################
    # EXIBIÇÃO DAS MÉTRICAS
    #############################

    # Exibe as métricas
    col1, col2 = st.columns(2)
    col3, col4 = st.columns(2)

    with col1:
        st.metric("Total de Pacotes", len(df))
    with col2:
        st.metric("Pacotes Enviados", stats["sent"])
    with col3:
        st.metric("Pacotes Recebidos", stats["received"])
    with col4:
        st.metric("Perda de Pacotes", stats["lost"])

    #############################
    # EXIBIÇÃO DOS GRÁFICOS
    #############################

    # Se o DataFrame não estiver vazio, processa os dados para os gráficos
    if not df.empty:
        # Classifica os IPs como LAN ou WAN
        df["ip_type"] = df["src_ip"].apply(
            lambda ip: "LAN" if isinstance(ip, str) and ip.startswith(("192.168.", "10.", "172.16.", "172.31.")) else "WAN"
        )
        df = df.sort_values(by="ip_type")

        # Calcula os 5 IPs de origem mais ativos
        src_ip_counts = df["src_ip"].value_counts().head(5)

        # Cria um gráfico de barras com os IPs de origem mais ativos
        fig_ip = px.bar(
            x=src_ip_counts.index,
            y=src_ip_counts.values,
            color=src_ip_counts.index.map(
                lambda ip: "LAN" if isinstance(ip, str) and ip.startswith(("192.168.", "10.", "172.16.", "172.31.")) else "WAN"
            ),
            title="Top 5 IPs de Origem",
            labels={"x": "IPs de Origem", "y": "Quantidade de Pacotes", "color": "Tipo de Rede"}
        )

        # Calcula a contagem de pacotes por protocolo
        protocol_counts = df["protocol"].value_counts()

        # Mapeia os números dos protocolos para nomes legíveis (ex.: 6 = TCP, 17 = UDP)
        protocol_names = {6: "TCP", 17: "UDP", 1: "ICMP"}
        protocol_labels = protocol_counts.index.map(lambda x: protocol_names.get(x, f"Protocol {x}"))

        # Cria um gráfico de barras para os protocolos mais usados
        fig_protocols = px.bar(
            x=protocol_counts.values,
            y=protocol_labels,
            orientation="h",
            title="Protocolos Mais Usados",
            labels={"x": "Quantidade de Pacotes", "y": "Protocolo"}
        )

        # Exibe os gráficos
        st.plotly_chart(fig_ip, key=f"chart_{st.session_state['iteration']}")
        st.plotly_chart(fig_protocols, key=f"protocol_chart_{st.session_state['iteration']}")

        # Gráfico de linha: Tráfego ao longo do tempo
        st.subheader("Tráfego de Rede ao Longo do Tempo")
        # Dropdown para selecionar o intervalo de tempo
        st.selectbox(
            "Intervalo de Tempo",
            options=["5s", "10s", "30s"],
            index=["5s", "10s", "30s"].index(st.session_state["traffic_interval"]),
            key="traffic_interval"
        )

        # Converte o timestamp para datetime, ajustando para o horário de Brasília (GMT-3)
        df["timestamp_dt"] = pd.to_datetime(df["timestamp"], unit="s").dt.tz_localize('UTC').dt.tz_convert('America/Sao_Paulo')

        # Filtra apenas os últimos 5 minutos para tornar o gráfico mais legível
        current_time = pd.Timestamp.now(tz='America/Sao_Paulo')
        time_threshold = current_time - timedelta(minutes=5)
        df = df[df["timestamp_dt"] >= time_threshold]

        # Arredonda os timestamps para o intervalo selecionado
        interval = st.session_state["traffic_interval"]
        df["time_bin"] = df["timestamp_dt"].dt.floor(interval)

        # Conta o número de pacotes por intervalo de tempo
        traffic_over_time = df.groupby("time_bin").size().reset_index(name="packet_count")

        # Cria o gráfico de linha
        fig_traffic = go.Figure()
        fig_traffic.add_trace(
            go.Scatter(
                x=traffic_over_time["time_bin"],
                y=traffic_over_time["packet_count"],
                mode="lines+markers",
                name="Pacotes por Intervalo de Tempo",
                marker=dict(size=8),
                line=dict(width=2)
            )
        )
        fig_traffic.update_layout(
            title=f"Tráfego de Rede ao Longo do Tempo (Intervalo: {interval})",
            xaxis_title="Tempo (Horário de Brasília)",
            yaxis_title="Número de Pacotes",
            xaxis=dict(
                tickformat="%H:%M:%S",
                tickangle=45,
                dtick=30000 if interval == "5s" else 60000 if interval == "10s" else 180000,
                range=[time_threshold, current_time]
            ),
            height=500
        )
        st.plotly_chart(fig_traffic, key=f"traffic_chart_{st.session_state['iteration']}")

    #############################
    # EXIBIÇÃO DA TABELA COM FILTROS E ORDENAÇÃO
    #############################

    # Exibe a seção de filtros e tabela
    st.subheader("Filtros de Pesquisa")
    col_search1, col_search2, col_search3, col_search4, col_clear = st.columns([3, 3, 3, 3, 1])
    with col_search1:
        st.text_input(
            "Filtrar por IP de Origem",
            value=st.session_state["search_src_ip"],
            key="search_src_ip",
            placeholder="Ex.: 192.168.1.1"
        )
    with col_search2:
        st.text_input(
            "Filtrar por IP de Destino",
            value=st.session_state["search_dst_ip"],
            key="search_dst_ip",
            placeholder="Ex.: 8.8.8.8"
        )
    with col_search3:
        st.text_input(
            "Filtrar por Protocolo",
            value=st.session_state["search_protocol"],
            key="search_protocol",
            placeholder="Ex.: TCP, UDP, ICMP"
        )
    with col_search4:
        st.selectbox(
            "Filtrar por Tempo",
            options=["Todos", "Últimos 5 minutos", "Últimos 15 minutos", "Últimos 30 minutos"],
            index=["Todos", "Últimos 5 minutos", "Últimos 15 minutos", "Últimos 30 minutos"].index(st.session_state["time_filter"]),
            key="time_filter"
        )
    with col_clear:
        st.button("Limpar Filtros", key="clear_filters", on_click=clear_filters)

    # Se o DataFrame não estiver vazio, aplica os filtros e exibe a tabela
    if not df.empty:
        # Aplica os filtros de pesquisa
        filtered_df = df.copy()

        # Filtro por IP de Origem
        if st.session_state["search_src_ip"]:
            try:
                filtered_df = filtered_df[
                    filtered_df["src_ip"].str.contains(
                        st.session_state["search_src_ip"], case=False, na=False, regex=False
                    )
                ]
            except Exception as e:
                st.warning(f"⚠️ Erro no filtro de IP de Origem: {e}. Verifique o formato do IP.")

        # Filtro por IP de Destino
        if st.session_state["search_dst_ip"]:
            try:
                filtered_df = filtered_df[
                    filtered_df["dst_ip"].str.contains(
                        st.session_state["search_dst_ip"], case=False, na=False, regex=False
                    )
                ]
            except Exception as e:
                st.warning(f"⚠️ Erro no filtro de IP de Destino: {e}. Verifique o formato do IP.")

        # Filtro por Protocolo
        if st.session_state["search_protocol"]:
            protocol_map = {"TCP": 6, "UDP": 17, "ICMP": 1}
            search_protocol = st.session_state["search_protocol"].upper()
            protocol_num = protocol_map.get(search_protocol, None)
            if protocol_num is not None:
                filtered_df = filtered_df[filtered_df["protocol"] == protocol_num]
            else:
                st.warning(f"⚠️ Protocolo '{st.session_state['search_protocol']}' inválido. Use TCP, UDP ou ICMP.")

        # Filtro por Tempo
        if st.session_state["time_filter"] != "Todos":
            current_time = pd.Timestamp.now(tz='America/Sao_Paulo')
            if st.session_state["time_filter"] == "Últimos 5 minutos":
                time_threshold = current_time - timedelta(minutes=5)
            elif st.session_state["time_filter"] == "Últimos 15 minutos":
                time_threshold = current_time - timedelta(minutes=15)
            elif st.session_state["time_filter"] == "Últimos 30 minutos":
                time_threshold = current_time - timedelta(minutes=30)
            filtered_df["timestamp_dt"] = pd.to_datetime(filtered_df["timestamp"], unit="s").dt.tz_localize('UTC').dt.tz_convert('America/Sao_Paulo')
            filtered_df = filtered_df[filtered_df["timestamp_dt"] >= time_threshold]

        # Aplica o filtro de pacotes bloqueados
        st.subheader("Logs de Pacotes")
        st.checkbox(
            "Exibir apenas pacotes bloqueados",
            value=st.session_state["show_blocked_only"],
            key="show_blocked_only",
            on_change=update_data
        )
        if st.session_state["show_blocked_only"]:
            filtered_df = filtered_df[filtered_df["action"] == "blocked"]

        # Adiciona opções de ordenação
        col_sort1, col_sort2 = st.columns(2)
        with col_sort1:
            st.selectbox(
                "Ordenar por",
                options=["timestamp", "src_ip", "dst_ip"],
                index=["timestamp", "src_ip", "dst_ip"].index(st.session_state["sort_by"]),
                key="sort_by"
            )
        with col_sort2:
            st.selectbox(
                "Ordem",
                options=["Ascendente", "Descendente"],
                index=["Ascendente", "Descendente"].index(st.session_state["sort_order"]),
                key="sort_order"
            )

        # Aplica a ordenação ao DataFrame
        ascending = True if st.session_state["sort_order"] == "Ascendente" else False
        filtered_df = filtered_df.sort_values(by=st.session_state["sort_by"], ascending=ascending)

        # Exibe a tabela ou uma mensagem se não houver dados
        if not filtered_df.empty:
            # Botão para exportar os dados filtrados
            if st.button("Exportar Logs Filtrados como CSV", key="export_filtered_button"):
                toggle_export_filtered(filtered_df)
            if st.session_state["export_filtered_data"] is not None:
                st.download_button(
                    label="Baixar Logs Filtrados",
                    data=st.session_state["export_filtered_data"],
                    file_name="firewall_logs_filtered.csv",
                    mime="text/csv",
                    key="download_filtered_button"
                )

            # Visualização Detalhada de Pacote
            st.subheader("Visualização Detalhada de Pacote")

            # Entrada do índice com validação
            packet_index_input = st.number_input(
                "Índice do Pacote (linha da tabela)",
                min_value=0,
                max_value=len(filtered_df) - 1,
                value=st.session_state["selected_packet_index"],
                step=1,
                key="packet_index_input",
                on_change=update_selected_packet_index
            )

            # Botão para ativar exibição de detalhes
            if st.button("Ver Detalhes do Pacote", key="view_packet_details"):
                st.session_state["show_details"] = True
                st.session_state["selected_packet_index"] = packet_index_input

            # Botão para ocultar detalhes
            if st.button("Ocultar Detalhes do Pacote", key="hide_packet_details"):
                st.session_state["show_details"] = False

            # Exibe os detalhes apenas se a flag estiver ativada
            if st.session_state["show_details"]:
                try:
                    index = st.session_state["selected_packet_index"]
                    if 0 <= index < len(filtered_df):
                        packet = filtered_df.iloc[index]
                        st.markdown("### Detalhes do Pacote")
                        for key, value in packet.items():
                            st.markdown(f"**{key}:** {value}")
                    else:
                        st.error("❌ Índice fora do intervalo da tabela.")
                except Exception as e:
                    st.error(f"❌ Erro ao tentar exibir o pacote: {e}")

            # Exibe a tabela
            st.dataframe(
                filtered_df[["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "action", "rule"]],
                key=f"table_{st.session_state['iteration']}"
            )
        else:
            st.info("ℹ️ Nenhum pacote encontrado com os filtros aplicados.")

        # Reseta o estado de exportação filtrada após 5 segundos
        if st.session_state["export_filtered_timestamp"] is not None:
            current_time = time.time()
            if current_time - st.session_state["export_filtered_timestamp"] >= 5:
                st.session_state["export_filtered_clicked"] = False
                st.session_state["export_filtered_data"] = None
                st.session_state["export_filtered_timestamp"] = None

#############################
# EXECUÇÃO DO DASHBOARD
#############################

# Executa o painel se o script for executado diretamente
if __name__ == "__main__":
    display_dashboard()