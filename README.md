# **Projeto Firewall - Monitoramento e Controle de Tráfego de Rede**

Este projeto é um **firewall interativo** desenvolvido em Python, que utiliza a biblioteca **Streamlit** para criar uma interface gráfica amigável, a biblioteca **Scapy** para capturar e processar pacotes de rede em tempo real, e **FastAPI** para gerenciar o bloqueio real de pacotes via `iptables`. O objetivo principal é monitorar o tráfego de rede, aplicar regras de firewall (tanto simuladas quanto reais), e exibir informações detalhadas sobre os pacotes capturados em um dashboard interativo. O projeto inclui funcionalidades avançadas como notificações de eventos suspeitos, visualização detalhada de pacotes, gerenciamento de regras, e uma interface separada para controle de bloqueio real, garantindo maior estabilidade e segurança.

---

## **Funcionalidades do Projeto**

O projeto é dividido em duas partes principais: o **dashboard Streamlit** (executado pelo `ig.py`) e o **controle de bloqueio real** (executado pelo `block_control.py` via FastAPI). Abaixo estão as funcionalidades detalhadas:

### **1. Dashboard Streamlit (Interface Gráfica)**
- **Captura de Pacotes em Tempo Real**:
  - Utiliza a biblioteca **Scapy** para capturar pacotes de rede.
  - Processa apenas pacotes IP, garantindo compatibilidade com a maioria das redes.
- **Métricas de Tráfego**:
  - Exibe o total de pacotes capturados, pacotes enviados, pacotes recebidos e perda de pacotes em tempo real.
- **Gráficos Interativos**:
  - **Top 5 IPs de Origem**: Mostra os IPs mais ativos, diferenciando LAN (ex.: 192.168.x.x) e WAN por cores.
  - **Protocolos Mais Usados**: Exibe a distribuição de protocolos (TCP, UDP, ICMP, etc.) em um gráfico de barras horizontais.
  - **Tráfego ao Longo do Tempo**: Gráfico de linha mostrando o tráfego nos últimos 5 minutos, com intervalos configuráveis (5s, 10s, 30s) e timestamps ajustados para o horário de Brasília (GMT-3).
- **Tabela de Logs de Pacotes**:
  - Lista todos os pacotes capturados com detalhes como timestamp, IPs de origem/destino, portas, protocolo, ação (allow/block) e regra aplicada.
  - Permite filtrar por IP de origem, IP de destino, protocolo (TCP, UDP, ICMP), intervalo de tempo (últimos 5, 15 ou 30 minutos) e pacotes bloqueados.
  - Suporta ordenação por timestamp, IP de origem ou IP de destino, em ordem ascendente ou descendente.
  - Inclui um botão "Limpar Filtros" para redefinir os filtros aplicados.
  - Permite exportar logs completos ou filtrados como arquivos CSV, com botões "Exportar Logs como CSV" e "Exportar Logs Filtrados como CSV".
- **Pausa e Retomada da Captura**:
  - Um botão "Pausar Captura" permite pausar a captura de pacotes sem perder os dados exibidos; "Retomar Captura" reativa a captura.
- **Notificações de Eventos Suspeitos**:
  - Exibe notificações em tempo real para pacotes bloqueados e picos de tráfego (mais de 50 pacotes em 10 segundos).
  - Mostra as últimas 5 notificações com timestamps ajustados para o horário de Brasília (GMT-3).
  - Inclui um botão "Limpar Notificações" para remover as notificações exibidas.
- **Visualização Detalhada de Pacotes**:
  - Permite selecionar um pacote da tabela pelo índice da linha para visualizar todos os seus detalhes (ex.: timestamp, IPs, portas, protocolo, ação, regra).
  - Inclui botões "Ver Detalhes do Pacote" e "Ocultar Detalhes do Pacote" para controlar a exibição.
- **Gerenciamento de Regras do Firewall (CRUD)**:
  - Exibe uma tabela com as regras atuais carregadas do arquivo `rules.json`.
  - Permite adicionar, editar e remover regras via uma interface de formulário.
  - Campos das regras incluem ação (allow/block), protocolo (ex.: tcp, udp, icmp), IP de origem, IP de destino, porta de origem e porta de destino.
  - Valida entradas (ex.: portas devem ser números inteiros) e exibe mensagens de sucesso ou erro após cada operação.
- **Link para Controle de Bloqueio Real**:
  - Inclui um link "Acessar Controle de Bloqueio Real" que redireciona para a página servida pelo FastAPI em `http://localhost:8000`.

### **2. Controle de Bloqueio Real (FastAPI)**
- **Página Web Separada**:
  - Uma interface web simples, acessível em `http://localhost:8000`, permite ativar e desativar o bloqueio real de pacotes.
  - Evita interferências do ciclo de atualização do Streamlit, garantindo estabilidade.
- **Aviso de Risco**:
  - Antes de ativar o bloqueio real, exibe um aviso destacando os riscos (ex.: perda de conexão com a internet, interrupção de serviços como VPNs, problemas em comunicações críticas, impacto em outros dispositivos na rede).
  - Requer que o usuário marque um checkbox ("Eu entendo os riscos e desejo prosseguir") antes de ativar o bloqueio.
- **Ativação do Bloqueio Real**:
  - Ao ativar, aplica as regras de bloqueio definidas no `rules.json` usando o comando `iptables`.
  - As regras são adicionadas às cadeias `INPUT` e `OUTPUT` do `iptables` para bloquear pacotes correspondentes (ex.: bloquear UDP na porta 53).
- **Desativação do Bloqueio Real**:
  - Ao desativar, executa o comando `iptables -F` nas cadeias `INPUT`, `OUTPUT` e `FORWARD`, removendo todas as regras de bloqueio.
  - Exibe mensagens de sucesso ("Bloqueio real desativado com sucesso!") ou erro, caso algo falhe.
- **Interface Dinâmica**:
  - Mostra o estado atual do bloqueio ("Bloqueio Real Ativado" ou "Bloqueio Real Desativado") com cores diferentes (vermelho para ativado, azul para desativado).
  - Oculta o aviso de risco quando o bloqueio está ativado e exibe o botão "Desativar Bloqueio Real".

### **3. Outras Características Técnicas**
- **Thread-Safe**:
  - Utiliza locks para garantir operações seguras em variáveis compartilhadas (logs e estatísticas) em um ambiente multithread.
- **Fuso Horário**:
  - Todos os timestamps (gráficos, notificações, tabela de logs) são ajustados para o horário de Brasília (GMT-3) usando a biblioteca `pytz`.
- **Exportação de Dados**:
  - Os logs completos e filtrados podem ser baixados como arquivos CSV, com mensagens de sucesso e botões de download que desaparecem automaticamente após 5 segundos.

---

## **Estrutura do Projeto**

A estrutura de diretórios do projeto é a seguinte:

```
firewall/
├── data.py                # Variáveis compartilhadas e locks para sincronização
├── regras.py              # Funções para carregar e salvar regras do firewall
├── main.py                # Captura e processamento de pacotes
├── ig.py                  # Interface gráfica com Streamlit (dashboard)
├── block_control.py       # Servidor FastAPI para controle de bloqueio real
├── rules.json             # Arquivo de configuração com as regras do firewall
├── requirements.txt       # Lista de dependências do projeto
├── templates/             # Diretório com o template HTML para o FastAPI
│   └── index.html         # Página web para controle de bloqueio real
├── static/                # Diretório com arquivos estáticos (CSS)
│   └── styles.css         # Estilos para a página de controle de bloqueio
└── README.md              # Documentação do projeto
```

---

## **Requisitos do Sistema**

Para executar o projeto, você precisará do seguinte:

- **Sistema Operacional**: Linux (testado no Ubuntu; outras distribuições devem funcionar, mas podem exigir ajustes).
- **Python 3.10 ou superior**.
- **Permissões de Root**: Necessárias para capturar pacotes (`Scapy`) e manipular regras do `iptables`.
- **Ferramentas do Sistema**:
  - `iptables`: Utilitário para gerenciar regras de firewall no Linux.
- **Bibliotecas Python**:
  - `streamlit`: Para a interface gráfica do dashboard.
  - `scapy`: Para captura e processamento de pacotes.
  - `pandas`: Para manipulação de dados em tabelas.
  - `plotly`: Para gráficos interativos.
  - `pytz`: Para manipulação de fusos horários.
  - `fastapi`: Para o servidor que gerencia o bloqueio real.
  - `uvicorn`: Servidor ASGI para rodar o FastAPI.
  - `jinja2`: Para renderizar templates HTML no FastAPI.

---

## **Como Configurar e Rodar o Projeto**

Siga os passos abaixo para configurar e executar o projeto. O processo é dividido em etapas para garantir que tudo funcione corretamente.

### **1. Clonar o Repositório**
Clone o repositório do projeto para o seu ambiente local:

```bash
git clone <URL_DO_REPOSITORIO>
cd firewall
```

### **2. Instalar Dependências do Sistema**
O projeto utiliza o `iptables` para aplicar regras de bloqueio real. Certifique-se de que ele está instalado no seu sistema:

```bash
sudo apt update
sudo apt install iptables
```

Verifique se o `iptables` está instalado corretamente:

```bash
iptables --version
```

Você deve ver uma saída como `iptables v1.8.7 (nf_tables)` ou similar.

### **3. Criar e Ativar um Ambiente Virtual**
Crie um ambiente virtual para gerenciar as dependências do projeto:

```bash
python3 -m venv .venv
```

Ative o ambiente virtual:

**Linux/MacOS**:
```bash
source .venv/bin/activate
```

**Windows** (caso esteja usando, embora o projeto seja testado em Linux):
```bash
.venv\Scripts\activate
```

### **4. Instalar as Dependências Python**
Com o ambiente virtual ativado, instale as dependências listadas no `requirements.txt`:

```bash
pip install -r requirements.txt
```

Se o arquivo `requirements.txt` não estiver atualizado, você pode instalar as dependências manualmente:

```bash
pip install streamlit scapy pandas plotly pytz fastapi uvicorn jinja2
```

### **5. Configurar Permissões para Captura de Pacotes**
A captura de pacotes com o `Scapy` e a manipulação do `iptables` requerem permissões administrativas. Você precisará executar os scripts com `sudo`, mas primeiro vamos garantir que o interpretador Python tenha as permissões necessárias para capturar pacotes sem erros.

**Descubra o caminho do interpretador Python no ambiente virtual**:

```bash
which python3
```

A saída deve ser algo como:

```
/home/deivi/Documentos/firewall/.venv/bin/python3
```

**Conceda permissões ao interpretador Python**:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /home/deivi/Documentos/firewall/.venv/bin/python3
```

Esse comando concede as capacidades `cap_net_raw` e `cap_net_admin` ao Python, permitindo que ele capture pacotes e manipule interfaces de rede sem erros de permissão.

### **6. Configurar Permissões para o Streamlit**
O Streamlit também precisa de permissões para rodar com privilégios administrativos, já que ele executa o `ig.py`. Descubra o caminho do executável do Streamlit no ambiente virtual:

```bash
which streamlit
```

A saída deve ser algo como:

```
/home/deivi/Documentos/firewall/.venv/bin/streamlit
```

**Conceda permissões ao executável do Streamlit**:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /home/deivi/Documentos/firewall/.venv/bin/streamlit
```

### **7. Verificar o Arquivo `rules.json`**
O arquivo `rules.json` contém as regras do firewall. Certifique-se de que ele existe no diretório do projeto e tem pelo menos uma regra para teste. Um exemplo de `rules.json`:

```json
[
    {
        "action": "block",
        "protocol": "udp",
        "dst_port": 53
    }
]
```

Se o arquivo não existir, crie-o com o conteúdo acima. Ele será usado tanto para o bloqueio simulado (no dashboard) quanto para o bloqueio real (via FastAPI).

### **8. Executar o Projeto**
O projeto precisa de dois terminais: um para rodar o servidor FastAPI (`block_control.py`) e outro para rodar o dashboard Streamlit (`ig.py`).

**Terminal 1: Executar o Servidor FastAPI para Controle de Bloqueio Real**

Execute o seguinte comando para iniciar o servidor FastAPI:

```bash
sudo /home/deivi/Documentos/firewall/.venv/bin/python block_control.py
```

- O comando requer `sudo` porque o `iptables` precisa de permissões administrativas para aplicar e remover regras.
- Você verá logs indicando que o servidor FastAPI está rodando em `http://0.0.0.0:8000`.
- Mantenha esse terminal aberto.

**Terminal 2: Executar o Dashboard Streamlit**

Em outro terminal, com o ambiente virtual ativado, execute o dashboard:

```bash
sudo /home/deivi/Documentos/firewall/.venv/bin/streamlit run ig.py
```

- O comando também requer `sudo` devido às permissões necessárias para captura de pacotes.
- O Streamlit abrirá automaticamente o navegador na URL `http://localhost:8501` (ou outra porta, se 8501 estiver ocupada).
- Mantenha esse terminal aberto.

### **9. Usar o Projeto**
- **Acesse o Dashboard**:
  - No navegador, em `http://localhost:8501`, você verá o "Painel de Tráfego de Rede".
  - Explore as métricas, gráficos e tabela de logs.
  - Use os filtros, ordene a tabela, exporte logs, pause/retome a captura e visualize detalhes de pacotes.
  - Na seção "Gerenciamento de Regras do Firewall", adicione, edite ou remova regras.
- **Acesse o Controle de Bloqueio Real**:
  - No dashboard, na seção "Controle de Bloqueio Real", clique no link "Acessar Controle de Bloqueio Real".
  - Isso abrirá uma nova aba em `http://localhost:8000`.
  - Você verá a mensagem "ℹ️ Bloqueio Real Desativado".
  - Para ativar o bloqueio real, marque o checkbox de confirmação e clique em "Ativar Bloqueio Real". O `iptables` aplicará as regras definidas no `rules.json`.
  - Para desativar, clique em "Desativar Bloqueio Real". O comando `iptables -F` será executado, limpando todas as regras das cadeias `INPUT`, `OUTPUT` e `FORWARD`.

---

## **Resolução de Problemas Comuns**

Aqui estão alguns problemas comuns que você pode encontrar ao configurar ou executar o projeto, junto com suas soluções:

### **Problema 1: Erro de Permissões ao Capturar Pacotes**
**Mensagem de Erro**: `PermissionError: [Errno 1] Operation not permitted` ao rodar `streamlit run ig.py`.

**Solução**:
- Certifique-se de que você concedeu as permissões corretas ao interpretador Python e ao Streamlit, conforme descrito nos passos 5 e 6.
- Verifique se está executando o comando com `sudo`:
  ```bash
  sudo /home/deivi/Documentos/firewall/.venv/bin/streamlit run ig.py
  ```
- Se o problema persistir, confirme o caminho do Python e Streamlit com `which python3` e `which streamlit`, e reaplique as permissões com `setcap`.

### **Problema 2: Erro ao Aplicar Regras no `iptables`**
**Mensagem de Erro**: `❌ Erro: iptables: Permission denied` na página de controle de bloqueio real (`http://localhost:8000`).

**Solução**:
- Certifique-se de que o `block_control.py` está sendo executado com `sudo`:
  ```bash
  sudo /home/deivi/Documentos/firewall/.venv/bin/python block_control.py
  ```
- Verifique se o `iptables` está instalado:
  ```bash
  sudo apt install iptables
  ```
- Se o erro persistir, verifique as permissões do usuário atual para manipular o `iptables`. Você pode testar manualmente com:
  ```bash
  sudo iptables -L
  ```

### **Problema 3: Página de Controle de Bloqueio Não Carrega**
**Mensagem de Erro**: "This site can’t be reached" ao acessar `http://localhost:8000`.

**Solução**:
- Confirme que o servidor FastAPI está rodando no Terminal 1. Você deve ver logs como:
  ```
  INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
  ```
- Verifique se a porta 8000 está livre. Liste os processos usando a porta:
  ```bash
  sudo lsof -i :8000
  ```
  Se outro processo estiver usando a porta, mate-o com:
  ```bash
  sudo kill -9 <PID>
  ```
  E então reinicie o `block_control.py`.
- Certifique-se de que os diretórios `templates/` e `static/` estão corretamente configurados com os arquivos `index.html` e `styles.css`.

### **Problema 4: Horário nos Gráficos ou Notificações Está Errado**
**Solução**:
- Verifique se a biblioteca `pytz` está instalada:
  ```bash
  pip install pytz
  ```
- Confirme que o relógio do sistema está sincronizado com o horário local:
  ```bash
  timedatectl
  ```
  Se o horário estiver errado, sincronize com:
  ```bash
  sudo dpkg-reconfigure tzdata
  ```
  E selecione "America/Sao_Paulo".

### **Problema 5: Regras Não São Aplicadas ou Removidas**
**Solução**:
- Certifique-se de que o `rules.json` contém regras válidas. Um exemplo mínimo:
  ```json
  [
      {
          "action": "block",
          "protocol": "udp",
          "dst_port": 53
      }
  ]
  ```
- Após ativar o bloqueio real, verifique as regras no `iptables`:
  ```bash
  sudo iptables -L -v -n
  ```
  Você deve ver as regras aplicadas nas cadeias `INPUT` e `OUTPUT`.
- Após desativar, verifique novamente. As cadeias devem estar vazias:
  ```
  Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
   pkts bytes target     prot opt in     out     source               destination         

  Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
   pkts bytes target     prot opt in     out     source               destination         
  ```
- Se as regras não forem removidas, confirme que o `block_control.py` está rodando com `sudo`.

### **Problema 6: Conflito de Portas no Streamlit**
**Mensagem de Erro**: `Address already in use` ao rodar `streamlit run ig.py`.

**Solução**:
- Identifique o processo usando a porta 8501 (ou a porta exibida no erro):
  ```bash
  sudo lsof -i :8501
  ```
- Mate o processo:
  ```bash
  sudo kill -9 <PID>
  ```
- Reinicie o Streamlit:
  ```bash
  sudo /home/deivi/Documentos/firewall/.venv/bin/streamlit run ig.py
  ```
- Alternativamente, especifique uma porta diferente:
  ```bash
  sudo /home/deivi/Documentos/firewall/.venv/bin/streamlit run ig.py --server.port 8502
  ```

### **Problema 7: Outras Regras do `iptables` São Removidas**
**Contexto**: O comando `iptables -F` usado ao desativar o bloqueio real limpa todas as regras das cadeias `INPUT`, `OUTPUT` e `FORWARD`, incluindo regras que não foram adicionadas pelo projeto.

**Solução**:
- Se você precisa preservar outras regras do `iptables`, modifique o `block_control.py` to revert to the specific rule removal logic (using `iptables -D` instead of `iptables -F`). This can be done by adjusting the `remove_iptables_blocking()` function to remove only the rules added by the script. Contact the developer to implement this change.

---

## **Explicação dos Comandos Utilizados**

- **`sudo apt update && sudo apt install iptables`**:
  Atualiza a lista de pacotes e instala o `iptables`, necessário para gerenciar regras de firewall no Linux.
- **`which python3` e `which streamlit`**:
  Retorna o caminho absoluto do interpretador Python e do executável Streamlit no ambiente virtual. Exemplo de saída: `/home/deivi/Documentos/firewall/.venv/bin/python3`.
- **`sudo setcap cap_net_raw,cap_net_admin=eip <CAMINHO>`**:
  Concede permissões ao Python e ao Streamlit para capturar pacotes e manipular interfaces de rede sem erros de permissão.
- **`sudo /home/deivi/Documentos/firewall/.venv/bin/python block_control.py`**:
  Inicia o servidor FastAPI para gerenciar o bloqueio real, rodando na porta 8000.
- **`sudo /home/deivi/Documentos/firewall/.venv/bin/streamlit run ig.py`**:
  Inicia o dashboard Streamlit, abrindo a interface gráfica no navegador.
- **`sudo iptables -L -v -n`**:
  Lista todas as regras do `iptables` com detalhes, útil para verificar se as regras foram aplicadas ou removidas corretamente.

---

## **Notas Finais**

- **Segurança**: O bloqueio real pode interromper comunicações críticas na sua rede. Use com cuidado e sempre teste em um ambiente controlado antes de aplicar em produção.
- **Customização**: O projeto pode ser estendido para incluir mais métricas, gráficos ou tipos de regras. Consulte o desenvolvedor para adicionar novas funcionalidades.
- **Fuso Horário**: O horário de Brasília (GMT-3) é usado por padrão. Se precisar de outro fuso horário, ajuste o código no `ig.py` (procure por `America/Sao_Paulo` e substitua pelo fuso desejado, como `America/New_York`).

Com isso, você deve conseguir configurar, executar e usar o projeto sem problemas. Se precisar de mais ajuda, entre em contato! 🚀