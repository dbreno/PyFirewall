import subprocess
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import uvicorn
import json
import os

app = FastAPI()

# Configuração de templates (HTML)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Caminho para o rules.json
RULES_FILE = "rules.json"

# Lista para armazenar os comandos do iptables que foram aplicados
iptables_commands = []

# Modelo para o estado do bloqueio
class BlockingState(BaseModel):
    enabled: bool

# Função para carregar as regras do rules.json
def load_rules():
    if not os.path.exists(RULES_FILE):
        return []
    try:
        with open(RULES_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Erro ao carregar rules.json: {e}")
        return []

# Função para aplicar as regras de bloqueio no iptables
def apply_iptables_blocking():
    rules = load_rules()
    iptables_commands.clear()

    for rule in rules:
        if rule.get("action") != "block":
            continue

        cmd_input = ["iptables", "-A", "INPUT"]
        cmd_output = ["iptables", "-A", "OUTPUT"]

        if "protocol" in rule:
            cmd_input.extend(["-p", rule["protocol"]])
            cmd_output.extend(["-p", rule["protocol"]])
        if "src_ip" in rule:
            cmd_input.extend(["-s", rule["src_ip"]])
            cmd_output.extend(["-s", rule["src_ip"]])
        if "dst_ip" in rule:
            cmd_input.extend(["-d", rule["dst_ip"]])
            cmd_output.extend(["-d", rule["dst_ip"]])
        if "src_port" in rule:
            cmd_input.extend(["--sport", str(rule["src_port"])])
            cmd_output.extend(["--sport", str(rule["src_port"])])
        if "dst_port" in rule:
            cmd_input.extend(["--dport", str(rule["dst_port"])])
            cmd_output.extend(["--dport", str(rule["dst_port"])])
        cmd_input.extend(["-j", "DROP"])
        cmd_output.extend(["-j", "DROP"])

        try:
            subprocess.run(cmd_input, check=True, capture_output=True, text=True)
            subprocess.run(cmd_output, check=True, capture_output=True, text=True)
            iptables_commands.append(("INPUT", cmd_input[2:]))
            iptables_commands.append(("OUTPUT", cmd_output[2:]))
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=500, detail=f"Erro ao aplicar regra: {e.stderr}")

    return True

# Função para remover as regras de bloqueio do iptables usando iptables -F
def remove_iptables_blocking():
    try:
        # Limpa todas as regras das cadeias INPUT, OUTPUT e FORWARD
        subprocess.run(["iptables", "-F", "INPUT"], check=True, capture_output=True, text=True)
        subprocess.run(["iptables", "-F", "OUTPUT"], check=True, capture_output=True, text=True)
        subprocess.run(["iptables", "-F", "FORWARD"], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Erro ao limpar regras com iptables -F: {e.stderr}")

    # Limpa a lista de comandos aplicados
    iptables_commands.clear()
    return True

# Estado global do bloqueio (simulando um session_state)
blocking_state = {"enabled": False}

# Rota para a página HTML
@app.get("/", response_class=HTMLResponse)
async def serve_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Rota para obter o estado atual do bloqueio
@app.get("/status", response_model=BlockingState)
async def get_status():
    return BlockingState(enabled=blocking_state["enabled"])

# Rota para ativar/desativar o bloqueio
@app.post("/toggle-blocking")
async def toggle_blocking(state: BlockingState):
    if state.enabled:
        if not blocking_state["enabled"]:
            success = apply_iptables_blocking()
            if success:
                blocking_state["enabled"] = True
                return {"message": "Bloqueio real ativado com sucesso!", "enabled": True}
            else:
                raise HTTPException(status_code=500, detail="Falha ao ativar o bloqueio real.")
        else:
            return {"message": "Bloqueio real já está ativado.", "enabled": True}
    else:
        if blocking_state["enabled"]:
            success = remove_iptables_blocking()
            if success:
                blocking_state["enabled"] = False
                return {"message": "Bloqueio real desativado com sucesso!", "enabled": False}
            else:
                raise HTTPException(status_code=500, detail="Falha ao desativar o bloqueio real.")
        else:
            return {"message": "Bloqueio real já está desativado.", "enabled": False}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)