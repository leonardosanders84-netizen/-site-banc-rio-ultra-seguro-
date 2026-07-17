"""
Site Bancário Ultra Seguro
Desenvolvido por: Leonardo Fagundes Sanders
Versão: 1.4 - Padrão bancário: 3 tentativas de login
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
import json
import hashlib
import secrets
from pathlib import Path
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

ARQUIVO_DADOS = Path("dados_site_seguro.bin")
ARQUIVO_CHAVE = Path(".chave_site")

app = FastAPI(debug=True, docs_url=None, redoc_url=None)

# 🔒 PADRÃO BANCÁRIO: 3 tentativas + bloqueio de 15min
TENTATIVAS_MAXIMAS = 3
TEMPO_BLOQUEIO_MINUTOS = 15
controle_tentativas = {}


class SegurancaTotal:
    @staticmethod
    def gerar_chave():
        chave = Fernet.generate_key()
        with open(ARQUIVO_CHAVE, "wb") as f:
            f.write(chave)
        try:
            ARQUIVO_CHAVE.chmod(0o600)
        except Exception:
            pass
        return chave

    @staticmethod
    def carregar_chave():
        if not ARQUIVO_CHAVE.exists():
            return SegurancaTotal.gerar_chave()
        with open(ARQUIVO_CHAVE, "rb") as f:
            return f.read()

    @staticmethod
    def criptografar(dados: str, chave: bytes):
        return Fernet(chave).encrypt(dados.encode("utf-8"))

    @staticmethod
    def descriptografar(dados: bytes, chave: bytes):
        try:
            return Fernet(chave).decrypt(dados).decode("utf-8")
        except Exception:
            raise HTTPException(status_code=500, detail="Sistema bloqueado: dados violados")

    @staticmethod
    def hash_senha(senha: str):
        salt = secrets.token_bytes(32)
        h = hashlib.pbkdf2_hmac("sha256", senha.encode(), salt, 800000)
        return f"{salt.hex()}:{h.hex()}"

    @staticmethod
    def verificar_senha(senha: str, hash_arm: str):
        if not hash_arm or ":" not in hash_arm:
            return False
        salt_hex, h_arm = hash_arm.split(":")
        salt = bytes.fromhex(salt_hex)
        gerado = hashlib.pbkdf2_hmac("sha256", senha.encode(), salt, 800000).hex()
        return secrets.compare_digest(gerado, h_arm)


CHAVE = SegurancaTotal.carregar_chave()


def carregar_contas():
    if not ARQUIVO_DADOS.exists():
        return {"contas": []}
    dados = SegurancaTotal.descriptografar(ARQUIVO_DADOS.read_bytes(), CHAVE)
    return json.loads(dados)


def salvar_contas(dados: dict):
    texto = json.dumps(dados)
    ARQUIVO_DADOS.write_bytes(SegurancaTotal.criptografar(texto, CHAVE))
    try:
        ARQUIVO_DADOS.chmod(0o600)
    except Exception:
        pass


@app.get("/", response_class=HTMLResponse)
def pagina_login():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Banco Seguro</title>
        <meta charset="utf-8">
        <style>
            body{font-family:Arial;max-width:400px;margin:50px auto;padding:20px;}
            .caixa{background:#f5f5f5;padding:25px;border-radius:8px;box-shadow:0 0 10px #0002;}
            input{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box;}
            button{background:#0b5ed7;color:white;border:none;padding:12px;width:100%;border-radius:4px;font-weight:bold;cursor:pointer;}
        </style>
    </head>
    <body>
        <div class="caixa">
            <h2>Acesso ao Sistema</h2>
            <form action="/painel" method="post">
                <input type="text" name="usuario" placeholder="Usuário" required>
                <input type="password" name="senha" placeholder="Senha" required>
                <button type="submit">Entrar</button>
            </form>
        </div>
    </body>
    </html>
    """


@app.post("/painel", response_class=HTMLResponse)
async def painel(request: Request):
    ip_cliente = request.client.host
    form = await request.form()
    usuario = form["usuario"]
    senha = form["senha"]

    # Verifica bloqueio
    if ip_cliente in controle_tentativas:
        dados_bloqueio = controle_tentativas[ip_cliente]
        if datetime.now() < dados_bloqueio["expira_em"]:
            restante = dados_bloqueio["expira_em"] - datetime.now()
            minutos = int(restante.total_seconds() // 60) + 1
            return f"<h3 style='color:red;text-align:center'>Bloqueado! Tente novamente em {minutos} minutos</h3><br><div style='text-align:center'><a href='/'><button style='width:auto;padding:8px 16px'>Voltar</button></a></div>"
        else:
            del controle_tentativas[ip_cliente]

    dados = carregar_contas()
    conta = None
    for c in dados["contas"]:
        if secrets.compare_digest(c["usuario"], usuario) and SegurancaTotal.verificar_senha(senha, c["senha_hash"]):
            conta = c
            break

    if not conta:
        if ip_cliente not in controle_tentativas:
            controle_tentativas[ip_cliente] = {"tentativas": 0, "expira_em": datetime.now()}
        
        controle_tentativas[ip_cliente]["tentativas"] += 1
        restantes = TENTATIVAS_MAXIMAS - controle_tentativas[ip_cliente]["tentativas"]

        if restantes <= 0:
            controle_tentativas[ip_cliente]["expira_em"] = datetime.now() + timedelta(minutes=TEMPO_BLOQUEIO_MINUTOS)
            return f"<h3 style='color:red;text-align:center'>⚠️ 3 tentativas erradas! Acesso bloqueado por {TEMPO_BLOQUEIO_MINUTOS} minutos</h3><br><div style='text-align:center'><a href='/'><button style='width:auto;padding:8px 16px'>Voltar</button></a></div>"
        
        return f"<h3 style='color:red;text-align:center'>Usuário ou senha inválidos! Restam {restantes} tentativa(s)</h3><br><div style='text-align:center'><a href='/'><button style='width:auto;padding:8px 16px'>Voltar</button></a></div>"

    # Login certo → zera contagem
    if ip_cliente in controle_tentativas:
        del controle_tentativas[ip_cliente]

    return f"""
    <html>
    <head>
        <title>Painel do Cliente</title>
        <style>
            body{{font-family:Arial;max-width:600px;margin:30px auto;padding:20px;}}
            .card{{background:#f8f9fa;padding:20px;border-radius:8px;margin:15px 0;}}
            input{{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box;}}
            button{{background:#198754;color:white;border:none;padding:12px;width:100%;border-radius:4px;font-weight:bold;cursor:pointer;}}
            a{{display:inline-block;margin-top:10px;text-decoration:none;color:#0b5ed7;font-weight:bold;}}
        </style>
    </head>
    <body>
        <h1>Bem-vindo, {conta['nome']}</h1>
        <div class="card">
            <h3>Saldo: R$ {conta['saldo']:.2f}</h3>
            <p>Conta: {conta['numero_conta']}</p>
        </div>
        <div class="card">
            <h4>Depositar</h4>
            <form action="/depositar" method="post">
                <input type="hidden" name="conta" value="{conta['numero_conta']}">
                <input type="number" step="0.01" name="valor" placeholder="Valor" required>
                <button>Confirmar</button>
            </form>
        </div>
        <br><a href='/'>Sair</a>
    </body>
    </html>
    """


@app.post("/depositar")
async def depositar(request: Request):
    form = await request.form()
    num_conta = form["conta"]
    valor = float(form["valor"])
    if valor <= 0:
        return "<h3 style='color:red;text-align:center'>Valor inválido</h3><br><div style='text-align:center'><a href='/painel'><button style='width:auto;padding:8px 16px'>Voltar</button></a></div>"
    dados = carregar_contas()
    for c in dados["contas"]:
        if c["numero_conta"] == num_conta:
            c["saldo"] += valor
            salvar_contas(dados)
            return f"<h3 style='color:green;text-align:center'>Depósito de R${valor:.2f} realizado!</h3><br><div style='text-align:center'><a href='/painel'><button style='width:auto;padding:8px 16px'>Voltar ao Painel</button></a></div>"
    return "<h3 style='color:red;text-align:center'>Conta não encontrada</h3><br><div style='text-align:center'><a href='/'><button style='width:auto;padding:8px 16px'>Voltar</button></a></div>"


@app.on_event("startup")
def criar_conta_teste():
    dados = carregar_contas()
    if not dados["contas"]:
        senha_hash = SegurancaTotal.hash_senha("Teste@123")
        dados["contas"].append({
            "nome": "Leonardo Fagundes Sanders",
            "usuario": "leonardo",
            "senha_hash": senha_hash,
            "numero_conta": "000001",
            "saldo": 0.0
        })
        salvar_contas(dados)