# Site Bancário Ultra Seguro
**Desenvolvido por Leonardo Fagundes Sanders**  
Versão 1.4 - Padrão bancário

## 🛠️ Tecnologias utilizadas
- Python 3.14+
- FastAPI
- Criptografia Fernet (AES-128)
- Hash de senha PBKDF2
- Proteção contra força bruta

## 🔒 Recursos de Segurança
- Dados criptografados
- Senhas nunca armazenadas em texto puro
- Limite de 3 tentativas de login
- Bloqueio automático por 15 minutos após falhas
- Detecção de alteração nos arquivos

## 🚀 Como executar
1. Instale as dependências:
```bash
pip install fastapi uvicorn cryptography python-multipart

2. Rode o servidor:
 bash
 uvicorn main:app -reloz
3. Acesse no navegador:  http://127.0.0.1:8000 
🔑 Acesso de teste
- Usuário:  leonardo 
- Senha:  Teste@123 
⚠️ Observação
Os arquivos  .chave_site  e  dados_site_seguro.bin  são gerados automaticamente e não são enviados ao repositório por segurança.

























