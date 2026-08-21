# Publicar o gerador no Render

O projeto está pronto para funcionar como um Web Service. Os dois usuários têm
logins separados, mas compartilham a mesma autorização do Mercado Livre.

## 1. Envie o projeto para um repositório privado

Suba esta pasta para GitHub, GitLab ou Bitbucket. Não inclua senhas, tokens nem
um arquivo `.env` real no repositório.

## 2. Crie o serviço

No Render, crie um **Blueprint** usando o arquivo `render.yaml`, ou um **Web
Service** com estas opções:

- Build Command: `pip install -r requirements.txt`
- Start Command: `python app.py`
- Health Check Path: `/health`

## 3. Configure as variáveis

Na aba **Environment** do Web Service, preencha:

- `DATABASE_URL`: use a **Internal Database URL** do PostgreSQL que você já tem.
- `PUBLIC_BASE_URL`: URL pública do novo serviço, sem barra final. Exemplo:
  `https://entrou-economizou.onrender.com`
- `MELI_CLIENT_ID` e `MELI_CLIENT_SECRET`: dados do aplicativo do Mercado Livre.
- `TOKEN_ENCRYPTION_KEY`: texto aleatório longo; não altere depois que o token
  estiver salvo.
- `APP_SESSION_SECRET`: outro texto aleatório longo.
- `APP_USER_1`, `APP_PASSWORD_1`, `APP_USER_2`, `APP_PASSWORD_2`: os dois acessos.

O arquivo `render.yaml` pode gerar automaticamente os dois segredos. As demais
variáveis precisam ser preenchidas no painel.

## 4. Ajuste o aplicativo do Mercado Livre

Cadastre como Redirect URI exatamente:

`https://SEU-SERVICO.onrender.com/oauth/callback`

Ela precisa corresponder ao valor de `PUBLIC_BASE_URL` seguido de
`/oauth/callback`. Depois, abra o gerador e use **Conectar Mercado Livre**. O
retorno agora é concluído automaticamente.

## Banco compartilhado

Na primeira inicialização o programa cria, no banco existente, somente estas
tabelas próprias:

- `entrou_economizou_meli_tokens`
- `entrou_economizou_oauth_pending`

Não é necessário criar outro PostgreSQL nem executar SQL manualmente. O token é
criptografado antes de ser gravado. A renovação usa uma trava de linha para que
dois dispositivos possam trabalhar ao mesmo tempo sem disputar o refresh token.

## Conferência rápida

Abra `https://SEU-SERVICO.onrender.com/health`. Quando tudo estiver configurado,
o campo `ready` deverá aparecer como `true`. Depois entre com cada um dos dois
usuários em dispositivos diferentes e faça uma busca de teste.
