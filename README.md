# NEXA Social Server 2.0

Backend Node.js sem dependências externas para contas NEXA, amizade, presença, mensagens diretas e conversas em grupo.

## Executar localmente

Requisitos: Node.js 20+.

Dentro desta pasta:

```bash
npm start
```

Execute `npm test` para rodar um teste automatizado do fluxo de cadastro, login, amizade, chat, grupos e bloqueios.

```bash
npm test
```

Por padrão, o servidor local iniciado diretamente escuta em `127.0.0.1:47821`. Verifique `http://127.0.0.1:47821/health`.

Para escolher a porta e os dados:

**PowerShell:**

```powershell
$env:NEXA_HOST="127.0.0.1"
$env:NEXA_PORT="47821"
$env:NEXA_DATA_DIR="$env:LOCALAPPDATA\NEXA-Social-Data"
node server.js
```

**Linux/macOS:**

```bash
NEXA_HOST=127.0.0.1 NEXA_PORT=47821 NEXA_DATA_DIR=/srv/nexa-social-data node server.js
```

O diretório de dados precisa ser persistente e restrito à conta de serviço. Faça backups frequentes do banco JSON.

## Hospedar para amigos em outros PCs

Para usuários externos, use um host com Node.js 20+, armazenamento persistente e domínio. O host precisa ter uma variável `PORT` disponível. O servidor escuta em `0.0.0.0` quando executado com `PORT` definido para compatibilidade com plataformas de hospedagem.

**Não publique o servidor diretamente em HTTP aberto.** Coloque-o atrás de um proxy HTTPS. Exemplo de configuração do Caddy (se o Caddy e o app estiverem na mesma máquina):

```caddyfile
social.seudominio.com {
    reverse_proxy 127.0.0.1:47821
}
```

Execute o processo Node na porta local 47821 (`NEXA_HOST=127.0.0.1 NEXA_PORT=47821`) e aponte o proxy para essa porta. Configure certificado TLS válido, backups, logs e persistência. A plataforma pode exigir `PORT` e `0.0.0.0`; nesse caso, configure o destino local conforme a documentação da hospedagem e preserve o proxy HTTPS fornecido.

Depois, em cada instalação do NEXA HUB, entre em Social, altere o endereço para `https://social.seudominio.com`, clique em testar conexão e crie uma conta.

## Endpoints principais

- `GET /health`
- `POST /api/register`, `POST /api/login`, `POST /api/logout`, `GET /api/me`
- `GET /api/social`, `POST /api/presence`, `POST /api/profile`
- `POST /api/friend-requests`, `POST /api/friend-requests/:id/accept`, `DELETE /api/friend-requests/:id`
- `GET /api/messages?with=username&after=id`, `POST /api/messages`
- `GET /api/groups`, `POST /api/groups`, `GET/POST /api/groups/:id/messages`
- `POST/DELETE /api/blocks...`, `DELETE /api/friends/:username`

API autenticada usa `Authorization: Bearer <token>`.

## Aviso de operação

O backend incluído é uma base funcional para testes e comunidades pequenas, não uma plataforma de produção auditada. Usa um banco JSON local e armazenamento síncrono, sem recuperação de senha, e-mail verificado, moderação administrativa, garantias de alta disponibilidade ou proteção contra todos os tipos de abuso. Antes de disponibilizá-lo publicamente, implemente banco transacional, backups, moderação, monitoramento e revisão de segurança/privacidade. Nunca armazene dados pessoais desnecessários e use senhas únicas.


## Perfil 2.0.2
O endpoint autenticado `POST /api/profile` salva nome público, avatar, cor de avatar e bio. A atualização é compatível com clientes que enviam apenas `displayName`.
