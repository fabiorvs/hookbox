# Hookbox

Uma caixa de entrada de webhooks auto-hospedada para testar integrações HTTP. Cada usuário cria endpoints com UUID, inspeciona método, caminho, query string, headers e corpo, e escolhe a resposta que o cliente receberá.

## Executar com Docker

```bash
cp .env.example .env
# edite SECRET_KEY e PUBLIC_BASE_URL
docker compose up -d --build
```

Acesse `http://localhost:8000`, crie sua conta e depois um endpoint. Os dados ficam no volume persistente `webhook_data`. Se a porta estiver ocupada, altere `PORT` e `PUBLIC_BASE_URL` no `.env`.

Para produção, coloque um proxy reverso com HTTPS (Caddy, Traefik ou Nginx) na frente da porta 8000 e defina `PUBLIC_BASE_URL=https://hooks.seudominio.com`.

### Nginx em `hookbox.seudominio.com`

O arquivo pronto está em `deploy/nginx/hookbox.seudominio.com.conf`. Na VPS:

```bash
sudo cp deploy/nginx/hookbox.seudominio.com.conf /etc/nginx/sites-available/hookbox.seudominio.com
sudo ln -s /etc/nginx/sites-available/hookbox.seudominio.com /etc/nginx/sites-enabled/hookbox.seudominio.com
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d hookbox.seudominio.com
```

No `.env`, use `PORT=8000` e `PUBLIC_BASE_URL=https://hookbox.seudominio.com`, depois aplique com `docker compose up -d`.

## Desenvolvimento local

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/flask --app app run --debug --port 8000
```

O banco é criado automaticamente em `instance/webhook-box.db`. O limite padrão por requisição é 1 MiB e pode ser alterado em `MAX_REQUEST_BYTES`.

## Segurança, limites e retenção

O primeiro usuário cadastrado se torna administrador. Depois dele, o administrador pode consultar, bloquear usuários e redefinir suas senhas em `/admin`. A troca administrativa de senha encerra as sessões anteriores do usuário. Para fechar novos cadastros, defina `ALLOW_REGISTRATION=false`.

As principais opções do `.env` são:

- `MAX_REQUESTS_PER_ENDPOINT`: quantidade máxima mantida por endpoint;
- `MAX_ENDPOINTS_PER_USER`: quota de endpoints ativos por usuário;
- `RETENTION_DAYS`: expiração automática das requisições;
- `SESSION_COOKIE_SECURE=true`: obrigatório quando o site usa HTTPS;
- `MAX_REQUEST_BYTES`: tamanho máximo aceito por payload.

Endpoints podem exigir o header `X-Hookbox-Secret`, simular atraso e respostas de erro, ser arquivados ou ter o UUID regenerado. O reenvio aceita apenas destinos públicos HTTP/HTTPS para reduzir o risco de SSRF.

## Backup

Com o contêiner em execução:

```bash
./scripts/backup.sh
```

O backup consistente do SQLite será salvo em `backups/`. Para restaurar, pare o serviço, preserve uma cópia do banco atual e substitua `/data/webhook-box.db` pelo arquivo escolhido.

## Teste rápido

Após criar um endpoint, use a URL exibida no painel:

```bash
curl -X POST 'http://localhost:8000/hook/SEU-UUID?origem=teste' \
  -H 'Content-Type: application/json' \
  -d '{"evento":"pagamento.aprovado"}'
```
