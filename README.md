# Phishing Verdict Pipeline (Gemini + VPN)

Classificacao automatica de EMLs em CSV com o Gateway de GenAI (Gemini), produzindo um novo arquivo com veredito por linha.

---

## Visao geral

Este projeto processa o arquivo dataset_fase1_final.csv e adiciona a coluna ai_phishing_verdict para cada registro.

Regras da classificacao:
- O modelo analisa somente eml_text.
- close_notes e explicitamente ignorado no prompt.
- O retorno aceito e estrito: phishing ou nao_phishing.

---

## Arquitetura da solucao

1. Leitura streaming do CSV (sem carregar tudo em memoria).
2. Agrupamento em batches de e-mails para reduzir volume de requests.
3. Chamada ao endpoint privado de exploracao (VPN).
4. Validacao rigorosa do JSON retornado pelo modelo.
5. Escrita incremental do CSV final com flush por batch.

---

## Estrutura

- classificar_emails_gemini.py: pipeline principal.
- dataset_fase1_final.csv: entrada.
- dataset_fase1_final_com_veredito.csv: saida final.
- dataset_fase1_lote_teste.csv: arquivo de validacao por lote.
- requirements.txt: dependencias.

---

## Requisitos

- Python 3.10+
- VPN corporativa conectada
- Acesso ao endpoint de exploracao da Plataforma de GenAI

Endpoint usado:
- https://api-private.dev.grupoboticario.com.br/global/v1/data-platform/explore-genai/chat/completions

---

## Instalacao

```bash
pip install -r requirements.txt
```

---

## Execucao

### Teste rapido (lote curto)

```bash
python classificar_emails_gemini.py \
  --input dataset_fase1_final.csv \
  --output dataset_fase1_lote_teste.csv \
  --start-line 1 \
  --end-line 200 \
  --batch-size 4 \
  --sleep-ms 1000
```

### Processamento completo

```bash
python classificar_emails_gemini.py \
  --input dataset_fase1_final.csv \
  --output dataset_fase1_final_com_veredito.csv \
  --identifier inic669 \
  --project-id gen-ai-tools-developer \
  --model gemini-2.0-flash \
  --batch-size 6 \
  --max-batch-chars 12000 \
  --sleep-ms 1000 \
  --max-retries 8
```

---

## Parametros principais

- --input: CSV de entrada
- --output: CSV de saida
- --identifier: identificador da iniciativa
- --project-id: projeto GCP
- --model: modelo Gemini
- --batch-size: maximo de EMLs por request
- --max-batch-chars: limite de caracteres por request
- --sleep-ms: pausa entre batches
- --max-retries: tentativas por batch
- --start-line e --end-line: recorte de execucao

---

## Formato de saida

Coluna adicionada:
- ai_phishing_verdict: phishing | nao_phishing | erro | skipped

Exemplo:

```csv
number,eml_text,close_notes,label,ai_phishing_verdict
RITM4255687,"...",...,0,nao_phishing
RITM4255853,"...",...,1,phishing
```

---

## Operacao e resiliencia

- Retry com backoff exponencial para falhas de rede e HTTP 429.
- Leitura de Retry-After quando fornecido pelo gateway.
- Escrita incremental com flush por batch para evitar perda de progresso.

---

## Troubleshooting

- 401/403: confirme VPN e ambiente.
- 429 recorrente: aumente --sleep-ms e/ou reduza --batch-size.
- Timeout: aumente --timeout-s.
- Falhas pontuais no output: linhas sao marcadas como erro para nao perder continuidade.

---

## Observacao de seguranca

Este repositório pode conter dados sensiveis de e-mail.
Evite publicar datasets e logs em ambientes externos sem governanca adequada.
