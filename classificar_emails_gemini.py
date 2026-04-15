#!/usr/bin/env python3
"""Classifica emails de um CSV como phishing ou nao_phishing usando Gemini via GenAI Gateway (VPN).

Entrada esperada:
- Coluna obrigatoria: eml_text
- Coluna close_notes e ignorada na inferencia (usada apenas em analises posteriores)

Saida:
- CSV com todas as colunas originais + ai_phishing_verdict
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any

import requests
from requests.exceptions import HTTPError

DEFAULT_ENDPOINT = (
    "https://api-private.dev.grupoboticario.com.br/"
    "global/v1/data-platform/explore-genai/chat/completions"
)
VALID_VERDICTS = {"phishing", "nao_phishing"}


@dataclass
class RowItem:
    line_no: int
    row: dict[str, str]
    eml_text: str


def normalize_json_response(text: str) -> str:
    cleaned = (text or "").strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].strip()
    return cleaned


def retry_after_seconds(response: requests.Response | None, fallback: int) -> int:
    if response is None:
        return fallback
    value = response.headers.get("Retry-After")
    if not value:
        return fallback
    try:
        return max(int(float(value)), fallback)
    except ValueError:
        return fallback


def build_prompt(batch: list[RowItem]) -> str:
    items = [{"line_no": i.line_no, "eml_text": i.eml_text} for i in batch]
    schema = {
        "results": [
            {"line_no": 1, "verdict": "phishing"},
            {"line_no": 2, "verdict": "nao_phishing"},
        ]
    }

    return (
        "Voce eh um classificador de seguranca de e-mails. "
        "Para cada item, classifique APENAS o eml_text como phishing ou nao_phishing. "
        "Ignore completamente close_notes e qualquer metadado externo. "
        "Retorne SOMENTE JSON valido, sem markdown, sem comentarios, sem texto adicional. "
        "Nao adicione campos extras.\n\n"
        f"FORMATO_EXATO: {json.dumps(schema, ensure_ascii=False)}\n\n"
        f"ITENS: {json.dumps(items, ensure_ascii=False)}"
    )


def parse_batch_response(content: str, expected_lines: set[int]) -> dict[int, str]:
    cleaned = normalize_json_response(content)
    payload = json.loads(cleaned)

    results = payload.get("results")
    if not isinstance(results, list):
        raise ValueError("Resposta sem campo 'results' valido")

    verdicts: dict[int, str] = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        line_no = item.get("line_no")
        verdict = str(item.get("verdict", "")).strip().lower()
        if isinstance(line_no, int) and verdict in VALID_VERDICTS and line_no in expected_lines:
            verdicts[line_no] = verdict

    missing = expected_lines - set(verdicts.keys())
    if missing:
        raise ValueError(f"Resposta incompleta. Linhas sem veredito: {sorted(missing)}")

    return verdicts


def call_gemini_batch(
    session: requests.Session,
    endpoint: str,
    model: str,
    project_id: str,
    identifier: str,
    timeout_s: int,
    batch: list[RowItem],
) -> dict[int, str]:
    payload: dict[str, Any] = {
        "model": model,
        "stream": False,
        "project_id": project_id,
        "session_id": str(uuid.uuid4()),
        "identifier": identifier,
        "prompt": {
            "type": "human",
            "content": [{"type": "text", "text": build_prompt(batch)}],
        },
        "tool_choice": None,
        "tools": None,
        "model_config": {"temperature": 0},
        "history": [],
        "prompt_id": None,
        "tool_calls": [],
        "tool_call_response": {"tool_call_id": None, "name": None},
    }

    response = session.post(endpoint, json=payload, timeout=timeout_s)
    response.raise_for_status()

    data = response.json()
    candidates = data.get("candidates") or []
    if not candidates:
        raise ValueError("Resposta sem candidates")

    content = str(candidates[0].get("content", ""))
    if not content.strip():
        raise ValueError("Resposta sem content")

    expected_lines = {r.line_no for r in batch}
    return parse_batch_response(content, expected_lines)


def call_with_retry(
    session: requests.Session,
    endpoint: str,
    model: str,
    project_id: str,
    identifier: str,
    timeout_s: int,
    max_retries: int,
    batch: list[RowItem],
) -> dict[int, str]:
    attempt = 0
    while True:
        attempt += 1
        try:
            return call_gemini_batch(
                session=session,
                endpoint=endpoint,
                model=model,
                project_id=project_id,
                identifier=identifier,
                timeout_s=timeout_s,
                batch=batch,
            )
        except HTTPError as exc:
            if attempt > max_retries:
                raise
            status = exc.response.status_code if exc.response is not None else None
            if status == 429:
                wait_s = retry_after_seconds(exc.response, min(2 ** (attempt - 1), 90))
            else:
                wait_s = min(2 ** (attempt - 1), 20)
            print(
                f"[batch {batch[0].line_no}-{batch[-1].line_no}] HTTP {status} "
                f"tentativa {attempt}/{max_retries} -> retry {wait_s}s"
            )
            time.sleep(wait_s)
        except Exception as exc:
            if attempt > max_retries:
                raise
            wait_s = min(2 ** (attempt - 1), 20)
            print(
                f"[batch {batch[0].line_no}-{batch[-1].line_no}] erro {exc} "
                f"tentativa {attempt}/{max_retries} -> retry {wait_s}s"
            )
            time.sleep(wait_s)


def process_csv(args: argparse.Namespace) -> None:
    csv.field_size_limit(sys.maxsize)

    with open(args.input, "r", encoding="utf-8", newline="") as f_in:
        reader = csv.DictReader(f_in)
        if not reader.fieldnames:
            raise ValueError("CSV de entrada sem cabecalho")
        if "eml_text" not in reader.fieldnames:
            raise ValueError("Coluna obrigatoria 'eml_text' nao encontrada")

        fieldnames = list(reader.fieldnames)
        if "ai_phishing_verdict" not in fieldnames:
            fieldnames.append("ai_phishing_verdict")

        with open(args.output, "w", encoding="utf-8", newline="") as f_out:
            writer = csv.DictWriter(f_out, fieldnames=fieldnames)
            writer.writeheader()

            with requests.Session() as session:
                batch: list[RowItem] = []
                batch_chars = 0
                total = 0
                valid = 0
                errors = 0

                def flush_batch() -> None:
                    nonlocal batch, batch_chars, errors
                    if not batch:
                        return
                    first = batch[0].line_no
                    last = batch[-1].line_no
                    try:
                        verdicts = call_with_retry(
                            session=session,
                            endpoint=args.endpoint,
                            model=args.model,
                            project_id=args.project_id,
                            identifier=args.identifier,
                            timeout_s=args.timeout_s,
                            max_retries=args.max_retries,
                            batch=batch,
                        )
                        for item in batch:
                            item.row["ai_phishing_verdict"] = verdicts[item.line_no]
                            writer.writerow(item.row)
                    except Exception as exc:
                        errors += len(batch)
                        print(f"[batch {first}-{last}] falha final: {exc}")
                        for item in batch:
                            item.row["ai_phishing_verdict"] = "erro"
                            writer.writerow(item.row)
                    f_out.flush()
                    print(f"[batch {first}-{last}] gravado")
                    batch = []
                    batch_chars = 0
                    if args.sleep_ms > 0:
                        time.sleep(args.sleep_ms / 1000)

                for row in reader:
                    total += 1

                    if total < args.start_line:
                        row["ai_phishing_verdict"] = "skipped"
                        writer.writerow(row)
                        continue
                    if args.end_line is not None and total > args.end_line:
                        row["ai_phishing_verdict"] = "skipped"
                        writer.writerow(row)
                        continue

                    text = str(row.get("eml_text", "") or "").strip()
                    if not text:
                        row["ai_phishing_verdict"] = "nao_phishing"
                        writer.writerow(row)
                        continue

                    valid += 1
                    item = RowItem(line_no=total, row=row, eml_text=text)
                    item_len = len(text)

                    if batch and (
                        len(batch) >= args.batch_size
                        or (batch_chars + item_len) > args.max_batch_chars
                    ):
                        flush_batch()

                    batch.append(item)
                    batch_chars += item_len

                    if total % 200 == 0:
                        print(
                            f"Progresso: lidas={total} validas={valid} erros={errors}"
                        )

                flush_batch()

    print("\nProcessamento concluido")
    print(f"Entrada : {args.input}")
    print(f"Saida   : {args.output}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Classifica eml_text em phishing/nao_phishing via Gemini"
    )
    parser.add_argument("--input", default="dataset_fase1_final.csv")
    parser.add_argument("--output", default="dataset_fase1_final_com_veredito.csv")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--model", default="gemini-2.0-flash")
    parser.add_argument("--identifier", default=os.getenv("GENAI_IDENTIFIER", "inic669"))
    parser.add_argument(
        "--project-id", default=os.getenv("GENAI_PROJECT_ID", "gen-ai-tools-developer")
    )
    parser.add_argument("--timeout-s", type=int, default=90)
    parser.add_argument("--max-retries", type=int, default=8)
    parser.add_argument("--sleep-ms", type=int, default=1000)
    parser.add_argument("--batch-size", type=int, default=6)
    parser.add_argument("--max-batch-chars", type=int, default=12000)
    parser.add_argument("--start-line", type=int, default=1)
    parser.add_argument("--end-line", type=int, default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    process_csv(args)


if __name__ == "__main__":
    main()
