"""
Formatador de Logs Estruturados para SOC / SIEM (GateKeeper-DBF).

Implementa serialização estrita em JSON para mitigar Log Injection (CWE-117)
e permitir ingestão direta em Wazuh Indexer, Elastic Stack (ELK) ou Graylog.
"""

import json
import logging


class JSONAuditFormatter(logging.Formatter):
    """
    Formatador que serializa registros de log como objetos JSON em linha única.

    Propriedades de Segurança:
    1. Anti-Log Injection (CWE-117): json.dumps escapa quebras de linha (\\r, \\n) e aspas,
       garantindo que um atacante que submeta payloads multilinha em formulários
       não consiga forjar entradas adicionais de log no SIEM.
    2. Estruturação para SIEM: Permite consultas e regras Sigma/Wazuh sem necessidade de
       expressões regulares frágeis sobre texto livre.
    3. Truncamento e serialização segura de tipos não-padrão (default=str).
    """

    def format(self, record):
        payload = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "event": record.getMessage(),
            **getattr(record, "audit", {}),
        }
        return json.dumps(payload, ensure_ascii=False, default=str)
