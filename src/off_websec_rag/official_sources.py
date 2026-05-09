from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OfficialSource:
    topic: str
    title: str
    url: str
    authority: str

    @property
    def slug(self) -> str:
        safe = "".join(ch.lower() if ch.isalnum() else "-" for ch in self.title)
        return "-".join(part for part in safe.split("-") if part)


OFFICIAL_SOURCES: tuple[OfficialSource, ...] = (
    OfficialSource(
        topic="sql_injection",
        title="OWASP SQL Injection Prevention Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="xss",
        title="OWASP Cross Site Scripting Prevention Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="ssrf",
        title="OWASP Server Side Request Forgery Prevention Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="injection",
        title="OWASP Top 10 A03 Injection",
        url="https://owasp.org/Top10/A03_2021-Injection/",
        authority="OWASP",
    ),
    OfficialSource(
        topic="ssrf",
        title="OWASP Top 10 A10 SSRF",
        url="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        authority="OWASP",
    ),
    OfficialSource(
        topic="sql_injection",
        title="MITRE CWE-89 SQL Injection",
        url="https://cwe.mitre.org/data/definitions/89.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="xss",
        title="MITRE CWE-79 Cross-site Scripting",
        url="https://cwe.mitre.org/data/definitions/79.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="ssrf",
        title="MITRE CWE-918 Server-Side Request Forgery",
        url="https://cwe.mitre.org/data/definitions/918.html",
        authority="MITRE",
    ),
)
