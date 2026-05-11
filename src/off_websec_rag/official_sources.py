from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OfficialSource:
    topic: str
    title: str
    url: str
    authority: str
    resource_type: str = "html"

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
        topic="dom_xss",
        title="OWASP DOM Based XSS Prevention Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
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
        topic="broken_access_control",
        title="OWASP Top 10 A01 Broken Access Control",
        url="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        authority="OWASP",
    ),
    OfficialSource(
        topic="security_misconfiguration",
        title="OWASP Top 10 A05 Security Misconfiguration",
        url="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        authority="OWASP",
    ),
    OfficialSource(
        topic="authentication",
        title="OWASP Top 10 A07 Identification and Authentication Failures",
        url="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        authority="OWASP",
    ),
    OfficialSource(
        topic="ssrf",
        title="OWASP Top 10 A10 SSRF",
        url="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        authority="OWASP",
    ),
    OfficialSource(
        topic="csrf",
        title="OWASP CSRF Prevention Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="file_upload",
        title="OWASP File Upload Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="command_injection",
        title="OWASP OS Command Injection Defense Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="xxe",
        title="OWASP XML External Entity Prevention Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="deserialization",
        title="OWASP Deserialization Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="authentication",
        title="OWASP Authentication Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="session_management",
        title="OWASP Session Management Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="access_control",
        title="OWASP Authorization Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="input_validation",
        title="OWASP Input Validation Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="api_security",
        title="OWASP REST Security Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="jwt",
        title="OWASP JSON Web Token for Java Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="web_testing",
        title="OWASP Testing Guide v4 PDF",
        url="https://owasp.org/www-project-web-security-testing-guide/assets/archive/OWASP_Testing_Guide_v4.pdf",
        authority="OWASP",
        resource_type="pdf",
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
    OfficialSource(
        topic="csrf",
        title="MITRE CWE-352 Cross-Site Request Forgery",
        url="https://cwe.mitre.org/data/definitions/352.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="path_traversal",
        title="MITRE CWE-22 Path Traversal",
        url="https://cwe.mitre.org/data/definitions/22.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="file_upload",
        title="MITRE CWE-434 Unrestricted File Upload",
        url="https://cwe.mitre.org/data/definitions/434.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="command_injection",
        title="MITRE CWE-78 OS Command Injection",
        url="https://cwe.mitre.org/data/definitions/78.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="xxe",
        title="MITRE CWE-611 XML External Entity Reference",
        url="https://cwe.mitre.org/data/definitions/611.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="authentication",
        title="MITRE CWE-287 Improper Authentication",
        url="https://cwe.mitre.org/data/definitions/287.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="access_control",
        title="MITRE CWE-862 Missing Authorization",
        url="https://cwe.mitre.org/data/definitions/862.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="deserialization",
        title="MITRE CWE-502 Deserialization of Untrusted Data",
        url="https://cwe.mitre.org/data/definitions/502.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="ssti",
        title="PortSwigger Server-Side Template Injection",
        url="https://portswigger.net/web-security/server-side-template-injection",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="request_smuggling",
        title="PortSwigger HTTP Request Smuggling",
        url="https://portswigger.net/web-security/request-smuggling",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="web_cache_poisoning",
        title="PortSwigger Web Cache Poisoning",
        url="https://portswigger.net/web-security/web-cache-poisoning",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="graphql",
        title="PortSwigger GraphQL API Vulnerabilities",
        url="https://portswigger.net/web-security/graphql",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="oauth",
        title="PortSwigger OAuth Authentication",
        url="https://portswigger.net/web-security/oauth",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="jwt",
        title="PortSwigger JWT Attacks",
        url="https://portswigger.net/web-security/jwt",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="cors",
        title="PortSwigger CORS Vulnerabilities",
        url="https://portswigger.net/web-security/cors",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="path_traversal",
        title="PortSwigger Path Traversal",
        url="https://portswigger.net/web-security/file-path-traversal",
        authority="PortSwigger",
    ),
)
