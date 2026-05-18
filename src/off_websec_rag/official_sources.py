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


OWASP_COMMUNITY_ATTACKS_INDEX_URL = "https://owasp.org/www-community/attacks/"


OFFICIAL_SOURCES: tuple[OfficialSource, ...] = (
    OfficialSource(
        topic="web_attack_index",
        title="OWASP Community Attacks Index",
        url=OWASP_COMMUNITY_ATTACKS_INDEX_URL,
        authority="OWASP",
    ),
    OfficialSource(
        topic="sql_injection",
        title="OWASP SQL Injection Prevention Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="sql_injection",
        title="OWASP Query Parameterization Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="nosql_injection",
        title="OWASP NoSQL Security Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="ldap_injection",
        title="OWASP LDAP Injection Prevention Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
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
        topic="dom_clobbering",
        title="OWASP DOM Clobbering Prevention Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html",
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
        topic="open_redirect",
        title="OWASP Unvalidated Redirects and Forwards Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="clickjacking",
        title="OWASP Clickjacking Defense Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
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
        topic="ddos",
        title="OWASP Denial of Service Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="mass_assignment",
        title="OWASP Mass Assignment Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="prototype_pollution",
        title="OWASP Prototype Pollution Prevention Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html",
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
        topic="graphql",
        title="OWASP GraphQL Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="websocket_security",
        title="OWASP WebSocket Security Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="security_headers",
        title="OWASP HTTP Headers Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="content_security_policy",
        title="OWASP Content Security Policy Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="xs_leaks",
        title="OWASP XS Leaks Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/XS_Leaks_Cheat_Sheet.html",
        authority="OWASP",
    ),
    OfficialSource(
        topic="ajax_security",
        title="OWASP AJAX Security Cheat Sheet",
        url="https://cheatsheetseries.owasp.org/cheatsheets/AJAX_Security_Cheat_Sheet.html",
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
        topic="nosql_injection",
        title="MITRE CWE-943 Improper Neutralization in Data Query Logic",
        url="https://cwe.mitre.org/data/definitions/943.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="ldap_injection",
        title="MITRE CWE-90 LDAP Injection",
        url="https://cwe.mitre.org/data/definitions/90.html",
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
        topic="open_redirect",
        title="MITRE CWE-601 Open Redirect",
        url="https://cwe.mitre.org/data/definitions/601.html",
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
        topic="ddos",
        title="MITRE CWE-400 Uncontrolled Resource Consumption",
        url="https://cwe.mitre.org/data/definitions/400.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="ddos",
        title="MITRE CWE-770 Allocation of Resources Without Limits or Throttling",
        url="https://cwe.mitre.org/data/definitions/770.html",
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
        topic="request_smuggling",
        title="MITRE CWE-444 HTTP Request Smuggling",
        url="https://cwe.mitre.org/data/definitions/444.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="access_control",
        title="MITRE CWE-639 Authorization Bypass Through User-Controlled Key",
        url="https://cwe.mitre.org/data/definitions/639.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="authentication",
        title="MITRE CWE-307 Improper Restriction of Excessive Authentication Attempts",
        url="https://cwe.mitre.org/data/definitions/307.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="mass_assignment",
        title="MITRE CWE-915 Mass Assignment Object Attribute Modification",
        url="https://cwe.mitre.org/data/definitions/915.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="prototype_pollution",
        title="MITRE CWE-915 Prototype Pollution Object Attribute Modification",
        url="https://cwe.mitre.org/data/definitions/915.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="clickjacking",
        title="MITRE CWE-1021 Clickjacking UI Layer Restriction",
        url="https://cwe.mitre.org/data/definitions/1021.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="prototype_pollution",
        title="MITRE CWE-1321 Prototype Pollution",
        url="https://cwe.mitre.org/data/definitions/1321.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="information_disclosure",
        title="MITRE CWE-209 Information Exposure Through Error Message",
        url="https://cwe.mitre.org/data/definitions/209.html",
        authority="MITRE",
    ),
    OfficialSource(
        topic="sql_injection",
        title="PortSwigger SQL Injection",
        url="https://portswigger.net/web-security/sql-injection",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="xss",
        title="PortSwigger Cross-site Scripting",
        url="https://portswigger.net/web-security/cross-site-scripting",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="csrf",
        title="PortSwigger Cross-site Request Forgery",
        url="https://portswigger.net/web-security/csrf",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="xxe",
        title="PortSwigger XML External Entity Injection",
        url="https://portswigger.net/web-security/xxe",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="ssrf",
        title="PortSwigger Server-side Request Forgery",
        url="https://portswigger.net/web-security/ssrf",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="nosql_injection",
        title="PortSwigger NoSQL Injection",
        url="https://portswigger.net/web-security/nosql-injection",
        authority="PortSwigger",
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
        topic="prototype_pollution",
        title="PortSwigger Prototype Pollution",
        url="https://portswigger.net/web-security/prototype-pollution",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="clickjacking",
        title="PortSwigger Clickjacking",
        url="https://portswigger.net/web-security/clickjacking",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="websocket_security",
        title="PortSwigger WebSockets Security",
        url="https://portswigger.net/web-security/websockets",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="access_control",
        title="PortSwigger Access Control Vulnerabilities",
        url="https://portswigger.net/web-security/access-control",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="authentication",
        title="PortSwigger Authentication Vulnerabilities",
        url="https://portswigger.net/web-security/authentication",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="host_header",
        title="PortSwigger HTTP Host Header Attacks",
        url="https://portswigger.net/web-security/host-header",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="race_condition",
        title="PortSwigger Race Conditions",
        url="https://portswigger.net/web-security/race-conditions",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="business_logic",
        title="PortSwigger Business Logic Vulnerabilities",
        url="https://portswigger.net/web-security/logic-flaws",
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
    OfficialSource(
        topic="command_injection",
        title="PortSwigger OS Command Injection",
        url="https://portswigger.net/web-security/os-command-injection",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="file_upload",
        title="PortSwigger File Upload Vulnerabilities",
        url="https://portswigger.net/web-security/file-upload",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="web_cache_deception",
        title="PortSwigger Web Cache Deception",
        url="https://portswigger.net/web-security/web-cache-deception",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="dom_xss",
        title="PortSwigger DOM-Based Vulnerabilities",
        url="https://portswigger.net/web-security/dom-based",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="information_disclosure",
        title="PortSwigger Information Disclosure",
        url="https://portswigger.net/web-security/information-disclosure",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="api_security",
        title="PortSwigger API Testing",
        url="https://portswigger.net/web-security/api-testing",
        authority="PortSwigger",
    ),
    OfficialSource(
        topic="web_llm_attacks",
        title="PortSwigger Web LLM Attacks",
        url="https://portswigger.net/web-security/llm-attacks",
        authority="PortSwigger",
    ),
)

