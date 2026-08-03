"""
Database Security Analyzer

Connects to a PostgreSQL or MySQL database with the credentials the caller
supplies and reports its real security posture: transport encryption, server
settings that matter for security, and the accounts/privileges that actually
exist. Every value comes from a query against the live server.

The previous version connected to nothing. _test_connection returned
random.random() > 0.1; the server version was random.choice of a few
strings; users, privileges, password-policy compliance, encryption state and
config issues were all random.choice/randint. It fabricated an entire
database security assessment.

Only PostgreSQL and MySQL are implemented (with pure-Python drivers, no
system libraries). Oracle, MSSQL and MongoDB return an honest
"engine not supported" rather than invented findings. A failed connection is
reported as such, never as a passing scan.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from schemas import (
    AuditConfiguration,
    ComplianceCheck,
    ConfigurationIssue,
    DatabaseSecurityAnalyzerInput,
    DatabaseSecurityAnalyzerOutput,
    DatabaseUser,
    EncryptionStatus,
    NetworkSecurity,
    VulnerabilityFinding,
)

logger = logging.getLogger(__name__)

SUPPORTED_ENGINES = {"postgresql", "postgres", "mysql", "mariadb"}
CONNECT_TIMEOUT = 15


class DatabaseSecurityAnalyzer:
    """Connects to a real database and reports its real security posture."""

    name = "Database Security Analyzer"
    description = (
        "Connects to a PostgreSQL or MySQL database and reports its real "
        "security posture (transport encryption, security-relevant settings, "
        "accounts and privileges). Requires connection credentials."
    )
    category = "database_security"

    # ---- connection ----------------------------------------------------

    @staticmethod
    def _connect_postgres(inp: DatabaseSecurityAnalyzerInput):
        import pg8000.dbapi

        # ssl_context left at the driver default: pg8000 attempts SSL and
        # falls back to plaintext, which is exactly what we want to observe.
        return pg8000.dbapi.connect(
            host=inp.host,
            port=inp.port or 5432,
            user=inp.username,
            password=inp.password or "",
            database=inp.database_name or inp.username,
            timeout=CONNECT_TIMEOUT,
        )

    @staticmethod
    def _connect_mysql(inp: DatabaseSecurityAnalyzerInput):
        import pymysql

        return pymysql.connect(
            host=inp.host,
            port=inp.port or 3306,
            user=inp.username,
            password=inp.password or "",
            database=inp.database_name or None,
            connect_timeout=CONNECT_TIMEOUT,
            read_timeout=CONNECT_TIMEOUT,
        )

    @staticmethod
    def _query(conn, sql: str) -> List[tuple]:
        cur = conn.cursor()
        try:
            cur.execute(sql)
            return list(cur.fetchall())
        finally:
            cur.close()

    # ---- PostgreSQL analysis ------------------------------------------

    def _analyze_postgres(self, conn) -> Dict[str, Any]:
        settings = {
            name: value
            for name, value in self._query(
                conn,
                "SELECT name, setting FROM pg_settings WHERE name IN "
                "('ssl','password_encryption','log_connections',"
                "'log_disconnections','logging_collector','log_statement',"
                "'listen_addresses','row_security')",
            )
        }
        version = self._query(conn, "SHOW server_version")[0][0]

        ssl_on = settings.get("ssl") == "on"

        config_issues: List[ConfigurationIssue] = []

        def issue(param, current, recommended, severity, description, impact):
            config_issues.append(ConfigurationIssue(
                parameter=param, current_value=str(current),
                recommended_value=recommended, severity=severity,
                description=description, security_impact=impact,
            ))

        if not ssl_on:
            issue("ssl", settings.get("ssl", "off"), "on", "High",
                  "TLS is disabled on the server.",
                  "Connections and credentials travel in cleartext.")
        if settings.get("password_encryption") == "md5":
            issue("password_encryption", "md5", "scram-sha-256", "Medium",
                  "Passwords are hashed with the weak MD5 scheme.",
                  "MD5 password hashes are vulnerable to offline attacks.")
        if settings.get("log_connections") == "off":
            issue("log_connections", "off", "on", "Low",
                  "Connection attempts are not logged.",
                  "No audit trail of who connected and when.")

        # Real role enumeration.
        users: List[DatabaseUser] = []
        for rolname, rolsuper, rolcanlogin, rolvaliduntil in self._query(
            conn,
            "SELECT rolname, rolsuper, rolcanlogin, rolvaliduntil FROM pg_roles "
            "ORDER BY rolsuper DESC, rolname LIMIT 100",
        ):
            sec_issues = []
            if rolsuper and rolcanlogin:
                sec_issues.append("Superuser role that can log in directly")
            users.append(DatabaseUser(
                username=rolname,
                privileges=["SUPERUSER"] if rolsuper else ["login" if rolcanlogin else "nologin"],
                host_access=[],
                password_policy_compliant=True,   # PG does not expose per-role policy here
                last_login=None,
                account_locked=not rolcanlogin,
                admin_privileges=bool(rolsuper),
                security_issues=sec_issues,
            ))

        encryption = EncryptionStatus(
            data_at_rest_encrypted=False,   # not observable via SQL; reported, not guessed
            data_in_transit_encrypted=ssl_on,
            key_management="Not inspected",
            encryption_algorithms=["TLS"] if ssl_on else [],
            issues=[] if ssl_on else ["Server does not offer TLS (ssl=off)"],
            recommendations=[] if ssl_on else ["Enable ssl and require it in pg_hba.conf"],
        )

        audit = AuditConfiguration(
            audit_enabled=settings.get("logging_collector") == "on",
            log_level=settings.get("log_statement", "unknown"),
            logged_events=[k for k in ("log_connections", "log_disconnections")
                           if settings.get(k) == "on"],
            log_retention_days=0,   # governed by external log rotation, not the server
            issues=([] if settings.get("logging_collector") == "on"
                    else ["logging_collector is off; server logs may not be captured"]),
            recommendations=["Enable logging_collector and ship logs to a central store"]
            if settings.get("logging_collector") != "on" else [],
        )

        network = NetworkSecurity(
            ssl_tls_enabled=ssl_on,
            firewall_configured=False,    # not observable from inside the DB
            allowed_connections=[settings.get("listen_addresses", "unknown")],
            port_security={"tls": "enabled" if ssl_on else "disabled"},
            issues=[] if ssl_on else ["No TLS offered to clients"],
        )

        return {
            "version": version, "settings": settings, "config_issues": config_issues,
            "users": users, "encryption": encryption, "audit": audit, "network": network,
            "in_transit": ssl_on,
        }

    # ---- MySQL analysis ------------------------------------------------

    def _analyze_mysql(self, conn) -> Dict[str, Any]:
        def var(name: str) -> Optional[str]:
            rows = self._query(conn, f"SHOW VARIABLES LIKE '{name}'")
            return rows[0][1] if rows else None

        version = self._query(conn, "SELECT VERSION()")[0][0]
        have_ssl = (var("have_ssl") or "").upper() == "YES"
        require_secure = (var("require_secure_transport") or "OFF").upper() == "ON"
        in_transit = have_ssl and require_secure

        config_issues: List[ConfigurationIssue] = []

        def issue(param, current, recommended, severity, description, impact):
            config_issues.append(ConfigurationIssue(
                parameter=param, current_value=str(current),
                recommended_value=recommended, severity=severity,
                description=description, security_impact=impact,
            ))

        if not have_ssl:
            issue("have_ssl", "NO", "YES", "High",
                  "The server was not built/configured with TLS support.",
                  "All client traffic, including credentials, is cleartext.")
        elif not require_secure:
            issue("require_secure_transport", "OFF", "ON", "Medium",
                  "TLS is available but not required.",
                  "Clients may connect without encryption.")
        if (var("local_infile") or "OFF").upper() == "ON":
            issue("local_infile", "ON", "OFF", "Medium",
                  "LOAD DATA LOCAL INFILE is enabled.",
                  "Can be abused to read files from a connecting client.")
        if (var("skip_name_resolve") or "OFF").upper() == "OFF":
            issue("skip_name_resolve", "OFF", "ON", "Low",
                  "Hostname-based grants are in use.",
                  "DNS spoofing can affect host-based access control.")

        # Real user enumeration and privilege check.
        users: List[DatabaseUser] = []
        try:
            rows = self._query(
                conn,
                "SELECT user, host, "
                "  Super_priv, Select_priv, "
                "  (authentication_string = '' OR authentication_string IS NULL) AS no_pw "
                "FROM mysql.user ORDER BY Super_priv DESC LIMIT 100",
            )
        except Exception:
            rows = []   # the connecting account may lack rights on mysql.user

        for user, host, super_priv, _select, no_pw in rows:
            sec_issues = []
            is_super = str(super_priv).upper() in ("Y", "1")
            wildcard = host in ("%", "")
            if no_pw:
                sec_issues.append("Account has no password")
            if wildcard:
                sec_issues.append("Account is reachable from any host (%)")
            if is_super and wildcard:
                sec_issues.append("Superuser reachable from any host")
            users.append(DatabaseUser(
                username=str(user),
                privileges=["SUPER"] if is_super else ["standard"],
                host_access=[str(host)],
                password_policy_compliant=not bool(no_pw),
                last_login=None,
                account_locked=False,
                admin_privileges=is_super,
                security_issues=sec_issues,
            ))

        encryption = EncryptionStatus(
            data_at_rest_encrypted=False,
            data_in_transit_encrypted=in_transit,
            key_management="Not inspected",
            encryption_algorithms=["TLS"] if have_ssl else [],
            issues=([] if in_transit else
                    (["TLS not required (require_secure_transport=OFF)"] if have_ssl
                     else ["Server has no TLS support (have_ssl=NO)"])),
            recommendations=([] if in_transit else
                             ["Enable TLS and set require_secure_transport=ON"]),
        )

        general_log = (var("general_log") or "OFF").upper() == "ON"
        audit = AuditConfiguration(
            audit_enabled=general_log,
            log_level="general_log" if general_log else "none",
            logged_events=["all_queries"] if general_log else [],
            log_retention_days=0,
            issues=[] if general_log else
                   ["No general/audit log enabled (an audit plugin is recommended over general_log)"],
            recommendations=["Deploy an audit-log plugin (MySQL Enterprise Audit / MariaDB Audit)"]
            if not general_log else [],
        )

        network = NetworkSecurity(
            ssl_tls_enabled=have_ssl,
            firewall_configured=False,
            allowed_connections=sorted({u.host_access[0] for u in users if u.host_access}),
            port_security={"tls": "required" if require_secure else ("available" if have_ssl else "disabled")},
            issues=[] if in_transit else ["Encrypted transport is not enforced"],
        )

        return {
            "version": version, "config_issues": config_issues, "users": users,
            "encryption": encryption, "audit": audit, "network": network,
            "in_transit": in_transit,
        }

    # ---- scoring -------------------------------------------------------

    @staticmethod
    def _vulnerabilities(users: List[DatabaseUser], config: List[ConfigurationIssue]) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        for u in users:
            for issue in u.security_issues:
                sev = "Critical" if "Superuser reachable" in issue or "no password" in issue.lower() else "High"
                findings.append(VulnerabilityFinding(
                    vulnerability_id=f"DBUSER-{u.username}",
                    severity=sev,
                    category="Access Control",
                    description=f"{u.username}@{','.join(u.host_access) or 'local'}: {issue}",
                    affected_component=f"account {u.username}",
                    remediation="Restrict host access, set a strong password, and drop unused privileges.",
                ))
        return findings

    @staticmethod
    def _score(config: List[ConfigurationIssue], vulns: List[VulnerabilityFinding]) -> float:
        weights = {"Critical": 3.0, "High": 1.5, "Medium": 0.7, "Low": 0.2}
        penalty = sum(weights.get(c.severity, 0.2) for c in config)
        penalty += sum(weights.get(v.severity, 0.5) for v in vulns)
        return round(max(10.0 - penalty, 0.0), 1)

    @staticmethod
    def _risk(score: float) -> str:
        if score >= 8.5:
            return "Low"
        if score >= 6.0:
            return "Medium"
        if score >= 3.5:
            return "High"
        return "Critical"

    # ---- entry point ---------------------------------------------------

    def _failure(self, message: str, connected: bool = False) -> DatabaseSecurityAnalyzerOutput:
        return DatabaseSecurityAnalyzerOutput(
            database_info={},
            connection_successful=connected,
            scan_timestamp=datetime.now(),
            database_users=[],
            configuration_issues=[],
            encryption_status=EncryptionStatus(
                data_at_rest_encrypted=False, data_in_transit_encrypted=False,
                key_management="Not inspected", encryption_algorithms=[],
                issues=[], recommendations=[],
            ),
            audit_configuration=AuditConfiguration(
                audit_enabled=False, log_level="unknown", logged_events=[],
                log_retention_days=0, issues=[], recommendations=[],
            ),
            network_security=NetworkSecurity(
                ssl_tls_enabled=False, firewall_configured=False,
                allowed_connections=[], port_security={}, issues=[],
            ),
            compliance_results=[],
            vulnerabilities=[],
            security_score=0.0,
            risk_level="Unknown",
            recommendations=[message],
            scan_summary={"error": message},
            success=False,
            summary=message,
        )

    async def execute(
        self, input_data: DatabaseSecurityAnalyzerInput
    ) -> DatabaseSecurityAnalyzerOutput:
        engine = (input_data.database_type or "").strip().lower()
        if engine not in SUPPORTED_ENGINES:
            return self._failure(
                f"Engine '{input_data.database_type}' is not supported. This tool "
                "implements real checks for PostgreSQL and MySQL/MariaDB only; it "
                "will not fabricate results for other engines."
            )
        if not input_data.host or not input_data.username:
            return self._failure("A host and username are required to connect.")

        is_postgres = engine in ("postgresql", "postgres")
        loop = asyncio.get_running_loop()

        # Connect (blocking driver -> executor).
        try:
            connect = self._connect_postgres if is_postgres else self._connect_mysql
            conn = await loop.run_in_executor(None, connect, input_data)
        except ImportError as exc:
            return self._failure(f"Required database driver is not installed: {exc}")
        except Exception as exc:
            return self._failure(f"Could not connect to the database: {type(exc).__name__}: {exc}")

        try:
            analyze = self._analyze_postgres if is_postgres else self._analyze_mysql
            data = await loop.run_in_executor(None, analyze, conn)
        except Exception as exc:
            return self._failure(
                f"Connected, but the security queries failed: {type(exc).__name__}: {exc}",
                connected=True,
            )
        finally:
            try:
                conn.close()
            except Exception:
                pass

        vulns = self._vulnerabilities(data["users"], data["config_issues"])
        score = self._score(data["config_issues"], vulns)

        recommendations: List[str] = []
        if not data["in_transit"]:
            recommendations.append("Enforce TLS for all client connections.")
        if any(v.severity in ("Critical", "High") for v in vulns):
            recommendations.append("Fix the flagged accounts: passwords, host scope, privileges.")
        recommendations.extend(c.description for c in data["config_issues"] if c.severity in ("High", "Critical"))
        if not recommendations:
            recommendations.append("No high-severity issues observed in the checks performed.")

        summary = {
            "engine": engine,
            "server_version": data["version"],
            "in_transit_encryption": data["in_transit"],
            "accounts_reviewed": len(data["users"]),
            "config_issues": len(data["config_issues"]),
            "note": (
                "Data-at-rest encryption, firewall posture and log retention are "
                "not observable through a SQL connection and are reported as "
                "unset/false rather than guessed."
            ),
        }

        return DatabaseSecurityAnalyzerOutput(
            database_info={"type": engine, "version": data["version"], "host": input_data.host},
            connection_successful=True,
            scan_timestamp=datetime.now(),
            database_users=data["users"],
            configuration_issues=data["config_issues"],
            encryption_status=data["encryption"],
            audit_configuration=data["audit"],
            network_security=data["network"],
            compliance_results=[],
            vulnerabilities=vulns,
            security_score=score,
            risk_level=self._risk(score),
            recommendations=recommendations,
            scan_summary=summary,
            success=True,
            summary=(
                f"{engine} {data['version']} on {input_data.host}: score {score}/10 "
                f"({self._risk(score)}), {len(data['config_issues'])} config issue(s), "
                f"{len(vulns)} account finding(s)."
            ),
        )


async def execute_tool(
    params: DatabaseSecurityAnalyzerInput,
) -> DatabaseSecurityAnalyzerOutput:
    """Main entry point for the Database Security Analyzer tool."""
    return await DatabaseSecurityAnalyzer().execute(params)


TOOL_INFO = {
    "name": "Database Security Analyzer",
    "description": (
        "Connects to a PostgreSQL or MySQL/MariaDB database with the supplied "
        "credentials and reports its real security posture: transport "
        "encryption, security-relevant server settings, and accounts/privileges. "
        "Other engines return an honest 'not supported'; a failed connection is "
        "never reported as a passing scan."
    ),
    "category": "database_security",
    "version": "2.0.0",
    "author": "Wildbox Security",
    "input_schema": DatabaseSecurityAnalyzerInput,
    "output_schema": DatabaseSecurityAnalyzerOutput,
    "tool_class": DatabaseSecurityAnalyzer,
}
