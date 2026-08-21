"""Synthetic Sysmon event definitions for detection content validation.

Events are shaped to satisfy Exabeam's Sysmon JSON parser
(`microsoft-sysmon-json-process-create-success-processcreate`), whose match
conditions require all four of these strings in the raw log::

    Microsoft-Windows-Sysmon
    Process Create:
    "ParentProcessId":
    "Image":

That parser splits ``Image`` into ``process_dir`` + ``process_name``, so
``process_name`` lands as a bare basename (``netsh.exe``), which is what the
converted Sigma rules match on. See EXA-EQL-WLDI-REGEX-ESCAPE notes in
CLAUDE.md for why the path-prefixed arms alone are not sufficient.

Every command line below is derived from the deployed rule's EQL so the
mapping from event to expected detection is exact, not approximate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

_SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
_SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
_SYSMON_GUID = "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"


@dataclass(frozen=True)
class Behavior:
    """One synthetic attacker behavior mapped to the rule it should trigger."""

    key: str
    title: str
    attack: str
    stage: str
    image: str
    command_line: str
    parent_image: str = r"C:\Windows\System32\cmd.exe"
    rule_name: str = ""
    rule_id: str = ""
    # Context table this behavior's process_name should become discoverable in.
    # A behavior must have a verifiable expected outcome: either it fires a named
    # rule, or it puts a value somewhere a table can match. Table-backed behaviors
    # have no Sigma rule and are not exempt from the invariant -- they satisfy the
    # other half of it.
    feeds_table: str = ""
    notes: str = ""


@dataclass(frozen=True)
class Scenario:
    """An ordered chain of behaviors telling one intrusion story."""

    key: str
    title: str
    description: str
    behaviors: list[Behavior] = field(default_factory=list)


# -- Healthcare pack ---------------------------------------------------------

_HEALTHCARE = Scenario(
    key="healthcare",
    title="Hospital ransomware intrusion",
    description=(
        "Lateral pivot into a clinical VLAN, LSASS credential theft on a legacy "
        "endpoint, Defender teardown, PHI staged into a password-protected "
        "archive, then recovery destruction before encryption."
    ),
    behaviors=[
        Behavior(
            key="netsh-rdp-forward",
            title="RDP port forwarding via netsh",
            attack="T1090",
            stage="Lateral Movement",
            image=r"C:\Windows\System32\netsh.exe",
            # Lead with the full executable name, as Sysmon records it and as
            # every other behavior here does. Bare "netsh " cannot satisfy a
            # rule arm matching on the binary name in the command line.
            command_line=(
                "netsh.exe interface portproxy add v4tov4 listenport=3389 "
                "listenaddress=0.0.0.0 connectport=3389 connectaddress=10.20.30.40"
            ),
            rule_name="[Sigma] RDP Port Forwarding Rule Added Via Netsh.EXE",
            rule_id="79904044-b01b-4c52-84eb-cea58a76a6c7",
        ),
        Behavior(
            key="comsvcs-lsass-dump",
            title="LSASS memory dump via comsvcs.dll",
            attack="T1003.001",
            stage="Credential Access",
            image=r"C:\Windows\System32\rundll32.exe",
            command_line=(
                r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump "
                r"672 C:\Windows\Temp\lsass.dmp full"
            ),
            rule_name="[Sigma] Process Memory Dump Via Comsvcs.DLL",
            rule_id="1a89ee98-a0ad-4492-945a-0070f02c1c9e",
        ),
        Behavior(
            key="defender-disable",
            title="Defender realtime protection disabled",
            attack="T1562.001",
            stage="Defense Evasion",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=(
                "powershell.exe -NoProfile -Command "
                "Set-MpPreference -DisableRealtimeMonitoring $true"
            ),
            rule_name="[Sigma] Powershell Defender Disable Scan Feature",
            rule_id="7b19100b-997b-4995-8dd2-f6028b465875",
            notes="Plaintext form only; base64 variants are out of EQL scope.",
        ),
        Behavior(
            key="7zip-phi-staging",
            title="PHI staged into password-protected archive",
            attack="T1560.001",
            stage="Collection",
            image=r"C:\Program Files\7-Zip\7z.exe",
            command_line=(
                r"7z.exe a -pTr0ub4dor3 -mhe=on C:\Windows\Temp\patients.7z "
                r"D:\Clinical\Records\*"
            ),
            rule_name=(
                "[Sigma] Compress Data and Lock With Password for "
                "Exfiltration With 7-ZIP"
            ),
            rule_id="2f59b4e3-2fad-4131-b580-9e0447023a7a",
        ),
        Behavior(
            key="bcdedit-recovery-off",
            title="Boot recovery disabled before encryption",
            attack="T1490",
            stage="Impact",
            image=r"C:\Windows\System32\bcdedit.exe",
            command_line="bcdedit.exe /set {default} recoveryenabled no",
            rule_name="[Sigma] Boot Configuration Tampering Via Bcdedit.EXE",
            rule_id="c21a5d0a-eee2-4fcc-ad59-6f779c3c0657",
        ),
    ],
)


# -- Insurance pack ----------------------------------------------------------
# Only the endpoint-sourced rule is simulatable here: the other four Insurance
# rules consume Entra ID / CloudTrail telemetry, which this generator does not
# synthesise.

_INSURANCE = Scenario(
    key="insurance",
    title="Insurance ransomware impact stage",
    description=(
        "Endpoint-observable stage of the insurance chain: shadow copy "
        "destruction ahead of encryption. The identity and cloud stages of that "
        "pack (Entra ID, CloudTrail) are not endpoint events and are out of "
        "scope for this generator."
    ),
    behaviors=[
        Behavior(
            key="vssadmin-shadow-delete",
            title="Shadow copies deleted via vssadmin",
            attack="T1490",
            stage="Impact",
            image=r"C:\Windows\System32\vssadmin.exe",
            command_line="vssadmin.exe delete shadows /all /quiet",
            rule_name=(
                "[Sigma] Shadow Copies Deletion Using Operating Systems Utilities"
            ),
            rule_id="e3971d6f-ef92-4eff-b391-1e1db88023d7",
        ),
    ],
)


# Unlike the two intrusion scenarios above, these behaviors do not map to a Sigma
# rule. They exist to put realistic AI-tooling values into `process_name` and
# `parent_process_name` -- what feeds the AI Agent Process Names and AI Dev Framework
# Process Names context tables (6 analytics rules each). Both tables are DEAD on every
# tenant measured, and endpoint process telemetry is the ONLY detection path for
# locally-run models: ollama, LM Studio and llama.cpp leave no network trace once the
# model is downloaded, so no proxy or DNS source can see them at all.
#
# `rule_name` is left empty; `feeds_table` names the target table instead, which is how
# these still satisfy the "every behavior has a verifiable outcome" invariant. The MITRE
# ids are the closest honest fit -- most of this is usage telemetry, not attacker
# behavior, and it is labelled that way deliberately.
#
# Executable names are REPRESENTATIVE. Tune them to what a given customer actually
# runs: a table populated from this list proves the pipeline works, not that the
# customer runs these tools.
_AI_TOOLING = Scenario(
    key="ai-tooling",
    title="Shadow AI and local model usage",
    description=(
        "Local model runtimes, desktop AI assistants, MCP servers and agent "
        "frameworks executing on an endpoint. Populates the two AI process-name "
        "context tables, which no network-side source can reach."
    ),
    behaviors=[
        # --- AI Agent Process Names -------------------------------------------
        Behavior(
            key="ollama-serve",
            title="Local model server started (ollama)",
            attack="T1059",
            stage="Local Model Runtime",
            image=r"C:\Users\Public\ollama\ollama.exe",
            command_line="ollama.exe serve",
            feeds_table="AI Agent Process Names",
            notes="No network trace after the model pull.",
        ),
        Behavior(
            key="lmstudio-server",
            title="LM Studio local inference server",
            attack="T1059",
            stage="Local Model Runtime",
            image=r"C:\Program Files\LM Studio\LM Studio.exe",
            command_line='"LM Studio.exe" --server --port 1234',
            feeds_table="AI Agent Process Names",
            notes="",
        ),
        Behavior(
            key="llamacpp-server",
            title="llama.cpp inference server",
            attack="T1059",
            stage="Local Model Runtime",
            image=r"C:\Tools\llama.cpp\llama-server.exe",
            command_line="llama-server.exe -m models/llama-3-8b.gguf --port 8080",
            feeds_table="AI Agent Process Names",
            notes="",
        ),
        Behavior(
            key="gpt4all-desktop",
            title="GPT4All desktop client",
            attack="T1059",
            stage="Local Model Runtime",
            image=r"C:\Program Files\GPT4All\gpt4all.exe",
            command_line="gpt4all.exe",
            feeds_table="AI Agent Process Names",
            notes="",
        ),
        Behavior(
            key="claude-desktop",
            title="Desktop AI assistant with MCP enabled",
            attack="T1059",
            stage="AI Assistant",
            image=r"C:\Users\jsmith\AppData\Local\Claude\claude.exe",
            command_line="claude.exe",
            feeds_table="AI Agent Process Names",
            notes="MCP config makes this a data-access path.",
        ),
        Behavior(
            key="cursor-ide",
            title="AI-assisted IDE",
            attack="T1059",
            stage="AI Assistant",
            image=r"C:\Users\jsmith\AppData\Local\Programs\cursor\Cursor.exe",
            command_line="Cursor.exe",
            feeds_table="AI Agent Process Names",
            notes="",
        ),
        Behavior(
            key="mcp-server-fs",
            title="MCP filesystem server spawned by an assistant",
            attack="T1059.007",
            stage="Agent Tooling",
            image=r"C:\Program Files\nodejs\node.exe",
            command_line=(
                r"node.exe C:\Users\jsmith\AppData\Roaming\npm\mcp-server-filesystem"
                r"\dist\index.js --root C:\Shared"
            ),
            parent_image=r"C:\Users\jsmith\AppData\Local\Claude\claude.exe",
            feeds_table="AI Agent Process Names",
            notes=(
                "Parent is the assistant -- the parent/child pair is the signal, "
                "not the binary alone."
            ),
        ),
        # --- AI Dev Framework Process Names -----------------------------------
        Behavior(
            key="langchain-agent",
            title="LangChain agent executed",
            attack="T1059.006",
            stage="Agent Framework",
            image=r"C:\Python312\python.exe",
            command_line="python.exe -m langchain.agents.run --tools shell,browser",
            feeds_table="AI Dev Framework Process Names",
            notes="",
        ),
        Behavior(
            key="llamaindex-ingest",
            title="LlamaIndex ingestion over a file share",
            attack="T1059.006",
            stage="Agent Framework",
            image=r"C:\Python312\python.exe",
            command_line=r"python.exe -m llama_index.ingest --src \\fileserver\finance",
            feeds_table="AI Dev Framework Process Names",
            notes=(
                "The source path is the interesting part -- a framework reading a "
                "corporate share."
            ),
        ),
        Behavior(
            key="autogen-multiagent",
            title="AutoGen multi-agent run",
            attack="T1059.006",
            stage="Agent Framework",
            image=r"C:\Python312\python.exe",
            command_line="python.exe -m autogen.agentchat --agents planner,coder,executor",
            feeds_table="AI Dev Framework Process Names",
            notes="Multi-agent implies delegation depth.",
        ),
        Behavior(
            key="crewai-run",
            title="CrewAI crew execution",
            attack="T1059.006",
            stage="Agent Framework",
            image=r"C:\Python312\python.exe",
            command_line="python.exe -m crewai run --crew research_crew",
            feeds_table="AI Dev Framework Process Names",
            notes="",
        ),
    ],
)


SCENARIOS: dict[str, Scenario] = {
    _HEALTHCARE.key: _HEALTHCARE,
    _INSURANCE.key: _INSURANCE,
    _AI_TOOLING.key: _AI_TOOLING,
}


def get_scenario(key: str) -> Scenario:
    """Return a scenario by key, or raise ValueError listing valid keys."""
    try:
        return SCENARIOS[key]
    except KeyError:
        valid = ", ".join(sorted(SCENARIOS))
        raise ValueError(f"Unknown scenario '{key}'. Valid: {valid}") from None


def list_behaviors(scenario: str | None = None) -> list[Behavior]:
    """Return behaviors for one scenario, or all behaviors when None."""
    if scenario is not None:
        return list(get_scenario(scenario).behaviors)
    out: list[Behavior] = []
    for sc in SCENARIOS.values():
        out.extend(sc.behaviors)
    return out


def _basename(path: str) -> str:
    """Return the trailing path component of a Windows path."""
    return path.rsplit("\\", 1)[-1]


def build_event(
    behavior: Behavior,
    *,
    hostname: str,
    user: str,
    when: datetime,
    marker: str,
    process_id: int = 4242,
    parent_process_id: int = 668,
) -> dict[str, Any]:
    """Build one Sysmon-shaped JSON event for a behavior.

    The output deliberately mirrors NXLog/Winlogbeat Sysmon JSON so it matches
    Exabeam's bundled parser rather than falling through to a generic JSON
    parser (which would leave process_name unpopulated).

    ``marker`` is written into RuleName so simulated events remain
    distinguishable from real telemetry in a shared tenant.
    """
    utc = when.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")
    return {
        "EventTime": utc,
        "Hostname": hostname,
        "EventType": "INFO",
        "Severity": "INFO",
        "SeverityValue": 2,
        "EventID": 1,
        "SourceName": _SYSMON_PROVIDER,
        "ProviderGuid": _SYSMON_GUID,
        "Version": 5,
        "Task": 1,
        "OpcodeValue": 0,
        "Opcode": "Info",
        "Channel": _SYSMON_CHANNEL,
        "Category": "Process Create (rule: ProcessCreate)",
        # "Process Create:" is a required parser condition.
        "Message": f"Process Create:\nRuleName: {marker}",
        "RuleName": marker,
        "UtcTime": utc,
        "ProcessGuid": f"{{{behavior.key}-{process_id}}}",
        "ProcessID": process_id,
        "ProcessId": str(process_id),
        "Image": behavior.image,
        "FileVersion": "10.0.19041.1",
        "Description": behavior.title,
        "Product": "Microsoft Windows Operating System",
        "Company": "Microsoft Corporation",
        "OriginalFileName": _basename(behavior.image),
        "CommandLine": behavior.command_line,
        "CurrentDirectory": "C:\\Windows\\system32\\",
        "User": user,
        "LogonGuid": f"{{logon-{hostname}}}",
        "LogonId": "0x3e7",
        "TerminalSessionId": 1,
        "IntegrityLevel": "High",
        "Hashes": (
            "MD5=9F914D42706FE215501044ACD85A32D5,"
            "SHA256=8A0A29438052FAED8A2532DA50455756"
            "C1C0A9B1E2E8B8C0A2A02C4C63C0AC7E"
        ),
        # "ParentProcessId": is a required parser condition, string-valued.
        "ParentProcessId": str(parent_process_id),
        "ParentProcessGuid": f"{{parent-{parent_process_id}}}",
        "ParentImage": behavior.parent_image,
        "ParentCommandLine": f'"{behavior.parent_image}"',
        "ParentUser": user,
    }


def build_events(
    scenario: str | None = None,
    *,
    behavior_key: str | None = None,
    hostname: str = "SIM-CLINICAL-01",
    # Verified 2026-07-31 on sademodev22: webhook-ingested Sysmon JSON lands
    # with `user` and `process_name` empty regardless of format (tested
    # DOMAIN\user and bare user; path, basename and forward-slash Image).
    # parent_process_name extracts from an identical regex, so this is a
    # platform-side extraction gap, not a payload shape problem. Entity
    # attribution therefore comes from `host`, and rules must match the binary
    # via process_command_line. Kept in the realistic DOMAIN\user form.
    user: str = "HOSPITAL\\svc_imaging",
    marker: str = "EXA-SIMULATION",
    start: datetime | None = None,
    spacing_seconds: int = 90,
) -> list[dict[str, Any]]:
    """Build the event list for a scenario, or a single behavior.

    Events are spaced backwards from ``start`` (default: now) so the chain
    reads as a progression rather than a burst, which is what the multi-stage
    correlation logic in the packs expects.
    """
    if behavior_key is not None:
        matches = [b for b in list_behaviors(scenario) if b.key == behavior_key]
        if not matches:
            valid = ", ".join(b.key for b in list_behaviors(scenario))
            raise ValueError(
                f"Unknown behavior '{behavior_key}'. Valid: {valid}"
            )
        behaviors = matches
    elif scenario is not None:
        behaviors = list(get_scenario(scenario).behaviors)
    else:
        behaviors = list_behaviors()

    base = start or datetime.now(UTC)
    total = len(behaviors)
    events: list[dict[str, Any]] = []
    for i, behavior in enumerate(behaviors):
        when = base - timedelta(seconds=spacing_seconds * (total - 1 - i))
        events.append(
            build_event(
                behavior,
                hostname=hostname,
                user=user,
                when=when,
                marker=marker,
                process_id=4242 + i,
            )
        )
    return events
