"""Help-output tests for every registered CLI command.

Uses typer.testing.CliRunner — no API calls, no keyring, no network.
All tests must pass in a clean environment with no tenant configured.
xfail marks commands that are defined in the spec but not yet implemented.
"""

from __future__ import annotations

import re

from typer.testing import CliRunner

from exa.cli.app import app

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


class _PlainRunner(CliRunner):
    """CliRunner that strips ANSI colour from help output.

    typer/rich force colour whenever ``GITHUB_ACTIONS`` or ``FORCE_COLOR`` is set
    (i.e. GitHub Actions, and this dev environment). Rich's highlighter then
    emits the option name ``--check`` as
    ``\\x1b[1;36m-\\x1b[0m\\x1b[1;36m-check\\x1b[0m`` -- the escape codes fragment
    the token, so a plain ``'--check' in result.output`` fails even though the
    flag is present. Stripping ANSI before the substring assertions makes these
    tests robust to colour, width, and TTY state everywhere.
    """

    def invoke(self, *args, **kwargs):
        result = super().invoke(*args, **kwargs)
        # click >=8.2 exposes .output via output_bytes (mixed stdout+stderr);
        # older versions proxy it through stdout_bytes. Strip ANSI from every
        # byte stream the assertions might read.
        for attr in ("output_bytes", "stdout_bytes", "stderr_bytes"):
            raw = getattr(result, attr, None)
            if raw:
                plain = _ANSI.sub("", raw.decode("utf-8", "replace"))
                setattr(result, attr, plain.encode("utf-8"))
        return result


runner = _PlainRunner()


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------


def test_root_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "configure" in result.output
    assert "update" in result.output
    assert "tables" in result.output
    assert "hotkey" in result.output
    assert "search" in result.output


# ---------------------------------------------------------------------------
# auth
# ---------------------------------------------------------------------------


def test_auth_help():
    result = runner.invoke(app, ["auth", "--help"])
    assert result.exit_code == 0
    assert "--tenant" in result.output
    assert "--collector" in result.output
    assert "--list-collectors" in result.output
    assert "--format" in result.output


# ---------------------------------------------------------------------------
# configure
# ---------------------------------------------------------------------------


def test_configure_help():
    result = runner.invoke(app, ["configure", "--help"])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------


def test_update_help():
    result = runner.invoke(app, ["update", "--help"])
    assert result.exit_code == 0
    assert "self" in result.output
    assert "--check" in result.output


def test_update_self_help():
    result = runner.invoke(app, ["update", "self", "--help"])
    assert result.exit_code == 0
    assert "--branch" in result.output


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def test_config_help():
    result = runner.invoke(app, ["config", "--help"])
    assert result.exit_code == 0
    assert "set" in result.output
    assert "get" in result.output
    assert "show" in result.output


# ---------------------------------------------------------------------------
# tables
# ---------------------------------------------------------------------------


def test_tables_help():
    result = runner.invoke(app, ["tables", "--help"])
    assert result.exit_code == 0
    assert "list" in result.output
    assert "create" in result.output
    assert "delete" in result.output
    assert "records" in result.output


def test_tables_list_help():
    result = runner.invoke(app, ["tables", "list", "--help"])
    assert result.exit_code == 0
    assert "--name" in result.output
    assert "--tenant" in result.output
    assert "--json" in result.output


def test_tables_create_help():
    result = runner.invoke(app, ["tables", "create", "--help"])
    assert result.exit_code == 0
    assert "--type" in result.output
    assert "--key" in result.output
    assert "--csv" in result.output
    assert "--replace" in result.output


def test_tables_delete_help():
    result = runner.invoke(app, ["tables", "delete", "--help"])
    assert result.exit_code == 0
    assert "--yes" in result.output
    assert "--purge-attributes" in result.output


def test_tables_records_help():
    result = runner.invoke(app, ["tables", "records", "--help"])
    assert result.exit_code == 0
    assert "list" in result.output
    assert "upload" in result.output
    assert "export" in result.output


def test_tables_records_list_help():
    result = runner.invoke(app, ["tables", "records", "list", "--help"])
    assert result.exit_code == 0
    assert "--limit" in result.output
    assert "--offset" in result.output
    assert "--json" in result.output


def test_tables_records_upload_help():
    result = runner.invoke(app, ["tables", "records", "upload", "--help"])
    assert result.exit_code == 0
    assert "--replace" in result.output
    assert "--key" in result.output


def test_tables_records_export_help():
    result = runner.invoke(app, ["tables", "records", "export", "--help"])
    assert result.exit_code == 0
    assert "--tenant" in result.output


# ---------------------------------------------------------------------------
# sigma
# ---------------------------------------------------------------------------


def test_sigma_help():
    result = runner.invoke(app, ["sigma", "--help"])
    assert result.exit_code == 0
    assert "convert" in result.output
    assert "deploy" in result.output
    assert "browse" in result.output


def test_sigma_convert_help():
    result = runner.invoke(app, ["sigma", "convert", "--help"])
    assert result.exit_code == 0
    assert "--rule" in result.output
    assert "--dir" in result.output
    assert "--deploy" in result.output


def test_sigma_deploy_help():
    result = runner.invoke(app, ["sigma", "deploy", "--help"])
    assert result.exit_code == 0
    assert "--rule" in result.output
    assert "--tenant" in result.output


def test_sigma_browse_help():
    result = runner.invoke(app, ["sigma", "browse", "--help"])
    assert result.exit_code == 0
    assert "--category" in result.output
    assert "--tag" in result.output
    assert "--search" in result.output


# ---------------------------------------------------------------------------
# splunk
# ---------------------------------------------------------------------------


def test_splunk_help():
    result = runner.invoke(app, ["splunk", "--help"])
    assert result.exit_code == 0
    assert "convert" in result.output
    assert "one" in result.output
    assert "deploy" in result.output


def test_splunk_convert_help():
    result = runner.invoke(app, ["splunk", "convert", "--help"])
    assert result.exit_code == 0
    assert "--verbose" in result.output
    assert "--output" in result.output


def test_splunk_one_help():
    result = runner.invoke(app, ["splunk", "one", "--help"])
    assert result.exit_code == 0
    assert "--title" in result.output
    assert "--json" in result.output


def test_splunk_deploy_help():
    result = runner.invoke(app, ["splunk", "deploy", "--help"])
    assert result.exit_code == 0
    assert "--dry-run" in result.output
    assert "--tenant" in result.output


# ---------------------------------------------------------------------------
# compliance
# ---------------------------------------------------------------------------


def test_compliance_help():
    result = runner.invoke(app, ["compliance", "--help"])
    assert result.exit_code == 0
    assert "audit" in result.output
    assert "sync-ootb" in result.output


def test_compliance_audit_help():
    result = runner.invoke(app, ["compliance", "audit", "--help"])
    assert result.exit_code == 0
    assert "--framework" in result.output
    assert "--lookback" in result.output
    assert "--output-html" in result.output


# ---------------------------------------------------------------------------
# cases / alerts
# ---------------------------------------------------------------------------


def test_cases_help():
    result = runner.invoke(app, ["cases", "--help"])
    assert result.exit_code == 0
    assert "list" in result.output
    assert "get" in result.output
    assert "update" in result.output


def test_alerts_help():
    result = runner.invoke(app, ["alerts", "--help"])
    assert result.exit_code == 0
    assert "list" in result.output
    assert "get" in result.output
    assert "update" in result.output


# ---------------------------------------------------------------------------
# case
# ---------------------------------------------------------------------------


def test_case_help():
    result = runner.invoke(app, ["case", "--help"])
    assert result.exit_code == 0
    assert "qualify" in result.output
    assert "outcome" in result.output
    assert "baseline" in result.output


def test_case_qualify_help():
    result = runner.invoke(app, ["case", "qualify", "--help"])
    assert result.exit_code == 0
    assert "--window" in result.output


def test_case_outcome_help():
    result = runner.invoke(app, ["case", "outcome", "--help"])
    assert result.exit_code == 0
    assert "list" in result.output
    assert "resolve" in result.output
    assert "sync" in result.output


def test_case_baseline_help():
    result = runner.invoke(app, ["case", "baseline", "--help"])
    assert result.exit_code == 0
    assert "--lookback" in result.output
    assert "--json" in result.output


# ---------------------------------------------------------------------------
# detection
# ---------------------------------------------------------------------------


def test_detection_help():
    result = runner.invoke(app, ["detection", "--help"])
    assert result.exit_code == 0
    assert "list" in result.output
    assert "export" in result.output
    assert "import" in result.output
    assert "diff" in result.output
    assert "snapshot" in result.output


def test_detection_snapshot_help():
    result = runner.invoke(app, ["detection", "snapshot", "--help"])
    assert result.exit_code == 0
    assert "--tenant" in result.output


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------


def test_search_help():
    result = runner.invoke(app, ["search", "--help"])
    assert result.exit_code == 0
    assert "--lookback" in result.output
    assert "--limit" in result.output
    assert "--tenant" in result.output


# ---------------------------------------------------------------------------
# hotkey
# ---------------------------------------------------------------------------


def test_hotkey_help():
    result = runner.invoke(app, ["hotkey", "--help"])
    assert result.exit_code == 0
    assert "analyze" in result.output
    assert "scan" in result.output
    assert "expand" in result.output
    assert "rollback" in result.output
    assert "autofix" in result.output


def test_hotkey_analyze_help():
    result = runner.invoke(app, ["hotkey", "analyze", "--help"])
    assert result.exit_code == 0
    assert "--ip-field" in result.output
    assert "--name-field" in result.output
    assert "--json" in result.output


def test_hotkey_scan_help():
    result = runner.invoke(app, ["hotkey", "scan", "--help"])
    assert result.exit_code == 0
    assert "--lookback" in result.output
    assert "--threshold" in result.output
    assert "--limit" in result.output


def test_hotkey_expand_help():
    result = runner.invoke(app, ["hotkey", "expand", "--help"])
    assert result.exit_code == 0
    assert "--zone" in result.output
    assert "--dry-run" in result.output
    assert "--enumerate" in result.output


def test_hotkey_autofix_help():
    result = runner.invoke(app, ["hotkey", "autofix", "--help"])
    assert result.exit_code == 0
    assert "--max-zones" in result.output
    assert "--dry-run" in result.output
    assert "--json" in result.output


def test_hotkey_rollback_help():
    result = runner.invoke(app, ["hotkey", "rollback", "--help"])
    assert result.exit_code == 0
    assert "--manifest" in result.output
    assert "--confirm" in result.output


# ---------------------------------------------------------------------------
# aillm / frameworks
# ---------------------------------------------------------------------------


def test_aillm_help():
    result = runner.invoke(app, ["aillm", "--help"])
    assert result.exit_code == 0


def test_frameworks_help():
    result = runner.invoke(app, ["frameworks", "--help"])
    assert result.exit_code == 0


def test_aillm_cycle_help():
    result = runner.invoke(app, ["aillm", "cycle", "--help"])
    assert result.exit_code == 0
    assert "--iterations" in result.output
    assert "--from-empty" in result.output
    assert "--tenant" in result.output


def test_aillm_report_help():
    result = runner.invoke(app, ["aillm", "report", "--help"])
    assert result.exit_code == 0
    assert "--format" in result.output
    assert "--lookback" in result.output
    assert "--tenant" in result.output


# ---------------------------------------------------------------------------
# assess (OOTB context-table auto-populator + classifier benchmark)
# ---------------------------------------------------------------------------


def test_assess_help():
    result = runner.invoke(app, ["assess", "--help"])
    assert result.exit_code == 0
    assert "benchmark" in result.output
    assert "--dashboards" in result.output
    assert "--apply" in result.output
    assert "--promote" in result.output
    assert "--tenant" in result.output


def test_assess_benchmark_help():
    result = runner.invoke(app, ["assess", "benchmark", "--help"])
    assert result.exit_code == 0
    assert "--golden" in result.output
    assert "--model" in result.output
    assert "--fail-under-precision" in result.output
    assert "--fail-under-pii-recall" in result.output


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------


def test_dashboard_help():
    result = runner.invoke(app, ["dashboard", "--help"])
    assert result.exit_code == 0
    assert "preview" in result.output


def test_dashboard_preview_help():
    result = runner.invoke(app, ["dashboard", "preview", "--help"])
    assert result.exit_code == 0
    assert "--format" in result.output
    assert "--scrub" in result.output
    assert "--tenant" in result.output


# ---------------------------------------------------------------------------
# simulate
# ---------------------------------------------------------------------------


def test_simulate_help():
    result = runner.invoke(app, ["simulate", "--help"])
    assert result.exit_code == 0
    assert "timing" in result.output


def test_simulate_timing_help():
    result = runner.invoke(app, ["simulate", "timing", "--help"])
    assert result.exit_code == 0
    assert "--scenario" in result.output
    assert "--deadline" in result.output
    assert "--tenant" in result.output


# ---------------------------------------------------------------------------
# Discoverability contract -- applies to every command, including future ones
# ---------------------------------------------------------------------------


def _walk_commands(typer_app, prefix="exa"):
    """Yield (invocation, callback) for every command, including sub-groups."""
    for cmd in typer_app.registered_commands:
        name = cmd.name or (cmd.callback.__name__ if cmd.callback else "")
        yield f"{prefix} {name}", cmd.callback
    for group in typer_app.registered_groups:
        inner = group.typer_instance
        if inner is None or not isinstance(inner.info.name, str):
            continue
        yield from _walk_commands(inner, f"{prefix} {inner.info.name}")


# Commands that genuinely do not need examples: no options, no arguments, and a
# single obvious behaviour. Keep this list SHORT -- if you are adding to it,
# the command probably does need an example.
_NO_EXAMPLES_NEEDED = {
    "exa version",       # prints a version string, takes nothing
    "exa configure",     # fully interactive prompt flow, carries a Related: block
    "exa dev connect",   # no options; reads two env vars
    "exa commands",      # its own output is the example
}


def test_every_command_shows_examples():
    """Every command must carry an `Examples:` block in its help.

    A group listing shows one line per command, which is rarely enough to know
    how to invoke it. Real sessions have been lost to guesses like
    `exa auth -t list`, `exa config --tenants` and `exa config -t` -- all
    reasonable, all wrong, and all avoidable if the help had shown a worked
    invocation.

    This is a contract for NEW commands as much as existing ones: adding a
    command without examples fails here.
    """
    missing = []
    for name, callback in _walk_commands(app):
        if name in _NO_EXAMPLES_NEEDED or callback is None:
            continue
        doc = callback.__doc__ or ""
        if "Examples:" not in doc:
            missing.append(name)
    assert not missing, (
        "These commands have no `Examples:` block in their docstring:\n  "
        + "\n  ".join(sorted(missing))
        + "\n\nAdd one using the \b escape so Typer preserves the line breaks:\n"
        '    """One-line summary.\n\n'
        "    \b\n"
        "    Examples:\n"
        "      exa thing do --flag value\n"
        '    """'
    )


def test_commands_command_finds_subcommands_by_keyword():
    """`exa commands <word>` must reach commands buried in groups.

    `exa --help` lists groups only, so a command whose group you cannot guess is
    unreachable from the top. This is the escape hatch; if it stops finding
    subcommands, discovery is broken again.
    """
    result = runner.invoke(app, ["commands", "tenant"])
    assert result.exit_code == 0
    assert "exa config tenants" in result.output, (
        "searching 'tenant' must surface `exa config tenants` -- the exact "
        "command real sessions failed to find"
    )


def test_commands_command_lists_more_than_the_root_help():
    """The flat list must be substantially larger than the group list."""
    flat = runner.invoke(app, ["commands"])
    root = runner.invoke(app, ["--help"])
    assert flat.exit_code == 0 and root.exit_code == 0
    flat_count = sum(1 for line in flat.output.splitlines() if line.strip().startswith("exa "))
    assert flat_count > 60, f"expected the flat list to cover the whole surface, got {flat_count}"
