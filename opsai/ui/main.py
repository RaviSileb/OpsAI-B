"""NiceGUI pages: overview, session workplace, analysis, audit, admin."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import secrets
import socket
import sqlite3
from typing import Any

from nicegui import app as nicegui_app
from nicegui import ui

from opsai.api.main import (
    ApiDeps,
    _deep_depseudonymize,
    build_api_router,
    create_deps,
    register_exception_handlers,
)
from opsai.app.bootstrap import get_app_db_path
from opsai.app.config import Settings
from opsai.auth.rbac import Role
from opsai.connectors.base import ConnectionProfile, ReadQuery
from opsai.connectors.file import FileConnector, to_log_record
from opsai.core.patterns import compute_templates
from opsai.core.policy import ExecutionPolicy
from opsai.core.query import OQLSyntaxError
from opsai.core.risk import check_policy, combine_risk
from opsai.db.models import HostRecord
from opsai.execution.engine import ApprovalRequiredError, ExecutionError, TargetRequiredError
from opsai.i18n.catalog import t
from opsai.masking.engine import build_payload
from opsai.providers.base import LLMMessage, LLMRequest
from opsai.providers.mock_provider import MockProvider
from opsai.providers.schema import validate_analysis

UI_STATE: dict[str, Any] = {"lang": "cs"}


def _tr(key: str) -> str:
    return t(UI_STATE["lang"], key)


def _query_param(name: str) -> str:
    client = ui.context.client
    if client is None or client.request is None:
        return ""
    return str(client.request.query_params.get(name, ""))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _has_webview() -> bool:
    return importlib.util.find_spec("webview") is not None


def _header(deps: ApiDeps) -> None:
    with ui.header().classes("items-center"):
        ui.label(f"{_tr('app_name')} — {_tr('app_subtitle')}").classes("font-bold")
        ui.space()
        ui.select(
            {"cs": "Čeština", "en": "English"},
            value=UI_STATE["lang"],
            label=_tr("language"),
            on_change=_on_language,
        ).classes("w-36")
        ui.button(_tr("nav_overview"), on_click=lambda: ui.navigate.to("/")).props("flat")
        ui.button(_tr("nav_execution"), on_click=lambda: ui.navigate.to("/execution")).props("flat")
        ui.button(_tr("nav_audit"), on_click=lambda: ui.navigate.to("/audit")).props("flat")
        ui.button(_tr("nav_admin"), on_click=lambda: ui.navigate.to("/admin")).props("flat")
    if not deps.settings.ai_live:
        ui.notify(_tr("offline_banner"), type="warning", close_button=True)


def _on_language(event: Any) -> None:
    UI_STATE["lang"] = str(event.value)
    ui.navigate.reload()


def build_ui(deps: ApiDeps) -> None:  # noqa: C901 - declarative page table
    """Register API router and pages on the NiceGUI app."""
    UI_STATE["lang"] = deps.settings.language
    nicegui_app.state.settings = deps.settings
    nicegui_app.state.deps = deps
    nicegui_app.include_router(build_api_router(deps))
    register_exception_handlers(nicegui_app)

    @ui.page("/")
    def overview_page() -> None:
        _header(deps)
        ui.label(_tr("sessions")).classes("text-2xl font-bold")
        with ui.row().classes("items-end gap-2"):
            name_input = ui.input(label=_tr("session_name"), value="Incident 1").classes("w-64")

            def create_session() -> None:
                deps.sessions.create_session(name_input.value or "Incident")
                ui.navigate.reload()

            ui.button(_tr("create"), on_click=create_session)
        sessions = deps.sessions.list_sessions()
        columns = [
            {"name": "name", "label": _tr("session_name"), "field": "name", "align": "left"},
            {"name": "records", "label": _tr("records"), "field": "record_count"},
            {"name": "status", "label": _tr("status"), "field": "status"},
        ]
        table = ui.table(columns=columns, rows=sessions, row_key="id", selection="single").classes(
            "w-full"
        )

        def selected_id() -> str | None:
            if not table.selected:
                return None
            return str(table.selected[0]["id"])

        with ui.row():
            ui.button(
                _tr("open"),
                on_click=lambda: (
                    ui.navigate.to(f"/session/{selected_id()}") if selected_id() else None
                ),
            )
            ui.button(_tr("delete"), color="negative", on_click=lambda: confirm_remove())

        def _delete(session_id: str) -> None:
            deps.sessions.delete_session(session_id)
            ui.navigate.reload()

        def confirm_remove() -> None:
            session_id = selected_id()
            if not session_id:
                return

            def do_delete() -> None:
                assert session_id is not None
                _delete(session_id)

            with ui.dialog() as dialog, ui.card():
                ui.label(_tr("confirm_delete"))
                with ui.row():
                    ui.button(_tr("cancel"), on_click=dialog.close)
                    ui.button(_tr("yes_delete"), color="negative", on_click=do_delete)
            dialog.open()

    @ui.page("/session/{session_id}")
    def session_page(session_id: str) -> None:
        _header(deps)
        sessions = {s["id"]: s for s in deps.sessions.list_sessions()}
        session = sessions.get(session_id)
        if session is None:
            ui.label(f"Session {session_id} not found")
            return
        ui.label(f"{session['name']}").classes("text-2xl font-bold")
        with ui.expansion(_tr("ingest_file"), icon="upload").classes("w-full"):
            with ui.row().classes("items-end gap-2"):
                path_input = ui.input(label=_tr("file_path"), value="").classes("w-96")
                status_label = ui.label("")

                async def ingest() -> None:
                    added = await _ingest_file(deps, session_id, path_input.value)
                    status_label.text = f"+{added}"
                    ui.navigate.reload()

                ui.button(_tr("load"), on_click=ingest)
            ui.label("").bind_text_from(status_label, "text")
        with ui.row().classes("items-end gap-2 w-full"):
            oql_input = ui.input(label=_tr("search_oql"), value="").classes("grow")

            def search() -> None:
                if oql_input.value.strip():
                    try:
                        deps.queries.record_history("", oql_input.value)
                    except ValueError:
                        pass  # invalid OQL surfaces below via query_records
                ui.navigate.to(f"/session/{session_id}?oql={oql_input.value}")

            ui.button(_tr("search"), on_click=search)
        with ui.row().classes("items-end gap-2 w-full"):
            saved_options = {"": _tr("oql_pick")}
            for saved in deps.queries.list_saved(""):
                saved_options[saved.oql] = f"{saved.name} — {saved.oql[:60]}"
            ui.select(
                saved_options,
                label=_tr("oql_saved"),
                on_change=lambda e: (
                    ui.navigate.to(f"/session/{session_id}?oql={e.value}") if e.value else None
                ),
            ).classes("w-96")
            history_options = {"": _tr("oql_pick")}
            for entry in deps.queries.history(""):
                history_options[entry.oql] = entry.oql[:80]
            ui.select(
                history_options,
                label=_tr("oql_history"),
                on_change=lambda e: (
                    ui.navigate.to(f"/session/{session_id}?oql={e.value}") if e.value else None
                ),
            ).classes("w-96")
            name_input = ui.input(label=_tr("oql_name"), value="").classes("w-64")

            def save_query() -> None:
                try:
                    deps.queries.save("", name_input.value, oql_input.value)
                except ValueError as exc:
                    ui.notify(str(exc), type="negative")
                    return
                ui.notify(_tr("oql_saved_ok"), type="positive")
                ui.navigate.reload()

            ui.button(_tr("oql_save"), on_click=save_query)
        oql = _query_param("oql")
        try:
            page = deps.sessions.query_records(session_id, oql=oql, limit=200, cursor=0)
            stats = deps.sessions.stats(session_id, oql=oql)
        except OQLSyntaxError as exc:
            ui.label(str(exc)).classes("text-red-600")
            return
        with ui.row().classes("gap-4"):
            ui.label(f"{_tr('records')}: {page['total']}").classes("font-bold")
            for level, count in sorted(stats["by_level"].items()):
                ui.badge(f"L{level}: {count}")
        if stats["by_level"]:
            pie_data = [
                {"name": f"level {level}", "value": count}
                for level, count in sorted(stats["by_level"].items())
            ]
            ui.echart({"series": [{"type": "pie", "data": pie_data}]}).classes("w-96 h-64")
        rows = [
            {
                "rid": r["rid"],
                "ts": str(r["ts"])[:23],
                "level": r["level"],
                "host": r["origin_host"] or "",
                "service": r["service"] or "",
                "message": (r["message"] or "")[:200],
            }
            for r in page["items"]
        ]
        ui.table(
            columns=[
                {"name": "rid", "label": "rid", "field": "rid"},
                {"name": "ts", "label": "ts", "field": "ts", "align": "left"},
                {"name": "level", "label": "level", "field": "level"},
                {"name": "host", "label": "host", "field": "host", "align": "left"},
                {"name": "service", "label": "service", "field": "service", "align": "left"},
                {"name": "message", "label": "message", "field": "message", "align": "left"},
            ],
            rows=rows,
            row_key="rid",
        ).classes("w-full")
        with ui.expansion("Templates", icon="pattern").classes("w-full"):
            templates = compute_templates([str(r["message"]) for r in page["items"]])
            ui.table(
                columns=[
                    {"name": "template", "label": "template", "field": "template", "align": "left"},
                    {"name": "count", "label": "count", "field": "count"},
                ],
                rows=[{"template": t.template[:160], "count": t.count} for t in templates[:20]],
            ).classes("w-full")
        ui.button(
            _tr("nav_analysis"),
            on_click=lambda: ui.navigate.to(f"/analysis?session_id={session_id}"),
        )

    @ui.page("/analysis")
    def analysis_page() -> None:
        _header(deps)
        ui.label(_tr("nav_analysis")).classes("text-2xl font-bold")
        default_session = _query_param("session_id")
        sessions = deps.sessions.list_sessions()
        options = {s["id"]: s["name"] for s in sessions}
        session_select = ui.select(
            options, value=default_session or None, label=_tr("nav_session")
        ).classes("w-96")
        oql_input = ui.input(label=_tr("search_oql"), value="level>=ERROR").classes("w-96")
        mode_select = ui.select(
            ["full", "messages", "patterns"], value="full", label=_tr("payload_mode")
        )
        preview_area = ui.textarea(label=_tr("masked_preview")).classes("w-full h-64")
        info_label = ui.label("")
        result_md = ui.markdown("")

        def preview() -> None:
            if not session_select.value:
                ui.notify("No session", type="negative")
                return
            try:
                page = deps.sessions.query_records(
                    str(session_select.value), oql=oql_input.value, limit=200, cursor=0
                )
            except OQLSyntaxError as exc:
                ui.notify(str(exc), type="negative")
                return
            if not page["items"]:
                ui.notify(_tr("no_records"), type="warning")
                return
            text, _meta = build_payload(page["items"], str(mode_select.value))
            engine = deps.engine_for(str(session_select.value))
            masked = engine.mask_text(text)
            sha = hashlib.sha256(masked.masked.encode("utf-8")).hexdigest()
            preview_area.value = masked.masked[:20000]
            tokens = MockProvider().estimate_tokens(masked.masked)
            info_label.text = (
                f"{_tr('masking_counts')}: {masked.counts} | "
                f"{_tr('estimate')}: {tokens} {_tr('tokens')} | sha256:{sha[:16]}…"
            )
            UI_STATE["last_preview"] = masked.masked

        async def analyze() -> None:
            if not session_select.value or "last_preview" not in UI_STATE:
                ui.notify("Preview first", type="warning")
                return
            engine = deps.engine_for(str(session_select.value))
            masked_text = UI_STATE["last_preview"]
            provider = MockProvider()
            request = LLMRequest(
                system="mock",
                messages=[LLMMessage(role="user", content=masked_text)],
            )
            response = provider.generate(request, "mock-analysis-v1")
            errors = validate_analysis(response.data)
            if errors:
                ui.notify("; ".join(errors), type="negative")
                return
            assert isinstance(response.data, dict)
            display, unknown = _deep_depseudonymize(
                response.data, engine.pseudonyms.as_dict(), engine
            )
            for step in display.get("remediation_plan", {}).get("steps", []):
                combined = combine_risk(
                    str(step.get("risk", "change")), str(step.get("command", ""))
                )
                step["risk"] = combined
                allowed, reason = check_policy(str(step.get("command", "")))
                step["policy_allowed"] = allowed
                if not allowed:
                    step["policy_reason"] = reason
            lines = [f"## {display.get('summary', '')}", ""]
            for hyp in display.get("hypotheses", []):
                lines.append(
                    f"- **{hyp.get('cause')}** "
                    f"({hyp.get('confidence_label')}, {hyp.get('confidence')})"
                )
            lines.append("")
            for step in display.get("remediation_plan", {}).get("steps", []):
                lines.append(f"### {step.get('order')}. {step.get('title')} [{step.get('risk')}]")
                lines.append(f"```{step.get('shell')}\n{step.get('command')}\n```")
            if unknown:
                lines.append(f"Unknown tokens: {unknown}")
            result_md.content = "\n".join(lines)
            deps.audit.append(
                "ai.dispatch",
                actor=Role.ANALYST.value,
                object_type="analysis",
                object_id="ui-mock",
                details={"provider": "mock", "live": False},
            )

        with ui.row():
            ui.button(_tr("preview"), on_click=preview)
            ui.button(_tr("analyze"), on_click=analyze, color="primary")

    @ui.page("/execution")
    def execution_page() -> None:  # noqa: C901 - declarative page
        _header(deps)
        ui.label(_tr("nav_execution")).classes("text-2xl font-bold")
        if not deps.settings.execution_enabled:
            ui.label(_tr("execution_disabled")).classes("text-red-600")
            return
        analyses = _list_analyses(deps)
        if not analyses:
            ui.label(_tr("no_analyses"))
            return
        options = {
            a["id"]: f"{a['created_at'][:16]} {a['provider']}/{a['model']}" for a in analyses
        }
        default_analysis = _query_param("analysis_id") or next(iter(options))
        analysis_select = ui.select(
            options, value=default_analysis, label=_tr("select_analysis")
        ).classes("w-96")
        run_id = _query_param("run_id")

        @ui.refreshable
        def dry_view() -> None:
            dry = UI_STATE.get("dry")
            if not dry:
                return
            ui.table(
                columns=[
                    {"name": "order", "label": "#", "field": "order"},
                    {"name": "title", "label": _tr("step"), "field": "title", "align": "left"},
                    {"name": "target", "label": _tr("target"), "field": "target", "align": "left"},
                    {"name": "env", "label": _tr("environment"), "field": "environment"},
                    {"name": "executor", "label": _tr("executor"), "field": "executor"},
                    {"name": "risk", "label": _tr("risk"), "field": "risk"},
                    {"name": "status", "label": _tr("status"), "field": "status"},
                ],
                rows=dry["steps"],
                row_key="order",
            ).classes("w-full")

        def do_dry() -> None:
            if not analysis_select.value:
                return
            session_id = next(a["session_id"] for a in analyses if a["id"] == analysis_select.value)
            mapping = deps.engine_for(session_id).pseudonyms.as_dict()
            try:
                UI_STATE["dry"] = deps.execution.dry_run(str(analysis_select.value), mapping)
            except ExecutionError as exc:
                ui.notify(str(exc), type="negative")
                return
            dry_view.refresh()

        def do_create(run_all: bool) -> None:
            if not analysis_select.value:
                return
            session_id = next(a["session_id"] for a in analyses if a["id"] == analysis_select.value)
            mapping = deps.engine_for(session_id).pseudonyms.as_dict()
            try:
                run = deps.execution.create_run(
                    str(analysis_select.value), "local", mapping, run_all=run_all
                )
            except ExecutionError as exc:
                ui.notify(str(exc), type="negative")
                return
            ui.navigate.to(f"/execution?analysis_id={analysis_select.value}&run_id={run['id']}")

        with ui.row():
            ui.button(_tr("dry_run"), on_click=do_dry)
            ui.button(_tr("create_run"), on_click=lambda: do_create(False))
            ui.button(_tr("run_all"), on_click=lambda: do_create(True), color="warning")
        dry_view()

        if run_id:
            _run_view(deps, run_id)

    @ui.page("/audit")
    def audit_page() -> None:
        _header(deps)
        ui.label(_tr("audit_events")).classes("text-2xl font-bold")
        result_label = ui.label("")

        def verify() -> None:
            ok, checked = deps.audit.verify()
            result_label.text = f"{_tr('chain_ok') if ok else _tr('chain_broken')} ({checked})"

        ui.button(_tr("verify_chain"), on_click=verify)
        events = deps.audit.list_events(limit=200)
        ui.table(
            columns=[
                {"name": "id", "label": "id", "field": "id"},
                {"name": "ts", "label": "ts", "field": "ts", "align": "left"},
                {"name": "actor", "label": "actor", "field": "actor", "align": "left"},
                {"name": "event_type", "label": "type", "field": "event_type", "align": "left"},
            ],
            rows=events,
            row_key="id",
        ).classes("w-full")

    @ui.page("/admin")
    def admin_page() -> None:
        _header(deps)
        ui.label(_tr("nav_admin")).classes("text-2xl font-bold")
        ui.label(f"{_tr('mode')}: {deps.settings.mode}")
        ui.label(f"execution_enabled: {deps.settings.execution_enabled}")
        ui.label(f"restricted_mode: {deps.settings.restricted_mode}")
        ui.label(f"ai_live: {deps.settings.ai_live}")
        ui.label(f"data_dir: {deps.settings.data_dir}")
        with ui.expansion(_tr("inventory"), icon="dns").classes("w-full"):
            hosts = deps.execution.inventory.list_hosts()
            ui.table(
                columns=[
                    {
                        "name": "hostname",
                        "label": _tr("hostname"),
                        "field": "hostname",
                        "align": "left",
                    },
                    {"name": "environment", "label": _tr("environment"), "field": "environment"},
                    {"name": "executor", "label": _tr("executor"), "field": "executor_type"},
                ],
                rows=[
                    {
                        "hostname": h.hostname,
                        "environment": h.environment,
                        "executor_type": h.executor_type,
                    }
                    for h in hosts
                ],
            ).classes("w-full")
            with ui.row().classes("items-end gap-2"):
                host_input = ui.input(label=_tr("hostname")).classes("w-48")
                env_input = ui.input(label=_tr("environment"), value="test").classes("w-32")

                def add_host() -> None:
                    if not host_input.value:
                        return
                    deps.execution.inventory.add(
                        HostRecord(
                            id="", hostname=host_input.value, environment=env_input.value or "test"
                        )
                    )
                    ui.navigate.reload()

                ui.button(_tr("inventory_add"), on_click=add_host)
        with ui.expansion(_tr("policy"), icon="policy").classes("w-full"):
            policy_text = ui.textarea(
                label=_tr("policy"),
                value=json.dumps(deps.execution.policies.get_execution().to_dict(), indent=2),
            ).classes("w-full h-64")

            def save_policy() -> None:
                try:
                    policy = ExecutionPolicy.from_dict(json.loads(policy_text.value))
                except (ValueError, json.JSONDecodeError) as exc:
                    ui.notify(str(exc), type="negative")
                    return
                deps.execution.policies.save_execution(policy)
                deps.audit.append(
                    "policy.updated",
                    actor="local",
                    object_type="policy",
                    object_id="execution-default",
                    details={"via": "ui"},
                )
                ui.notify("OK", type="positive")

            ui.button(_tr("save_policy"), on_click=save_policy)


async def _ingest_file(deps: ApiDeps, session_id: str, path: str) -> int:
    connector = FileConnector()
    profile = ConnectionProfile(
        id="adhoc", name="adhoc", connector_type="file", config={"path": path}
    )
    added_total = 0
    async for batch in connector.read(profile, ReadQuery()):
        records = [to_log_record(raw, "file", None) for raw in batch.records]
        result = deps.sessions.add_records(session_id, records)
        added_total += int(result["added"])
        if batch.truncated or result["status"] == "TRUNCATED":
            break
    return added_total


def _list_analyses(deps: ApiDeps) -> list[dict[str, Any]]:
    with sqlite3.connect(get_app_db_path(deps.settings)) as conn:
        rows = conn.execute(
            "SELECT id, session_id, provider, model, created_at FROM analyses"
            " ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
    return [
        {"id": r[0], "session_id": r[1], "provider": r[2], "model": r[3], "created_at": r[4]}
        for r in rows
    ]


def _run_view(deps: ApiDeps, run_id: str) -> None:
    try:
        run = deps.execution.get_run(run_id)
    except ExecutionError as exc:
        ui.label(str(exc)).classes("text-red-600")
        return
    ui.separator()
    with ui.row().classes("items-center gap-4"):
        ui.label(f"run {run_id[:8]}… — {run['status']}").classes("text-xl font-bold")
        ui.button(_tr("refresh"), on_click=ui.navigate.reload).props("flat")
    user_input = ui.input(label="user", value="local").classes("w-32")
    table = ui.table(
        columns=[
            {"name": "ord", "label": "#", "field": "ord"},
            {"name": "title", "label": _tr("step"), "field": "title", "align": "left"},
            {"name": "target", "label": _tr("target"), "field": "target", "align": "left"},
            {"name": "risk", "label": _tr("risk"), "field": "risk"},
            {"name": "status", "label": _tr("status"), "field": "status"},
            {"name": "exit", "label": _tr("exit_code"), "field": "exit_code"},
        ],
        rows=run["steps"],
        row_key="ord",
        selection="single",
    ).classes("w-full")

    def selected_order() -> int | None:
        if not table.selected:
            return None
        return int(table.selected[0]["ord"])

    def selected_step() -> dict[str, Any] | None:
        order = selected_order()
        if order is None:
            return None
        return next((s for s in run["steps"] if s["ord"] == order), None)

    command_input = ui.input(label=_tr("command")).classes("w-full")
    reason_input = ui.input(label=_tr("reason")).classes("w-96")

    def refresh_command() -> None:
        step = selected_step()
        command_input.value = step["command_final"] if step else ""

    ui.button(_tr("refresh"), on_click=refresh_command).props("flat")

    def act(fn: Any) -> None:
        order = selected_order()
        if order is None:
            ui.notify("No step selected", type="warning")
            return
        try:
            fn(order)
        except (ApprovalRequiredError, TargetRequiredError) as exc:
            ui.notify(str(exc), type="warning")
            return
        except ExecutionError as exc:
            ui.notify(str(exc), type="negative")
            return
        ui.navigate.reload()

    def act_runwide(fn: Any) -> None:
        try:
            fn()
        except ExecutionError as exc:
            ui.notify(str(exc), type="negative")
            return
        ui.navigate.reload()

    with ui.row():
        ui.button(
            _tr("run_step"),
            on_click=lambda: act(
                lambda o: deps.execution.run_step(
                    run_id, o, user_input.value or "local", command=command_input.value or None
                )
            ),
        )
        ui.button(
            _tr("approve_step"),
            on_click=lambda: act(
                lambda o: deps.execution.approve_step(run_id, o, user_input.value or "local")
            ),
            color="primary",
        )
        ui.button(
            _tr("skip_step"),
            on_click=lambda: act(
                lambda o: deps.execution.skip_step(
                    run_id, o, user_input.value or "local", reason_input.value
                )
            ),
        )
        ui.button(
            _tr("abort_step"),
            on_click=lambda: act(
                lambda o: deps.execution.abort_step(run_id, o, user_input.value or "local")
            ),
            color="negative",
        )
    with ui.row():
        ui.button(
            _tr("run_all"),
            on_click=lambda: act_runwide(
                lambda: deps.execution.run_remaining(run_id, user_input.value or "local")
            ),
        )
        ui.button(
            _tr("start_rollback"),
            on_click=lambda: _start_rollback_ui(deps, run_id, user_input.value or "local"),
        )
        ui.button(
            _tr("abort_run"),
            on_click=lambda: act_runwide(
                lambda: deps.execution.abort_run(run_id, user_input.value or "local")
            ),
            color="negative",
        )
    with ui.expansion(_tr("output"), icon="terminal").classes("w-full"):
        for step in run["steps"]:
            if step["stdout_text"] or step["stderr_text"]:
                ui.label(f"#{step['ord']} {step['title']} (exit {step['exit_code']})").classes(
                    "font-bold"
                )
                ui.code((step["stdout_text"] or "")[:4000]).classes("w-full")


def _start_rollback_ui(deps: ApiDeps, run_id: str, user: str) -> None:
    try:
        rollback = deps.execution.start_rollback(run_id, user)
    except ExecutionError as exc:
        ui.notify(str(exc), type="negative")
        return
    ui.navigate.to(f"/execution?run_id={rollback['id']}")


def run_desktop(settings: Settings) -> None:
    """Run the desktop UI: native window with browser fallback (FR-811)."""
    deps = create_deps(settings)
    build_ui(deps)
    secret = secrets.token_urlsafe(32)
    if _has_webview():
        ui.run(
            host="127.0.0.1",
            port=_free_port(),
            native=True,
            title="OpsAI",
            storage_secret=secret,
            reload=False,
        )
    else:
        ui.run(
            host="127.0.0.1",
            port=_free_port(),
            native=False,
            title="OpsAI",
            storage_secret=secret,
            reload=False,
            show=True,
        )


def run_server_ui(settings: Settings) -> None:
    """Run the server UI + API in one process (Docker form)."""
    deps = create_deps(settings)
    build_ui(deps)
    secret = secrets.token_urlsafe(32)
    ui.run(
        host=settings.host,
        port=settings.port,
        native=False,
        title="OpsAI",
        storage_secret=secret,
        reload=False,
        show=False,
    )
