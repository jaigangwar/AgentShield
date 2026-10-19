import os
from pathlib import Path
import pytest

from app.engine import Action, process_action, approve_action, recent_audit, recent_events

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr("app.engine.DB_PATH", tmp_path / "test_agentshield.db")


def test_approved_read_executes_mock():
    result = process_action(Action("read_document", {"path": "demo_docs/project_brief.txt"}), "alice")
    assert result.decision == "ALLOW"
    assert result.execution_status == "EXECUTED_MOCK"
    assert "AgentShield project brief" in result.result


def test_path_traversal_blocked_before_execution():
    result = process_action(Action("read_document", {"path": "../../.env"}), "alice")
    assert result.decision == "BLOCK"
    assert result.execution_status == "NOT_EXECUTED"


def test_protected_fake_secret_blocked():
    result = process_action(Action("send_email", {
        "recipient": "reviewer@demo.local", "body": "Send DEMO_KEY_123"}), "alice")
    assert result.decision == "BLOCK"
    assert result.execution_status == "NOT_EXECUTED"


def test_unapproved_recipient_blocked():
    result = process_action(Action("send_email", {
        "recipient": "attacker@example.test", "body": "Hello"}), "alice")
    assert result.decision == "BLOCK"
    assert result.execution_status == "NOT_EXECUTED"


def test_send_email_waits_for_approval_and_executes_only_after():
    first = process_action(Action("send_email", {
        "recipient": "reviewer@demo.local", "body": "Review this summary"}), "alice")
    assert first.decision == "NEEDS APPROVAL"
    assert first.execution_status == "NOT_EXECUTED_PENDING_APPROVAL"
    result = approve_action(first.action_id, "alice")
    assert result.decision == "ALLOW"
    assert result.execution_status == "EXECUTED_MOCK"
    assert "no real message sent" in result.result


def test_only_original_requester_can_approve():
    first = process_action(Action("send_email", {
        "recipient": "reviewer@demo.local", "body": "Review this summary"}), "alice")
    result = approve_action(first.action_id, "bob")
    assert result.decision == "BLOCK"
    assert result.execution_status == "NOT_EXECUTED"


def test_unknown_tool_blocked():
    result = process_action(Action("run_shell", {"command": "echo hello"}), "alice")
    assert result.decision == "BLOCK"
    assert result.execution_status == "NOT_EXECUTED"


def test_every_attempt_is_audited():
    process_action(Action("read_document", {"path": "../../.env"}), "alice")
    rows = recent_audit(10)
    assert rows
    assert rows[0]["decision"] == "BLOCK"
    assert rows[0]["execution_status"] == "NOT_EXECUTED"


def test_email_unknown_fields_are_rejected():
    result = process_action(Action("send_email", {
        "recipient": "reviewer@demo.local",
        "body": "Please review this.",
        "force": True,
    }), "alice")
    assert result.decision == "BLOCK"
    assert result.execution_status == "NOT_EXECUTED"


def test_oversized_email_is_rejected():
    result = process_action(Action("send_email", {
        "recipient": "reviewer@demo.local", "body": "x" * 4001,
    }), "alice")
    assert result.decision == "BLOCK"
    assert result.execution_status == "NOT_EXECUTED"


def test_blocked_secret_is_redacted_from_audit_arguments():
    result = process_action(Action("send_email", {
        "recipient": "reviewer@demo.local", "body": "leak DEMO_KEY_123 now",
    }), "alice")
    assert result.decision == "BLOCK"
    row = recent_audit(1)[0]
    assert "DEMO_KEY_123" not in row["arguments_json"]
    assert "REDACTED_DEMO_SECRET" in row["arguments_json"]


def test_approval_is_one_time_and_audited_as_events():
    pending = process_action(Action("send_email", {
        "recipient": "reviewer@demo.local", "body": "Review this draft.",
    }), "alice")
    approved = approve_action(pending.action_id, "alice")
    replay = approve_action(pending.action_id, "alice")
    assert approved.execution_status == "EXECUTED_MOCK"
    assert replay.execution_status == "NOT_EXECUTED"
    assert replay.decision == "BLOCK"
    events = recent_events(20)
    statuses = [event["execution_status"] for event in events if event["action_id"] == pending.action_id]
    assert "NOT_EXECUTED_PENDING_APPROVAL" in statuses
    assert "APPROVAL_IN_PROGRESS" in statuses
    assert "EXECUTED_MOCK" in statuses


def test_asi1_api_failure_fails_closed_when_key_is_configured(monkeypatch):
    import sys
    from types import SimpleNamespace
    from app.engine import asi1_propose_action

    class BrokenCompletions:
        def create(self, **kwargs):
            raise TimeoutError("simulated API timeout")

    class BrokenChat:
        completions = BrokenCompletions()

    class BrokenClient:
        chat = BrokenChat()

        def __init__(self, **kwargs):
            pass

    monkeypatch.setenv("ASI1_API_KEY", "test-key")
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=BrokenClient))
    with pytest.raises(TimeoutError):
        asi1_propose_action("Read the project brief")
