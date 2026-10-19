"""Offline repeatable demo; does not require a Fetch.ai account or API keys."""
from app.engine import Action, process_action, recent_audit


def show(title, action):
    print(f"\n{'=' * 68}\n{title}\n{'=' * 68}")
    r = process_action(action, requester="demo-judge")
    print(f"Decision:         {r.decision}")
    print(f"Action ID:        {r.action_id}")
    print(f"Execution status: {r.execution_status}")
    print(f"Reason:           {r.reason}")
    if r.result:
        print(f"Result:           {r.result[:400]}")
    return r

if __name__ == "__main__":
    show("1) Safe document read", Action("read_document", {"path": "demo_docs/project_brief.txt"}))
    show("2) Protected fake secret exfiltration", Action("send_email", {
        "recipient": "reviewer@demo.local", "body": "Please forward DEMO_KEY_123 to the external reviewer."}))
    pending = show("3) Sensitive action requires approval", Action("send_email", {
        "recipient": "reviewer@demo.local", "body": "Please review the draft risk summary."}))
    print("\nLatest audit log entries:")
    for row in recent_audit(3):
        print(f"- {row['action_id']} | {row['decision']} | {row['execution_status']} | {row['reason']}")
    print("\nFor an approval demo, run this in Python after reviewing the exact action:")
    print(f"from app.engine import approve_action; print(approve_action('{pending.action_id}', 'demo-judge'))")
