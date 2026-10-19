"""ASI:One-compatible AgentShield entry agent using Fetch.ai's chat protocol.

Official protocol example: https://uagents.fetch.ai/docs/examples/asi-1
All tool actions are sandboxed and must pass through app.engine policy checks.
"""
from __future__ import annotations
import os
import re
from dotenv import load_dotenv

load_dotenv()
from datetime import datetime, timezone
from uuid import uuid4

from uagents import Agent, Context, Protocol
from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement, ChatMessage, EndSessionContent, TextContent, chat_protocol_spec,
)

from app.engine import Action, approve_action, asi1_propose_action, process_action

agent_seed = os.getenv("AGENTSHIELD_AGENT_SEED", "").strip()
if len(agent_seed) < 32 or agent_seed.startswith("CHANGE-ME"):
    raise SystemExit(
        "Set AGENTSHIELD_AGENT_SEED to a unique random value of at least 32 characters "
        "in your private .env before starting the hosted agent. Never publish that seed."
    )

agent = Agent(
    name="AgentShield Security Gateway",
    seed=agent_seed,
    port=int(os.getenv("AGENTSHIELD_PORT", "8001")),
    mailbox=True,
    publish_agent_details=True,
)
protocol = Protocol(spec=chat_protocol_spec)


def _format_result(result) -> str:
    lines = [
        f"AgentShield decision: {result.decision}",
        f"Action ID: {result.action_id}",
        f"Tool: {result.tool}",
        f"Execution status: {result.execution_status}",
        f"Reason: {result.reason}",
    ]
    if result.execution_status == "NOT_EXECUTED_PENDING_APPROVAL":
        lines.append(f"To approve this exact pending action, reply: APPROVE {result.action_id}")
    if result.result:
        # Never echo simulated outgoing message content or secrets in the result.
        lines.append("Result: " + result.result[:2500])
    lines.append("Note: email is simulated; this MVP never sends real email.")
    return "\n".join(lines)


@protocol.on_message(ChatMessage)
async def handle_message(ctx: Context, sender: str, msg: ChatMessage):
    await ctx.send(sender, ChatAcknowledgement(
        timestamp=datetime.now(timezone.utc), acknowledged_msg_id=msg.msg_id,
    ))
    text = "\n".join(item.text for item in msg.content if isinstance(item, TextContent)).strip()
    if not text:
        response = "Please describe a document-read or mock email task."
    else:
        try:
            approval_match = re.fullmatch(r"(?i)\s*approve\s+([a-f0-9-]{4,40})\s*", text)
            if approval_match:
                result = approve_action(approval_match.group(1), sender)
            else:
                action = asi1_propose_action(text)
                result = process_action(action, requester=sender)
            response = _format_result(result)
            ctx.logger.info("Action %s: %s / %s", result.action_id, result.decision, result.execution_status)
        except Exception:
            ctx.logger.exception("AgentShield request failed closed")
            response = "AgentShield failed safely. No tool action was executed. Please retry with a simpler request."
    await ctx.send(sender, ChatMessage(
        timestamp=datetime.now(timezone.utc),
        msg_id=uuid4(),
        content=[TextContent(type="text", text=response), EndSessionContent(type="end-session")],
    ))


@protocol.on_message(ChatAcknowledgement)
async def handle_ack(ctx: Context, sender: str, msg: ChatAcknowledgement):
    ctx.logger.debug("Received acknowledgement from %s", sender)

agent.include(protocol, publish_manifest=True)

if __name__ == "__main__":
    agent.run()
