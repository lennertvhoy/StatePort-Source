"""Credential-entry gate for an approved Telegram launcher.

This module intentionally cannot start a bot.  It only proves that the
credential can be entered without echo and validated in memory.  A sanctioned
launcher must separately inject the StatePort API sink, binding and approval.
"""

from __future__ import annotations

import argparse

from .polling import LiveTelegramApproval, TelegramCredentials


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an approved Telegram credential through hidden input")
    parser.add_argument("--approval-reference", required=True)
    parser.add_argument("--binding-reference", required=True)
    parser.add_argument("--chat-identity-digest", required=True)
    args = parser.parse_args()
    approval = LiveTelegramApproval(
        args.approval_reference,
        args.binding_reference,
        args.chat_identity_digest,
        allow_polling=True,
    )
    TelegramCredentials.prompt(approval)
    print("Telegram credential accepted in memory; no bot was started and nothing was persisted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
