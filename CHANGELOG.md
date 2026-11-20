# Changelog

## [0.1.0]

First release.

- `request_secret` tool: the agent asks for a secret, you enter it in a masked card, and the model only gets the path of an owner-only file.
- Paste guard: messages with a URL that includes a password, a known token format, a private key, or a secret-looking assignment are caught before sending. A message that is only one random-looking string is caught too. Store it and send a reference, send it as is, or edit the message.
- Redaction: stored values in command output, error messages, and the model's replies become `[REDACTED: NAME]` before the model sees them and before they are saved to the session file.
- `/secrets` command to list, add, delete, and clear stored secrets.
- Secrets live in `~/.pi/agent/secrets/` (mode `0700`, files `0600`) and expire after 24 hours.
