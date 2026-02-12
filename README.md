# Agent Command - Claude Code Client

Claude Code plugin for [agent-command](https://github.com/daliborhlava/agent-command) monitoring server.

Sends real-time events to a central dashboard including:
- Session start/end
- Tool usage (pre/post)
- Conversation transcript
- Permission prompts

## Installation

```bash
# Add the marketplace
/plugin marketplace add daliborhlava/agent-command-client-claude-code

# Install the plugin
/plugin install agent-command-client@agent-command
```

## Configuration

Set the dashboard server URL via environment variable:

```bash
export AGENT_COMMAND_URL="http://your-server:8787"
```

Default: `http://localhost:8787`

Add to your `~/.bashrc` or `~/.zshrc` for persistence.

Optional identity overrides (normally not needed):

```bash
export AGENT_COMMAND_AGENT_TYPE="claude-code"
export AGENT_COMMAND_AGENT_SOURCE="hooks"
```

## Server

The monitoring server is available at [daliborhlava/agent-command](https://github.com/daliborhlava/agent-command).

## Updates

```bash
/plugin marketplace update
```

## License

MIT
