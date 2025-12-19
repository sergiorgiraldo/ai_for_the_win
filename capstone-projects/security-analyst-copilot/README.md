# Security Analyst Copilot

A conversational AI assistant that helps security analysts investigate alerts, gather context, and take response actions.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export ANTHROPIC_API_KEY="your-key-here"

# Run the application
python src/main.py

# Or run with Streamlit UI
streamlit run src/app.py
```

## Project Structure

```
security-analyst-copilot/
├── README.md
├── requirements.txt
├── src/
│   ├── main.py              # Main entry point
│   ├── app.py               # Streamlit UI
│   ├── agent/
│   │   ├── copilot.py       # Main copilot agent
│   │   ├── tools.py         # Agent tools
│   │   └── state.py         # State management
│   ├── integrations/
│   │   ├── siem.py          # SIEM integration
│   │   ├── threat_intel.py  # TI lookups
│   │   └── mitre.py         # ATT&CK mapping
│   └── utils/
│       ├── config.py        # Configuration
│       └── logging.py       # Logging setup
├── tests/
│   └── test_copilot.py
└── docker/
    ├── Dockerfile
    └── docker-compose.yml
```

## Core Features Checklist

- [ ] Chat interface for natural language interaction
- [ ] SIEM integration for log queries
- [ ] Threat intelligence lookups (IP, domain, hash)
- [ ] MITRE ATT&CK mapping
- [ ] Incident documentation generation

## Advanced Features Checklist

- [ ] Multi-turn conversation memory
- [ ] Playbook execution assistance
- [ ] Alert correlation
- [ ] Response action suggestions
- [ ] Learning from analyst feedback

## Development Notes

Add your development notes here as you build the project.
