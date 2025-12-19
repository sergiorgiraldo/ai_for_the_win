# Resources

Curated resources for the AI Security Training Program.

## Directory Structure

```
resources/
├── README.md                    # This file
├── tools-and-resources.md       # Comprehensive tools and APIs guide
├── prompt-library/              # Security analysis prompts
│   └── *.md                     # Individual prompt templates
└── cheatsheets/                 # Quick reference guides
    ├── cursor-cheatsheet.md     # Cursor IDE shortcuts
    ├── claude-code-cheatsheet.md # Claude Code reference
    ├── google-adk-cheatsheet.md # Google ADK guide
    └── langchain-cheatsheet.md  # LangChain patterns
```

## Quick Links

| Resource | Description |
|----------|-------------|
| [Tools & Resources](./tools-and-resources.md) | 70+ tools, APIs, datasets |
| [Prompt Library](./prompt-library/) | Ready-to-use security prompts |
| [Cheatsheets](./cheatsheets/) | Quick reference guides |

## Tools & Resources Overview

The main resources file includes:

- **AI Development Tools**: Cursor, Claude Code, GitHub Copilot
- **LLM APIs**: Anthropic, OpenAI, local models via Ollama
- **ML Libraries**: scikit-learn, PyTorch, XGBoost
- **Security Tools**: YARA, Sigma, Volatility, MISP
- **Datasets**: Malware samples, network traffic, threat intel
- **Pre-trained Models**: Security-specific embeddings and classifiers

## Prompt Library

The prompt library contains tested prompts for:

- Log analysis and parsing
- Threat detection and classification
- IOC extraction
- Incident summarization
- MITRE ATT&CK mapping
- Malware behavior analysis
- Vulnerability assessment

### Using Prompts

```python
from pathlib import Path

# Load a prompt template
prompt_path = Path("resources/prompt-library/log-analysis.md")
template = prompt_path.read_text()

# Customize with your data
prompt = template.format(logs=your_log_data)
```

## Cheatsheets

Quick reference guides for common tools:

### Cursor IDE
- Keyboard shortcuts
- AI features (Cmd+K, Cmd+L)
- Configuration tips

### Claude Code
- CLI commands
- Session management
- Best practices

### LangChain
- Common patterns
- Chain templates
- Tool definitions

## Contributing Resources

To add new resources:

1. Add entries to `tools-and-resources.md` for tools/APIs
2. Create new files in `prompt-library/` for prompts
3. Add to `cheatsheets/` for quick references
4. Update this README with new additions

### Resource Format

For tools and resources entries:

```markdown
### Tool Name

**URL**: https://example.com
**Type**: Commercial / Open Source / API
**Use Case**: Brief description of security application

**Example**:
```python
# Code example
```
```

## External Resources

Beyond this repository:

- [MITRE ATT&CK](https://attack.mitre.org/) - Adversary tactics and techniques
- [VirusTotal](https://www.virustotal.com/) - File/URL analysis
- [Awesome Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence)
- [Sigma Rules](https://github.com/SigmaHQ/sigma) - Detection rules
- [YARA Rules](https://github.com/Yara-Rules/rules) - Malware detection
