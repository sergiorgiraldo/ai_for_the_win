# Cursor IDE Complete Guide

The AI-native IDE that supercharges your security tool development.

---

## 📋 Table of Contents

1. [Why Cursor for Security AI Development](#why-cursor-for-security-ai-development)
2. [Installation](#installation)
3. [Initial Setup](#initial-setup)
4. [Key Features](#key-features)
5. [AI Models Configuration](#ai-models-configuration)
6. [Keyboard Shortcuts](#keyboard-shortcuts)
7. [Security-Focused Workflows](#security-focused-workflows)
8. [Best Practices](#best-practices)

---

## 🎯 Why Cursor for Security AI Development

Cursor is built on VS Code but adds native AI capabilities that are essential for building AI-powered security tools:

| Feature | Benefit for Security Development |
|---------|----------------------------------|
| **Inline AI Chat** | Get instant explanations of malware code, log formats, or attack techniques |
| **Codebase-Aware Completions** | AI understands your entire security tool codebase |
| **Multi-File Editing** | Refactor detection rules across multiple files simultaneously |
| **Composer Mode** | Build entire security agents from natural language descriptions |
| **Terminal Integration** | Run security tools with AI-assisted command building |

---

## 💾 Installation

### Download

```bash
# Visit
https://cursor.sh/

# Or direct download links:
# Windows: https://download.cursor.sh/windows/installer
# macOS: https://download.cursor.sh/mac/installer
# Linux: https://download.cursor.sh/linux/appImage
```

### Windows Installation

1. Download the installer from cursor.sh
2. Run `CursorSetup.exe`
3. Follow installation wizard
4. Launch Cursor from Start Menu

### macOS Installation

```bash
# Using Homebrew
brew install --cask cursor

# Or download .dmg and drag to Applications
```

### Linux Installation

```bash
# AppImage
chmod +x cursor-*.AppImage
./cursor-*.AppImage

# Or extract and run
./cursor
```

---

## ⚙️ Initial Setup

### 1. Sign In / Create Account

When you first launch Cursor:
1. Click "Sign In" or "Create Account"
2. You can use GitHub, Google, or email
3. Free tier includes limited AI requests
4. Pro ($20/month) unlocks unlimited requests

### 2. Import VS Code Settings

If you have VS Code installed:
1. Cursor will prompt to import settings
2. Select "Import from VS Code"
3. This brings over extensions, themes, and keybindings

### 3. Configure AI Provider

Go to **Settings** > **Cursor** > **Models**:

```json
{
  "cursor.aiProvider": "anthropic",
  "cursor.defaultModel": "claude-sonnet-4-20250514",
  "cursor.enableLongContext": true
}
```

### 4. Install Essential Extensions

Press `Ctrl+Shift+X` (Cmd+Shift+X on Mac) and install:

```
# Core Development
ms-python.python
ms-python.vscode-pylance
ms-toolsai.jupyter

# Git Integration
eamodio.gitlens
mhutchie.git-graph

# Security & Analysis
redhat.vscode-yaml
ms-vscode.hexeditor
timonwong.shellcheck

# Docker & Remote
ms-vscode-remote.remote-ssh
ms-azuretools.vscode-docker

# Formatting
esbenp.prettier-vscode
ms-python.black-formatter
```

---

## 🚀 Key Features

### Feature 1: Inline Chat (`Ctrl+L` / `Cmd+L`)

Select code and press `Ctrl+L` to ask questions:

```python
# Select this malware analysis function
def analyze_pe_file(filepath):
    pe = pefile.PE(filepath)
    # ... complex analysis code
    return results

# Press Ctrl+L and ask:
# "Explain what this function does step by step"
# "How can I add entropy calculation to this?"
# "What YARA signatures could detect this behavior?"
```

### Feature 2: Composer (`Ctrl+I` / `Cmd+I`)

Press `Ctrl+I` for multi-file AI editing:

```
Prompt: "Create a LangChain agent that:
1. Takes a suspicious URL as input
2. Checks it against VirusTotal API
3. Downloads and analyzes the content if safe
4. Generates a threat report"

Cursor will:
- Create new files as needed
- Import required libraries
- Implement the full agent
- Add error handling
```

### Feature 3: Codebase Chat (`Ctrl+Shift+L` / `Cmd+Shift+L`)

Ask questions about your entire codebase:

```
"Where do we handle MITRE ATT&CK mappings?"
"Show me all places where we parse Windows event logs"
"How does the threat scoring work?"
```

### Feature 4: Terminal AI (`Ctrl+K` in Terminal)

Get AI help with terminal commands:

```bash
# Press Ctrl+K in terminal and type:
"Run volatility3 to list processes from memory.dmp"

# Cursor suggests:
vol -f memory.dmp windows.pslist.PsList
```

### Feature 5: @ Mentions

Reference specific context in prompts:

```
@file:detection_rules.py - Reference a specific file
@folder:agents/ - Reference an entire folder
@codebase - Search entire codebase
@docs - Reference documentation
@web - Search the web
```

---

## 🤖 AI Models Configuration

### Available Models

| Model | Best For | Speed | Cost |
|-------|----------|-------|------|
| **claude-sonnet-4-20250514** | Complex security analysis, long context | Medium | $$ |
| **claude-3-opus** | Deepest reasoning, architecture design | Slow | $$$ |
| **gpt-4-turbo** | General coding, function calling | Medium | $$ |
| **gpt-4o** | Fast responses, balanced quality | Fast | $ |
| **cursor-small** | Quick completions, simple tasks | Very Fast | $ |

### Model-Specific Settings

```json
// settings.json
{
  // Default model for most tasks
  "cursor.defaultModel": "claude-sonnet-4-20250514",

  // Use faster model for autocomplete
  "cursor.autocomplete.model": "cursor-small",

  // Use strongest model for Composer
  "cursor.composer.model": "claude-3-opus",

  // Context settings
  "cursor.enableLongContext": true,
  "cursor.maxContextLines": 10000,

  // Privacy
  "cursor.enableTelemetry": false,
  "cursor.privacyMode": false
}
```

### Custom API Keys (Optional)

If you prefer using your own API keys:

```json
{
  "cursor.anthropicApiKey": "sk-ant-...",
  "cursor.openaiApiKey": "sk-...",
  "cursor.useOwnApiKeys": true
}
```

---

## ⌨️ Keyboard Shortcuts

### Essential Shortcuts

| Action | Windows/Linux | macOS |
|--------|--------------|-------|
| **Inline Chat** | `Ctrl+L` | `Cmd+L` |
| **Composer** | `Ctrl+I` | `Cmd+I` |
| **Codebase Chat** | `Ctrl+Shift+L` | `Cmd+Shift+L` |
| **Terminal AI** | `Ctrl+K` (in terminal) | `Cmd+K` |
| **Accept Suggestion** | `Tab` | `Tab` |
| **Reject Suggestion** | `Escape` | `Escape` |
| **Next Suggestion** | `Alt+]` | `Option+]` |
| **Previous Suggestion** | `Alt+[` | `Option+[` |
| **Trigger Suggestion** | `Ctrl+Space` | `Cmd+Space` |

### Custom Keybindings for Security Work

Add to `keybindings.json`:

```json
[
  // Quick analyze selected code
  {
    "key": "ctrl+shift+a",
    "command": "cursor.chat.sendSelection",
    "args": { "prompt": "Analyze this code for security vulnerabilities" }
  },

  // Generate YARA rule from selection
  {
    "key": "ctrl+shift+y",
    "command": "cursor.chat.sendSelection",
    "args": { "prompt": "Generate a YARA rule to detect this pattern" }
  },

  // Explain malware behavior
  {
    "key": "ctrl+shift+m",
    "command": "cursor.chat.sendSelection",
    "args": { "prompt": "Explain what this malware code does" }
  }
]
```

---

## 🔐 Security-Focused Workflows

### Workflow 1: Analyzing Malware Samples

```python
# 1. Open a malware analysis file
# 2. Select suspicious code
# 3. Press Ctrl+L and ask:

"""
Prompts to use:
- "What Windows API calls indicate malicious behavior?"
- "Identify any obfuscation techniques used"
- "What persistence mechanisms does this implement?"
- "Map this code to MITRE ATT&CK techniques"
- "Generate IOCs from this sample"
"""
```

### Workflow 2: Building Detection Rules

```
# Use Composer (Ctrl+I) with prompts like:

"Create a Sigma rule that detects:
- PowerShell downloading files from the internet
- Base64 encoded commands
- Execution from temp directories
Include references to MITRE ATT&CK T1059.001"

"Convert this Sigma rule to a Splunk query"

"Generate a YARA rule from these strings: [paste strings]"
```

### Workflow 3: Developing AI Agents

```
# In Composer mode:

"Build a LangChain agent for incident response that can:
1. Parse Windows Security event logs
2. Identify failed login attempts
3. Correlate with known bad IPs from threat intel
4. Generate a timeline of suspicious activity
5. Recommend containment actions

Use these files as reference:
@file:agents/base_agent.py
@folder:config/"
```

### Workflow 4: Code Review for Vulnerabilities

```python
# Select your code and ask:

"Review this code for:
1. SQL injection vulnerabilities
2. Command injection risks
3. Hardcoded credentials
4. Insecure deserialization
5. Path traversal issues

Provide specific line numbers and remediation steps."
```

---

## 💡 Best Practices

### 1. Use .cursorrules File

Create `.cursorrules` in your project root to customize AI behavior:

```markdown
# .cursorrules

## Project Context
This is an AI-powered security tool for threat detection and incident response.

## Code Style
- Use type hints for all Python functions
- Follow PEP 8 style guidelines
- Include docstrings with security considerations
- Log all security-relevant actions

## Security Requirements
- Never log sensitive data (passwords, API keys, PII)
- Validate all external inputs
- Use parameterized queries for databases
- Implement proper error handling without exposing internals

## Preferred Libraries
- Use `langchain` for LLM operations
- Use `pydantic` for data validation
- Use `loguru` for logging
- Use `httpx` for async HTTP requests

## Response Format
- Include MITRE ATT&CK references where applicable
- Add IOC extraction for malware analysis
- Reference relevant CVEs when discussing vulnerabilities
```

### 2. Provide Context in Prompts

❌ Bad prompt:
```
"Fix this code"
```

✅ Good prompt:
```
"This function parses Windows Event Log 4688 (Process Creation).
It's currently missing extraction of:
- Parent process information
- Command line arguments
- Token elevation type

Add these fields and include proper error handling for malformed logs."
```

### 3. Use Incremental Development

Instead of asking for complete implementations:

```
Step 1: "Create the class structure for a VirusTotal scanner agent"
Step 2: "Add the file hash lookup method"
Step 3: "Add rate limiting and retry logic"
Step 4: "Add result caching"
Step 5: "Add async batch scanning support"
```

### 4. Review AI Suggestions Carefully

Always verify AI-generated security code:

```python
# AI might suggest:
def check_password(user_input, stored_hash):
    return user_input == stored_hash  # ❌ WRONG - comparing plaintext to hash!

# You need to catch this and fix:
def check_password(user_input, stored_hash):
    return bcrypt.checkpw(user_input.encode(), stored_hash)  # ✅ Correct
```

### 5. Leverage Multi-File Context

When working on complex features:

```
@file:models/threat.py
@file:agents/detection_agent.py
@file:config/rules.yaml

"Add a new threat type 'cryptominer' with:
- Detection rules based on CPU usage patterns
- Network IOCs for mining pools
- Process name patterns
Update all relevant files to support this new threat type."
```

---

## 🔧 Troubleshooting

### AI Not Responding

1. Check internet connection
2. Verify you haven't exceeded rate limits
3. Try switching models
4. Restart Cursor

### Slow Completions

```json
// Reduce context size
{
  "cursor.maxContextLines": 5000,
  "cursor.autocomplete.debounceMs": 200
}
```

### Wrong Language Completions

```json
// Force Python for security tools
{
  "cursor.language.preferredLanguage": "python"
}
```

### Privacy Concerns

```json
// Enable privacy mode
{
  "cursor.privacyMode": true,
  "cursor.enableTelemetry": false,
  "cursor.excludeFromIndexing": [
    "**/secrets/**",
    "**/.env",
    "**/credentials/**",
    "**/samples/**"
  ]
}
```

---

## 📚 Additional Resources

- [Cursor Documentation](https://docs.cursor.sh)
- [Cursor Discord Community](https://discord.gg/cursor)
- [VS Code Keybindings Reference](https://code.visualstudio.com/docs/getstarted/keybindings)
- [Python Extension Documentation](https://code.visualstudio.com/docs/python/python-tutorial)

---

**Next**: [Claude Code CLI Guide](./claude-code-guide.md)
