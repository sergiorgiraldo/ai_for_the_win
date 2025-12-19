# Templates

Production-ready templates for building AI-powered security tools.

## Directory Structure

```
templates/
├── README.md                           # This file
├── agents/
│   └── security-agent-langchain.py     # LangChain security agent template
└── mcp-servers/
    ├── threat-intel-mcp-server.py      # Threat intel MCP server
    └── virustotal-mcp-server.py        # VirusTotal integration
```

## Available Templates

### Security Agent (LangChain)

**File**: `agents/security-agent-langchain.py`

A production-ready template for building security analysis agents using LangChain.

**Features**:
- ReAct agent pattern implementation
- Tool integration (IP lookup, domain analysis, hash check)
- Memory management for conversation context
- Structured output parsing
- Error handling and retry logic

**Usage**:
```python
from security_agent import SecurityAgent

agent = SecurityAgent(api_key="your-anthropic-key")
result = agent.investigate("Analyze this IP: 185.143.223.47")
print(result)
```

### MCP Servers

Model Context Protocol (MCP) servers for Claude integration.

#### Threat Intel MCP Server

**File**: `mcp-servers/threat-intel-mcp-server.py`

Provides threat intelligence lookup capabilities to Claude.

**Capabilities**:
- IP reputation lookup
- Domain analysis
- File hash checking
- CVE information retrieval

#### VirusTotal MCP Server

**File**: `mcp-servers/virustotal-mcp-server.py`

Integrates VirusTotal API with Claude.

**Capabilities**:
- File hash analysis
- URL scanning
- Domain reports
- IP address reports

## Using Templates

### 1. Copy and Customize

```bash
# Copy template to your project
cp templates/agents/security-agent-langchain.py my_project/agent.py

# Edit to customize for your use case
```

### 2. Install Dependencies

```bash
pip install langchain langchain-anthropic python-dotenv
```

### 3. Configure Environment

```bash
# Create .env file
echo "ANTHROPIC_API_KEY=your-key-here" > .env
```

### 4. Run

```python
from agent import SecurityAgent

agent = SecurityAgent()
agent.run("Your query here")
```

## Template Features

### Agent Template Features

| Feature | Description |
|---------|-------------|
| Tool Registry | Easy-to-extend tool definitions |
| Memory | Conversation and investigation history |
| Structured Output | Pydantic models for type safety |
| Logging | Rich console output |
| Error Handling | Graceful degradation |

### MCP Server Features

| Feature | Description |
|---------|-------------|
| Schema Validation | Input/output validation |
| Caching | Response caching for performance |
| Rate Limiting | API rate limit handling |
| Authentication | Secure API key management |

## Extending Templates

### Adding New Tools

```python
from langchain.tools import StructuredTool
from pydantic import BaseModel, Field

class MyToolInput(BaseModel):
    param: str = Field(description="Parameter description")

def my_tool_function(param: str) -> dict:
    """Tool implementation."""
    return {"result": "data"}

my_tool = StructuredTool.from_function(
    func=my_tool_function,
    name="my_tool",
    description="What this tool does",
    args_schema=MyToolInput
)

# Add to agent's tool list
agent.tools.append(my_tool)
```

### Adding MCP Capabilities

```python
@mcp.tool()
def new_capability(param: str) -> str:
    """New MCP capability."""
    return result
```

## Best Practices

### Security

- Never hardcode API keys
- Validate all inputs
- Sanitize outputs for logging
- Use rate limiting for external APIs

### Performance

- Cache repeated lookups
- Batch API calls when possible
- Use async for I/O-bound operations
- Implement timeouts

### Error Handling

- Catch and log all exceptions
- Provide meaningful error messages
- Implement retry logic for transient failures
- Graceful degradation when services unavailable

## Contributing Templates

To add new templates:

1. Create template file in appropriate directory
2. Include comprehensive docstrings
3. Add usage examples
4. Include error handling
5. Update this README

### Template Requirements

- [ ] Well-documented code
- [ ] Type hints
- [ ] Error handling
- [ ] Usage examples
- [ ] Configuration via environment variables
- [ ] No hardcoded secrets
