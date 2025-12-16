# Lab Exercises

Hands-on exercises for each module of the AI Security Training Program.

---

## 📋 Lab Index

### Phase 1: Foundations

| Lab | Module | Description | Difficulty |
|-----|--------|-------------|------------|
| [Lab 01](./lab01-phishing-classifier/) | 1.1 | Build a phishing email classifier | ⭐ Beginner |
| [Lab 02](./lab02-malware-clustering/) | 1.1 | Malware family clustering with unsupervised learning | ⭐⭐ Intermediate |
| [Lab 03](./lab03-anomaly-detection/) | 1.1 | Network anomaly detection | ⭐⭐ Intermediate |
| [Lab 04](./lab04-llm-security/) | 1.2 | LLM prompt injection testing | ⭐⭐ Intermediate |

### Phase 2: Offensive AI

| Lab | Module | Description | Difficulty |
|-----|--------|-------------|------------|
| [Lab 05](./lab05-recon-agent/) | 2.1 | AI-powered reconnaissance agent | ⭐⭐ Intermediate |
| [Lab 06](./lab06-vuln-scanner/) | 2.2 | LLM-powered code vulnerability scanner | ⭐⭐⭐ Advanced |
| [Lab 07](./lab07-adversarial-ml/) | 2.4 | Crafting adversarial samples | ⭐⭐⭐ Advanced |
| [Lab 08](./lab08-prompt-injection/) | 2.4 | Advanced prompt injection techniques | ⭐⭐⭐ Advanced |

### Phase 3: DFIR AI

| Lab | Module | Description | Difficulty |
|-----|--------|-------------|------------|
| [Lab 09](./lab09-detection-pipeline/) | 3.1 | Build a threat detection pipeline | ⭐⭐⭐ Advanced |
| [Lab 10](./lab10-ir-copilot/) | 3.2 | Incident response copilot | ⭐⭐⭐ Advanced |
| [Lab 11](./lab11-forensic-agent/) | 3.3 | Automated forensic analysis agent | ⭐⭐⭐⭐ Expert |
| [Lab 12](./lab12-malware-analysis/) | 3.4 | AI-assisted malware triage | ⭐⭐⭐ Advanced |
| [Lab 13](./lab13-threat-intel/) | 3.5 | Threat intel processing pipeline | ⭐⭐⭐ Advanced |

### Phase 4: Advanced

| Lab | Module | Description | Difficulty |
|-----|--------|-------------|------------|
| [Lab 14](./lab14-multi-agent/) | 4.1 | Multi-agent security system | ⭐⭐⭐⭐ Expert |
| [Lab 15](./lab15-mlsecops/) | 4.2 | MLSecOps pipeline | ⭐⭐⭐⭐ Expert |

---

## 🚀 Getting Started with Labs

### Prerequisites

1. Complete the [Development Environment Setup](../setup/dev-environment-setup.md)
2. Ensure all dependencies are installed
3. Configure API keys in `.env` file

### Lab Structure

Each lab folder contains:

```
labXX-name/
├── README.md           # Lab instructions
├── requirements.txt    # Additional dependencies (if any)
├── starter/            # Starter code
│   └── main.py
├── solution/           # Reference solution
│   └── main.py
├── data/               # Sample data for the lab
└── tests/              # Unit tests
    └── test_solution.py
```

### Running Labs

```bash
# Navigate to lab directory
cd labs/lab01-phishing-classifier

# Read instructions
cat README.md

# Run starter code
python starter/main.py

# Run tests (after implementing)
pytest tests/
```

---

## 📊 Lab Completion Tracking

| Lab | Status | Date Completed | Notes |
|-----|--------|----------------|-------|
| Lab 01 | ⬜ Not Started | | |
| Lab 02 | ⬜ Not Started | | |
| Lab 03 | ⬜ Not Started | | |
| ... | | | |

---

## 💡 Tips for Success

1. **Read the entire lab before starting** - Understand the goals and requirements
2. **Use the starter code** - Don't reinvent the wheel
3. **Test incrementally** - Run tests after each major change
4. **Ask for help** - Use the AI assistants when stuck
5. **Document your work** - Add comments explaining your approach
6. **Compare with solutions** - Learn from reference implementations

---

## 🔗 Additional Resources

Each lab may reference:
- Specific sections of the [curriculum](../curriculum/ai-security-training-program.md)
- External datasets from [resources](../resources/tools-and-resources.md)
- Documentation for tools and frameworks

---

**Coming Soon**: Individual lab content will be added progressively.

