# Automated Threat Hunter

An automated system that continuously hunts for threats using ML-based detection and LLM-powered analysis.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export ANTHROPIC_API_KEY="your-key-here"

# Run the detection pipeline
python src/main.py

# Run with sample data
python src/main.py --demo
```

## Project Structure

```
automated-threat-hunter/
├── README.md
├── requirements.txt
├── src/
│   ├── main.py              # Main entry point
│   ├── pipeline/
│   │   ├── ingestor.py      # Log ingestion
│   │   ├── ml_filter.py     # ML-based filtering
│   │   ├── llm_enricher.py  # LLM enrichment
│   │   ├── correlator.py    # Event correlation
│   │   └── verdict.py       # Verdict generation
│   ├── detections/
│   │   ├── sigma_rules/     # Sigma detection rules
│   │   └── ml_models/       # Trained ML models
│   └── utils/
│       ├── config.py
│       └── metrics.py
├── tests/
│   └── test_pipeline.py
└── docker/
    └── docker-compose.yml
```

## Core Features Checklist

- [ ] Log ingestion from multiple sources
- [ ] ML-based anomaly detection
- [ ] Rule-based detection (Sigma)
- [ ] LLM-powered alert analysis
- [ ] Detection priority scoring

## Advanced Features Checklist

- [ ] Behavioral baselines per user/host
- [ ] Attack chain detection
- [ ] Automated enrichment pipeline
- [ ] Alert suppression/tuning
- [ ] Metrics dashboard

## Pipeline Architecture

```
Logs → Ingest → ML Filter → LLM Enrich → Correlate → Verdict → Alert
```

## Development Notes

Add your development notes here as you build the project.
