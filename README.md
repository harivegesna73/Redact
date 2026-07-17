# PII Redaction Tool

## Approach

This solution employs a hybrid Natural Language Processing (NLP) and rule-based architecture using Microsoft Presidio, the spaCy NLP engine, and the Faker library.

To meet the strict requirements of redacting complex financial and legal documents (like a Red Herring Prospectus), the following custom engineering strategies were implemented:

- **Canonical Aliasing for 1:1 Consistency**: An internal memory vault (`self.alias_vault`) is maintained during execution. Detected entities are stripped of corporate suffixes (e.g., "Limited", "LLP") and articles (e.g., "The") to generate a root key. This ensures that variations like "KSH International Limited" and "KSH International" resolve to the exact same synthetic alias globally throughout the document.

- **Context-Aware Allow-Listing**: To preserve readability, a domain-specific deny list protects legal and procedural terminology (e.g., "Book Running Lead Managers", "Registrar to the Offer", "Companies Act") from being falsely flagged as organizations by the NER model.

- **Non-Maximum Suppression (NMS)**: To prevent entity fragmentation (where a company name inside an email address causes the string to shred into multiple fake names), an interval-merging algorithm sorts detections by length and score, dropping smaller overlapping fragments in favor of the largest cohesive entity span.

- **Custom Pattern Recognizers**: The default Presidio engine is optimized for Western data. Custom regular expressions were injected into the registry to perfectly capture spaced Indian phone numbers, specific Date of Birth formats (preventing the over-redaction of standard business dates), and multi-line Indian address blocks.

## Tradeoffs, False Positives, and False Negatives

**Tradeoff (NER vs. LLM)**: Utilizing a Large Language Model (LLM) would yield deeper semantic understanding to differentiate between a legal act and a company name. However, parsing a 100+ page prospectus through an LLM introduces severe latency, high API costs, and significant data privacy risks. A localized Presidio/spaCy pipeline processes the document in seconds, entirely offline, ensuring absolute data security at the cost of slight precision drops on edge-case nouns.

**False Negatives (Missed PII)**: The tool achieved 0 False Negatives (100% Recall) on the test set. By tuning the `score_threshold` and adding custom regex patterns for localized data (like Indian phone numbers), the system successfully captured all target PII.

**False Positives (Incorrectly Flagged)**: The tool generated 3 False Positives during the evaluation. The spaCy NER model occasionally struggles with heavily capitalized, multi-word legal entities. For example, "Maharashtra State Tax on Professions, Trades, Callings and Employment Act, 1975" was partially fragmented and flagged as an organization, despite the statutory context filter.

## Extending to a New PII Type

The architecture is completely modular and designed for infinite extensibility. Adding a new, proprietary, or region-specific PII type (e.g., an Indian PAN Card) requires no changes to the core loops. It follows a simple 4-step process:

1. **Define the Pattern**: Create a Presidio `Pattern` with the specific regex (e.g., `r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"`).

2. **Register the Recognizer**: Wrap the pattern in a `PatternRecognizer` and register it to the engine (`self.pii_engine.registry.add_recognizer(...)`).

3. **Update Target Entities**: Append the new entity label (e.g., `"INDIA_PAN"`) to the `target_entities` array passed during instantiation.

4. **Map the Output**: Add a conditional block in the `_get_mock_data` router to return structurally accurate synthetic data via Faker (e.g., using `self.synthetic_gen.bothify()`).

## Evaluation Report

### Methodology

To provide a defensible and realistic evaluation, the system was tested against an `evaluate_labeled_samples` pipeline. Instead of relying on a single synthetic sentence, heavily dense, real-world paragraphs and table cells were extracted directly from the Red Herring Prospectus.

These samples were hand-labeled with two arrays:

- **`pii_terms` (Ground Truth 1)**: Substrings that are genuine PII and must be redacted.
- **`non_pii_terms` (Ground Truth 0)**: Substrings that are procedural, legal, or generic (e.g., "Registrar to the Offer", "Companies Act, 1956") and must survive intact.

The script parsed the samples and evaluated whether the target strings were successfully obscured or incorrectly altered, generating an exact Confusion Matrix.

### Final Metrics (Prospectus Ground-Truth Sample)

| Metric | Count |
|---|---|
| True Positives (TP - Correctly Redacted) | 11 |
| True Negatives (TN - Correctly Ignored) | 14 |
| False Positives (FP - Incorrectly Flagged) | 3 |
| False Negatives (FN - Missed PII) | 0 |

### Score Summary

| Score | Value |
|---|---|
| Accuracy | 89.29% |
| Precision | 78.57% |
| Recall | 100.00% |

## Step-by-Step Setup and Execution

### 1. Navigate to the project folder

Open your terminal and ensure you are in the directory where your project files are located.

```bash
cd path/to/your/pii-redaction-tool
```

### 2. Create and activate the virtual environment

Create a fresh isolated environment and activate it to manage your dependencies.

```bash
# Create the virtual environment
python3 -m venv venv

# Activate the environment
source venv/bin/activate
```

### 3. Install dependencies

Install all required libraries, including the spaCy model needed for accurate PII detection.

```bash
# Install requirements
pip install -r requirements.txt

# Download the required spaCy model
pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.7.1/en_core_web_lg-3.7.1-py3-none-any.whl
```

### 4. Run the local server

Once the environment is prepared, use the Python built-in server to host your frontend files.

```bash
cd pii-redaction-tool
python3 main.py
```