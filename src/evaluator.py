#src/evaluator.py
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score


def evaluate_redaction(y_true, y_pred, label="Overall"):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)

    print("\n" + "=" * 50)
    print(f"               EVALUATION METRICS ({label})")
    print("=" * 50)
    print(f"True Positives (TP - Correctly Redacted):   {tp}")
    print(f"True Negatives (TN - Correctly Ignored):    {tn}")
    print(f"False Positives (FP - Incorrectly Flagged): {fp}")
    print(f"False Negatives (FN - Missed PII):          {fn}")
    print("-" * 50)
    print(f"Accuracy:  {accuracy:.4f} ({accuracy * 100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision * 100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall * 100:.2f}%)")
    print("=" * 50 + "\n")

    return {
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
        "accuracy": accuracy, "precision": precision, "recall": recall,
    }


def evaluate_labeled_samples(redactor, samples, label="Document Sample"):
    """Runs the redactor over a list of labeled samples and aggregates a
    single precision/recall/accuracy report across all of them.

    Each sample is a dict:
        {
            "text": "<original paragraph or cell text>",
            "pii_terms": ["<substring that IS pii, should disappear>", ...],
            "non_pii_terms": ["<substring that is NOT pii, must survive>", ...],
        }

    This is meant to replace evaluating against a single hand-written
    sentence: pull real paragraphs/cells out of the actual document you're
    redacting (including ones you know contain names, emails, phones, dates,
    and ones you know contain generic legal terms that should NOT be
    redacted), and label them once. That gives you a real, defensible
    precision/recall number instead of one synthetic example.
    """
    y_true = []
    y_pred = []
    per_sample_results = []

    for sample in samples:
        original = sample["text"]
        redacted = redactor.redact_text(original)

        sample_true = []
        sample_pred = []

        for term in sample.get("pii_terms", []):
            sample_true.append(1)
            sample_pred.append(0 if term in redacted else 1)

        for term in sample.get("non_pii_terms", []):
            sample_true.append(0)
            sample_pred.append(1 if term not in redacted else 0)

        y_true.extend(sample_true)
        y_pred.extend(sample_pred)
        per_sample_results.append({
            "text": original,
            "redacted": redacted,
            "y_true": sample_true,
            "y_pred": sample_pred,
        })

    metrics = evaluate_redaction(y_true, y_pred, label=label)
    return metrics, per_sample_results