"""
evaluate_waf.py - score the WAF's detection rules against a labeled dataset.

Instead of just eyeballing "it blocked my curl command", this script
runs every payload in dataset/test_payloads.json through waf.scan_value()
and compares the predicted label to the true label, then reports:

  - overall accuracy
  - per-class precision / recall / F1 score
  - the list of misclassified payloads (false positives and false negatives)

This also writes dataset/results.json, which app.py reads to show a
"Detection Accuracy Benchmark" panel on the /dashboard page.

Run with:  python evaluate_waf.py
"""

import json
import os
from collections import defaultdict
from datetime import datetime, timezone

from waf import scan_value

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_FILE = os.path.join(BASE_DIR, "dataset", "test_payloads.json")
RESULTS_FILE = os.path.join(BASE_DIR, "dataset", "results.json")

CLEAN_LABEL = "clean"


def predict(payload):
    """Run one payload through the WAF's detection logic. Mirrors what
    waf.inspect_request() does for a single value, without needing a
    real Flask request object."""
    result = scan_value(payload)
    return result[0] if result else CLEAN_LABEL


def evaluate(dataset):
    all_labels = sorted({entry["label"] for entry in dataset} | {CLEAN_LABEL})

    # counts[label] = {"tp": int, "fp": int, "fn": int, "support": int}
    counts = {label: defaultdict(int) for label in all_labels}
    mistakes = []
    correct = 0

    for entry in dataset:
        actual = entry["label"]
        predicted = predict(entry["payload"])

        counts[actual]["support"] += 1

        if predicted == actual:
            correct += 1
            counts[actual]["tp"] += 1
        else:
            counts[actual]["fn"] += 1
            counts[predicted]["fp"] += 1
            mistakes.append({"payload": entry["payload"], "actual": actual, "predicted": predicted})

    per_class = {}
    for label in all_labels:
        tp = counts[label]["tp"]
        fp = counts[label]["fp"]
        fn = counts[label]["fn"]
        support = counts[label]["support"]

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

        per_class[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support,
        }

    total = len(dataset)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": total,
        "correct": correct,
        "accuracy": correct / total if total else 0.0,
        "per_class": per_class,
        "mistakes": mistakes,
    }


def print_report(results):
    print("=" * 70)
    print(f"WAF Detection Benchmark  ({results['total']} labeled payloads)")
    print("=" * 70)
    print(f"Overall accuracy: {results['accuracy'] * 100:.1f}%  "
          f"({results['correct']}/{results['total']} correct)\n")

    header = f"{'Class':<16}{'Precision':>10}{'Recall':>10}{'F1':>10}{'Support':>10}"
    print(header)
    print("-" * len(header))
    for label, m in results["per_class"].items():
        print(f"{label:<16}{m['precision']:>10.2f}{m['recall']:>10.2f}{m['f1']:>10.2f}{m['support']:>10}")

    if results["mistakes"]:
        print(f"\nMisclassified payloads ({len(results['mistakes'])}):")
        for m in results["mistakes"]:
            print(f"  - {m['payload']!r}  actual={m['actual']!r}  predicted={m['predicted']!r}")
    else:
        print("\nNo misclassifications.")
    print()


def main():
    with open(DATASET_FILE) as f:
        dataset = json.load(f)

    results = evaluate(dataset)
    print_report(results)

    with open(RESULTS_FILE, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results written to {RESULTS_FILE}")


if __name__ == "__main__":
    main()
