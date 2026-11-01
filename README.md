# AI Firewall — Hybrid Prompt-Injection Detection

A Python security prototype that screens messages for prompt-injection attempts using rule-based detection and a pretrained machine-learning classifier.

Developed in Google Colab, the project explores how combining two detection methods can help identify suspicious instructions before they are forwarded to an AI application.

## Problem Statement

Prompt-injection attacks attempt to manipulate an AI application through instructions embedded in incoming text. These instructions may ask the AI to disregard its original task, reveal hidden instructions, bypass restrictions, or expose sensitive information.

This project addresses the need for an additional screening layer that distinguishes potentially malicious instructions from ordinary requests.

## Project Objectives

- Detect common prompt-injection patterns.
- Integrate a pretrained classifier for an additional detection signal.
- Combine both detectors into an allow-or-block decision.
- Evaluate predictions against labeled attack and benign examples.
- Identify missed attacks and incorrectly blocked legitimate messages.

## Detection Approach

### 1. Rule-Based Detection

The first layer uses Python regular expressions to identify suspicious instruction patterns, including requests to:

- Ignore or disregard previous instructions.
- Reveal a system prompt or hidden configuration.
- Enter an unrestricted or jailbreak mode.
- Bypass safety restrictions.
- Disable filters.

When a pattern matches, the detector returns a flag and the matching rule.

### 2. Machine-Learning Detection

The second layer uses the pretrained Hugging Face model:

`protectai/deberta-v3-base-prompt-injection-v2`

The model classifies text as `SAFE` or `INJECTION` and returns a confidence score.

This project integrates the pretrained model; it does not train a new model from scratch.

### 3. Combined Decision

The firewall blocks a message if either detector flags it:

`blocked = rule_flag or ml_flag`

A message is allowed only when neither detector flags it.

## Workflow

Incoming message → Rule and model checks → Combined decision → ALLOWED or BLOCKED

The notebook displays the message verdict, rule-based explanation, model label, and confidence score.

## Evaluation

The starter evaluation contains 20 manually labeled messages:

- 10 prompt-injection examples.
- 10 benign requests.

The evaluation reports:

- True positives: attacks correctly blocked.
- False negatives: attacks incorrectly allowed.
- True negatives: benign messages correctly allowed.
- False positives: benign messages incorrectly blocked.
- Accuracy, precision, recall, and F1 score.

Numerical results should be reported from the executed notebook. Performance on this small example set should not be interpreted as a general real-world detection rate.

## Technology Stack

- Python
- Google Colab
- Python regular expressions (`re`)
- Hugging Face Transformers
- PyTorch
- SentencePiece
- pandas
- Pretrained DeBERTa prompt-injection classifier

## Running the Notebook

1. Open the project’s `.ipynb` notebook in Google Colab.
2. Run the dependency-installation cell.
3. Run the rule-based detector cell.
4. Load the pretrained classifier.
5. Run the combined firewall function.
6. Run the labeled evaluation and inspect the results.

The initial setup requires internet access to install dependencies and download the model.

Both detector layers must initialize successfully before running the combined firewall in the provided implementation.

## Demonstration Scope

The demonstration shows how messages receive allow-or-block decisions.

The included `protected_ai` function uses a placeholder response for allowed messages. It does not connect to a downstream language model or demonstrate that an attack succeeds against an unprotected model.

## Limitations

- The evaluation uses a small, manually constructed example set.
- Several attack examples closely resemble the rules, limiting how well the test measures generalization.
- Unfamiliar wording, obfuscation, or context-dependent attacks may evade detection.
- Legitimate text discussing attacks may be incorrectly blocked.
- Blocking when either detector flags a message can increase false positives.
- Model confidence is not a guarantee that a classification is correct.
- The prototype screens text; it does not enforce tool permissions, isolate execution, or control network access.

## Future Work

- Evaluate rules alone, the classifier alone, and the combined approach separately.
- Expand testing with independent datasets and more varied benign examples.
- Test obfuscated, multilingual, and indirect prompt injections.
- Measure processing latency alongside detection performance.
- Add explicit handling for long inputs and model failures.
- Connect the filter to an actual AI application for end-to-end evaluation.
- Add a simple interface for interactive testing.

## Intended Contribution

The project demonstrates the integration of rule-based and machine-learning detection into a single filtering workflow, along with an evaluation process that makes both successful detections and errors visible.
