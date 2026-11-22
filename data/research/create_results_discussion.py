import os


# ============================================================
# ZERO GUARD - STEP 15.10
# RESULTS AND DISCUSSION
# ============================================================

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RESULT_DIR = os.path.join(
    PROJECT_DIR,
    "data",
    "research",
    "processed",
    "evaluation",
    "gnn_ready_publication",
    "results"
)

OUTPUT_FILE = os.path.join(
    RESULT_DIR,
    "ZERO_GUARD_RESULTS_AND_DISCUSSION.txt"
)


# ============================================================
# VERIFIED EXPERIMENTAL RESULTS
# ============================================================

results_text = r"""
======================================================================
ZERO GUARD
AI-BASED ZERO-DAY ATTACK DETECTION USING GRAPH NEURAL NETWORKS
======================================================================

RESULTS AND DISCUSSION
======================================================================


4. RESULTS AND DISCUSSION
----------------------------------------------------------------------

4.1 Independent Test Evaluation

The proposed ZeroGuard Graph Neural Network (GNN) was evaluated on
an independent test dataset containing 100,000 samples. The evaluation
was performed using the trained publication GNN model without
retraining the model on the independent test data.

The test feature matrix contained 100,000 samples and 78 features.
The independent test graph contained 635,700 edges. Feature-label
alignment and graph validation both passed successfully before
evaluation.

The model generated predictions for all 100,000 test samples. A total
of 33,840 samples were predicted as benign, while 66,160 samples were
predicted as attacks.


4.2 Confusion Matrix Analysis

The confusion matrix obtained during the independent evaluation is
shown in Table 1.

The model produced 29,056 true negative (TN) predictions, meaning that
these benign samples were correctly classified as benign. The model
also produced 45,216 true positive (TP) predictions, corresponding to
attack samples correctly identified as attacks.

There were 20,944 false positives (FP), where benign samples were
classified as attacks. The evaluation also produced 4,784 false
negatives (FN), where attack samples were classified as benign.

The confusion matrix demonstrates that the model identified a large
number of attack samples while also producing a substantial number of
false-positive predictions. Therefore, both detection capability and
false-alarm reduction remain important considerations for practical
deployment.


4.3 Overall Classification Performance

The overall classification performance is summarized in Table 2.

The ZeroGuard GNN achieved an accuracy of 74.2720%. The precision was
68.3434%, while the recall reached 90.4320%. The resulting F1-score was
77.8512%. The calculated specificity was 58.1120%.

The recall value indicates that the model correctly identified a high
proportion of attack samples in the independent test set. This is
particularly relevant for intrusion detection because missed attacks
can remain undetected.

The precision of 68.3434% indicates that a proportion of samples
classified as attacks were false positives. This is reflected by the
20,944 false-positive predictions in the confusion matrix.

The F1-score of 77.8512% provides a combined measure of precision and
recall and summarizes the balance between correctly identifying attacks
and limiting false-positive predictions.

The specificity of 58.1120% indicates that 58.1120% of benign samples
were correctly identified as benign in this evaluation.


4.4 Unseen Attack-Family Evaluation

A separate evaluation was performed for two attack families:
DDoS and PortScan.

The training-data verification showed zero training rows for both
DDoS and PortScan in the evaluated training configuration. Therefore,
these attack families were treated as unseen during the independent
test evaluation.

For DDoS, 25,000 test samples were evaluated. The model correctly
detected 21,668 samples and missed 3,332 samples, resulting in a
detection rate of 86.6720%.

For PortScan, 25,000 test samples were evaluated. The model detected
23,548 samples and missed 1,452 samples, resulting in a detection rate
of 94.1920%.

The results demonstrate that the model was able to identify both
attack families despite their absence from the evaluated training
rows. The detection rates were different between the two attack
families, indicating that model performance can vary according to the
characteristics of the network behavior represented by each attack
family.


4.5 Discussion

The experimental results indicate that the graph-based approach used
by ZeroGuard can identify attack-related patterns in an independent
network dataset.

The recall of 90.4320% is an important result because it shows that
the model identified a substantial proportion of attack samples in the
independent evaluation. The unseen-family results provide additional
evidence that the trained model was able to classify DDoS and PortScan
samples that were absent from the evaluated training configuration.

At the same time, the results show an important limitation. The
specificity was 58.1120% and the false-positive count was 20,944.
Consequently, a practical Security Operations Center (SOC) deployment
would need mechanisms for reducing false alarms and prioritizing
alerts.

The results should therefore be interpreted as evidence of the
model's performance under the evaluated experimental configuration,
rather than as proof that the system can detect every possible
zero-day attack. Zero-day attacks can differ substantially in their
network behavior, and broader validation using additional unseen
attack families and datasets would strengthen the generalization
claim.

Overall, the evaluation establishes a quantitative baseline for the
ZeroGuard GNN detection component and provides measurable evidence
for further development of the complete SOC workflow, including alert
generation, incident management, and automated response.


4.6 Summary of Experimental Results

The main experimental results are:

- Independent test samples: 100,000
- True negatives: 29,056
- False positives: 20,944
- False negatives: 4,784
- True positives: 45,216
- Accuracy: 74.2720%
- Precision: 68.3434%
- Recall: 90.4320%
- F1-score: 77.8512%
- Specificity: 58.1120%
- DDoS detection rate: 86.6720%
- PortScan detection rate: 94.1920%

The corresponding confusion matrix, performance metrics, and unseen
attack-family figures are included in the ZeroGuard publication
results package.


======================================================================
FIGURE REFERENCES
======================================================================

Figure 1:
figure_1_confusion_matrix.png

Figure 2:
figure_2_classification_metrics.png

Figure 3:
figure_3_unseen_attack_detection.png


======================================================================
TABLE REFERENCES
======================================================================

Table 1:
table_1_confusion_matrix.csv

Table 2:
table_2_overall_performance.csv

Table 3:
table_3_unseen_attack_families.csv


======================================================================
END OF RESULTS AND DISCUSSION
======================================================================
"""


# ============================================================
# WRITE OUTPUT
# ============================================================

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as file:

    file.write(results_text.strip() + "\n")


# ============================================================
# VERIFY
# ============================================================

if not os.path.exists(OUTPUT_FILE):

    raise RuntimeError(
        "Results and Discussion file was not created."
    )


print("=" * 70)
print("ZERO GUARD - STEP 15.10")
print("RESULTS AND DISCUSSION")
print("=" * 70)

print()
print("PASS - Results and Discussion generated")

print()
print("Output:")
print(OUTPUT_FILE)

print()
print("Size:")
print(f"{os.path.getsize(OUTPUT_FILE):,} bytes")

print()
print("Sections included:")
print("PASS - Independent Test Evaluation")
print("PASS - Confusion Matrix Analysis")
print("PASS - Overall Classification Performance")
print("PASS - Unseen Attack-Family Evaluation")
print("PASS - Discussion")
print("PASS - Summary of Experimental Results")
print("PASS - Figure References")
print("PASS - Table References")

print()
print("=" * 70)
print("STEP 15.10 COMPLETE")
print("=" * 70)