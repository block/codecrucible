package decision

// CWEQuestion classifies a reported mechanism; it does not certify validity.
// Keep this contract shared by runtime classification and fixed-case evaluation.
func CWEQuestion(options map[string]string) Question {
	return Choice("Classify the primary root-cause mechanism described by the finding using the supplied source. Choose the most specific justified definition, respecting its mapping notes. Distinguish a root cause from a consequence. If distinct root causes are combined, use none_of_these. This bounded candidate list may omit the correct CWE: use none_of_these then. Do not force a Base/Variant when its distinguishing condition is unproven. This classification does not validate exploitability or certify the finding.", options)
}
