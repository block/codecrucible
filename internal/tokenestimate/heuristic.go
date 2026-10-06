package tokenestimate

import "math"

// heuristicCount estimates token count using a content-aware chars/token ratio
// plus a 10% safety margin. Code tokenizes much more densely than prose — every
// brace, paren, operator, and separator becomes its own token — so a fixed 4.0
// undercounts C/Rust/Go by 25-35%.
func heuristicCount(text string) int {
	chars := len(text) // byte length ≈ char length for ASCII-heavy source code
	ratio := charsPerTokenRatio(text)
	raw := float64(chars) / ratio
	return int(math.Ceil(raw * 1.1))
}

// charsPerTokenRatio samples the first 4KB to classify the text and pick a
// chars/token ratio. Punctuation density is a strong signal: prose runs ~2%,
// source code runs 12-20%. Returns a ratio between 3.0 (dense code) and 4.0
// (prose). The sample is small to keep counting cheap even on large files.
func charsPerTokenRatio(text string) float64 {
	sample := text
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	if len(sample) == 0 {
		return 4.0
	}
	var punct int
	for i := 0; i < len(sample); i++ {
		switch sample[i] {
		case '{', '}', '(', ')', '[', ']', ';', ',', '.', ':',
			'<', '>', '=', '-', '+', '*', '/', '&', '|', '!',
			'"', '\'', '#', '%', '^', '~', '?', '@', '\\':
			punct++
		}
	}
	density := float64(punct) / float64(len(sample))
	switch {
	case density > 0.12:
		return 3.0
	case density > 0.06:
		return 3.5
	default:
		return 4.0
	}
}
