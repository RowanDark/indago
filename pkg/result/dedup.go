package result

// Deduplicate removes results with identical (Type, Value, Source) triples,
// keeping the first occurrence. Order is preserved.
func Deduplicate(results []Result) []Result {
	seen := make(map[string]struct{})
	out := make([]Result, 0, len(results))
	for _, r := range results {
		key := string(r.Type) + "|" + r.Value + "|" + r.Source
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}
	return out
}

// DeduplicateByValue removes results with identical (Type, Value) pairs
// regardless of source, keeping the highest-confidence occurrence.
func DeduplicateByValue(results []Result) []Result {
	rank := map[Confidence]int{
		ConfidenceHigh:   3,
		ConfidenceMedium: 2,
		ConfidenceLow:    1,
		"":               0,
	}

	best := make(map[string]Result)
	order := make([]string, 0)

	for _, r := range results {
		key := string(r.Type) + "|" + r.Value
		existing, found := best[key]
		if !found {
			best[key] = r
			order = append(order, key)
		} else if rank[r.Confidence] > rank[existing.Confidence] {
			best[key] = r
		}
	}

	out := make([]Result, 0, len(order))
	for _, key := range order {
		out = append(out, best[key])
	}
	return out
}
