package result

import "sort"

// SortBy defines a sort strategy for results.
type SortBy string

const (
	SortByModule     SortBy = "module"
	SortByType       SortBy = "type"
	SortByConfidence SortBy = "confidence"
	SortByTimestamp  SortBy = "timestamp"
)

// Sort sorts results in-place by the given strategy.
// Within a strategy's primary grouping, results are sub-sorted by Value
// alphabetically for deterministic output.
func Sort(results []Result, by SortBy) {
	confidenceRank := map[Confidence]int{
		ConfidenceHigh:   3,
		ConfidenceMedium: 2,
		ConfidenceLow:    1,
		"":               0,
	}

	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		switch by {
		case SortByModule:
			if a.Module != b.Module {
				return a.Module < b.Module
			}
			return a.Value < b.Value
		case SortByType:
			if a.Type != b.Type {
				return a.Type < b.Type
			}
			return a.Value < b.Value
		case SortByConfidence:
			ra, rb := confidenceRank[a.Confidence], confidenceRank[b.Confidence]
			if ra != rb {
				return ra > rb // descending
			}
			return a.Value < b.Value
		case SortByTimestamp:
			if !a.Timestamp.Equal(b.Timestamp) {
				return a.Timestamp.Before(b.Timestamp)
			}
			return a.Value < b.Value
		default:
			return a.Value < b.Value
		}
	})
}
