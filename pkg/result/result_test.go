package result

import (
	"testing"
	"time"
)

func TestNew_SetsTimestamp(t *testing.T) {
	before := time.Now()
	r := New(TypeEmail, "test@example.com", "source", "module")
	after := time.Now()

	if r.Timestamp.IsZero() {
		t.Fatal("expected non-zero Timestamp")
	}
	if r.Timestamp.Before(before) || r.Timestamp.After(after) {
		t.Errorf("Timestamp %v not in expected range [%v, %v]", r.Timestamp, before, after)
	}
}

func TestNew_InitializesMeta(t *testing.T) {
	r := New(TypeEmail, "test@example.com", "source", "module")
	if r.Meta == nil {
		t.Fatal("expected non-nil Meta map")
	}
}

func TestWithConfidence(t *testing.T) {
	r := New(TypeEmail, "test@example.com", "source", "module")
	got := r.WithConfidence(ConfidenceHigh)

	if got.Confidence != ConfidenceHigh {
		t.Errorf("expected confidence %q, got %q", ConfidenceHigh, got.Confidence)
	}
	if r.Confidence != "" {
		t.Errorf("original result was mutated: confidence = %q", r.Confidence)
	}
}

func TestWithTags_Appends(t *testing.T) {
	base := New(TypeEmail, "test@example.com", "source", "module")

	r1 := base.WithTags("tag1", "tag2")
	r2 := base.WithTags("tag3")

	if len(r1.Tags) != 2 {
		t.Errorf("r1: expected 2 tags, got %d: %v", len(r1.Tags), r1.Tags)
	}
	if r1.Tags[0] != "tag1" || r1.Tags[1] != "tag2" {
		t.Errorf("r1: unexpected tags: %v", r1.Tags)
	}

	if len(r2.Tags) != 1 {
		t.Errorf("r2: expected 1 tag, got %d: %v", len(r2.Tags), r2.Tags)
	}
	if r2.Tags[0] != "tag3" {
		t.Errorf("r2: unexpected tags: %v", r2.Tags)
	}
}

func TestWithMeta_SetsKey(t *testing.T) {
	r := New(TypeEmail, "test@example.com", "source", "module")
	got := r.WithMeta("key", "value")

	if got.Meta["key"] != "value" {
		t.Errorf("expected Meta[\"key\"]=\"value\", got %v", got.Meta["key"])
	}
}

func TestWithMeta_InitialisesNilMap(t *testing.T) {
	r := Result{Meta: nil}
	got := r.WithMeta("key", "value")

	if got.Meta == nil {
		t.Fatal("expected non-nil Meta after WithMeta on nil map")
	}
	if got.Meta["key"] != "value" {
		t.Errorf("expected Meta[\"key\"]=\"value\", got %v", got.Meta["key"])
	}
}
