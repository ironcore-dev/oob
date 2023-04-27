package controllers

import (
	"math"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func newRandInt64() *int64 {
	return &(&struct{ x int64 }{1 + rand.Int63nRange(0, math.MaxInt64)}).x
}

func getCondition(conds []metav1.Condition, typ string) *metav1.Condition {
	for _, c := range conds {
		if c.Type == typ {
			return &c
		}
	}
	return nil
}

func setCondition(conds []metav1.Condition, cond metav1.Condition) []metav1.Condition {
	if cond.LastTransitionTime.IsZero() {
		cond.LastTransitionTime = metav1.Now()
	}

	c := getCondition(conds, cond.Type)
	if c == nil {
		return []metav1.Condition{cond}
	}

	if cond.Status == c.Status && !c.LastTransitionTime.IsZero() {
		cond.LastTransitionTime = c.LastTransitionTime
	}

	return []metav1.Condition{cond}
}

// TODO: Remove this ugly workaround for https://github.com/kubernetes-sigs/controller-runtime/issues/2125
type fouw struct{}

var forceOwnershipUglyWorkaround = fouw{}

func (fouw) ApplyToSubResourcePatch(opts *client.SubResourcePatchOptions) {
	opts.Force = &(&struct{ x bool }{true}).x
}
