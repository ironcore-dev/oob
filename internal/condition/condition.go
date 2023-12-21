package condition

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

func GetCondition(conds []metav1.Condition, typ string) *metav1.Condition {
	for _, c := range conds {
		if c.Type == typ {
			return &c
		}
	}
	return nil
}

func SetCondition(conds []metav1.Condition, cond metav1.Condition) []metav1.Condition {
	if cond.LastTransitionTime.IsZero() {
		cond.LastTransitionTime = metav1.Now()
	}

	c := GetCondition(conds, cond.Type)
	if c == nil {
		return []metav1.Condition{cond}
	}

	if cond.Status == c.Status && !c.LastTransitionTime.IsZero() {
		cond.LastTransitionTime = c.LastTransitionTime
	}

	return []metav1.Condition{cond}
}
