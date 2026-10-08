package toolkit

import "testing"

func TestPlannerFromDegradesWithoutPlanner(t *testing.T) {
	if _, ok := PlannerFrom(NewBaseDeps(nil, nil)); ok {
		t.Fatal("a BaseDeps without a planner must report none")
	}
	if _, ok := PlannerFrom(struct{}{}); ok {
		t.Fatal("a non-provider must report none")
	}
}
