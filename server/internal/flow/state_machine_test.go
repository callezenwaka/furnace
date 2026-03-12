package flow

import "testing"

func TestCanTransition(t *testing.T) {
	if !CanTransition(StateInitiated, StateUserPicked) {
		t.Fatal("expected initiated -> user_picked to be valid")
	}
	if CanTransition(StateComplete, StateMFAPending) {
		t.Fatal("expected complete -> mfa_pending to be invalid")
	}
}

func TestNormalizeScenario(t *testing.T) {
	if got := NormalizeScenario("mfa_fail"); got != ScenarioMFAFail {
		t.Fatalf("expected mfa_fail, got %q", got)
	}
	if got := NormalizeScenario("unknown"); got != ScenarioNormal {
		t.Fatalf("expected normal for unknown scenario, got %q", got)
	}
}
