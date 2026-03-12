package flow

type State string

type Scenario string

const (
	StateInitiated   State = "initiated"
	StateUserPicked  State = "user_picked"
	StateMFAPending  State = "mfa_pending"
	StateMFAApproved State = "mfa_approved"
	StateMFADenied   State = "mfa_denied"
	StateComplete    State = "complete"
	StateError       State = "error"
)

const (
	ScenarioNormal        Scenario = "normal"
	ScenarioMFAFail       Scenario = "mfa_fail"
	ScenarioAccountLocked Scenario = "account_locked"
	ScenarioSlowMFA       Scenario = "slow_mfa"
	ScenarioExpiredToken  Scenario = "expired_token"
)

var validTransitions = map[State]map[State]struct{}{
	StateInitiated: {
		StateUserPicked: {},
		StateError:      {},
	},
	StateUserPicked: {
		StateMFAPending: {},
		StateComplete:   {},
		StateError:      {},
	},
	StateMFAPending: {
		StateMFAApproved: {},
		StateMFADenied:   {},
		StateError:       {},
	},
	StateMFAApproved: {
		StateComplete: {},
	},
	StateComplete:  {},
	StateMFADenied: {},
	StateError:     {},
}

func CanTransition(from State, to State) bool {
	transitions, ok := validTransitions[from]
	if !ok {
		return false
	}
	_, ok = transitions[to]
	return ok
}

func NormalizeScenario(value string) Scenario {
	s := Scenario(value)
	switch s {
	case ScenarioMFAFail, ScenarioAccountLocked, ScenarioSlowMFA, ScenarioExpiredToken:
		return s
	default:
		return ScenarioNormal
	}
}

func RequiresMFA(method string) bool {
	switch method {
	case "totp", "push", "sms", "magic_link":
		return true
	default:
		return false
	}
}
