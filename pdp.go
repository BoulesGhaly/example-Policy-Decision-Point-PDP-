package main

import (
	"fmt"
	"strconv"
	"time"
)

var counter int
var countercondition int
var keeptrack int
var policynum int

type PolicySet struct {
	Policies []Policy
}

type Policy struct {
	Name  string
	Rules []Rule
}

type Rule struct {
	Name        string
	Target      string
	Conditions  []Condition
	Effect      string
	Obligations []Obligation
}

type Condition struct {
	Attribute string
	Operator  string
	Value     string
}

type Obligation struct {
	Action  string
	Details map[string]string
}

func evaluatePolicySet(policySet PolicySet, input map[string]string) (string, []Obligation) {
	policynum = 0
	for _, policy := range policySet.Policies {
		policynum = policynum + 1
		counter = 0
		for _, rule := range policy.Rules {
			counter = counter + 1
			if evaluateConditions(rule.Conditions, input, counter, policynum) {
				fmt.Printf("Applied Rule: %s\n", rule.Name)
				if rule.Effect == "permit" {
					return "permit", rule.Obligations
				}
			}
		}
	}
	return "deny", nil
}

func evaluateConditions(conditions []Condition, input map[string]string, counter int, policynum int) bool {
	keeptrack = 0
	countercondition = 0
	for _, condition := range conditions {
		countercondition = countercondition + 1
		value, exists := input[condition.Attribute]
		if !exists {
			//fmt.Printf("Condition failed: %s not found in input\n", condition.Attribute)
			return false
		}
		if !evaluateCondition(condition.Operator, value, condition.Value) {
			//fmt.Printf("Condition failed: %s %s %s (input value: %s)\n", condition.Attribute, condition.Operator, condition.Value, value)
			if policynum == 1 {
				keeptrack = keeptrack + 1
				if counter == 2 && keeptrack == 2 {
					return false
				}
				if counter == 1 {
					return false
				}
			}
			if policynum != 1 {
				return false
			}

		}
	}
	return true
}

func evaluateCondition(operator, value, expected string) bool {
	switch operator {
	case "==":
		return value == expected
	case ">":
		return compareValues(value, expected, ">")
	case "<":
		return compareValues(value, expected, "<")
	case "!=":
		return compareValues(value, expected, "!=")
	default:
		return false
	}
}

func compareValues(value, expected, operator string) bool {
	// Try parsing as time
	layout := "15:04:05"
	valTime, err1 := time.Parse(layout, value)
	expTime, err2 := time.Parse(layout, expected)
	if err1 == nil && err2 == nil {
		switch operator {
		case ">":
			return valTime.After(expTime)
		case "<":
			return valTime.Before(expTime)
		}
	}

	// Try parsing as int
	valInt, err1 := strconv.Atoi(value)
	expInt, err2 := strconv.Atoi(expected)
	if err1 == nil && err2 == nil {
		switch operator {
		case "==":
			return valInt == expInt
		case ">":
			return valInt > expInt
		case "<":
			return valInt < expInt
		case "!=":
			return valInt != expInt
		}
	}

	return true
}

func main() {
	// Define example policy set
	policySet := PolicySet{
		Policies: []Policy{
			{
				Name: "serviceAccess",
				Rules: []Rule{
					{
						Name:   "normalUserBehavior",
						Target: `request.service == "service"`,
						Conditions: []Condition{
							{"CurrentTime", ">", "08:00:00"},
							{"CurrentTime", "<", "18:00:00"},
							{"user.accessRate", "<", "database.accessRateThreshold"},
						},
						Effect: "permit",
					},
					{
						Name:   "atypicalUserBehavior",
						Target: "request.service == \"service\"",
						Conditions: []Condition{
							{"CurrentTime", "<", "08:00:00"},
							{"CurrentTime", ">", "18:00:00"},
							{"user.accessRate", ">", "database.accessRateThreshold"},
						},
						Effect: "permit",
						Obligations: []Obligation{
							{
								Action: "apply_sfc",
								Details: map[string]string{
									"sfc":            "ssf.mfa, ssf.ids",
									"ssf.mfa_action": "two-factor authentication",
									"ssf.ids_action": "anomaly detection",
								},
							},
						},
					},
				},
			},
			{
				Name: "fingerprint",
				Rules: []Rule{
					{
						Name:   "normalFingerprint",
						Target: `request.service == "service"`,
						Conditions: []Condition{
							{"device.fingerprint", "==", "database.savedFingerprint"},
						},
						Effect: "permit",
					},
					{
						Name:   "differentSerialNum",
						Target: `request.service == "service"`,
						Conditions: []Condition{
							{"device.serialNum", "!=", "database.savedSerialNum"},
						},
						Effect: "deny",
					},
					{
						Name:   "differentFingerprint",
						Target: `request.service == "service"`,
						Conditions: []Condition{
							{"device.fingerprint", "!=", "database.savedFingerprint"},
						},
						Effect: "permit",
						Obligations: []Obligation{
							{
								Action: "apply_sfc",
								Details: map[string]string{
									"sfc":               "ssf_ips, ssf_logger",
									"ssf.ids_action":    "anomaly based intrusion detection",
									"ssf.logger_action": "headerlogging",
								},
							},
						},
					},
				},
			},
		},
	}
	// Define input scenarios
	scenarios := []map[string]string{
		// Existing scenarios
		{
			"request.service":              "service",
			"CurrentTime":                  "09:00:00",
			"user.accessRate":              "5",
			"database.accessRateThreshold": "10",
		},
		{
			"request.service":              "service",
			"CurrentTime":                  "07:00:00",
			"user.accessRate":              "12",
			"database.accessRateThreshold": "10",
		},
		{
			"request.service":              "service",
			"CurrentTime":                  "19:00:00",
			"user.accessRate":              "15",
			"database.accessRateThreshold": "10",
		},
	}

	for i, input := range scenarios {
		fmt.Printf("Scenario %d:\n", i+1)
		decision, obligations := evaluatePolicySet(policySet, input)
		fmt.Printf("Decision: %s\n", decision)
		if decision == "permit" {
			fmt.Println("Obligations:")
			for _, obligation := range obligations {
				fmt.Printf("  Action: %s\n", obligation.Action)
				for key, value := range obligation.Details {
					fmt.Printf("    %s: %s\n", key, value)
				}
			}
		}
		fmt.Println()
	}
}
