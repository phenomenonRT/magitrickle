package models

import "strings"

const keeneticPolicyTargetPrefix = "keenetic-policy:"

type InterfaceInfo struct {
	ID   string
	Name string
	Kind string
}

func KeeneticPolicyTarget(name string) string {
	return keeneticPolicyTargetPrefix + name
}

func ParseKeeneticPolicyTarget(target string) (string, bool) {
	name, ok := strings.CutPrefix(target, keeneticPolicyTargetPrefix)
	return name, ok && name != ""
}
