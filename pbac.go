package pbac

import (
	"fmt"

	siftjs "github.com/bhoriuchi/go-siftjs"
)

const (
	// AllowEffect allow
	AllowEffect = "allow"

	// DenyEffect deny
	DenyEffect = "deny"
)

// AccessPolicyCollection a collection of access policies
type AccessPolicyCollection []AccessPolicy

// FlattenStatements produces a flat attay of access statements
func (c *AccessPolicyCollection) FlattenStatements() *[]AccessStatement {
	statements := make([]AccessStatement, 0)
	collection := *c
	for _, policy := range collection {
		statements = append(statements, policy.Statement...)
	}
	return &statements
}

// AccessPolicy defines an access policy containing one or more access statements
type AccessPolicy struct {
	ID        string            `json:"id" yaml:"id"`
	Name      string            `json:"name" yaml:"name"`
	Version   string            `json:"version" yaml:"version"`
	Statement []AccessStatement `json:"statement" yaml:"statement"`
}

// AccessPolicyMutation defines a mutation of an access policy
type AccessPolicyMutation struct {
	Name      string                    `json:"name" yaml:"name"`
	Version   string                    `json:"version" yaml:"version"`
	Statement []AccessStatementMutation `json:"statement" yaml:"statement"`
}

// ValidateCreate validates an AccessPolicy create document
func (c *AccessPolicyMutation) ValidateCreate() error {
	if c.Name == "" {
		return fmt.Errorf("required field %q not specified", "name")
	}
	if c.Version == "" {
		return fmt.Errorf("required field %q not specified", "version")
	}
	if len(c.Statement) == 0 {
		return fmt.Errorf("no statements were specified")
	}
	for i, s := range c.Statement {
		if err := s.ValidateCreate(); err != nil {
			return fmt.Errorf("statement %d: %s", i, err.Error())
		}
	}

	return nil
}

// AccessStatement an access policy statement
type AccessStatement struct {
	ID        string      `json:"id" yaml:"id"`
	Effect    string      `json:"effect" yaml:"effect"`
	Action    interface{} `json:"action" yaml:"action"`
	Resource  interface{} `json:"resource" yaml:"resource"`
	Condition interface{} `json:"condition" yaml:"condition"`
}

// AccessStatementMutation an access policy mutation
type AccessStatementMutation struct {
	Effect    string      `json:"effect" yaml:"effect"`
	Action    interface{} `json:"action" yaml:"action"`
	Resource  interface{} `json:"resource" yaml:"resource"`
	Condition interface{} `json:"condition" yaml:"condition"`
}

// ValidateCreate validates an AccessStatement create document
func (c *AccessStatementMutation) ValidateCreate() error {
	if c.Effect != AllowEffect && c.Effect != DenyEffect {
		return fmt.Errorf("invalid access statement effect")
	}
	if !isValidArrayOrString(c.Action) {
		return fmt.Errorf("invalid action")
	}
	if !isValidArrayOrString(c.Resource) {
		return fmt.Errorf("invalid resource")
	}
	if !isMap(c.Condition) {
		return fmt.Errorf("invalid condition")
	}
	return nil
}

// AccessRequest is the request for resource access
type AccessRequest struct {
	Action   string
	Resource string
	Context  interface{}
}

// internal access request type
type effectiveAccessRequest struct {
	effect  string
	request *AccessRequest
}

// NewPBAC creates a new PBAC
func NewPBAC(policy *[]AccessStatement) *PBAC {
	return &PBAC{policy: policy}
}

// PBAC policy based access control
type PBAC struct {
	policy *[]AccessStatement
}

// SetPolicy updates the policy
func (c *PBAC) SetPolicy(policy *[]AccessStatement) {
	c.policy = policy
}

// Evaluate evaluates the access request against the policy
func (c *PBAC) Evaluate(req *AccessRequest) bool {
	// check for denies
	if c.matchStatements(&effectiveAccessRequest{
		effect:  DenyEffect,
		request: req,
	}) {
		return false
	}

	// check for allows
	if c.matchStatements(&effectiveAccessRequest{
		effect:  AllowEffect,
		request: req,
	}) {
		return true
	}

	// no matches are a deny
	return false
}

// matches all policy statements against the request
func (c *PBAC) matchStatements(req *effectiveAccessRequest) bool {
	context, err := arrayify(req.request.Context)
	if err != nil {
		return false
	}
	if c.policy == nil {
		return false
	}

	// dereference pointer
	policy := *c.policy
	for _, s := range policy {
		actions, err := arrayify(s.Action)
		if err != nil {
			return false
		}
		resources, err := arrayify(s.Resource)
		if err != nil {
			return false
		}
		if req.effect == s.Effect &&
			matchCollection(actions, req.request.Action) &&
			matchCollection(resources, req.request.Resource) &&
			len(siftjs.Sift(s.Condition, context)) > 0 {
			return true
		}
	}
	return false
}

// matches a collection with a value
func matchCollection(values []interface{}, value interface{}) bool {
	val := fmt.Sprintf("%v", value)
	if val == "" {
		return false
	}
	for _, v := range values {
		s := fmt.Sprintf("%v", v)
		if val == s {
			return true
		} else if s != "" {
			end := len(s) - 1
			if s[end:] == "*" && val[:end] == s[:end] {
				return true
			}
		}
	}
	return false
}
