package pbac

import (
	"encoding/json"
	"testing"
)

var policyJSON = `
[
	{
		"effect": "allow",
		"action": "*",
		"resource": "*",
		"condition": {
			"claims": {
				"resource_access": {
					"service": {
						"roles": {
							"$all": ["root"]
						}
					}
				}
			}
		}
	},
	{
		"effect": "deny",
		"action": "*",
		"resource": "*",
		"condition": {
			"claims": {
				"resource_access": {
					"service": {
						"roles": {
							"$all": ["disabled"]
						}
					}
				}
			}
		}
	}
]
`
var req1JSON = `
{
	"action": "read",
	"resource": "/api/service/foo",
	"context": {
		"http_method": "GET",
		"uri": "/api/service/foo",
		"client_address": "::1",
		"claims": {
			"resource_access": {
				"service": {
					"roles": ["user", "root"]
				}
			}
		}
	}
}
`

var req2JSON = `
{
	"action": "read",
	"resource": "/api/service/foo",
	"context": {
		"http_method": "GET",
		"uri": "/api/service/foo",
		"client_address": "::1",
		"claims": {
			"resource_access": {
				"service": {
					"roles": ["user"]
				}
			}
		}
	}
}
`

var req3JSON = `
{
	"action": "read",
	"resource": "/api/service/foo",
	"context": {
		"http_method": "GET",
		"uri": "/api/service/foo",
		"client_address": "::1",
		"claims": {
			"resource_access": {
				"service": {
					"roles": ["root", "disabled"]
				}
			}
		}
	}
}
`

func TestPBAC(t *testing.T) {
	policy := make([]AccessStatement, 0)
	json.Unmarshal([]byte(policyJSON), &policy)
	pbac := NewPBAC(&policy)

	req1 := AccessRequest{}
	json.Unmarshal([]byte(req1JSON), &req1)

	req2 := AccessRequest{}
	json.Unmarshal([]byte(req2JSON), &req2)

	req3 := AccessRequest{}
	json.Unmarshal([]byte(req3JSON), &req3)

	allow1 := pbac.Evaluate(&req1)
	allow2 := pbac.Evaluate(&req2)
	allow3 := pbac.Evaluate(&req3)

	if !allow1 {
		t.Errorf("failed to match req1")
	}
	if allow2 {
		t.Errorf("failed to match req2")
	}
	if allow3 {
		t.Errorf("failed to match req3")
	}
}
