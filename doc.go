/*
Package pbac provides policy based access control using policy statements similar to AWS IAM

Usage

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
	var reqJSON = `
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
	policy := make([]AccessStatement, 0)
	json.Unmarshal([]byte(policyJSON), &policy)
	pbac := NewPBAC(&policy)

	req := AccessRequest{}
	json.Unmarshal([]byte(reqJSON), &req)
	allowed := pbac.Evaluate(req)
*/
package pbac
