# Casbin SegmentQ Adapter

[![Go Report Card](https://goreportcard.com/badge/github.com/segmentq/casbin-segmentq-adapter)](https://goreportcard.com/report/github.com/segmentq/casbin-segmentq-adapter)
[![Go Reference](https://pkg.go.dev/badge/github.com/segmentq/casbin-segmentq-adapter.svg)](https://pkg.go.dev/github.com/segmentq/casbin-segmentq-adapter)
[![Build](https://github.com/segmentq/casbin-segmentq-adapter/actions/workflows/build.yml/badge.svg)](https://github.com/segmentq/casbin-segmentq-adapter/actions/workflows/build.yml)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=segmentq_casbin-segmentq-adapter&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=segmentq_casbin-segmentq-adapter)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=segmentq_casbin-segmentq-adapter&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=segmentq_casbin-segmentq-adapter)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=segmentq_casbin-segmentq-adapter&metric=coverage)](https://sonarcloud.io/summary/new_code?id=segmentq_casbin-segmentq-adapter)

The [SegmentQ DB](https://github.com/segmentq/db) adapter for [Casbin](https://github.com/casbin/casbin). 
You can use this library to load and save policies to an SegmentQ DB.

## Installation
```shell
go get github.com/segmentq/casbin-segmentq-adapter
```

## Simple Example

```go
package main

import (
	"context"
	adapter "github.com/segmentq/casbin-segmentq-adapter"
	"github.com/casbin/casbin/v2"
	"github.com/segmentq/db"
)

func main() {
	// Initialize some instance of SegmentQ DB
	segmentq, _ := db.NewDB(context.Background())
	
	// Initialize a SegmentQ adapter and use it in a Casbin enforcer:
	// The adapter will use a SegmentQ DB Index named "casbin_rule".
	// If it doesn't exist, the adapter will create it automatically.
	a, _ := adapter.NewAdapter(segmentq)

	// Create the enforcer
	e := casbin.NewEnforcer("examples/rbac_model.conf", a)

	// Load the policy from DB.
	e.LoadPolicy()

	// Check the permission.
	e.Enforce("alice", "data1", "read")

	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)

	// Save the policy back to DB.
	e.SavePolicy()
}
```
