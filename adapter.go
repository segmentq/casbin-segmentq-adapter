package sqadapter

import (
	"fmt"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/mmcloughlin/meow"
	"github.com/segmentq/db"
	api "github.com/segmentq/protos-api-go"
	"google.golang.org/api/iterator"
	"strconv"
	"strings"
)

const DefaultIndexName = "casbin_rule"

type Adapter struct {
	db              *db.DB
	indexName       string
	indexDefinition *api.IndexDefinition
	index           *db.Index
}

type Option func(a *Adapter)

func NewAdapter(db *db.DB, opts ...Option) (*Adapter, error) {
	a := &Adapter{
		db:        db,
		indexName: DefaultIndexName,
	}

	for _, opt := range opts {
		opt(a)
	}

	err := a.init()
	if err != nil {
		return nil, err
	}
	return a, nil
}

func WithIndexName(name string) Option {
	return func(a *Adapter) {
		a.indexName = name
	}
}

func (a *Adapter) init() error {
	if index, err := a.db.GetIndexByName(a.indexName); err == nil {
		// Index is already initialised
		a.index = index
		return nil
	}

	a.setDefaultIndexDefinition()

	index, err := a.db.CreateIndex(a.indexDefinition)
	if err != nil {
		return err
	}

	a.index = index
	return nil
}

func (a *Adapter) setDefaultIndexDefinition() {
	stringType := &api.FieldDefinition_Scalar{Scalar: api.ScalarType_DATA_TYPE_STRING}

	a.indexDefinition = &api.IndexDefinition{
		Name: a.indexName,
		Fields: []*api.FieldDefinition{
			{Name: "id", DataType: stringType, IsPrimary: true},
			{Name: "ptype", DataType: stringType},
			{Name: "v0", DataType: stringType},
			{Name: "v1", DataType: stringType},
			{Name: "v2", DataType: stringType},
			{Name: "v3", DataType: stringType},
			{Name: "v4", DataType: stringType},
			{Name: "v5", DataType: stringType},
		},
	}
}

// LoadPolicy loads all policy rules from the storage.
func (a *Adapter) LoadPolicy(model model.Model) error {
	var innerErr error
	err := a.index.GetAllSegments(func(segment *api.Segment) bool {
		err2 := persist.LoadPolicyLine(policyLine(segment), model)
		if err2 != nil {
			innerErr = err2
			return false
		}
		return true
	})
	if err != nil {
		return err
	}
	if innerErr != nil {
		return innerErr
	}

	return nil
}

func policyLine(segment *api.Segment) string {
	var pType string
	values := make([]string, 8)

	for _, f := range segment.Fields {
		switch f.Name {
		case "ptype":
			pType = f.GetStringValue().GetValue()
		default:
			i, _ := strconv.Atoi(f.Name[1:])
			values[i] = f.GetStringValue().GetValue()
		}
	}

	policy := pType
	for _, v := range values {
		if len(v) == 0 {
			break
		}
		policy += ", "
		policy += v
	}

	return policy
}

// SavePolicy saves all policy rules to the storage.
func (a *Adapter) SavePolicy(model model.Model) error {
	segments := make([]*api.Segment, 0)

	for pType, ast := range model["p"] {
		for _, rule := range ast.Policy {
			segments = append(segments, policyArgs(pType, rule))
		}
	}

	for pType, ast := range model["g"] {
		for _, rule := range ast.Policy {
			segments = append(segments, policyArgs(pType, rule))
		}
	}

	err := a.index.Truncate()
	if err != nil {
		return err
	}

	for _, segment := range segments {
		_, err2 := a.index.InsertSegment(segment)
		if err2 != nil {
			return err2
		}
	}

	return nil
}

func policyID(ptype string, rule []string) string {
	data := strings.Join(append([]string{ptype}, rule...), ",")
	sum := meow.Checksum(0, []byte(data))
	return fmt.Sprintf("%x", sum)
}

func policyArgs(ptype string, rule []string) *api.Segment {
	id := policyID(ptype, rule)
	segment := &api.Segment{
		Fields: make([]*api.SegmentField, 8),
	}

	segment.Fields[0] = &api.SegmentField{
		Name:  "id",
		Value: &api.SegmentField_StringValue{StringValue: &api.SegmentFieldString{Value: id}},
	}
	segment.Fields[1] = &api.SegmentField{
		Name:  "ptype",
		Value: &api.SegmentField_StringValue{StringValue: &api.SegmentFieldString{Value: ptype}},
	}

	l := len(rule)
	for i := 0; i < 6; i++ {
		value := ""
		if i < l {
			value = rule[i]
		}

		segment.Fields[2+i] = &api.SegmentField{
			Name:  "v" + strconv.Itoa(i),
			Value: &api.SegmentField_StringValue{StringValue: &api.SegmentFieldString{Value: value}},
		}
	}

	return segment
}

// AddPolicy adds a policy rule to the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	_, err := a.index.InsertSegment(policyArgs(ptype, rule))
	return err
}

// RemovePolicy removes a policy rule from the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	_, err := a.index.DeleteSegment(policyID(ptype, rule))
	return err
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	lookup := &api.Lookup{
		Fields: []*api.LookupField{
			{
				Name:  "ptype",
				Value: &api.LookupField_StringValue{StringValue: &api.SegmentFieldString{Value: ptype}},
			},
		},
	}

	idx := fieldIndex + len(fieldValues)
	for i := 0; i < 6; i++ {
		if fieldIndex <= i && idx > i && fieldValues[i-fieldIndex] != "" {
			lookup.Fields = append(lookup.Fields, &api.LookupField{
				Name: "v" + strconv.Itoa(i),
				Value: &api.LookupField_StringValue{StringValue: &api.SegmentFieldString{
					Value: fieldValues[i-fieldIndex],
				}},
			})
		}
	}

	it, err := a.index.Lookup(lookup)
	if err != nil {
		return err
	}

	for {
		key, err2 := it.Next(nil)
		if err2 == iterator.Done {
			break
		}
		if err2 != nil {
			return err2
		}
		if _, err2 = a.index.DeleteSegment(key); err2 != nil {
			return err2
		}
	}

	return nil
}
