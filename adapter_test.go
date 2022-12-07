package sqadapter

import (
	"context"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/segmentq/db"
	api "github.com/segmentq/protos-api-go"
	"reflect"
	"testing"
)

func testNewAdapter(t *testing.T) *Adapter {
	sq, _ := db.NewDB(context.Background())
	a, err := NewAdapter(sq)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func rbacModel() model.Model {
	m, _ := model.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`)
	return m
}

func rbacPolicies(model model.Model) {
	loadPolicyLineArray([]string{
		"p, alice, data1, read",
		"p, bob, data2, write",
		"p, data2_admin, data2, read",
		"p, data2_admin, data2, write",
		"g, alice, data2_admin",
	}, model)
}

func loadPolicyLineArray(policies []string, model model.Model) {
	for _, p := range policies {
		_ = persist.LoadPolicyLine(p, model)
	}
}

func TestAdapter_AddPolicy(t *testing.T) {
	a := testNewAdapter(t)
	type fields struct {
		db              *db.DB
		indexName       string
		indexDefinition *api.IndexDefinition
		index           *db.Index
	}
	type args struct {
		sec   string
		ptype string
		rule  []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test length 3",
			fields: fields{
				db:              a.db,
				indexName:       a.indexName,
				indexDefinition: a.indexDefinition,
				index:           a.index,
			},
			args: args{
				sec:   "",
				ptype: "p",
				rule:  []string{"subject", "object", "action"},
			},
			wantErr: false,
		},
		{
			name: "test length 4",
			fields: fields{
				db:              a.db,
				indexName:       a.indexName,
				indexDefinition: a.indexDefinition,
				index:           a.index,
			},
			args: args{
				sec:   "",
				ptype: "p",
				rule:  []string{"subject", "object", "action", "effect"},
			},
			wantErr: false,
		},
		{
			name: "test length 5",
			fields: fields{
				db:              a.db,
				indexName:       a.indexName,
				indexDefinition: a.indexDefinition,
				index:           a.index,
			},
			args: args{
				sec:   "",
				ptype: "p",
				rule:  []string{"priority", "subject", "object", "action", "effect"},
			},
			wantErr: false,
		},
		{
			name: "test length 6",
			fields: fields{
				db:              a.db,
				indexName:       a.indexName,
				indexDefinition: a.indexDefinition,
				index:           a.index,
			},
			args: args{
				sec:   "",
				ptype: "p",
				rule:  []string{"priority", "domain", "subject", "object", "action", "effect"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Adapter{
				db:              tt.fields.db,
				indexName:       tt.fields.indexName,
				indexDefinition: tt.fields.indexDefinition,
				index:           tt.fields.index,
			}
			if err := a.AddPolicy(tt.args.sec, tt.args.ptype, tt.args.rule); (err != nil) != tt.wantErr {
				t.Errorf("AddPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAdapter_LoadPolicy(t *testing.T) {
	a := testNewAdapter(t)
	m := rbacModel()
	rbacPolicies(m)

	_ = a.SavePolicy(m)

	type fields struct {
		db              *db.DB
		indexName       string
		indexDefinition *api.IndexDefinition
		index           *db.Index
	}
	type args struct {
		model model.Model
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "golden path",
			fields: fields{
				db:              a.db,
				indexName:       a.indexName,
				indexDefinition: a.indexDefinition,
				index:           a.index,
			},
			args: args{
				model: rbacModel(),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Adapter{
				db:              tt.fields.db,
				indexName:       tt.fields.indexName,
				indexDefinition: tt.fields.indexDefinition,
				index:           tt.fields.index,
			}
			if err := a.LoadPolicy(tt.args.model); (err != nil) != tt.wantErr {
				t.Errorf("LoadPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAdapter_RemoveFilteredPolicy(t *testing.T) {
	type fields struct {
		db              *db.DB
		indexName       string
		indexDefinition *api.IndexDefinition
		index           *db.Index
	}
	type args struct {
		sec         string
		ptype       string
		fieldIndex  int
		fieldValues []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Adapter{
				db:              tt.fields.db,
				indexName:       tt.fields.indexName,
				indexDefinition: tt.fields.indexDefinition,
				index:           tt.fields.index,
			}
			if err := a.RemoveFilteredPolicy(tt.args.sec, tt.args.ptype, tt.args.fieldIndex, tt.args.fieldValues...); (err != nil) != tt.wantErr {
				t.Errorf("RemoveFilteredPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAdapter_RemovePolicy(t *testing.T) {
	type fields struct {
		db              *db.DB
		indexName       string
		indexDefinition *api.IndexDefinition
		index           *db.Index
	}
	type args struct {
		sec   string
		ptype string
		rule  []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Adapter{
				db:              tt.fields.db,
				indexName:       tt.fields.indexName,
				indexDefinition: tt.fields.indexDefinition,
				index:           tt.fields.index,
			}
			if err := a.RemovePolicy(tt.args.sec, tt.args.ptype, tt.args.rule); (err != nil) != tt.wantErr {
				t.Errorf("RemovePolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAdapter_SavePolicy(t *testing.T) {
	ad := testNewAdapter(t)
	m := rbacModel()
	rbacPolicies(m)

	type fields struct {
		db              *db.DB
		indexName       string
		indexDefinition *api.IndexDefinition
		index           *db.Index
	}
	type args struct {
		model model.Model
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "golden path",
			fields: fields{
				db:              ad.db,
				indexName:       ad.indexName,
				indexDefinition: ad.indexDefinition,
				index:           ad.index,
			},
			args: args{
				model: m,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Adapter{
				db:              tt.fields.db,
				indexName:       tt.fields.indexName,
				indexDefinition: tt.fields.indexDefinition,
				index:           tt.fields.index,
			}
			if err := a.SavePolicy(tt.args.model); (err != nil) != tt.wantErr {
				t.Errorf("SavePolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAdapter_setDefaultIndexDefinition(t *testing.T) {
	type fields struct {
		db              *db.DB
		indexName       string
		indexDefinition *api.IndexDefinition
		index           *db.Index
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Adapter{
				db:              tt.fields.db,
				indexName:       tt.fields.indexName,
				indexDefinition: tt.fields.indexDefinition,
				index:           tt.fields.index,
			}
			a.setDefaultIndexDefinition()
		})
	}
}

func TestNewAdapter(t *testing.T) {
	type args struct {
		db   *db.DB
		opts []Option
	}
	tests := []struct {
		name    string
		args    args
		want    *Adapter
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAdapter(tt.args.db, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAdapter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAdapter() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithIndexName(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		args args
		want Option
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WithIndexName(tt.args.name); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithIndexName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_policyArgs(t *testing.T) {
	type args struct {
		ptype string
		rule  []string
	}
	tests := []struct {
		name string
		args args
		want *api.Segment
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := policyArgs(tt.args.ptype, tt.args.rule); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("policyArgs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_policyID(t *testing.T) {
	type args struct {
		ptype string
		rule  []string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := policyID(tt.args.ptype, tt.args.rule); got != tt.want {
				t.Errorf("policyID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_policyLine(t *testing.T) {
	type args struct {
		segment *api.Segment
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := policyLine(tt.args.segment); got != tt.want {
				t.Errorf("policyLine() = %v, want %v", got, tt.want)
			}
		})
	}
}
