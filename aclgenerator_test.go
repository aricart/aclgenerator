package aclgenerator

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_RejectBadMacros(t *testing.T) {
	ctx := newACLGeneratorCtx(createAccount("A", "a:AA"), createUser("U", "u:UU"))
	ctx.RejectBadMacros()
	type test struct {
		src        string
		result     []string
		shouldFail bool
	}
	tests := []test{
		{src: "{{unknown}}", shouldFail: true},
		{src: "value", result: []string{"value"}},
		{src: "account.name.{{account-name()}}", result: []string{"account.name.A"}},
		{src: "user.name.{{name()}}", result: []string{"user.name.U"}},
		{src: "account.subject.{{account-subject()}}", result: []string{fmt.Sprintf("account.subject.%s", ctx.acc.Subject)}},
		{src: "user.subject.{{subject()}}", result: []string{fmt.Sprintf("user.subject.%s", ctx.user.Subject)}},
		{src: "user.tag.{{tag(u)}}", result: []string{"user.tag.UU"}},
		{src: "account.tag.{{account-tag(a)}}", result: []string{"account.tag.AA"}},
	}
	for _, tt := range tests {
		acls, err := ctx.ProcessTemplate(tt.src)
		if tt.shouldFail {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.NotNil(t, acls)
			require.Equal(t, tt.result, acls)
		}
	}
}

func Test_ParseAccountName(t *testing.T) {
	ctx := newACLGeneratorCtx(createAccount("A"), createUser("U"))
	ctx.setParseFn(ParseAccountName)
	type test struct {
		src    string
		result []string
	}
	tests := []test{
		{src: "value"},
		{src: "{{unknown}}"},
		{src: "account.name.{{account-name()}}", result: []string{"account.name.A"}},
		{src: "user.name.{{name()}}"},
		{src: "account.subject.{{account-subject()}}"},
		{src: "user.subject.{{subject()}}"},
		{src: "user.tag.{{tag(a)}}"},
		{src: "account.tag.{{account-tag(b)}}"},
	}
	for _, tt := range tests {
		if tt.result == nil {
			tt.result = []string{tt.src}
		}
		acls, err := ctx.ProcessTemplate(tt.src)
		require.NoError(t, err)
		require.NotNil(t, acls)
		require.Equal(t, tt.result, acls)
	}
}

func Test_ParseUserName(t *testing.T) {
	ctx := newACLGeneratorCtx(createAccount("A"), createUser("U"))
	ctx.setParseFn(ParseUserName)
	type test struct {
		src    string
		result []string
	}
	tests := []test{
		{src: "value"},
		{src: "{{unknown}}"},
		{src: "account.name.{{account-name()}}"},
		{src: "user.name.{{name()}}", result: []string{"user.name.U"}},
		{src: "account.subject.{{account-subject()}}"},
		{src: "user.subject.{{subject()}}"},
		{src: "user.tag.{{tag(a)}}"},
		{src: "account.tag.{{account-tag(b)}}"},
	}
	for _, tt := range tests {
		if tt.result == nil {
			tt.result = []string{tt.src}
		}
		acls, err := ctx.ProcessTemplate(tt.src)
		require.NoError(t, err)
		require.NotNil(t, acls)
		require.Equal(t, tt.result, acls)
	}
}

func Test_ParseAccountSubject(t *testing.T) {
	ctx := newACLGeneratorCtx(createAccount("A"), createUser("U"))
	ctx.setParseFn(ParseAccountSubject)
	type test struct {
		src    string
		result []string
	}
	tests := []test{
		{src: "value"},
		{src: "{{unknown}}"},
		{src: "account.name.{{account-name()}}"},
		{src: "user.name.{{name()}}"},
		{src: "account.subject.{{account-subject()}}", result: []string{fmt.Sprintf("account.subject.%s", ctx.acc.Subject)}},
		{src: "user.subject.{{subject()}}"},
		{src: "user.tag.{{tag(a)}}"},
		{src: "account.tag.{{account-tag(b)}}"},
	}
	for _, tt := range tests {
		if tt.result == nil {
			tt.result = []string{tt.src}
		}
		acls, err := ctx.ProcessTemplate(tt.src)
		require.NoError(t, err)
		require.NotNil(t, acls)
		require.Equal(t, tt.result, acls)
	}
}

func Test_ParseUserSubject(t *testing.T) {
	ctx := newACLGeneratorCtx(createAccount("A"), createUser("U"))
	ctx.setParseFn(ParseUserSubject)
	type test struct {
		src    string
		result []string
	}
	tests := []test{
		{src: "value"},
		{src: "{{unknown}}"},
		{src: "account.name.{{account-name()}}"},
		{src: "user.name.{{name()}}"},
		{src: "account.subject.{{account-subject()}}"},
		{src: "user.subject.{{subject()}}", result: []string{fmt.Sprintf("user.subject.%s", ctx.user.Subject)}},
		{src: "user.tag.{{tag(a)}}"},
		{src: "account.tag.{{account-tag(b)}}"},
	}
	for _, tt := range tests {
		if tt.result == nil {
			tt.result = []string{tt.src}
		}
		acls, err := ctx.ProcessTemplate(tt.src)
		require.NoError(t, err)
		require.NotNil(t, acls)
		require.Equal(t, tt.result, acls)
	}
}

func Test_ParseAccountTags(t *testing.T) {
	ctx := newACLGeneratorCtx(createAccount("A", "a:one", "b:two", "b:three"), createUser("U"))
	ctx.setParseFn(ParseAccountTags)
	type test struct {
		src    string
		result []string
	}
	tests := []test{
		{src: "value"},
		{src: "{{unknown}}"},
		{src: "account.name.{{account-name()}}"},
		{src: "user.name.{{name()}}"},
		{src: "account.subject.{{account-subject()}}"},
		{src: "user.subject.{{subject()}}"},
		{src: "account.tag.{{account-tag(b)}}", result: []string{"account.tag.two", "account.tag.three"}},
		{src: "user.tag.{{tag(a)}}"},
	}
	for _, tt := range tests {
		if tt.result == nil {
			tt.result = []string{tt.src}
		}
		acls, err := ctx.ProcessTemplate(tt.src)
		require.NoError(t, err)
		require.NotNil(t, acls)
		require.Equal(t, tt.result, acls)
	}
}

func Test_ParseUserTags(t *testing.T) {
	ctx := newACLGeneratorCtx(createAccount("A"), createUser("U", "c:c"))
	ctx.setParseFn(ParseUserTags)
	type test struct {
		src    string
		result []string
	}
	tests := []test{
		{src: "value"},
		{src: "{{unknown}}"},
		{src: "account.name.{{account-name()}}"},
		{src: "user.name.{{name()}}"},
		{src: "account.subject.{{account-subject()}}"},
		{src: "user.subject.{{subject()}}"},
		{src: "account.tag.{{account-tag(b)}}"},
		{src: "user.tag.{{tag(c)}}", result: []string{"user.tag.c"}},
	}
	for _, tt := range tests {
		if tt.result == nil {
			tt.result = []string{tt.src}
		}
		acls, err := ctx.ProcessTemplate(tt.src)
		require.NoError(t, err)
		require.NotNil(t, acls)
		require.Equal(t, tt.result, acls)
	}
}

func createUser(name string, tags ...string) *jwt.UserClaims {
	ukp, _ := nkeys.CreateUser()
	pk, _ := ukp.PublicKey()
	uc := jwt.NewUserClaims(pk)
	uc.Name = name
	uc.Tags = tags
	return uc
}

func createAccount(name string, tags ...string) *jwt.AccountClaims {
	akp, _ := nkeys.CreateAccount()
	pk, _ := akp.PublicKey()
	ac := jwt.NewAccountClaims(pk)
	ac.Name = name
	ac.Tags = tags
	return ac
}

func Test_UserTags(t *testing.T) {
	ctx := newACLGeneratorCtx(createAccount("A"), createUser("U", "a:aa", "a", "b:one", "b:two", "c:three", "c:four", "c:five"))

	type test struct {
		s      string
		result []string
	}
	tests := []test{
		{"{{tag(a)}}", []string{"aa"}},
		{"{{TAG(a)}}", []string{"aa"}},
		{"{{tag(b)}}", []string{"one", "two"}},
		{"{{tag(b)}}.{{tag(a)}}", []string{"one.aa", "two.aa"}},
		{"KV_{{tag(c)}}.>", []string{"KV_three.>", "KV_four.>", "KV_five.>"}},
		{"hello.{{weird}}.>", []string{"hello.{{weird}}.>"}},
	}
	for _, tt := range tests {
		results, err := ctx.ProcessTemplate(tt.s)
		require.NoError(t, err)
		assert.EqualValues(t, tt.result, results)
	}
}

func logA(t *testing.T, arg []string) {
	for _, s := range arg {
		t.Log(s)
	}
}

func Test_KV_GenerateAccess(t *testing.T) {
	a, err := ParseGenerateKvAdmin("{{kv_admin()}}")
	require.NoError(t, err)
	logA(t, a)

	a, err = ParseGenerateKvRead("{{ kv_read() }}")
	require.NoError(t, err)
	logA(t, a)

	a, err = ParseGenerateKvWrite("{{kv_write(key=a)}}")
	require.NoError(t, err)
	logA(t, a)
}

func Benchmark_TagParsingNone(b *testing.B) {
	b.StopTimer()
	a, err := randomStringArray(30, 15)
	require.NoError(b, err)

	for idx, v := range a {
		a[idx] = fmt.Sprintf("aaaa:%s", v)
	}
	ac := createAccount("A", a...)
	uc := createUser("U", a...)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		newACLGeneratorCtx(ac, uc)
	}
	b.StopTimer()
}

func Benchmark_AccountName(b *testing.B) {
	b.StopTimer()
	a, err := randomStringArray(10, 15)
	require.NoError(b, err)

	for idx, v := range a {
		a[idx] = fmt.Sprintf("idx:%s", v)
	}
	ac := createAccount("A", a...)
	uc := createUser("U", a...)

	ctx := newACLGeneratorCtx(ac, uc)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ctx.ProcessTemplate("{{account-name()}}")
	}
	b.StopTimer()
}

func Benchmark_UserName(b *testing.B) {
	b.StopTimer()
	a, err := randomStringArray(10, 15)
	require.NoError(b, err)

	for idx, v := range a {
		a[idx] = fmt.Sprintf("idx:%s", v)
	}
	ac := createAccount("A", a...)
	uc := createUser("U", a...)

	ctx := newACLGeneratorCtx(ac, uc)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ctx.ProcessTemplate("{{name()}}")
	}
	b.StopTimer()
}

func randomString(n int) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	v := make([]byte, n)
	for i := range v {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		v[i] = letters[num.Int64()]
	}
	return string(v), nil
}

func randomStringArray(arrayLength int, stringLength int) ([]string, error) {
	randomStrings := make([]string, arrayLength)

	for i := 0; i < arrayLength; i++ {
		randomString, err := randomString(stringLength)
		if err != nil {
			return nil, err
		}
		randomStrings[i] = randomString
	}

	return randomStrings, nil
}
