package aclgenerator

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/nats-io/jwt/v2"
)

var (
	mustacheRE = regexp.MustCompile(`{{2}([^}]+)}{2}`)

	accountNameRE = regexp.MustCompile(`(?i)^account-name\(\)`)
	userNameRE    = regexp.MustCompile(`(?i)^name\(\)`)

	accountTagRE = regexp.MustCompile(`(?i)^account-tag\(([^)]+)\)`)
	userTagRE    = regexp.MustCompile(`(?i)^tag\(([^)]+)\)`)

	accountSubjectRE = regexp.MustCompile(`(?i)^account-subject\(\)`)
	userSubjectRE    = regexp.MustCompile(`(?i)^subject\(\)`)

	// {{ kvAdmin(bucket={{tag}}) }}
	kvAdminRE = regexp.MustCompile(`(?i)^{{2}[\s+]?kv_admin\(([^)]*)\)[\s+]?}{2}`)
	kvReadRE  = regexp.MustCompile(`(?i)^{{2}[\s+]?kv_read\(([^)]*)\)[\s+]?}{2}`)
	kvWriteRE = regexp.MustCompile(`(?i)^{{2}[\s+]?kv_write\(([^)]*)\)[\s+]?}{2}`)
)

// Macro is created by a parse function that matches some operation
// configuration between double mustaches `{{op}}`. Once created,
// it is given a chance to initialize with a context that provides
// the account and user configurations.
type Macro interface {
	// Resolve calculates the values the macro will inject
	Resolve(ctx *ACLGeneratorCtx) error
	// Values return the list of values calculated during a Resolve
	// This API is needed by the context to generate Permutations
	// related to all the Macros for the current subject.
	Values() []string
	// AddPermutedValue adds to the list of PermutedValues
	// This is used by the context to add Permutations generated
	AddPermutedValue(s string)
	// RenderPermute replaces the portion of the template value
	// that matches its initialization source string with the
	// resolved permuted value for the specified iteration
	RenderPermute(template string, idx int) string
}

type Generator interface {
	Render(template string) []string
}

var (
	props     map[string]*regexp.Regexp
	propsLock = sync.Mutex{}
)

func getProperty(s string, name string) string {
	re := getPropertyRE(name)
	var v string
	if m := re.FindStringSubmatch(s); m != nil {
		v = m[1]
	}
	return v
}

func buildPropertyRE(name string) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`(?i)%s=(\w+)`, name))
}

func getPropertyRE(name string) *regexp.Regexp {
	propsLock.Lock()
	defer propsLock.Unlock()
	if props == nil {
		props = make(map[string]*regexp.Regexp)
	}
	re := props[name]
	if re == nil {
		re = buildPropertyRE(name)
		props[name] = re
	}
	return re
}

func ParseGenerateKvAdmin(s string) ([]string, error) {
	if m := kvAdminRE.FindStringSubmatch(s); m != nil {
		config := strings.TrimSpace(m[1])

		bucket := getProperty(config, "bucket")
		if bucket == "" {
			bucket = "*"
		}
		prefix := getProperty(config, "prefix")
		if prefix == "" {
			prefix = "$JS.API"
		}

		return []string{
			fmt.Sprintf("%s.INFO", prefix),
			fmt.Sprintf("%s.STREAM.LIST", prefix),
			fmt.Sprintf("%s.STREAM.CREATE.%s", prefix, bucket),
			fmt.Sprintf("%s.STREAM.DELETE.%s", prefix, bucket),
		}, nil
	}
	return nil, nil
}

func ParseGenerateKvRead(s string) ([]string, error) {
	if m := kvReadRE.FindStringSubmatch(s); m != nil {
		config := strings.TrimSpace(m[1])
		// bucket=name
		// prefix=prefix
		// key=subj
		bucket := getProperty(config, "bucket")
		if bucket == "" {
			bucket = "*"
		}
		key := getProperty(config, "key")
		if key == "" {
			key = ">"
		} else {
			key = fmt.Sprintf("$KV.%s.%s", bucket, key)
		}

		prefix := getProperty(config, "prefix")
		if prefix == "" {
			prefix = "$JS.API"
		}

		return []string{
			fmt.Sprintf("%s.STREAM.INFO.%s", prefix, bucket),
			fmt.Sprintf("%s.DIRECT.GET.%s.%s", prefix, bucket, key),
			fmt.Sprintf("%s.STREAM.MSG.GET.%s", prefix, bucket),
			fmt.Sprintf("%s.CONSUMER.CREATE.%s.*.%s", prefix, bucket, key),
		}, nil
	}
	return nil, nil
}

func ParseGenerateKvWrite(s string) ([]string, error) {
	if m := kvWriteRE.FindStringSubmatch(s); m != nil {
		config := strings.TrimSpace(m[1])
		// bucket=name
		// prefix=prefix
		// key=subj
		bucket := getProperty(config, "bucket")
		if bucket == "" {
			bucket = "*"
		}
		key := getProperty(config, "key")
		if key == "" {
			key = ">"
		} else {
			key = fmt.Sprintf("$KV.%s.%s", bucket, key)
		}

		prefix := getProperty(config, "prefix")
		if prefix == "" {
			prefix = "$JS.API"
		}
		return []string{fmt.Sprintf("$KV.%s.%s", bucket, key)}, nil
	}
	return nil, nil
}

type baseMacro struct {
	src      string
	values   []string
	permutes []string
	arg      string
}

func (b *baseMacro) AddPermutedValue(s string) {
	b.permutes = append(b.permutes, s)
}

func (b *baseMacro) Values() []string {
	return b.values
}

func (b *baseMacro) RenderPermute(template string, idx int) string {
	return strings.Replace(template, b.src, b.permutes[idx], -1)
}

func normalizeTemplate(s string) string {
	v := s
	if strings.HasPrefix(v, "{{") && strings.HasSuffix(v, "}}") {
		end := len(v) - 2
		v = v[2:end]
	}
	return strings.TrimSpace(v)
}

func ParseAccountTags(s string) (Macro, error) {
	a := AccountTag{}
	a.src = s
	if m := accountTagRE.FindStringSubmatch(normalizeTemplate(s)); m != nil {
		tagName := strings.ToLower(strings.TrimSpace(m[1]))
		if tagName == "" {
			return nil, fmt.Errorf("tag name is empty: %s", s)
		}
		a.arg = tagName
		return &a, nil
	}
	return nil, nil
}

func ParseUserTags(s string) (Macro, error) {
	a := UserTag{}
	a.src = s
	if m := userTagRE.FindStringSubmatch(normalizeTemplate(s)); m != nil {
		tagName := strings.ToLower(strings.TrimSpace(m[1]))
		if tagName == "" {
			return nil, fmt.Errorf("tag name is empty: %s", s)
		}
		a.arg = tagName
		return &a, nil
	}
	return nil, nil
}

func ParseAccountName(s string) (Macro, error) {
	a := AccountName{}
	a.src = s
	if m := accountNameRE.FindStringSubmatch(normalizeTemplate(s)); m != nil {
		return &a, nil
	}
	return nil, nil
}

func ParseUserName(s string) (Macro, error) {
	un := UserName{}
	un.src = s
	if m := userNameRE.FindStringSubmatch(normalizeTemplate(s)); m != nil {
		return &un, nil
	}
	return nil, nil
}

func ParseAccountSubject(s string) (Macro, error) {
	a := AccountSubject{}
	a.src = s
	if m := accountSubjectRE.FindStringSubmatch(normalizeTemplate(s)); m != nil {
		return &a, nil
	}
	return nil, nil
}

func ParseUserSubject(s string) (Macro, error) {
	us := UserSubject{}
	us.src = s
	if m := userSubjectRE.FindStringSubmatch(normalizeTemplate(s)); m != nil {
		return &us, nil
	}
	return nil, nil
}

type (
	AccountName    struct{ baseMacro }
	UserName       struct{ baseMacro }
	AccountSubject struct{ baseMacro }
	UserSubject    struct{ baseMacro }
	AccountTag     struct{ baseMacro }
	UserTag        struct{ baseMacro }
)

type ParseFn func(s string) (Macro, error)

func ParseFns() []ParseFn {
	return []ParseFn{
		ParseAccountName, ParseUserName,
		ParseAccountSubject, ParseUserSubject,
		ParseAccountTags, ParseUserTags,
	}
}

type GeneratorFn func(s string) ([]string, error)

func GeneratorFns() []GeneratorFn {
	return []GeneratorFn{
		ParseGenerateKvRead,
		ParseGenerateKvWrite,
		ParseGenerateKvAdmin,
	}
}

func (an *AccountName) Resolve(ctx *ACLGeneratorCtx) error {
	n := strings.TrimSpace(ctx.acc.Name)
	if len(n) == 0 {
		return errors.New("account name is empty")
	}
	an.values = []string{n}
	return nil
}

func (an *UserName) Resolve(ctx *ACLGeneratorCtx) error {
	n := strings.TrimSpace(ctx.user.Name)
	if len(n) == 0 {
		return errors.New("user name is empty")
	}
	an.values = []string{n}
	return nil
}

func (an *AccountSubject) Resolve(ctx *ACLGeneratorCtx) error {
	n := ctx.acc.Subject
	if len(n) == 0 {
		return errors.New("account subject/issuer is empty")
	}
	an.values = []string{n}
	return nil
}

func (an *UserSubject) Resolve(ctx *ACLGeneratorCtx) error {
	n := ctx.user.Subject
	if len(n) == 0 {
		return errors.New("user subject is empty")
	}
	an.values = []string{n}
	return nil
}

func (an *AccountTag) Resolve(ctx *ACLGeneratorCtx) error {
	tags := ctx.AccountTags()
	values := tags[an.arg]
	if len(values) == 0 {
		return fmt.Errorf("account tag %q doesn't exist", an.arg)
	}
	an.values = values
	return nil
}

func (an *UserTag) Resolve(ctx *ACLGeneratorCtx) error {
	tags := ctx.UserTags()
	values := tags[an.arg]
	if len(values) == 0 {
		return fmt.Errorf("user tag %q doesn't exist", an.arg)
	}
	an.values = values
	return nil
}

func newACLGeneratorCtx(acc *jwt.AccountClaims, user *jwt.UserClaims) *ACLGeneratorCtx {
	ctx := ACLGeneratorCtx{}
	ctx.acc = acc
	ctx.user = user
	ctx.fns = ParseFns()

	return &ctx
}

type ACLGeneratorCtx struct {
	fns             []ParseFn
	acc             *jwt.AccountClaims
	user            *jwt.UserClaims
	userTags        map[string][]string
	accountTags     map[string][]string
	rejectBadMacros bool
}

// RejectBadMacros will configure the generator to reject
// templates (strings that are enclosed in double
// mustaches) that could not be parsed by a known Macro
func (ctx *ACLGeneratorCtx) RejectBadMacros() {
	ctx.rejectBadMacros = true
}

func (ctx *ACLGeneratorCtx) setParseFn(fn ParseFn) {
	ctx.fns = []ParseFn{fn}
}

func (ctx *ACLGeneratorCtx) UserTags() map[string][]string {
	if ctx.userTags == nil {
		ctx.userTags = ctx.processTags(ctx.user.Tags)
	}
	return ctx.userTags
}

func (ctx *ACLGeneratorCtx) AccountTags() map[string][]string {
	if ctx.accountTags == nil {
		ctx.accountTags = ctx.processTags(ctx.acc.Tags)
	}
	return ctx.accountTags
}

// processTags processes the tag lists by normalizing the tag names
// and creating a map[string][]string
func (ctx *ACLGeneratorCtx) processTags(list jwt.TagList) map[string][]string {
	m := make(map[string][]string)
	for _, t := range list {
		idx := strings.Index(t, ":")
		if idx != -1 {
			name := strings.ToLower(strings.TrimSpace(t[:idx]))
			value := strings.TrimSpace(t[idx+1:])
			if value != "" {
				a := m[name]
				a = append(a, value)
				m[name] = a
			}
		}
	}
	return m
}

// fillPermutes calculates all the permutes for all the parsed
// macros, values are then stored in the macro, which will then
// be asked to render the template
func (ctx *ACLGeneratorCtx) fillPermutes(macros ...Macro) int {
	var a [][]string
	for _, macro := range macros {
		a = append(a, macro.Values())
	}
	count, b := permute(a...)
	for _, v := range b {
		for idx, m := range macros {
			m.AddPermutedValue(v[idx])
		}
	}
	return count
}

// permute generates all the permutations for the given set of arrays
func permute(a ...[]string) (int, [][]string) {
	c := 1
	for _, a := range a {
		c *= len(a)
	}
	if c == 0 {
		return 0, nil
	}
	p := make([][]string, c)
	b := make([]string, c*len(a))
	n := make([]int, len(a))
	s := 0
	for i := range p {
		e := s + len(a)
		pi := b[s:e]
		p[i] = pi
		s = e
		for j, n := range n {
			pi[j] = a[j][n]
		}
		for j := len(n) - 1; j >= 0; j-- {
			n[j]++
			if n[j] < len(a[j]) {
				break
			}
			n[j] = 0
		}
	}
	return c, p
}

func (ctx *ACLGeneratorCtx) Process(template string) ([]string, error) {
	var buf []string
	a, err := ctx.processGenerators(template)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return []string{template}, nil
	}
	for _, v := range a {
		aa, err := ctx.processTemplate(v)
		for _, v := range aa {
			if err != nil {
				return nil, err
			}
			vr := &jwt.ValidationResults{}
			jwt.Subject(v).Validate(vr)
			if errs := vr.Errors(); len(errs) != 0 {
				return nil, errs[0]
			}
			buf = append(buf, v)
		}
	}
	return buf, nil
}

func (ctx *ACLGeneratorCtx) processGenerators(template string) ([]string, error) {
	t := strings.TrimSpace(template)
	if t == "" {
		return []string{t}, nil
	}
	// generators must start with a {{ and end with a }}
	if strings.HasPrefix(t, "{{") && strings.HasSuffix(t, "}}") {
		// this is a candidate - remove the braces, so we can parse other macros
		t = strings.TrimSuffix(strings.TrimPrefix(t, "{{"), "}}")
		// by processing templates gain ability to nest macros...
		// {{ kv_admin(bucket={{tag(bucket)}}) }}
		// kv_admin(bucket={{tag(bucket))}})
		// kv_admin(bucket=hello)
		// {{ kv_admin(bucket=hello) }}
		// and then the expansion
		a, err := ctx.processTemplate(t)
		if err != nil {
			return nil, err
		}
		var buf []string
		for _, v := range a {
			// re-wrap so the generator matches
			tt := fmt.Sprintf("{{ %s }}", v)
			for _, fn := range GeneratorFns() {
				values, err := fn(tt)
				if err != nil {
					return nil, err
				}
				if values != nil {
					for _, vv := range values {
						buf = append(buf, vv)
					}
				}
			}
		}
		return buf, nil
	}
	return nil, nil
}

// processTemplate takes a subject possibly containing templates, and parses
// any macros it may contain, returning a list of subjects that the template
// mapped or an error if the macro encountered an error or a render resolved
// into an invalid subject.
func (ctx *ACLGeneratorCtx) processTemplate(subj string) ([]string, error) {
	subj = strings.TrimSpace(subj)
	if subj == "" {
		return []string{subj}, nil
	}

	// parse all the macros
	var macros []Macro
	// look for the closest `{{ }}` - we can have several of these in a single template
	placeHolders := mustacheRE.FindAllString(subj, -1)
	// if no placeholders, nothing to do
	if len(placeHolders) == 0 {
		return []string{subj}, nil
	}
	for _, ph := range placeHolders {
		ok := false
		for _, fn := range ctx.fns {
			m, err := fn(ph)
			if err != nil {
				return nil, err
			}
			if m != nil {
				if err := m.Resolve(ctx); err != nil {
					return nil, err
				}
				macros = append(macros, m)
				ok = true
				break
			}
		}
		if !ok && ctx.rejectBadMacros {
			return nil, fmt.Errorf("bad macro: %q", ph)
		}
	}

	count := ctx.fillPermutes(macros...)

	// this will result in acls[count]
	var acls []string
	for i := 0; i < count; i++ {
		// for each render, we copy the original template
		// and process all the macros parsed in order
		// permute() returned the values rendered by each
		// macro for the correct generation of all the permutations
		t := subj
		for _, m := range macros {
			t = m.RenderPermute(t, i)
		}
		acls = append(acls, t)
	}

	return acls, nil
}
