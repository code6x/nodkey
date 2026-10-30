package client

import (
	"context"

	"github.com/code6x/nodkey/internal/api"
)

// Probe asks the broker for the keys that this client may use: the call
// of nodkey ssh-agent, which needs no tap on the phone. It is the broker
// check of nodkey doctor (DESIGN.md section 15). own is this client's
// version. It returns the number of keys, and the warnings about the
// versions of the client and the broker (warnVersions); they hold only
// fixed text and release versions. The error is an *Error or the cause
// of ctx, as of Post.
func (b *Broker) Probe(ctx context.Context, own string) (keys int, warnings []string, err error) {
	b.warnVersions(own, func(text string) { warnings = append(warnings, text) })
	defer b.warnVersions("", nil)
	ans, err := Post[api.KeysAnswer](ctx, b, api.PathKeys, []byte("{}"), nil)
	if err != nil {
		return 0, warnings, err
	}
	if err := checkKeys(ans.Keys); err != nil {
		return 0, warnings, &Error{Status: 200, text: "the key list of the broker is not valid"}
	}
	return len(ans.Keys), warnings, nil
}
