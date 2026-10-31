package main

import (
	"fmt"
	"log/slog"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/broker"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/ntfy"
	"github.com/code6x/nodkey/internal/telegram"
)

// channel is the approval channel of a running broker: Telegram or ntfy,
// by the section that the config has (DESIGN.md section 7). It takes the
// place of Telegram in the start and stop order of section 15.
//
// approver is not embedded: the core looks for the optional parts of the
// approver (grant lists, alarms, warnings) in the value it gets, so it must
// get the approver itself.
type channel struct {
	approver approval.Approver
	alert    broker.AlertFunc
	inform   broker.NoticeFunc
	loud     broker.NoticeFunc
}

// newChannel makes the approver of the channel that cfg has. foreignTap is
// for Telegram only: ntfy answers carry no sender to record.
func newChannel(cfg *config.Broker, log *slog.Logger, foreignTap func(audit.ForeignTap)) (*channel, error) {
	if cfg.Ntfy == nil {
		tg, err := telegram.New(cfg.Telegram, telegram.Options{Logger: log, ForeignTap: foreignTap})
		if err != nil {
			return nil, err
		}
		return &channel{approver: tg, alert: tg.Alert, inform: tg.Inform, loud: tg.InformLoud}, nil
	}
	n := cfg.Ntfy
	data, err := config.ReadPrivateFile(n.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("ntfy: cannot read the access token: %w", err) // names the path, never the content
	}
	token, err := ntfy.NewToken(string(data))
	clear(data)
	if err != nil {
		return nil, err
	}
	ap, err := ntfy.New(ntfy.Config{Server: n.Server, RequestTopic: n.RequestTopic, AnswerTopic: n.AnswerTopic,
		PublishToken: token, ReadToken: token}, ntfy.Options{Logger: log})
	if err != nil {
		return nil, err
	}
	// ntfy has no silent notice: the broker's own notices go out as alerts.
	return &channel{approver: ap, alert: ap.Alert, inform: ap.Alert, loud: ap.Alert}, nil
}
