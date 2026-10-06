package mailer

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"

	"github.com/bravo68web/oauth-impl/internal/config"
)

var ErrDisabled = fmt.Errorf("mailer disabled")

type Mailer interface {
	Enabled() bool
	Send(to, subject, text string) error
}

type Nop struct{}

func (Nop) Enabled() bool { return false }

func (Nop) Send(string, string, string) error { return ErrDisabled }

type smtpMailer struct {
	cfg config.SMTPConfig
}

func New(cfg config.SMTPConfig) (Mailer, error) {
	if !cfg.Enabled {
		return Nop{}, nil
	}
	if strings.TrimSpace(cfg.Host) == "" || strings.TrimSpace(cfg.From) == "" {
		return nil, fmt.Errorf("smtp.enabled requires smtp.host and smtp.from")
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	return &smtpMailer{cfg: cfg}, nil
}

func (m *smtpMailer) Enabled() bool { return true }

func (m *smtpMailer) Send(to, subject, text string) error {
	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)
	var conn net.Conn
	var err error
	tlsConfig := &tls.Config{ServerName: m.cfg.Host}
	if m.cfg.ImplicitTLS {
		conn, err = tls.Dial("tcp", addr, tlsConfig)
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = client.Close() }()

	if !m.cfg.ImplicitTLS && m.cfg.StartTLS {
		if err := client.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	if m.cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(m.cfg.From); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("To: %s\r\nFrom: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		to, m.cfg.From, subject, text)
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
