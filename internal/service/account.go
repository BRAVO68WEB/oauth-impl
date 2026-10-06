package service

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/mailer"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/repository"
)

var (
	ErrRateLimited          = fmt.Errorf("too many requests")
	ErrBadToken             = fmt.Errorf("invalid or expired token")
	ErrRegistrationDisabled = fmt.Errorf("registration is disabled")
)

type AccountService struct {
	users                *UserService
	userRepo             *repository.UserRepository
	emails               *repository.EmailTokenRepository
	logins               *repository.LoginEventRepository
	sessions             *SessionService
	tokens               *repository.TokenRepository
	mail                 mailer.Mailer
	logout               *LogoutService
	hooks                *WebhookDispatcher
	trusted              []string
	issuer               string
	resetTTL             time.Duration
	registrationDisabled bool
	lim                  *rateLimiter
	mu                   sync.Mutex
	lastMail             map[string]time.Time
}

func NewAccountService(
	users *UserService,
	userRepo *repository.UserRepository,
	emails *repository.EmailTokenRepository,
	logins *repository.LoginEventRepository,
	sessions *SessionService,
	tokens *repository.TokenRepository,
	mail mailer.Mailer,
	logout *LogoutService,
	cfg *config.Config,
) *AccountService {
	if mail == nil {
		mail = mailer.Nop{}
	}
	ttl := cfg.Security.ResetTokenLifetime
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	issuer := cfg.Security.Issuer
	if issuer == "" {
		issuer = fmt.Sprintf("http://localhost:%d", cfg.Server.Port)
	}
	return &AccountService{
		users:                users,
		userRepo:             userRepo,
		emails:               emails,
		logins:               logins,
		sessions:             sessions,
		tokens:               tokens,
		mail:                 mail,
		logout:               logout,
		trusted:              append([]string{}, cfg.Security.TrustedProxies...),
		issuer:               issuer,
		resetTTL:             ttl,
		registrationDisabled: cfg.Security.DisableRegistration,
		lim:                  newRateLimiter(),
		lastMail:             map[string]time.Time{},
	}
}

func (a *AccountService) SetWebhooks(d *WebhookDispatcher) {
	if a != nil {
		a.hooks = d
	}
}

func (a *AccountService) EmitRegistered(user *models.User, source, provider string) {
	if a == nil || user == nil {
		return
	}
	data := map[string]any{
		"user_id": user.ID, "username": user.Username, "email": user.Email,
	}
	if source != "" {
		data["source"] = source
		data["provider"] = provider
	}
	a.emit(EventUserRegistered, data)
}

func (a *AccountService) emit(event string, data map[string]any) {
	if a == nil || a.hooks == nil {
		return
	}
	a.hooks.Emit(event, data)
}

func (a *AccountService) RegistrationDisabled() bool {
	return a != nil && a.registrationDisabled
}

func (a *AccountService) Register(username, password, email, phone string) (*models.User, error) {
	if a.RegistrationDisabled() {
		return nil, ErrRegistrationDisabled
	}
	user, err := a.users.InsertUser(NewUser{
		Username: username,
		Password: password,
		Email:    email,
		Phone:    phone,
	})
	if err != nil {
		return nil, err
	}
	if email != "" {
		a.sendVerify(user)
	}
	a.emit(EventUserRegistered, map[string]any{
		"user_id": user.ID, "username": user.Username, "email": user.Email,
	})
	return user, nil
}

func (a *AccountService) Forgot(identifier, ip string) error {
	if !a.lim.allow("forgot-ip:"+ip, 20, time.Hour) {
		return ErrRateLimited
	}
	user := a.findUser(identifier)
	data := map[string]any{"identifier": identifier, "ip": ip, "matched": false}
	if user != nil {
		data["matched"] = true
		data["user_id"] = user.ID
		data["username"] = user.Username
		data["email"] = user.Email
	}
	if !a.mail.Enabled() {
		a.emit(EventForgotPassword, data)
		return mailer.ErrDisabled
	}
	if user == nil || user.Email == "" {
		a.emit(EventForgotPassword, data)
		return nil
	}
	if !a.lim.allow("forgot:"+user.Email, 5, time.Hour) {
		return ErrRateLimited
	}
	token, err := a.emails.Create(user.ID, "reset", a.resetTTL)
	if err != nil {
		return err
	}
	a.emit(EventForgotPassword, data)
	body := fmt.Sprintf("Reset your password:\n\n%s/reset?token=%s\n\nThis link expires in %s.\n", a.issuer, token, a.resetTTL)
	return a.mail.Send(user.Email, "Password reset", body)
}

func (a *AccountService) Reset(token, password, ip string) error {
	if !a.lim.allow("reset-ip:"+ip, 10, time.Hour) {
		return ErrRateLimited
	}
	userID, err := a.emails.Consume(token, "reset")
	if err != nil {
		return ErrBadToken
	}
	if err := a.users.SetPassword(userID, password); err != nil {
		return err
	}
	if user, err := a.userRepo.GetByID(userID); err == nil {
		a.sendPasswordChanged(user)
		a.emit(EventPasswordReset, map[string]any{
			"user_id": user.ID, "username": user.Username, "email": user.Email, "ip": ip, "source": "reset",
		})
	}
	return nil
}

func (a *AccountService) Verify(token string) error {
	userID, err := a.emails.Consume(token, "verify")
	if err != nil {
		return ErrBadToken
	}
	user, err := a.userRepo.GetByID(userID)
	if err != nil {
		return err
	}
	user.EmailVerified = true
	if err := a.userRepo.UpdateProfile(user); err != nil {
		return err
	}
	a.emit(EventEmailVerified, map[string]any{
		"user_id": user.ID, "username": user.Username, "email": user.Email,
	})
	return nil
}

func (a *AccountService) SendVerification(user *models.User) error {
	if !a.mail.Enabled() {
		return mailer.ErrDisabled
	}
	if user == nil || user.Email == "" {
		return fmt.Errorf("user has no email")
	}
	return a.sendVerify(user)
}

func (a *AccountService) ChangePassword(userID, current, next, keepAccess, keepSID string) error {
	if err := a.users.ChangePassword(userID, current, next); err != nil {
		return err
	}
	a.afterCredentialChange(userID, keepAccess, keepSID)
	if user, err := a.userRepo.GetByID(userID); err == nil {
		a.emit(EventChangePassword, map[string]any{
			"user_id": user.ID, "username": user.Username, "email": user.Email, "source": "self_service",
		})
	}
	return nil
}

func (a *AccountService) AdminSetPassword(userID, password string) error {
	if err := a.users.SetPassword(userID, password); err != nil {
		return err
	}
	if user, err := a.userRepo.GetByID(userID); err == nil {
		a.sendPasswordChanged(user)
		a.emit(EventChangePassword, map[string]any{
			"user_id": user.ID, "username": user.Username, "email": user.Email, "source": "management",
		})
	}
	return nil
}

func (a *AccountService) SetDisabled(user *models.User, disabled bool) error {
	user.Disabled = disabled
	if err := a.userRepo.UpdateProfile(user); err != nil {
		return err
	}
	if !disabled {
		return nil
	}
	_ = a.tokens.RevokeAllForUser(user.ID)
	sids, err := a.sessions.RevokeAllExcept(user.ID, "")
	if err != nil {
		return err
	}
	for _, sid := range sids {
		a.logout.Notify(sid, user.ID)
	}
	a.emit(EventUserDisabled, map[string]any{
		"user_id": user.ID, "username": user.Username, "email": user.Email,
	})
	return nil
}

func (a *AccountService) RevokeSession(userID, sid string) error {
	sess, err := a.sessions.GetAny(sid)
	if err != nil || sess.UserID != userID {
		return sql.ErrNoRows
	}
	a.logout.End(sid)
	return nil
}

func (a *AccountService) Record(user *models.User, r *http.Request, success, mfa bool) {
	if a == nil || user == nil {
		return
	}
	ev := &models.LoginEvent{
		UserID:    user.ID,
		Success:   success,
		MFA:       mfa,
		IP:        a.RequestIP(r),
		UserAgent: "",
		CreatedAt: time.Now(),
	}
	if r != nil {
		ev.UserAgent = r.UserAgent()
	}
	seen := false
	if ev.IP != "" {
		seen, _ = a.logins.HasIP(user.ID, ev.IP)
	}
	if err := a.logins.Insert(ev); err != nil {
		log.Printf("login event: %v", err)
	}
	event := EventLoginFailed
	if success {
		event = EventLogin
	}
	data := map[string]any{
		"user_id": user.ID, "username": user.Username, "email": user.Email,
		"ip": ev.IP, "user_agent": ev.UserAgent, "mfa": mfa, "success": success,
	}
	if success && ev.IP != "" && !seen {
		data["new_ip"] = true
	}
	a.emit(event, data)
	if success {
		a.users.TouchLastLogin(user.ID)
		a.maybeLoginMail(user, ev)
		return
	}
	a.maybeFailMail(user, ev)
}

func (a *AccountService) Activity(userID string, limit int) ([]*models.LoginEvent, error) {
	return a.logins.ListByUser(userID, limit)
}

func (a *AccountService) LoginAnalytics(userID string, window time.Duration) (*models.LoginAnalytics, error) {
	if window <= 0 {
		window = 30 * 24 * time.Hour
	}
	if window > 366*24*time.Hour {
		window = 366 * 24 * time.Hour
	}
	out, err := a.logins.Analytics(userID, time.Now().Add(-window))
	if err != nil {
		return nil, err
	}
	out.Window = window.String()
	return out, nil
}

func (a *AccountService) RequestIP(r *http.Request) string {
	if a == nil {
		return ClientIP(r, nil)
	}
	return ClientIP(r, a.trusted)
}

func (a *AccountService) afterCredentialChange(userID, keepAccess, keepSID string) {
	_ = a.tokens.RevokeOtherFamilies(userID, keepAccess)
	sids, err := a.sessions.RevokeAllExcept(userID, keepSID)
	if err != nil {
		log.Printf("revoke sessions for %s: %v", userID, err)
		return
	}
	for _, sid := range sids {
		a.logout.Notify(sid, userID)
	}
	if user, err := a.userRepo.GetByID(userID); err == nil {
		a.sendPasswordChanged(user)
	}
}

func (a *AccountService) findUser(identifier string) *models.User {
	if identifier == "" {
		return nil
	}
	if user, err := a.userRepo.GetByUsername(identifier); err == nil {
		return user
	}
	if user, err := a.userRepo.GetByEmail(identifier); err == nil {
		return user
	}
	return nil
}

func (a *AccountService) sendVerify(user *models.User) error {
	if !a.mail.Enabled() || user.Email == "" {
		return nil
	}
	token, err := a.emails.Create(user.ID, "verify", a.resetTTL)
	if err != nil {
		log.Printf("verify token: %v", err)
		return err
	}
	body := fmt.Sprintf("Confirm your email:\n\n%s/verify-email?token=%s\n", a.issuer, token)
	if err := a.mail.Send(user.Email, "Confirm your email", body); err != nil {
		log.Printf("verify mail: %v", err)
		return err
	}
	return nil
}

func (a *AccountService) sendPasswordChanged(user *models.User) {
	if !a.mail.Enabled() || user == nil || user.Email == "" {
		return
	}
	body := fmt.Sprintf("The password for %s was changed.\n\nIf you did not do this, reset it from %s/forgot\n", user.Username, a.issuer)
	if err := a.mail.Send(user.Email, "Password changed", body); err != nil {
		log.Printf("password-changed mail: %v", err)
	}
}

func (a *AccountService) maybeLoginMail(user *models.User, ev *models.LoginEvent) {
	if !a.mail.Enabled() || user.Email == "" {
		return
	}
	if !a.markMail("login:"+user.ID, 10*time.Minute) {
		return
	}
	body := fmt.Sprintf("New sign-in for %s\n\nTime: %s\nIP: %s\nAgent: %s\n",
		user.Username, ev.CreatedAt.Format(time.RFC3339), ev.IP, ev.UserAgent)
	if err := a.mail.Send(user.Email, "New sign-in", body); err != nil {
		log.Printf("login mail: %v", err)
	}
}

func (a *AccountService) maybeFailMail(user *models.User, ev *models.LoginEvent) {
	n, err := a.logins.CountFailuresSince(user.ID, time.Now().Add(-15*time.Minute))
	if err != nil || n < 5 {
		return
	}
	if a.markMail("bruteforce:"+user.ID, 15*time.Minute) {
		a.emit(EventBruteforce, map[string]any{
			"user_id": user.ID, "username": user.Username, "email": user.Email,
			"ip": ev.IP, "user_agent": ev.UserAgent, "failures": n, "window": "15m",
		})
	}
	if !a.mail.Enabled() || user.Email == "" {
		return
	}
	if !a.markMail("fail:"+user.ID, time.Hour) {
		return
	}
	body := fmt.Sprintf("%d failed sign-in attempts for %s in the last 15 minutes.\n\nLatest IP: %s\n", n, user.Username, ev.IP)
	if err := a.mail.Send(user.Email, "Failed sign-in attempts", body); err != nil {
		log.Printf("failed-login mail: %v", err)
	}
}

func (a *AccountService) markMail(key string, window time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if last, ok := a.lastMail[key]; ok && time.Since(last) < window {
		return false
	}
	a.lastMail[key] = time.Now()
	return true
}

type rateLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{hits: map[string][]time.Time{}}
}

func (l *rateLimiter) allow(key string, max int, window time.Duration) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := now.Add(-window)
	prev := l.hits[key]
	kept := prev[:0]
	for _, t := range prev {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= max {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}
