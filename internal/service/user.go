package service

import (
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/pkg/passhash"
)

type UserService struct {
	userRepo *repository.UserRepository
	totpSvc  *TOTPService
	cfg      *config.SecurityConfig
	hasher   passhash.Hasher
}

func NewUserService(userRepo *repository.UserRepository, totpSvc *TOTPService, cfg *config.SecurityConfig, hasher passhash.Hasher) *UserService {
	if hasher == nil {
		panic("passhash.Hasher is required")
	}
	return &UserService{
		userRepo: userRepo,
		totpSvc:  totpSvc,
		cfg:      cfg,
		hasher:   hasher,
	}
}

type NewUser struct {
	Username      string
	Password      string
	Email         string
	Phone         string
	GivenName     string
	FamilyName    string
	EmailVerified bool
	Disabled      bool
	Attributes    map[string]string
}

func (s *UserService) CreateUser(username, password, email, phone string) (*models.User, error) {
	return s.InsertUser(NewUser{
		Username: username,
		Password: password,
		Email:    email,
		Phone:    phone,
	})
}

func (s *UserService) InsertUser(in NewUser) (*models.User, error) {
	if in.Username == "" || in.Password == "" {
		return nil, fmt.Errorf("username and password are required")
	}
	if s.cfg != nil {
		if err := CheckPassword(s.cfg.Password, in.Username, in.Password); err != nil {
			return nil, err
		}
	}

	existing, _ := s.userRepo.GetByUsername(in.Username)
	if existing != nil {
		return nil, fmt.Errorf("username already exists")
	}

	hashedPassword, err := s.hasher.Hash(in.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		ID:            uuid.New().String(),
		Username:      in.Username,
		PasswordHash:  hashedPassword,
		Email:         in.Email,
		PhoneNumber:   in.Phone,
		GivenName:     in.GivenName,
		FamilyName:    in.FamilyName,
		EmailVerified: in.EmailVerified && in.Email != "",
		Disabled:      in.Disabled,
		Attributes:    in.Attributes,
		CreatedAt:     time.Now(),
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

func (s *UserService) GetUser(id string) (*models.User, error) {
	return s.userRepo.GetByID(id)
}

func (s *UserService) GetUserByUsername(username string) (*models.User, error) {
	return s.userRepo.GetByUsername(username)
}

func (s *UserService) ListUsers() ([]*models.User, error) {
	return s.userRepo.List()
}

func (s *UserService) Authenticate(username, password string) (*models.User, error) {
	if username == "" || password == "" {
		return nil, fmt.Errorf("invalid credentials")
	}

	user, err := s.userRepo.GetByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	if user.Disabled {
		return nil, fmt.Errorf("invalid credentials")
	}

	if err := s.hasher.Verify(user.PasswordHash, password); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	s.maybeRehash(user, password)

	return user, nil
}

func (s *UserService) maybeRehash(user *models.User, password string) {
	re, ok := s.hasher.(passhash.Rehasher)
	if !ok || !re.NeedsRehash(user.PasswordHash) {
		return
	}
	encoded, err := s.hasher.Hash(password)
	if err != nil {
		log.Printf("password rehash failed for user %s: %v", user.ID, err)
		return
	}
	if err := s.userRepo.UpdatePasswordHash(user.ID, encoded); err != nil {
		log.Printf("password rehash store failed for user %s: %v", user.ID, err)
		return
	}
	user.PasswordHash = encoded
}

func (s *UserService) AuthenticateWithMFA(username, password, totpCode string) (*models.User, bool, error) {
	user, err := s.Authenticate(username, password)
	if err != nil {
		return nil, false, err
	}

	if s.cfg.MFA.Required {
		mfaEnabled, err := s.totpSvc.IsMFAEnabled(user.ID)
		if err != nil {
			return nil, false, fmt.Errorf("failed to check MFA status: %w", err)
		}

		if mfaEnabled {
			if totpCode == "" {
				return user, false, nil
			}

			valid, err := s.totpSvc.VerifyLogin(user.ID, totpCode)
			if err != nil || !valid {
				return nil, false, fmt.Errorf("invalid TOTP code")
			}
		}
	}

	return user, true, nil
}

func (s *UserService) SetAttributes(id string, attrs map[string]string) error {
	return s.userRepo.SetAttributes(id, attrs)
}

func (s *UserService) UpdateProfile(user *models.User) error {
	return s.userRepo.UpdateProfile(user)
}

func (s *UserService) SetPassword(id, password string) error {
	if password == "" {
		return fmt.Errorf("password is required")
	}
	username := ""
	if user, err := s.userRepo.GetByID(id); err == nil && user != nil {
		username = user.Username
	}
	if s.cfg != nil {
		if err := CheckPassword(s.cfg.Password, username, password); err != nil {
			return err
		}
	}
	hashed, err := s.hasher.Hash(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	return s.userRepo.UpdatePasswordHash(id, hashed)
}

func (s *UserService) ChangePassword(id, current, next string) error {
	if next == "" {
		return fmt.Errorf("password is required")
	}
	user, err := s.userRepo.GetByID(id)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if err := s.hasher.Verify(user.PasswordHash, current); err != nil {
		return fmt.Errorf("invalid credentials")
	}
	return s.SetPassword(id, next)
}

func (s *UserService) TouchLastLogin(id string) {
	_ = s.userRepo.TouchLastLogin(id, time.Now())
}
