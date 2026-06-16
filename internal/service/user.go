package service

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/repository"
)

type UserService struct {
	userRepo  *repository.UserRepository
	totpSvc   *TOTPService
	cfg       *config.SecurityConfig
}

func NewUserService(userRepo *repository.UserRepository, totpSvc *TOTPService, cfg *config.SecurityConfig) *UserService {
	return &UserService{
		userRepo: userRepo,
		totpSvc:  totpSvc,
		cfg:      cfg,
	}
}

func (s *UserService) CreateUser(username, password, email, phone string) (*models.User, error) {
	if username == "" || password == "" {
		return nil, fmt.Errorf("username and password are required")
	}

	existing, _ := s.userRepo.GetByUsername(username)
	if existing != nil {
		return nil, fmt.Errorf("username already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		ID:           uuid.New().String(),
		Username:     username,
		PasswordHash: string(hashedPassword),
		Email:        email,
		PhoneNumber:  phone,
		CreatedAt:    time.Now(),
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
	user, err := s.userRepo.GetByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	return user, nil
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
