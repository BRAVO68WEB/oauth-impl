package service

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

type ClientService struct {
	clientRepo *repository.ClientRepository
}

func NewClientService(clientRepo *repository.ClientRepository) *ClientService {
	return &ClientService{clientRepo: clientRepo}
}

type CreateClientInput struct {
	Name                                       string
	RedirectURIs                               []string
	GrantTypes                                 []string
	Scopes                                     []string
	TokenEndpointAuthMethod                    string
	DPoPBoundAccessTokens                      bool
	RequirePushedAuthorizationRequests         bool
	BackchannelTokenDeliveryMode               string
	BackchannelClientNotificationEndpoint      string
	BackchannelAuthenticationRequestSigningAlg string
}

func (s *ClientService) CreateClient(input CreateClientInput) (*models.Client, error) {
	if input.Name == "" {
		return nil, fmt.Errorf("name is required")
	}

	if input.TokenEndpointAuthMethod == "" {
		input.TokenEndpointAuthMethod = "client_secret_basic"
	}

	client := &models.Client{
		ID:                                    uuid.New().String(),
		Secret:                                generateSecret(),
		Name:                                  input.Name,
		RedirectURIs:                          input.RedirectURIs,
		GrantTypes:                            input.GrantTypes,
		Scopes:                                input.Scopes,
		TokenEndpointAuthMethod:               input.TokenEndpointAuthMethod,
		DPoPBoundAccessTokens:                 input.DPoPBoundAccessTokens,
		RequirePushedAuthorizationRequests:    input.RequirePushedAuthorizationRequests,
		BackchannelTokenDeliveryMode:          input.BackchannelTokenDeliveryMode,
		BackchannelClientNotificationEndpoint: input.BackchannelClientNotificationEndpoint,
		BackchannelAuthenticationRequestSigningAlg: input.BackchannelAuthenticationRequestSigningAlg,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.clientRepo.Create(client); err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return client, nil
}

func (s *ClientService) GetClient(id string) (*models.Client, error) {
	return s.clientRepo.GetByID(id)
}

func (s *ClientService) ListClients() ([]*models.Client, error) {
	return s.clientRepo.List()
}

func (s *ClientService) UpdateClient(client *models.Client) error {
	client.UpdatedAt = time.Now()
	return s.clientRepo.Update(client)
}

func (s *ClientService) DeleteClient(id string) error {
	return s.clientRepo.Delete(id)
}

func (s *ClientService) ValidateClient(clientID, clientSecret string) (*models.Client, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}

	client, err := s.clientRepo.GetByID(clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found")
	}

	if client.TokenEndpointAuthMethod != "none" && client.Secret != clientSecret {
		return nil, fmt.Errorf("invalid client credentials")
	}

	return client, nil
}

func (s *ClientService) ValidateGrantType(client *models.Client, grantType string) error {
	for _, gt := range client.GrantTypes {
		if gt == grantType {
			return nil
		}
	}
	return fmt.Errorf("client not authorized for %s grant", grantType)
}

func generateSecret() string {
	secret, err := crypto.GenerateToken()
	if err != nil {
		return uuid.New().String()
	}
	return secret
}
