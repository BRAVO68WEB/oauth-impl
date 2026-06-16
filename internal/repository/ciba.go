package repository

import (
	"database/sql"
	"time"

	"github.com/bravo68web/oauth-impl/internal/models"
)

type CIBARepository struct {
	db *sql.DB
}

func NewCIBARepository(db *sql.DB) *CIBARepository {
	return &CIBARepository{db: db}
}

func (r *CIBARepository) Save(req *models.CIBARequest) error {
	query := `INSERT INTO ciba_requests (auth_req_id, client_id, user_id, binding_message, user_code,
		status, delivery_mode, expires_at, interval, client_notification_token)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		req.AuthReqID, req.ClientID, req.UserID, req.BindingMessage,
		req.UserCode, req.Status, req.DeliveryMode, req.ExpiresAt,
		req.Interval, req.ClientNotificationToken,
	)
	return err
}

func (r *CIBARepository) GetByID(authReqID string) (*models.CIBARequest, error) {
	query := `SELECT auth_req_id, client_id, user_id, binding_message, user_code,
		status, delivery_mode, expires_at, interval, client_notification_token
		FROM ciba_requests WHERE auth_req_id = ?`

	req := &models.CIBARequest{}
	err := r.db.QueryRow(query, authReqID).Scan(
		&req.AuthReqID, &req.ClientID, &req.UserID, &req.BindingMessage,
		&req.UserCode, &req.Status, &req.DeliveryMode, &req.ExpiresAt,
		&req.Interval, &req.ClientNotificationToken,
	)
	return req, err
}

func (r *CIBARepository) UpdateStatus(authReqID, status string) error {
	_, err := r.db.Exec("UPDATE ciba_requests SET status = ? WHERE auth_req_id = ?", status, authReqID)
	return err
}

func (r *CIBARepository) GetPending() ([]*models.CIBARequest, error) {
	query := `SELECT auth_req_id, client_id, user_id, binding_message, user_code,
		status, delivery_mode, expires_at, interval, client_notification_token
		FROM ciba_requests WHERE status = 'pending' AND expires_at > ?
		ORDER BY expires_at DESC`

	rows, err := r.db.Query(query, time.Now())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	requests := make([]*models.CIBARequest, 0)
	for rows.Next() {
		req := &models.CIBARequest{}
		err := rows.Scan(
			&req.AuthReqID, &req.ClientID, &req.UserID, &req.BindingMessage,
			&req.UserCode, &req.Status, &req.DeliveryMode, &req.ExpiresAt,
			&req.Interval, &req.ClientNotificationToken,
		)
		if err != nil {
			return nil, err
		}
		requests = append(requests, req)
	}
	return requests, nil
}
