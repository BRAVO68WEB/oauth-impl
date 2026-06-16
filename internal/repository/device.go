package repository

import (
	"database/sql"
	"encoding/json"

	"github.com/bravo68web/oauth-impl/internal/models"
)

type DeviceCodeRepository struct {
	db *sql.DB
}

func NewDeviceCodeRepository(db *sql.DB) *DeviceCodeRepository {
	return &DeviceCodeRepository{db: db}
}

func (r *DeviceCodeRepository) Save(dc *models.DeviceCode) error {
	scopes, _ := json.Marshal(dc.Scopes)
	query := `INSERT INTO device_codes (device_code, user_code, client_id, scopes, status, expires_at, interval)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		dc.DeviceCode, dc.UserCode, dc.ClientID,
		string(scopes), dc.Status, dc.ExpiresAt, dc.Interval,
	)
	return err
}

func (r *DeviceCodeRepository) GetByDeviceCode(deviceCode string) (*models.DeviceCode, error) {
	query := `SELECT device_code, user_code, client_id, scopes, status, expires_at, interval
		FROM device_codes WHERE device_code = ?`

	dc := &models.DeviceCode{}
	var scopes string

	err := r.db.QueryRow(query, deviceCode).Scan(
		&dc.DeviceCode, &dc.UserCode, &dc.ClientID,
		&scopes, &dc.Status, &dc.ExpiresAt, &dc.Interval,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(scopes), &dc.Scopes); err != nil {
		return nil, err
	}
	return dc, nil
}

func (r *DeviceCodeRepository) GetByUserCode(userCode string) (*models.DeviceCode, error) {
	query := `SELECT device_code, user_code, client_id, scopes, status, expires_at, interval
		FROM device_codes WHERE user_code = ?`

	dc := &models.DeviceCode{}
	var scopes string

	err := r.db.QueryRow(query, userCode).Scan(
		&dc.DeviceCode, &dc.UserCode, &dc.ClientID,
		&scopes, &dc.Status, &dc.ExpiresAt, &dc.Interval,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(scopes), &dc.Scopes); err != nil {
		return nil, err
	}
	return dc, nil
}

func (r *DeviceCodeRepository) UpdateStatus(deviceCode, status string) error {
	_, err := r.db.Exec("UPDATE device_codes SET status = ? WHERE device_code = ?", status, deviceCode)
	return err
}
