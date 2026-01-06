package ratelimiter

import (
	"testing"
	"time"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr error
	}{
		{
			name: "valid config",
			config: Config{
				Rate:      100,
				Window:    time.Minute,
				BurstSize: 100,
			},
			wantErr: nil,
		},
		{
			name: "zero rate",
			config: Config{
				Rate:   0,
				Window: time.Minute,
			},
			wantErr: ErrInvalidRate,
		},
		{
			name: "negative rate",
			config: Config{
				Rate:   -1,
				Window: time.Minute,
			},
			wantErr: ErrInvalidRate,
		},
		{
			name: "zero window",
			config: Config{
				Rate:   100,
				Window: 0,
			},
			wantErr: ErrInvalidWindow,
		},
		{
			name: "negative window",
			config: Config{
				Rate:   100,
				Window: -time.Minute,
			},
			wantErr: ErrInvalidWindow,
		},
		{
			name: "negative burst size",
			config: Config{
				Rate:      100,
				Window:    time.Minute,
				BurstSize: -1,
			},
			wantErr: ErrInvalidBurstSize,
		},
		{
			name: "zero burst size is valid",
			config: Config{
				Rate:      100,
				Window:    time.Minute,
				BurstSize: 0,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_WithBurstSize(t *testing.T) {
	config := Config{
		Rate:      100,
		Window:    time.Minute,
		BurstSize: 100,
	}

	newConfig := config.WithBurstSize(200)

	// Original should be unchanged
	if config.BurstSize != 100 {
		t.Error("Original config should be unchanged")
	}

	// New config should have new burst size
	if newConfig.BurstSize != 200 {
		t.Errorf("Expected BurstSize=200, got %d", newConfig.BurstSize)
	}

	// Other fields should be preserved
	if newConfig.Rate != 100 || newConfig.Window != time.Minute {
		t.Error("Other fields should be preserved")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Rate != 100 {
		t.Errorf("Expected Rate=100, got %d", config.Rate)
	}

	if config.Window != time.Minute {
		t.Errorf("Expected Window=1m, got %v", config.Window)
	}

	if config.BurstSize != 100 {
		t.Errorf("Expected BurstSize=100, got %d", config.BurstSize)
	}

	// Default config should be valid
	if err := config.Validate(); err != nil {
		t.Errorf("Default config should be valid: %v", err)
	}
}
