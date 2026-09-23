package llm

import "testing"

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid",
			cfg: Config{
				Providers: map[string]ProviderConfig{
					"local-big": {Type: ProviderOpenAICompat, BaseURL: "http://127.0.0.1:11434/v1", Model: "m"},
				},
				Tasks: map[string][]string{"extract": {"local-big"}},
			},
		},
		{
			name:    "empty config is valid (no LLM configured)",
			cfg:     Config{},
			wantErr: false,
		},
		{
			name: "unknown provider type",
			cfg: Config{
				Providers: map[string]ProviderConfig{"p": {Type: "bogus", BaseURL: "http://x/v1", Model: "m"}},
			},
			wantErr: true,
		},
		{
			name: "openaicompat missing base_url",
			cfg: Config{
				Providers: map[string]ProviderConfig{"p": {Type: ProviderOpenAICompat, Model: "m"}},
			},
			wantErr: true,
		},
		{
			name: "anthropic without base_url is fine (adapter defaults it)",
			cfg: Config{
				Providers: map[string]ProviderConfig{"p": {Type: ProviderAnthropic, Model: "m"}},
			},
			wantErr: false,
		},
		{
			name: "relative base_url when given is rejected regardless of type",
			cfg: Config{
				Providers: map[string]ProviderConfig{"p": {Type: ProviderAnthropic, BaseURL: "/v1", Model: "m"}},
			},
			wantErr: true,
		},
		{
			name: "missing model",
			cfg: Config{
				Providers: map[string]ProviderConfig{"p": {Type: ProviderAnthropic, BaseURL: "https://api.anthropic.com", Model: ""}},
			},
			wantErr: true,
		},
		{
			name: "task references unknown provider",
			cfg: Config{
				Providers: map[string]ProviderConfig{"p": {Type: ProviderAnthropic, BaseURL: "https://api.anthropic.com", Model: "m"}},
				Tasks:     map[string][]string{"extract": {"missing"}},
			},
			wantErr: true,
		},
		{
			name: "unknown task name",
			cfg: Config{
				Providers: map[string]ProviderConfig{"p": {Type: ProviderAnthropic, BaseURL: "https://api.anthropic.com", Model: "m"}},
				Tasks:     map[string][]string{"summarize": {"p"}},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsLocalHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"127.0.0.1:11434", true},
		{"127.0.0.1", true},
		{"[::1]:8080", true},
		{"::1", true},
		{"localhost:11434", true},
		{"llama.local", true},
		{"192.168.1.5:11434", true},
		{"10.0.0.1", true},
		{"169.254.1.1", true},
		{"8.8.8.8", false},
		{"api.anthropic.com", false},
		{"api.openai.com:443", false},
		{"evil.example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := IsLocalHost(tt.host); got != tt.want {
				t.Errorf("IsLocalHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}
