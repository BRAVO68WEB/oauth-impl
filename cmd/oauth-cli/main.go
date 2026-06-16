package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"
)

var (
	serverURL string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "oauth-cli",
		Short: "OAuth Implementation Server Management CLI",
		Long:  "A CLI tool for managing the OAuth Implementation Server",
	}

	rootCmd.PersistentFlags().StringVar(&serverURL, "server", "http://127.0.0.1:8080", "OAuth server URL")

	rootCmd.AddCommand(
		initCmd(),
		serverCmd(),
		clientCmd(),
		userCmd(),
		tokenCmd(),
		cibaCmd(),
		flowCmd(),
		mfaCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func serverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Server management commands",
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Check server status",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := http.Get(serverURL + "/health")
			if err != nil {
				return fmt.Errorf("server is not reachable: %w", err)
			}
			defer resp.Body.Close()

			var result map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			fmt.Printf("Server Status: %s\n", result["status"])
			fmt.Printf("Time: %s\n", result["time"])
			return nil
		},
	}

	discoveryCmd := &cobra.Command{
		Use:   "discovery",
		Short: "Show OIDC discovery information",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := http.Get(serverURL + "/.well-known/openid-configuration")
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			for k, v := range result {
				fmt.Fprintf(w, "%s:\t%v\n", k, v)
			}
			w.Flush()
			return nil
		},
	}

	cmd.AddCommand(statusCmd, discoveryCmd)
	return cmd
}

func clientCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "client",
		Short: "Client management commands",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all clients",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := http.Get(serverURL + "/api/clients")
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var clients []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "ID\tNAME\tGRANT TYPES\tAUTH METHOD\n")
			for _, c := range clients {
				fmt.Fprintf(w, "%s\t%s\t%v\t%s\n",
					c["id"], c["name"], c["grant_types"], c["token_endpoint_auth_method"])
			}
			w.Flush()
			return nil
		},
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new client",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			redirectURIs, _ := cmd.Flags().GetStringSlice("redirect-uri")
			grantTypes, _ := cmd.Flags().GetStringSlice("grant-type")
			scopes, _ := cmd.Flags().GetStringSlice("scope")

			if name == "" {
				return fmt.Errorf("name is required")
			}

			body := map[string]interface{}{
				"name":          name,
				"redirect_uris": redirectURIs,
				"grant_types":   grantTypes,
				"scopes":        scopes,
			}

			jsonBody, _ := json.Marshal(body)
			resp, err := http.Post(serverURL+"/api/clients", "application/json", bytes.NewBuffer(jsonBody))
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if resp.StatusCode != http.StatusCreated {
				errMsg := result["error_description"]
				if errMsg == nil {
					errMsg = result["error"]
				}
				return fmt.Errorf("failed to create client: %v", errMsg)
			}

			fmt.Printf("Client created successfully!\n")
			fmt.Printf("Client ID: %s\n", result["id"])
			fmt.Printf("Client Secret: %s\n", result["secret"])
			return nil
		},
	}

	createCmd.Flags().StringP("name", "n", "", "Client name")
	createCmd.Flags().StringSliceP("redirect-uri", "r", []string{}, "Redirect URIs")
	createCmd.Flags().StringSliceP("grant-type", "g", []string{"authorization_code"}, "Grant types")
	createCmd.Flags().StringSliceP("scope", "s", []string{"openid"}, "Scopes")

	getCmd := &cobra.Command{
		Use:   "get [client-id]",
		Short: "Get client details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := http.Get(serverURL + "/api/clients/" + args[0])
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			for k, v := range result {
				fmt.Fprintf(w, "%s:\t%v\n", k, v)
			}
			w.Flush()
			return nil
		},
	}

	deleteCmd := &cobra.Command{
		Use:   "delete [client-id]",
		Short: "Delete a client",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := http.NewRequest("DELETE", serverURL+"/api/clients/"+args[0], nil)
			if err != nil {
				return err
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			fmt.Printf("Client %s deleted successfully\n", args[0])
			return nil
		},
	}

	cmd.AddCommand(listCmd, createCmd, getCmd, deleteCmd)
	return cmd
}

func userCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "User management commands",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all users",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := http.Get(serverURL + "/api/users")
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var users []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "ID\tUSERNAME\tEMAIL\n")
			for _, u := range users {
				fmt.Fprintf(w, "%s\t%s\t%s\n",
					u["id"], u["username"], u["email"])
			}
			w.Flush()
			return nil
		},
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new user",
		RunE: func(cmd *cobra.Command, args []string) error {
			username, _ := cmd.Flags().GetString("username")
			password, _ := cmd.Flags().GetString("password")
			email, _ := cmd.Flags().GetString("email")

			if username == "" || password == "" {
				return fmt.Errorf("username and password are required")
			}

			body := map[string]interface{}{
				"username": username,
				"password": password,
				"email":    email,
			}

			jsonBody, _ := json.Marshal(body)
			resp, err := http.Post(serverURL+"/api/users", "application/json", bytes.NewBuffer(jsonBody))
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if resp.StatusCode != http.StatusCreated {
				errMsg := result["error_description"]
				if errMsg == nil {
					errMsg = result["error"]
				}
				return fmt.Errorf("failed to create user: %v", errMsg)
			}

			fmt.Printf("User created successfully!\n")
			fmt.Printf("User ID: %s\n", result["id"])
			fmt.Printf("Username: %s\n", result["username"])
			return nil
		},
	}

	createCmd.Flags().StringP("username", "u", "", "Username")
	createCmd.Flags().StringP("password", "p", "", "Password")
	createCmd.Flags().StringP("email", "e", "", "Email")

	getCmd := &cobra.Command{
		Use:   "get [user-id]",
		Short: "Get user details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := http.Get(serverURL + "/api/users/" + args[0])
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			for k, v := range result {
				fmt.Fprintf(w, "%s:\t%v\n", k, v)
			}
			w.Flush()
			return nil
		},
	}

	cmd.AddCommand(listCmd, createCmd, getCmd)
	return cmd
}

func tokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Token management commands",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID, _ := cmd.Flags().GetString("client-id")
			userID, _ := cmd.Flags().GetString("user-id")

			url := serverURL + "/api/tokens?"
			if clientID != "" {
				url += "client_id=" + clientID + "&"
			}
			if userID != "" {
				url += "user_id=" + userID
			}

			resp, err := http.Get(url)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var tokens []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "TOKEN\tCLIENT ID\tUSER ID\tTYPE\tEXPIRES\n")
			for _, t := range tokens {
				token := t["token"].(string)
				if len(token) > 20 {
					token = token[:20] + "..."
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					token, t["client_id"], t["user_id"], t["token_type"], t["expires_at"])
			}
			w.Flush()
			return nil
		},
	}

	listCmd.Flags().String("client-id", "", "Filter by client ID")
	listCmd.Flags().String("user-id", "", "Filter by user ID")

	introspectCmd := &cobra.Command{
		Use:   "introspect [token]",
		Short: "Introspect a token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := "token=" + args[0]
			resp, err := http.Post(serverURL+"/oauth/introspect",
				"application/x-www-form-urlencoded",
				bytes.NewBufferString(body))
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			for k, v := range result {
				fmt.Fprintf(w, "%s:\t%v\n", k, v)
			}
			w.Flush()
			return nil
		},
	}

	revokeCmd := &cobra.Command{
		Use:   "revoke [token]",
		Short: "Revoke a token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := http.NewRequest("POST", serverURL+"/api/tokens/"+args[0]+"/revoke", nil)
			if err != nil {
				return err
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			fmt.Printf("Token revoked successfully\n")
			return nil
		},
	}

	cmd.AddCommand(listCmd, introspectCmd, revokeCmd)
	return cmd
}

func cibaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ciba",
		Short: "CIBA request management commands",
	}

	pendingCmd := &cobra.Command{
		Use:   "pending",
		Short: "List pending CIBA requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := http.Get(serverURL + "/ciba/pending")
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var requests []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&requests); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "AUTH REQ ID\tCLIENT ID\tBINDING MSG\tSTATUS\tEXPIRES\n")
			for _, r := range requests {
				authReqID := r["auth_req_id"].(string)
				if len(authReqID) > 20 {
					authReqID = authReqID[:20] + "..."
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					authReqID, r["client_id"], r["binding_message"], r["status"], r["expires_at"])
			}
			w.Flush()
			return nil
		},
	}

	approveCmd := &cobra.Command{
		Use:   "approve [auth-req-id]",
		Short: "Approve a CIBA request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			userID, _ := cmd.Flags().GetString("user-id")

			url := fmt.Sprintf("%s/ciba/approve?auth_req_id=%s", serverURL, args[0])
			if userID != "" {
				url += "&user_id=" + userID
			}

			resp, err := http.Post(url, "", nil)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var result map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			fmt.Printf("CIBA request approved: %s\n", result["status"])
			return nil
		},
	}

	approveCmd.Flags().StringP("user-id", "u", "", "User ID to associate with the approval")

	denyCmd := &cobra.Command{
		Use:   "deny [auth-req-id]",
		Short: "Deny a CIBA request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reason, _ := cmd.Flags().GetString("reason")

			url := fmt.Sprintf("%s/ciba/deny?auth_req_id=%s", serverURL, args[0])
			if reason != "" {
				url += "&reason=" + reason
			}

			resp, err := http.Post(url, "", nil)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var result map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			fmt.Printf("CIBA request denied: %s\n", result["status"])
			return nil
		},
	}

	denyCmd.Flags().StringP("reason", "r", "", "Reason for denial")

	cmd.AddCommand(pendingCmd, approveCmd, denyCmd)
	return cmd
}

func flowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "flow",
		Short: "OAuth flow testing commands",
	}

	clientCredsCmd := &cobra.Command{
		Use:   "client-credentials",
		Short: "Test client credentials flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID, _ := cmd.Flags().GetString("client-id")
			clientSecret, _ := cmd.Flags().GetString("client-secret")
			scope, _ := cmd.Flags().GetString("scope")

			if clientID == "" || clientSecret == "" {
				return fmt.Errorf("client-id and client-secret are required")
			}

			body := fmt.Sprintf("grant_type=client_credentials&scope=%s", scope)
			req, err := http.NewRequest("POST", serverURL+"/oauth/token", bytes.NewBufferString(body))
			if err != nil {
				return err
			}
			req.SetBasicAuth(clientID, clientSecret)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if errMsg, ok := result["error"]; ok {
				fmt.Printf("Error: %s - %s\n", errMsg, result["error_description"])
				return nil
			}

			fmt.Printf("Access Token: %s\n", result["access_token"])
			fmt.Printf("Token Type: %s\n", result["token_type"])
			fmt.Printf("Expires In: %v\n", result["expires_in"])
			fmt.Printf("Scope: %s\n", result["scope"])
			return nil
		},
	}

	clientCredsCmd.Flags().String("client-id", "", "Client ID")
	clientCredsCmd.Flags().String("client-secret", "", "Client Secret")
	clientCredsCmd.Flags().String("scope", "openid", "Scopes")

	deviceCmd := &cobra.Command{
		Use:   "device",
		Short: "Test device authorization flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID, _ := cmd.Flags().GetString("client-id")
			clientSecret, _ := cmd.Flags().GetString("client-secret")
			scope, _ := cmd.Flags().GetString("scope")

			if clientID == "" || clientSecret == "" {
				return fmt.Errorf("client-id and client-secret are required")
			}

			body := fmt.Sprintf("scope=%s", scope)
			req, err := http.NewRequest("POST", serverURL+"/oauth/device", bytes.NewBufferString(body))
			if err != nil {
				return err
			}
			req.SetBasicAuth(clientID, clientSecret)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			fmt.Printf("Device Code: %s\n", result["device_code"])
			fmt.Printf("User Code: %s\n", result["user_code"])
			fmt.Printf("Verification URI: %s\n", result["verification_uri"])
			fmt.Printf("Expires In: %v seconds\n", result["expires_in"])
			return nil
		},
	}

	deviceCmd.Flags().String("client-id", "", "Client ID")
	deviceCmd.Flags().String("client-secret", "", "Client Secret")
	deviceCmd.Flags().String("scope", "openid", "Scopes")

	cmd.AddCommand(clientCredsCmd, deviceCmd)
	return cmd
}

func initCmd() *cobra.Command {
	var outputPath string
	var withMFA bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize server configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := `# OAuth Implementation Server Configuration
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: false
    cert_file: ""
    key_file: ""

database:
  path: "./oauth.db"
  migrations: true

security:
  access_token_lifetime: 3600s
  refresh_token_lifetime: 86400s
  authorization_code_lifetime: 600s
  device_code_lifetime: 1800s
  ciba_request_lifetime: 120s
  request_uri_lifetime: 60s
  require_pkce: true
  allow_plain_pkce: false
  issuer: "http://localhost:8080"
  mfa:
    enabled: false
    required: false
    issuer: "OAuthImplServer"
    digits: 6
    period: 30

queue:
  type: "memory"
  poll_interval: 5s
  max_pending: 100

oidc:
  issuer: "http://localhost:8080"
  supported_scopes:
    - openid
    - profile
    - email
    - address
    - phone
    - offline_access
  supported_claims:
    - sub
    - name
    - given_name
    - family_name
    - email
    - email_verified
    - preferred_username
  supported_grant_types:
    - authorization_code
    - client_credentials
    - refresh_token
    - urn:ietf:params:oauth:grant-type:device_code
    - urn:openid:params:grant-type:ciba
  supported_auth_methods:
    - client_secret_basic
    - client_secret_post
    - client_secret_jwt
    - private_key_jwt
    - none
`
			if withMFA {
				cfg = strings.Replace(cfg, "enabled: false", "enabled: true", 1)
				cfg = strings.Replace(cfg, "required: false", "required: true", 1)
			}

			if outputPath == "" {
				outputPath = "config.yaml"
			}

			if err := os.WriteFile(outputPath, []byte(cfg), 0644); err != nil {
				return fmt.Errorf("failed to write config file: %w", err)
			}

			fmt.Printf("Configuration file written to: %s\n", outputPath)
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: config.yaml)")
	cmd.Flags().BoolVar(&withMFA, "mfa", false, "Enable MFA in generated config")

	return cmd
}

func mfaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mfa",
		Short: "MFA management commands",
	}

	enableCmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable MFA for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			userID, _ := cmd.Flags().GetString("user-id")
			showSecret, _ := cmd.Flags().GetBool("show-secret")

			if userID == "" {
				return fmt.Errorf("user-id is required")
			}

			resp, err := http.PostForm(serverURL+"/api/users/"+userID+"/mfa/enable", nil)
			if err != nil {
				return fmt.Errorf("failed to enable MFA: %w", err)
			}
			defer resp.Body.Close()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if showSecret {
				fmt.Printf("MFA Secret: %s\n", result["secret"])
				fmt.Printf("Add this to your authenticator manually, then run:\n")
				fmt.Printf("  oauth-cli mfa verify --user-id %s\n", userID)
			} else {
				qrURI, _ := result["qr_uri"].(string)
				qrBase64, _ := result["qr_base64"].(string)
				secret, _ := result["secret"].(string)

				fmt.Println("┌─────────────────────────────────────────────┐")
				fmt.Println("│  Scan this QR code with your authenticator  │")
				fmt.Println("└─────────────────────────────────────────────┘")
				fmt.Println()

				if qrBase64 != "" {
					qrBytes, err := base64.StdEncoding.DecodeString(qrBase64)
					if err == nil {
						qr, err := qrcode.New(qrURI, qrcode.Medium)
						if err == nil {
							_ = qrBytes
							fmt.Println(qr.ToSmallString(false))
						}
					}
				}

				fmt.Println()
				fmt.Printf("Secret: %s\n", secret)
				fmt.Printf("Issuer: OAuthImplServer\n")
				fmt.Println()
				fmt.Printf("Enter code to verify: ")
				
				var code string
				fmt.Scanln(&code)
				
				if code != "" {
					verifyResp, err := http.Post(
						serverURL+"/api/users/"+userID+"/mfa/verify",
						"application/json",
						bytes.NewBufferString(fmt.Sprintf(`{"code":"%s"}`, code)),
					)
					if err != nil {
						return fmt.Errorf("failed to verify MFA: %w", err)
					}
					defer verifyResp.Body.Close()

					var verifyResult map[string]interface{}
					if err := json.NewDecoder(verifyResp.Body).Decode(&verifyResult); err != nil {
						return fmt.Errorf("failed to decode response: %w", err)
					}

					if verifyResp.StatusCode == http.StatusOK {
						fmt.Println("✅ MFA verified and enabled successfully")
					} else {
						errMsg := verifyResult["error_description"]
						if errMsg == nil {
							errMsg = verifyResult["error"]
						}
						fmt.Printf("❌ MFA verification failed: %v\n", errMsg)
					}
				}
			}

			return nil
		},
	}

	enableCmd.Flags().String("user-id", "", "User ID")
	enableCmd.Flags().Bool("show-secret", false, "Show secret text instead of QR code")

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify MFA code for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			userID, _ := cmd.Flags().GetString("user-id")
			code, _ := cmd.Flags().GetString("code")

			if userID == "" || code == "" {
				return fmt.Errorf("user-id and code are required")
			}

			data := map[string]string{
				"code": code,
			}

			jsonData, _ := json.Marshal(data)
			resp, err := http.Post(serverURL+"/api/users/"+userID+"/mfa/verify",
				"application/json", bytes.NewBuffer(jsonData))
			if err != nil {
				return fmt.Errorf("failed to verify MFA: %w", err)
			}
			defer resp.Body.Close()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if resp.StatusCode == http.StatusOK {
				fmt.Println("✅ MFA verified and enabled successfully")
			} else {
				errMsg := result["error_description"]
				if errMsg == nil {
					errMsg = result["error"]
				}
				return fmt.Errorf("MFA verification failed: %v", errMsg)
			}

			return nil
		},
	}

	verifyCmd.Flags().String("user-id", "", "User ID")
	verifyCmd.Flags().String("code", "", "TOTP code")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Check MFA status for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			userID, _ := cmd.Flags().GetString("user-id")
			if userID == "" {
				return fmt.Errorf("user-id is required")
			}

			resp, err := http.Get(serverURL + "/api/users/" + userID + "/mfa/status")
			if err != nil {
				return fmt.Errorf("failed to check MFA status: %w", err)
			}
			defer resp.Body.Close()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if resp.StatusCode != http.StatusOK {
				errMsg := result["error_description"]
				if errMsg == nil {
					errMsg = result["error"]
				}
				return fmt.Errorf("failed to check MFA status: %v", errMsg)
			}

			fmt.Printf("User ID: %s\n", result["user_id"])
			fmt.Printf("MFA Enabled: %v\n", result["mfa_enabled"])
			return nil
		},
	}

	statusCmd.Flags().String("user-id", "", "User ID")

	cmd.AddCommand(enableCmd, verifyCmd, statusCmd)
	return cmd
}
