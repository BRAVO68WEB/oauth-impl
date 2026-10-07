package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
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
	rootCmd.PersistentFlags().StringVar(&mgmtClientID, "client-id", "", "Management client ID")
	rootCmd.PersistentFlags().StringVar(&mgmtClientSecret, "client-secret", "", "Management client secret")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "config.yaml", "Config file used for management credentials")

	rootCmd.AddCommand(
		initCmd(),
		serverCmd(),
		clientCmd(),
		userCmd(),
		tokenCmd(),
		cibaCmd(),
		flowCmd(),
		mfaCmd(),
		scopeCmd(),
		resourceCmd(),
		consentCmd(),
		webhookCmd(),
		analyticsCmd(),
		auditCmd(),
		keysCmd(),
		orgCmd(),
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
			defer func() { _ = resp.Body.Close() }()

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
			defer func() { _ = resp.Body.Close() }()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			for k, v := range result {
				_, _ = fmt.Fprintf(w, "%s:\t%v\n", k, v)
			}
			_ = w.Flush()
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
			resp, err := apiGet(serverURL + "/api/clients")
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var clients []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "ID\tNAME\tGRANT TYPES\tAUTH METHOD\n")
			for _, c := range clients {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%v\t%s\n",
					c["id"], c["name"], c["grant_types"], c["token_endpoint_auth_method"])
			}
			_ = w.Flush()
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

			dcrEnabled, _ := cmd.Flags().GetBool("dcr-enabled")
			cimdEnabled, _ := cmd.Flags().GetBool("cimd-enabled")
			body := map[string]interface{}{
				"name":          name,
				"redirect_uris": redirectURIs,
				"grant_types":   grantTypes,
				"scopes":        scopes,
				"dcr_enabled":   dcrEnabled,
				"cimd_enabled":  cimdEnabled,
			}

			jsonBody, _ := json.Marshal(body)
			resp, err := apiPost(serverURL+"/api/clients", "application/json", bytes.NewBuffer(jsonBody))
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

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
	createCmd.Flags().Bool("dcr-enabled", false, "Allow this app when tenant dynamic registration is on")
	createCmd.Flags().Bool("cimd-enabled", false, "Allow this app when tenant client metadata documents are on")

	updateCmd := &cobra.Command{
		Use:   "update [client-id]",
		Short: "Update per-app DCR, CIMD, or forced DPoP flags",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(serverURL + "/api/clients/" + args[0])
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			var client map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&client); err != nil {
				return err
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("failed to load client: %v", client["error_description"])
			}
			if cmd.Flags().Changed("dcr-enabled") {
				v, _ := cmd.Flags().GetBool("dcr-enabled")
				client["dcr_enabled"] = v
			}
			if cmd.Flags().Changed("cimd-enabled") {
				v, _ := cmd.Flags().GetBool("cimd-enabled")
				client["cimd_enabled"] = v
			}
			if cmd.Flags().Changed("dpop") {
				v, _ := cmd.Flags().GetBool("dpop")
				client["dpop_bound_access_tokens"] = v
			}
			delete(client, "secret")
			body, _ := json.Marshal(client)
			put, err := apiPut(serverURL+"/api/clients/"+args[0], "application/json", bytes.NewReader(body))
			if err != nil {
				return err
			}
			defer func() { _ = put.Body.Close() }()
			if put.StatusCode != http.StatusOK {
				var result map[string]any
				_ = json.NewDecoder(put.Body).Decode(&result)
				return fmt.Errorf("failed to update client: %v", result["error_description"])
			}
			fmt.Printf("Client %s updated\n", args[0])
			return nil
		},
	}
	updateCmd.Flags().Bool("dcr-enabled", false, "Allow this app when tenant dynamic registration is on")
	updateCmd.Flags().Bool("cimd-enabled", false, "Allow this app when tenant client metadata documents are on")
	updateCmd.Flags().Bool("dpop", false, "Require DPoP for every token from this app")

	getCmd := &cobra.Command{
		Use:   "get [client-id]",
		Short: "Get client details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(serverURL + "/api/clients/" + args[0])
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			for k, v := range result {
				_, _ = fmt.Fprintf(w, "%s:\t%v\n", k, v)
			}
			_ = w.Flush()
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

			resp, err := withManagement(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			fmt.Printf("Client %s deleted successfully\n", args[0])
			return nil
		},
	}

	masterCmd := &cobra.Command{
		Use:   "master",
		Short: "Create a master client with all permissions",
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]interface{}{
				"name": "Master Client",
				"redirect_uris": []string{
					"https://localhost/Callback",
					"http://localhost:3000/callback",
					"http://localhost:8080/callback",
				},
				"grant_types": []string{
					"authorization_code",
					"client_credentials",
					"refresh_token",
					"password",
					"urn:ietf:params:oauth:grant-type:device_code",
					"urn:openid:params:grant-type:ciba",
					"urn:ietf:params:oauth:grant-type:token-exchange",
				},
				"scopes": []string{
					"openid", "profile", "email", "address", "phone", "offline_access",
					"read", "write", "admin",
				},
				"token_endpoint_auth_method":            "client_secret_basic",
				"dpop_bound_access_tokens":              false,
				"require_pushed_authorization_requests": false,
				"backchannel_token_delivery_mode":       "poll",
			}

			jsonBody, _ := json.Marshal(body)
			resp, err := apiPost(serverURL+"/api/clients", "application/json", bytes.NewBuffer(jsonBody))
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if resp.StatusCode != http.StatusCreated {
				errMsg := result["error_description"]
				if errMsg == nil {
					errMsg = result["error"]
				}
				return fmt.Errorf("failed to create master client: %v", errMsg)
			}

			fmt.Println("╔══════════════════════════════════════════════════════════════╗")
			fmt.Println("║                    Master Client Created                     ║")
			fmt.Println("╠══════════════════════════════════════════════════════════════╣")
			fmt.Printf("║  Client ID:     %-44s ║\n", result["id"])
			fmt.Printf("║  Client Secret: %-44s ║\n", result["secret"])
			fmt.Println("╠══════════════════════════════════════════════════════════════╣")
			fmt.Println("║  Grant Types:                                               ║")
			fmt.Println("║    • authorization_code                                      ║")
			fmt.Println("║    • client_credentials                                      ║")
			fmt.Println("║    • refresh_token                                           ║")
			fmt.Println("║    • password                                                ║")
			fmt.Println("║    • device_code (RFC 8628)                                  ║")
			fmt.Println("║    • ciba                                                    ║")
			fmt.Println("║    • token_exchange (RFC 8693)                               ║")
			fmt.Println("╠══════════════════════════════════════════════════════════════╣")
			fmt.Println("║  Scopes: openid profile email address phone offline_access   ║")
			fmt.Println("║          read write admin                                    ║")
			fmt.Println("╚══════════════════════════════════════════════════════════════╝")
			return nil
		},
	}

	cmd.AddCommand(listCmd, createCmd, getCmd, updateCmd, deleteCmd, masterCmd)
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
			resp, err := apiGet(serverURL + "/api/users")
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var users []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "ID\tUSERNAME\tEMAIL\n")
			for _, u := range users {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n",
					u["id"], u["username"], u["email"])
			}
			_ = w.Flush()
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
			resp, err := apiPost(serverURL+"/api/users", "application/json", bytes.NewBuffer(jsonBody))
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

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
			resp, err := apiGet(serverURL + "/api/users/" + args[0])
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			for k, v := range result {
				_, _ = fmt.Fprintf(w, "%s:\t%v\n", k, v)
			}
			_ = w.Flush()
			return nil
		},
	}

	passwordCmd := &cobra.Command{
		Use:   "password [user-id]",
		Short: "Set a user's password",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			password, _ := cmd.Flags().GetString("password")
			if password == "" {
				return fmt.Errorf("password is required")
			}
			body, _ := json.Marshal(map[string]string{"password": password})
			resp, err := apiPost(serverURL+"/api/users/"+args[0]+"/password", "application/json", bytes.NewBuffer(body))
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("set password failed: %s", resp.Status)
			}
			fmt.Println("Password updated")
			return nil
		},
	}
	passwordCmd.Flags().StringP("password", "p", "", "New password")

	disableCmd := &cobra.Command{
		Use:   "disable [user-id]",
		Short: "Disable a user",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return patchUserDisabled(args[0], true) },
	}
	enableCmd := &cobra.Command{
		Use:   "enable [user-id]",
		Short: "Enable a user",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return patchUserDisabled(args[0], false) },
	}

	cmd.AddCommand(listCmd, createCmd, getCmd, passwordCmd, disableCmd, enableCmd)
	return cmd
}

func patchUserDisabled(userID string, disabled bool) error {
	body, _ := json.Marshal(map[string]bool{"disabled": disabled})
	req, err := http.NewRequest(http.MethodPatch, serverURL+"/api/users/"+userID, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := withManagement(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("update user failed: %s", resp.Status)
	}
	if disabled {
		fmt.Println("User disabled")
	} else {
		fmt.Println("User enabled")
	}
	return nil
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

			resp, err := apiGet(url)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var tokens []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "TOKEN\tCLIENT ID\tUSER ID\tTYPE\tEXPIRES\n")
			for _, t := range tokens {
				token := t["token"].(string)
				if len(token) > 20 {
					token = token[:20] + "..."
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					token, t["client_id"], t["user_id"], t["token_type"], t["expires_at"])
			}
			_ = w.Flush()
			return nil
		},
	}

	listCmd.Flags().String("client-id", "", "Filter by client ID")
	listCmd.Flags().String("user-id", "", "Filter by user ID")

	refreshCmd := &cobra.Command{
		Use:   "refresh",
		Short: "Refresh token management",
	}
	refreshList := &cobra.Command{
		Use:   "list",
		Short: "List refresh tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID, _ := cmd.Flags().GetString("client-id")
			userID, _ := cmd.Flags().GetString("user-id")
			path := serverURL + "/api/refresh-tokens?"
			if clientID != "" {
				path += "client_id=" + clientID + "&"
			}
			if userID != "" {
				path += "user_id=" + userID
			}
			resp, err := apiGet(path)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			var tokens []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "ID\tCLIENT ID\tUSER ID\tFAMILY\tEXPIRES\n")
			for _, t := range tokens {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", t["id"], t["client_id"], t["user_id"], t["family_id"], t["expires_at"])
			}
			_ = w.Flush()
			return nil
		},
	}
	refreshList.Flags().String("client-id", "", "Filter by client ID")
	refreshList.Flags().String("user-id", "", "Filter by user ID")
	refreshRevoke := &cobra.Command{
		Use:   "revoke [id]",
		Short: "Revoke a refresh token by public id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiPost(serverURL+"/api/refresh-tokens/"+args[0]+"/revoke", "", nil)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("revoke failed: %s", resp.Status)
			}
			fmt.Println("Refresh token revoked")
			return nil
		},
	}
	refreshCmd.AddCommand(refreshList, refreshRevoke)

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
			defer func() { _ = resp.Body.Close() }()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			for k, v := range result {
				_, _ = fmt.Fprintf(w, "%s:\t%v\n", k, v)
			}
			_ = w.Flush()
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

			resp, err := withManagement(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			fmt.Printf("Token revoked successfully\n")
			return nil
		},
	}

	cmd.AddCommand(listCmd, introspectCmd, revokeCmd, refreshCmd)
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
			resp, err := apiGet(serverURL + "/ciba/pending")
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var requests []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&requests); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "AUTH REQ ID\tCLIENT ID\tBINDING MSG\tSTATUS\tEXPIRES\n")
			for _, r := range requests {
				authReqID := r["auth_req_id"].(string)
				if len(authReqID) > 20 {
					authReqID = authReqID[:20] + "..."
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					authReqID, r["client_id"], r["binding_message"], r["status"], r["expires_at"])
			}
			_ = w.Flush()
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

			resp, err := apiPost(url, "", nil)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

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

			resp, err := apiPost(url, "", nil)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

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
			defer func() { _ = resp.Body.Close() }()

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
			defer func() { _ = resp.Body.Close() }()

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

			resp, err := apiPostForm(serverURL+"/api/users/"+userID+"/mfa/enable", nil)
			if err != nil {
				return fmt.Errorf("failed to enable MFA: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

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
				_, _ = fmt.Scanln(&code)

				if code != "" {
					verifyResp, err := apiPost(
						serverURL+"/api/users/"+userID+"/mfa/verify",
						"application/json",
						bytes.NewBufferString(fmt.Sprintf(`{"code":"%s"}`, code)),
					)
					if err != nil {
						return fmt.Errorf("failed to verify MFA: %w", err)
					}
					defer func() { _ = verifyResp.Body.Close() }()

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
			resp, err := apiPost(serverURL+"/api/users/"+userID+"/mfa/verify",
				"application/json", bytes.NewBuffer(jsonData))
			if err != nil {
				return fmt.Errorf("failed to verify MFA: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

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

			resp, err := apiGet(serverURL + "/api/users/" + userID + "/mfa/status")
			if err != nil {
				return fmt.Errorf("failed to check MFA status: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

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

func scopeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scope",
		Short: "Scope management commands",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all scopes",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(serverURL + "/api/scopes")
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var scopes []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&scopes); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "NAME\tDESCRIPTION\tRESOURCE SERVER\tDEFAULT\n")
			for _, s := range scopes {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%v\n",
					s["name"], s["description"], s["resource_server"], s["is_default"])
			}
			_ = w.Flush()
			return nil
		},
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new scope",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			description, _ := cmd.Flags().GetString("description")
			resourceServer, _ := cmd.Flags().GetString("resource-server")
			isDefault, _ := cmd.Flags().GetBool("default")

			if name == "" {
				return fmt.Errorf("name is required")
			}

			body := map[string]interface{}{
				"name":            name,
				"description":     description,
				"resource_server": resourceServer,
				"is_default":      isDefault,
			}

			jsonBody, _ := json.Marshal(body)
			resp, err := apiPost(serverURL+"/api/scopes", "application/json", bytes.NewBuffer(jsonBody))
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if resp.StatusCode != http.StatusCreated {
				errMsg := result["error_description"]
				if errMsg == nil {
					errMsg = result["error"]
				}
				return fmt.Errorf("failed to create scope: %v", errMsg)
			}

			fmt.Printf("Scope created: %s\n", result["name"])
			return nil
		},
	}

	createCmd.Flags().StringP("name", "n", "", "Scope name")
	createCmd.Flags().StringP("description", "d", "", "Scope description")
	createCmd.Flags().String("resource-server", "", "Resource server URI")
	createCmd.Flags().Bool("default", false, "Is default scope")

	deleteCmd := &cobra.Command{
		Use:   "delete [name]",
		Short: "Delete a scope",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := http.NewRequest("DELETE", serverURL+"/api/scopes/"+args[0], nil)
			if err != nil {
				return err
			}

			resp, err := withManagement(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			fmt.Printf("Scope deleted: %s\n", args[0])
			return nil
		},
	}

	cmd.AddCommand(listCmd, createCmd, deleteCmd)
	return cmd
}

func resourceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "resource",
		Short: "Resource server management commands",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all resource servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(serverURL + "/api/resources")
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var resources []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&resources); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "URI\tNAME\tDESCRIPTION\tSCOPES\n")
			for _, r := range resources {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%v\n",
					r["uri"], r["name"], r["description"], r["scopes"])
			}
			_ = w.Flush()
			return nil
		},
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Register a resource server",
		RunE: func(cmd *cobra.Command, args []string) error {
			uri, _ := cmd.Flags().GetString("uri")
			name, _ := cmd.Flags().GetString("name")
			description, _ := cmd.Flags().GetString("description")
			scopes, _ := cmd.Flags().GetStringSlice("scopes")

			if uri == "" || name == "" {
				return fmt.Errorf("uri and name are required")
			}

			body := map[string]interface{}{
				"uri":         uri,
				"name":        name,
				"description": description,
				"scopes":      scopes,
			}

			jsonBody, _ := json.Marshal(body)
			resp, err := apiPost(serverURL+"/api/resources", "application/json", bytes.NewBuffer(jsonBody))
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			if resp.StatusCode != http.StatusCreated {
				errMsg := result["error_description"]
				if errMsg == nil {
					errMsg = result["error"]
				}
				return fmt.Errorf("failed to create resource: %v", errMsg)
			}

			fmt.Printf("Resource registered: %s\n", result["uri"])
			return nil
		},
	}

	createCmd.Flags().StringP("uri", "u", "", "Resource URI (e.g., https://api.example.com)")
	createCmd.Flags().StringP("name", "n", "", "Resource name")
	createCmd.Flags().StringP("description", "d", "", "Resource description")
	createCmd.Flags().StringSliceP("scopes", "s", []string{}, "Allowed scopes")

	deleteCmd := &cobra.Command{
		Use:   "delete [uri]",
		Short: "Delete a resource server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := http.NewRequest("DELETE", serverURL+"/api/resources/"+args[0], nil)
			if err != nil {
				return err
			}

			resp, err := withManagement(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			fmt.Printf("Resource deleted: %s\n", args[0])
			return nil
		},
	}

	cmd.AddCommand(listCmd, createCmd, deleteCmd)
	return cmd
}

func consentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "consent",
		Short: "Consent management commands",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List consents for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			userID, _ := cmd.Flags().GetString("user-id")
			if userID == "" {
				return fmt.Errorf("user-id is required")
			}

			resp, err := apiGet(serverURL + "/api/consents?user_id=" + userID)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			var consents []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&consents); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "CLIENT ID\tSCOPES\tGRANTED AT\n")
			for _, c := range consents {
				_, _ = fmt.Fprintf(w, "%s\t%v\t%s\n",
					c["client_id"], c["scopes"], c["granted_at"])
			}
			_ = w.Flush()
			return nil
		},
	}

	listCmd.Flags().String("user-id", "", "User ID")

	revokeCmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke consent for a user and client",
		RunE: func(cmd *cobra.Command, args []string) error {
			userID, _ := cmd.Flags().GetString("user-id")
			clientID, _ := cmd.Flags().GetString("client-id")

			if userID == "" || clientID == "" {
				return fmt.Errorf("user-id and client-id are required")
			}

			req, err := http.NewRequest("DELETE", serverURL+"/api/consents?user_id="+userID+"&client_id="+clientID, nil)
			if err != nil {
				return err
			}

			resp, err := withManagement(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			fmt.Printf("Consent revoked for user %s and client %s\n", userID, clientID)
			return nil
		},
	}

	revokeCmd.Flags().String("user-id", "", "User ID")
	revokeCmd.Flags().String("client-id", "", "Client ID")

	cmd.AddCommand(listCmd, revokeCmd)
	return cmd
}

func keysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Key generation commands for OAuch conformance",
	}

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate DPoP and client signing keys for OAuch",
		RunE: func(cmd *cobra.Command, args []string) error {
			outputDir, _ := cmd.Flags().GetString("output")
			dpopOnly, _ := cmd.Flags().GetBool("dpop-only")
			clientOnly, _ := cmd.Flags().GetBool("client-only")

			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}

			generateAll := !dpopOnly && !clientOnly

			if generateAll || dpopOnly {
				if err := generateDPoPKey(outputDir); err != nil {
					return fmt.Errorf("failed to generate DPoP key: %w", err)
				}
			}

			if generateAll || clientOnly {
				if err := generateClientKey(outputDir); err != nil {
					return fmt.Errorf("failed to generate client key: %w", err)
				}
			}

			if generateAll {
				if err := generateOAuchConfig(outputDir); err != nil {
					return fmt.Errorf("failed to generate OAuch config: %w", err)
				}
			}

			fmt.Printf("Keys generated in: %s\n", outputDir)
			fmt.Println()
			fmt.Println("Files:")
			if generateAll || dpopOnly {
				fmt.Printf("  DPoP Private Key:  %s/dpop-private.jwk\n", outputDir)
				fmt.Printf("  DPoP Public Key:   %s/dpop-public.jwk\n", outputDir)
				fmt.Printf("  DPoP Private PEM:  %s/dpop-private.pem\n", outputDir)
			}
			if generateAll || clientOnly {
				fmt.Printf("  Client Private:    %s/client-private.jwk\n", outputDir)
				fmt.Printf("  Client Public:     %s/client-public.jwk\n", outputDir)
				fmt.Printf("  Client Private PEM:%s/client-private.pem\n", outputDir)
				fmt.Printf("  Client JWKS:       %s/client-jwks.json\n", outputDir)
			}
			if generateAll {
				fmt.Printf("  OAuch Config:      %s/oauch-config.json\n", outputDir)
				fmt.Println()
				fmt.Println("Paste the contents of oauch-config.json into your OAuch site settings.")
			}
			return nil
		},
	}

	generateCmd.Flags().StringP("output", "o", "./keys", "Output directory")
	generateCmd.Flags().Bool("dpop-only", false, "Generate only DPoP key")
	generateCmd.Flags().Bool("client-only", false, "Generate only client signing key")

	rotateCmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate the active signing keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiPost(serverURL+"/api/keys/rotate", "application/json", nil)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			var result map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return err
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("key rotation failed: %v", result["error_description"])
			}
			fmt.Printf("Signing keys rotated: %v\n", result["kids"])
			return nil
		},
	}

	cmd.AddCommand(generateCmd, rotateCmd)
	return cmd
}

type jwkKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	D   string `json:"d,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	E   string `json:"e,omitempty"`
	N   string `json:"n,omitempty"`
	P   string `json:"p,omitempty"`
	Q   string `json:"q,omitempty"`
	Dp  string `json:"dp,omitempty"`
	Dq  string `json:"dq,omitempty"`
	Qi  string `json:"qi,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

type jwks struct {
	Keys []jwkKey `json:"keys"`
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateDPoPKey(dir string) error {
	fmt.Println("Generating DPoP EC P-256 key...")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// Use ECDH API to get key bytes (non-deprecated in Go 1.26)
	ecdhKey, _ := key.ECDH()
	pubBytes := ecdhKey.PublicKey().Bytes()
	x := b64(pubBytes[1:33])
	y := b64(pubBytes[33:65])

	privBytes := ecdhKey.Bytes()
	d := b64(privBytes)

	privJWK := jwkKey{
		Kty: "EC",
		Crv: "P-256",
		D:   d,
		X:   x,
		Y:   y,
		Kid: "dpop-key-1",
		Use: "sig",
		Alg: "ES256",
	}

	pubJWK := jwkKey{
		Kty: "EC",
		Crv: "P-256",
		X:   x,
		Y:   y,
		Kid: "dpop-key-1",
		Use: "sig",
		Alg: "ES256",
	}

	privJSON, _ := json.MarshalIndent(privJWK, "", "  ")
	pubJSON, _ := json.MarshalIndent(pubJWK, "", "  ")

	if err := os.WriteFile(dir+"/dpop-private.jwk", privJSON, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(dir+"/dpop-public.jwk", pubJSON, 0644); err != nil {
		return err
	}

	privPEM, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(dir+"/dpop-private.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privPEM}), 0600); err != nil {
		return err
	}

	fmt.Println("  ✓ DPoP key generated")
	return nil
}

func generateClientKey(dir string) error {
	fmt.Println("Generating Client RSA 2048 key...")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privJWK := jwkKey{
		Kty: "RSA",
		E:   b64(big.NewInt(int64(key.E)).Bytes()),
		N:   b64(key.N.Bytes()),
		D:   b64(key.D.Bytes()),
		P:   b64(key.Primes[0].Bytes()),
		Q:   b64(key.Primes[1].Bytes()),
		Dp:  b64(key.Precomputed.Dp.Bytes()),
		Dq:  b64(key.Precomputed.Dq.Bytes()),
		Qi:  b64(key.Precomputed.Qinv.Bytes()),
		Kid: "client-key-1",
		Use: "sig",
		Alg: "RS256",
	}

	pubJWK := jwkKey{
		Kty: "RSA",
		E:   b64(big.NewInt(int64(key.E)).Bytes()),
		N:   b64(key.N.Bytes()),
		Kid: "client-key-1",
		Use: "sig",
		Alg: "RS256",
	}

	privJSON, _ := json.MarshalIndent(privJWK, "", "  ")
	pubJSON, _ := json.MarshalIndent(pubJWK, "", "  ")

	if err := os.WriteFile(dir+"/client-private.jwk", privJSON, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(dir+"/client-public.jwk", pubJSON, 0644); err != nil {
		return err
	}

	privPEM := x509.MarshalPKCS1PrivateKey(key)
	if err := os.WriteFile(dir+"/client-private.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privPEM}), 0600); err != nil {
		return err
	}

	jwksJSON, _ := json.MarshalIndent(jwks{Keys: []jwkKey{pubJWK}}, "", "  ")
	if err := os.WriteFile(dir+"/client-jwks.json", jwksJSON, 0644); err != nil {
		return err
	}

	fmt.Println("  ✓ Client signing key generated")
	return nil
}

func generateOAuchConfig(dir string) error {
	dpopBytes, err := os.ReadFile(dir + "/dpop-private.jwk")
	if err != nil {
		return err
	}
	clientBytes, err := os.ReadFile(dir + "/client-private.jwk")
	if err != nil {
		return err
	}

	var dpopKey, clientKey map[string]interface{}
	_ = json.Unmarshal(dpopBytes, &dpopKey)
	_ = json.Unmarshal(clientBytes, &clientKey)

	config := map[string]interface{}{
		"DPoPSigningKey":                dpopKey,
		"RequestSigningKey":             clientKey,
		"ClientAuthenticationMechanism": 3,
	}

	configJSON, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile(dir+"/oauch-config.json", configJSON, 0644)
}
