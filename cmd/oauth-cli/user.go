package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

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
