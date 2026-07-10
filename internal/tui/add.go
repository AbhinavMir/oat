package tui

import (
	"github.com/AbhinavMir/oat/internal/totp"
	"github.com/AbhinavMir/oat/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
)

func addForm() *huh.Form {
	f := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Key("domain").
				Title("Domain").
				Placeholder("google.com"),
			huh.NewInput().
				Key("user").
				Title("Username").
				Placeholder("you@google.com"),
			huh.NewInput().
				Key("secret").
				Title("Secret or otpauth:// URI").
				Placeholder("JBSWY3DPEHPK3PXP").
				Validate(validSecret),
		),
	).WithTheme(huh.ThemeCharm()).WithShowHelp(true)
	return f
}

func validSecret(s string) error {
	_, _, _, err := totp.Parse(s)
	return err
}

// Start launches the full-screen interactive vault browser.
func Start(v *vault.Vault) error {
	_, err := tea.NewProgram(New(v), tea.WithAltScreen()).Run()
	return err
}
