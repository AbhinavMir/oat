package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/AbhinavMir/oat/internal/totp"
	"github.com/AbhinavMir/oat/internal/tui"
	"github.com/AbhinavMir/oat/internal/vault"
	"github.com/atotto/clipboard"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		run(cmdBrowse)
		return
	}

	switch args[0] {
	case "add":
		run(func() error { return cmdAdd(args[1:]) })
	case "ls", "list":
		run(cmdList)
	case "get", "code":
		run(func() error { return cmdGet(args[1:]) })
	case "rm", "remove":
		run(func() error { return cmdRemove(args[1:]) })
	case "-h", "--help", "help":
		usage()
	case "-v", "--version", "version":
		fmt.Println("oat 0.1.0")
	default:
		// `oat google.com` is shorthand for adding that domain.
		run(func() error { return cmdAdd(args) })
	}
}

func run(fn func() error) {
	if err := fn(); err != nil {
		fmt.Fprintln(os.Stderr, lipgloss.NewStyle().Foreground(lipgloss.Color("#E06C75")).Render("oat: "+err.Error()))
		os.Exit(1)
	}
}

func open() (*vault.Vault, error) {
	return vault.Open(askNew, askUnlock)
}

func cmdBrowse() error {
	v, err := open()
	if err != nil {
		return err
	}
	return tui.Start(v)
}

func cmdAdd(args []string) error {
	v, err := open()
	if err != nil {
		return err
	}

	if len(args) == 3 {
		return addFromArgs(v, args[0], args[1], args[2])
	}

	var domain, user, secret string
	if len(args) >= 1 {
		domain = args[0]
	}
	if len(args) >= 2 {
		user = args[1]
	}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Domain").Placeholder("google.com").Value(&domain),
			huh.NewInput().Title("Username").Placeholder("you@google.com").Value(&user),
			huh.NewInput().Title("Secret or otpauth:// URI").Value(&secret).Validate(func(s string) error {
				_, _, _, e := totp.Parse(s)
				return e
			}),
		),
	).WithTheme(huh.ThemeCharm())
	if err := form.Run(); err != nil {
		return err
	}
	return addFromArgs(v, domain, user, secret)
}

func addFromArgs(v *vault.Vault, domain, user, secret string) error {
	p, issuer, account, err := totp.Parse(secret)
	if err != nil {
		return err
	}
	if strings.TrimSpace(domain) == "" {
		domain = issuer
	}
	if strings.TrimSpace(user) == "" {
		user = account
	}
	if strings.TrimSpace(domain) == "" {
		return errors.New("a domain is required")
	}
	err = v.Add(vault.Account{
		Domain:    domain,
		Username:  user,
		Secret:    p.Secret,
		Digits:    p.Digits,
		Period:    p.Period,
		Algorithm: p.Algorithm,
	})
	if err != nil {
		return err
	}
	fmt.Printf("added %s (%s)\n", domain, user)
	return nil
}

func cmdList() error {
	v, err := open()
	if err != nil {
		return err
	}
	if v.Access.Detected {
		warn(v.Access.Reason)
	}
	if len(v.Accounts) == 0 {
		fmt.Println("no accounts yet — try: oat add google.com")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "DOMAIN\tUSERNAME")
	for _, a := range v.Accounts {
		fmt.Fprintf(tw, "%s\t%s\n", a.Domain, a.Username)
	}
	return tw.Flush()
}

func cmdGet(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: oat get <query>")
	}
	v, err := open()
	if err != nil {
		return err
	}
	if v.Access.Detected {
		warn(v.Access.Reason)
	}
	matches := v.Find(strings.Join(args, " "))
	if len(matches) == 0 {
		return errors.New("no matching account")
	}
	a := v.Accounts[matches[0]]
	code, err := totp.Code(totp.Params{Secret: a.Secret, Digits: a.Digits, Period: a.Period, Algorithm: a.Algorithm}, time.Now())
	if err != nil {
		return err
	}
	_ = clipboard.WriteAll(code)
	fmt.Printf("%s  %s (%s)\n", code, a.Domain, a.Username)
	return nil
}

func cmdRemove(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: oat rm <query>")
	}
	v, err := open()
	if err != nil {
		return err
	}
	matches := v.Find(strings.Join(args, " "))
	if len(matches) == 0 {
		return errors.New("no matching account")
	}
	a := v.Accounts[matches[0]]
	confirm := true
	if os.Getenv("OAT_PASSWORD") == "" {
		confirm = false
		if err := huh.NewConfirm().
			Title(fmt.Sprintf("Delete %s (%s)?", a.Domain, a.Username)).
			Value(&confirm).
			WithTheme(huh.ThemeCharm()).
			Run(); err != nil {
			return nil
		}
	}
	if !confirm {
		return nil
	}
	if err := v.RemoveAt(matches[0]); err != nil {
		return err
	}
	fmt.Printf("removed %s (%s)\n", a.Domain, a.Username)
	return nil
}

func askNew() (string, error) {
	if p := os.Getenv("OAT_PASSWORD"); p != "" {
		return p, nil
	}
	var pw, confirm string
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Create a master password").
				EchoMode(huh.EchoModePassword).Value(&pw).
				Validate(func(s string) error {
					if len(s) < 1 {
						return errors.New("password cannot be empty")
					}
					return nil
				}),
			huh.NewInput().Title("Confirm password").
				EchoMode(huh.EchoModePassword).Value(&confirm),
		),
	).WithTheme(huh.ThemeCharm()).Run()
	if err != nil {
		return "", err
	}
	if pw != confirm {
		return "", errors.New("passwords do not match")
	}
	return pw, nil
}

func askUnlock() (string, error) {
	if p := os.Getenv("OAT_PASSWORD"); p != "" {
		return p, nil
	}
	var pw string
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Unlock oat").
				EchoMode(huh.EchoModePassword).Value(&pw),
		),
	).WithTheme(huh.ThemeCharm()).Run()
	return pw, err
}

func warn(reason string) {
	fmt.Fprintln(os.Stderr, lipgloss.NewStyle().
		Foreground(lipgloss.Color("#1B1712")).
		Background(lipgloss.Color("#E06C75")).
		Bold(true).Padding(0, 1).
		Render("⚠ "+reason))
}

func usage() {
	fmt.Print(`oat — local, encrypted one-time passwords

  oat                 open the vault browser
  oat add [domain]    add an account (interactive)
  oat add d u secret  add an account (non-interactive)
  oat ls              list accounts
  oat get <query>     print + copy the current code for a match
  oat rm <query>      remove an account

The vault is sealed with XChaCha20-Poly1305. The key is kept in your OS
keychain and can be recovered with your master password. oat warns you if
the vault file was changed by anything other than oat.
`)
}
