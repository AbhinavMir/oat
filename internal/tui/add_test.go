package tui

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/AbhinavMir/oat/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
)

func key(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// runCmd executes a cmd like the bubbletea runtime, but drops any command that
// doesn't produce a message quickly (tick/blink timers) so the harness can't
// block or loop forever.
func runCmd(cmd tea.Cmd) []tea.Msg {
	if cmd == nil {
		return nil
	}
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	select {
	case msg := <-done:
		switch m := msg.(type) {
		case tea.BatchMsg:
			var out []tea.Msg
			for _, c := range m {
				out = append(out, runCmd(c)...)
			}
			return out
		case nil:
			return nil
		default:
			return []tea.Msg{msg}
		}
	case <-time.After(40 * time.Millisecond):
		return nil
	}
}

// drive feeds a message and then processes the resulting command cascade,
// mirroring how the real program threads model + commands.
func drive(m tea.Model, msg tea.Msg) tea.Model {
	queue := []tea.Msg{msg}
	for i := 0; i < 200 && len(queue) > 0; i++ {
		next := queue[0]
		queue = queue[1:]
		var cmd tea.Cmd
		m, cmd = m.Update(next)
		for _, produced := range runCmd(cmd) {
			if _, isTick := produced.(tickMsg); isTick {
				continue
			}
			queue = append(queue, produced)
		}
	}
	return m
}

func openVault(t *testing.T) *vault.Vault {
	t.Helper()
	v, err := vault.Open(func() (string, error) { return "x", nil }, func() (string, error) { return "x", nil })
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return v
}

func TestTUIAddPersists(t *testing.T) {
	t.Setenv("OAT_DIR", filepath.Join(t.TempDir(), "oat"))
	t.Setenv("OAT_PASSWORD", "x")

	var m tea.Model = New(openVault(t))
	m = drive(m, tea.WindowSizeMsg{Width: 80, Height: 24})
	m = drive(m, key("a"))
	m = drive(m, key("github.com"))
	m = drive(m, tea.KeyMsg{Type: tea.KeyTab})
	m = drive(m, key("octocat"))
	m = drive(m, tea.KeyMsg{Type: tea.KeyTab})
	m = drive(m, key("JBSWY3DPEHPK3PXP"))
	m = drive(m, tea.KeyMsg{Type: tea.KeyEnter})

	reopened := openVault(t)
	if len(reopened.Accounts) != 1 {
		t.Fatalf("expected 1 saved account on disk, got %d", len(reopened.Accounts))
	}
	a := reopened.Accounts[0]
	if a.Domain != "github.com" || a.Username != "octocat" || a.Secret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("wrong data persisted: %+v", a)
	}
}

// A mistyped field can be corrected with shift+tab instead of restarting.
func TestTUIAddBackEdit(t *testing.T) {
	t.Setenv("OAT_DIR", filepath.Join(t.TempDir(), "oat"))
	t.Setenv("OAT_PASSWORD", "x")

	var m tea.Model = New(openVault(t))
	m = drive(m, tea.WindowSizeMsg{Width: 80, Height: 24})
	m = drive(m, key("a"))
	m = drive(m, key("github.com"))
	m = drive(m, tea.KeyMsg{Type: tea.KeyTab})
	m = drive(m, key("wrongname")) // typo
	m = drive(m, tea.KeyMsg{Type: tea.KeyShiftTab})
	m = drive(m, tea.KeyMsg{Type: tea.KeyTab}) // back onto username
	for i := 0; i < len("wrongname"); i++ {
		m = drive(m, tea.KeyMsg{Type: tea.KeyBackspace})
	}
	m = drive(m, key("octocat"))
	m = drive(m, tea.KeyMsg{Type: tea.KeyTab})
	m = drive(m, key("JBSWY3DPEHPK3PXP"))
	m = drive(m, tea.KeyMsg{Type: tea.KeyEnter})

	got := openVault(t)
	if len(got.Accounts) != 1 || got.Accounts[0].Username != "octocat" {
		t.Fatalf("back-edit failed: %+v", got.Accounts)
	}
}

// Esc cancels the add without saving anything.
func TestTUIAddEscCancels(t *testing.T) {
	t.Setenv("OAT_DIR", filepath.Join(t.TempDir(), "oat"))
	t.Setenv("OAT_PASSWORD", "x")

	var m tea.Model = New(openVault(t))
	m = drive(m, tea.WindowSizeMsg{Width: 80, Height: 24})
	m = drive(m, key("a"))
	m = drive(m, key("github.com"))
	m = drive(m, tea.KeyMsg{Type: tea.KeyEsc})

	if got := openVault(t); len(got.Accounts) != 0 {
		t.Fatalf("esc should cancel, but saved: %+v", got.Accounts)
	}
}
