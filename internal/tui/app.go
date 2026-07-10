package tui

import (
	"fmt"
	"hash/fnv"
	"io"
	"strings"
	"time"

	"github.com/AbhinavMir/oat/internal/totp"
	"github.com/AbhinavMir/oat/internal/vault"
	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

const (
	modeList = iota
	modeAdd
	modeConfirm
)

type tickMsg time.Time

func tick() tea.Cmd {
	return tea.Tick(200*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

type item struct {
	a   vault.Account
	idx int
}

func (i item) Title() string       { return i.a.Domain }
func (i item) Description() string { return i.a.Username }
func (i item) FilterValue() string { return i.a.Domain + " " + i.a.Username }

type model struct {
	v     *vault.Vault
	list  list.Model
	mode  int
	form  *huh.Form
	now   time.Time
	width int

	toast      string
	toastUntil time.Time
}

// New builds the interactive model over an already-unlocked vault.
func New(v *vault.Vault) model {
	l := list.New(nil, itemDelegate{}, 0, 0)
	l.Title = ""
	l.SetShowTitle(false)
	l.SetShowStatusBar(false)
	l.SetShowHelp(false)
	l.SetFilteringEnabled(true)
	l.Styles.FilterPrompt = lipgloss.NewStyle().Foreground(amber)
	l.Styles.FilterCursor = lipgloss.NewStyle().Foreground(amber)

	m := model{v: v, list: l, mode: modeList, now: time.Now()}
	m.refresh()
	return m
}

func (m *model) refresh() {
	items := make([]list.Item, len(m.v.Accounts))
	for i, a := range m.v.Accounts {
		items[i] = item{a: a, idx: i}
	}
	m.list.SetItems(items)
}

func (m model) Init() tea.Cmd { return tick() }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tickMsg:
		m.now = time.Time(msg)
		if !m.toastUntil.IsZero() && m.now.After(m.toastUntil) {
			m.toast = ""
		}
		return m, tick()

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.list.SetSize(msg.Width, listHeight(msg.Height))
		if m.mode == modeAdd {
			return m.updateAdd(msg)
		}
		return m, nil
	}

	// While adding, every message belongs to the form so its command
	// cascade (field navigation, submit) is threaded and observed.
	if m.mode == modeAdd {
		return m.updateAdd(msg)
	}

	km, ok := msg.(tea.KeyMsg)
	if !ok {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}
	if m.mode == modeConfirm {
		return m.updateConfirm(km)
	}
	return m.updateList(km)
}

func (m model) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	filtering := m.list.FilterState() == list.Filtering
	if !filtering {
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "a":
			m.startAdd()
			return m, m.form.Init()
		case "x", "d":
			if _, ok := m.selected(); ok {
				m.mode = modeConfirm
			}
			return m, nil
		case "c", "enter":
			cmd := m.copySelected()
			return m, cmd
		}
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m model) updateConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "enter":
		if it, ok := m.selected(); ok {
			if err := m.v.RemoveAt(it.idx); err == nil {
				m.refresh()
				m.flash("deleted")
			} else {
				m.flash("delete failed")
			}
		}
		m.mode = modeList
	default:
		m.mode = modeList
	}
	return m, nil
}

func (m model) updateAdd(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && k.Type == tea.KeyEsc {
		m.mode = modeList
		return m, nil
	}
	f, cmd := m.form.Update(msg)
	if form, ok := f.(*huh.Form); ok {
		m.form = form
	}
	switch m.form.State {
	case huh.StateCompleted:
		m.commitAdd()
		m.mode = modeList
		return m, nil
	case huh.StateAborted:
		m.mode = modeList
		return m, nil
	}
	return m, cmd
}

func (m *model) startAdd() {
	m.form = addForm()
	m.mode = modeAdd
}

func (m *model) commitAdd() {
	p, issuer, account, err := totp.Parse(m.form.GetString("secret"))
	if err != nil {
		m.flash("invalid secret")
		return
	}
	domain := strings.TrimSpace(m.form.GetString("domain"))
	if domain == "" {
		domain = issuer
	}
	user := strings.TrimSpace(m.form.GetString("user"))
	if user == "" {
		user = account
	}
	err = m.v.Add(vault.Account{
		Domain:    domain,
		Username:  user,
		Secret:    p.Secret,
		Digits:    p.Digits,
		Period:    p.Period,
		Algorithm: p.Algorithm,
	})
	if err != nil {
		m.flash("save failed")
		return
	}
	m.refresh()
	m.flash("added " + domain)
}

func (m *model) selected() (item, bool) {
	it, ok := m.list.SelectedItem().(item)
	return it, ok
}

func (m *model) copySelected() tea.Cmd {
	it, ok := m.selected()
	if !ok {
		return nil
	}
	code, err := totp.Code(paramsOf(it.a), m.now)
	if err != nil {
		m.flash("no code")
		return nil
	}
	if clipboard.WriteAll(code) != nil {
		m.flash("copy unavailable")
		return nil
	}
	m.flash("copied " + code)
	return nil
}

func (m *model) flash(s string) {
	m.toast = s
	m.toastUntil = m.now.Add(2 * time.Second)
}

func (m model) View() string {
	if m.mode == modeAdd && m.form != nil {
		hint := footerStyle.Render(
			descStyle.Render("tab/") + keyStyle.Render("shift+tab") + descStyle.Render(" move  ") +
				keyStyle.Render("enter") + descStyle.Render(" save  ") +
				keyStyle.Render("esc") + descStyle.Render(" cancel"))
		return "\n" + header(m.v) + "\n\n" + m.form.View() + "\n" + hint
	}

	var b strings.Builder
	b.WriteString("\n" + header(m.v) + "\n\n")
	b.WriteString(m.list.View())
	b.WriteString("\n" + m.codePanel() + "\n")

	if m.mode == modeConfirm {
		if it, ok := m.selected(); ok {
			b.WriteString(footerStyle.Render(
				fmt.Sprintf("delete %s (%s)?  ", it.a.Domain, it.a.Username)) +
				keyStyle.Render("y") + descStyle.Render(" yes  ") +
				keyStyle.Render("n") + descStyle.Render(" no"))
			return b.String()
		}
	}
	b.WriteString(m.footer())
	return b.String()
}

func (m model) codePanel() string {
	it, ok := m.selected()
	if !ok {
		return metaText.Render("  no accounts yet — press ") +
			keyStyle.Render("a") + metaText.Render(" to add one")
	}
	p := paramsOf(it.a)
	code, err := totp.Code(p, m.now)
	if err != nil {
		return bannerStyle.Render(" bad secret ")
	}
	remaining := totp.Remaining(p, m.now)

	pretty := code
	if len(code) == 6 {
		pretty = code[:3] + " " + code[3:]
	}
	inner := codeText.Render(spaced(pretty)) + "\n" +
		bar(remaining, p.Period, 22) + "  " +
		metaText.Render(fmt.Sprintf("%2ds", remaining))
	box := codeBox.Render(inner)

	label := metaText.Render(it.a.Domain + "  ·  " + it.a.Username)
	toast := ""
	if m.toast != "" {
		toast = "   " + toastStyle.Render(m.toast)
	}
	return box + "\n  " + label + toast
}

func (m model) footer() string {
	keys := []struct{ k, d string }{
		{"/", "search"}, {"c", "copy"}, {"a", "add"}, {"x", "delete"}, {"q", "quit"},
	}
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = keyStyle.Render(k.k) + descStyle.Render(" "+k.d)
	}
	return footerStyle.Render(strings.Join(parts, descStyle.Render("  ·  ")))
}

func header(v *vault.Vault) string {
	line := logoStyle.Render("🥣 oat") + "  " + tagStyle.Render("one-time passwords, sealed")
	if v.Access.Detected {
		line += "\n" + bannerStyle.Render("⚠ "+v.Access.Reason)
	}
	return "  " + line
}

func listHeight(total int) int {
	h := total - 12
	if h < 3 {
		h = 3
	}
	return h
}

func paramsOf(a vault.Account) totp.Params {
	return totp.Params{Secret: a.Secret, Digits: a.Digits, Period: a.Period, Algorithm: a.Algorithm}
}

func spaced(s string) string {
	return strings.Join(strings.Split(s, ""), " ")
}

func bar(remaining, period, width int) string {
	if period <= 0 {
		period = 30
	}
	filled := remaining * width / period
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	c := barColor(remaining)
	on := lipgloss.NewStyle().Foreground(c).Render(strings.Repeat("█", filled))
	off := lipgloss.NewStyle().Foreground(dim).Render(strings.Repeat("░", width-filled))
	return on + off
}

// itemDelegate renders one account row.
type itemDelegate struct{}

func (itemDelegate) Height() int                         { return 1 }
func (itemDelegate) Spacing() int                        { return 1 }
func (itemDelegate) Update(tea.Msg, *list.Model) tea.Cmd { return nil }
func (itemDelegate) Render(w io.Writer, l list.Model, index int, li list.Item) {
	i, ok := li.(item)
	if !ok {
		return
	}
	cursor := "  "
	name := lipgloss.NewStyle().Foreground(ink)
	if index == l.Index() {
		cursor = lipgloss.NewStyle().Foreground(amber).Render("▎ ")
		name = name.Bold(true).Foreground(cream)
	}
	fmt.Fprint(w, cursor+chip(i.a.Domain)+" "+name.Render(i.a.Domain)+"  "+descStyle.Render(i.a.Username))
}

var chipPalette = []lipgloss.Color{
	"#E8B04B", "#98C379", "#61AFEF", "#C678DD", "#E06C75", "#56B6C2", "#D19A66",
}

func chip(s string) string {
	letter := "?"
	if s != "" {
		letter = strings.ToUpper(string([]rune(s)[0]))
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	c := chipPalette[h.Sum32()%uint32(len(chipPalette))]
	return lipgloss.NewStyle().
		Background(c).
		Foreground(lipgloss.Color("#1B1712")).
		Bold(true).
		Padding(0, 1).
		Render(letter)
}
