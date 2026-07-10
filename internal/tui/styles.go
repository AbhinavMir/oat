package tui

import "github.com/charmbracelet/lipgloss"

var (
	amber = lipgloss.Color("#E8B04B")
	cream = lipgloss.Color("#F3E3C3")
	dim   = lipgloss.Color("#7A7266")
	red   = lipgloss.Color("#E06C75")
	green = lipgloss.Color("#98C379")
	ink   = lipgloss.Color("#ECE6D8")

	logoStyle = lipgloss.NewStyle().Bold(true).Foreground(amber)
	tagStyle  = lipgloss.NewStyle().Foreground(dim).Italic(true)

	bannerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#1B1712")).
			Background(red).
			Bold(true).
			Padding(0, 1)

	codeBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(amber).
		Padding(1, 4).
		Align(lipgloss.Center)

	codeText = lipgloss.NewStyle().Bold(true).Foreground(cream)

	metaText = lipgloss.NewStyle().Foreground(dim)

	toastStyle = lipgloss.NewStyle().Bold(true).Foreground(green)

	footerStyle = lipgloss.NewStyle().Foreground(dim).Padding(0, 1)

	keyStyle  = lipgloss.NewStyle().Foreground(amber)
	descStyle = lipgloss.NewStyle().Foreground(dim)
)

func barColor(remaining int) lipgloss.Color {
	switch {
	case remaining <= 5:
		return red
	case remaining <= 10:
		return amber
	default:
		return green
	}
}
