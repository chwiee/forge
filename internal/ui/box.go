package ui

import (
	"fmt"
	"strings"
)

// Row is one key/value line of a summary box. Value may contain color codes.
type Row struct {
	Key   string
	Value string
}

// Box prints a rounded summary panel.
func (u *UI) Box(title string, rows []Row) {
	width := 0
	for _, r := range rows {
		if l := 2 + 9 + visibleLen(r.Value) + 2; l > width {
			width = l
		}
	}
	if l := visibleLen(title) + 6; l > width {
		width = l
	}
	if width > u.width-4 && u.width > 40 {
		width = u.width - 4
	}
	border := func(s string) string { return u.paint(cDim, s) }

	var b strings.Builder
	top := border("╭─ ") + u.bold(u.paint(cEmber, title)) + " " + border(strings.Repeat("─", max(0, width-visibleLen(title)-3))+"╮")
	b.WriteString("  " + top + "\n")
	for _, r := range rows {
		val := r.Value
		if visibleLen(val) > width-13 {
			val = truncate(stripANSI(val), width-13)
		}
		line := fmt.Sprintf("  %s %s", u.paint(cGray, pad(r.Key, 9)), val)
		fill := width - visibleLen(line)
		b.WriteString("  " + border("│") + line + strings.Repeat(" ", max(0, fill)) + border("│") + "\n")
	}
	b.WriteString("  " + border("╰"+strings.Repeat("─", width)+"╯"))
	u.println("")
	u.println(b.String())
}

func stripANSI(s string) string {
	var b strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case r == '\x1b':
			esc = true
		case esc && r == 'm':
			esc = false
		case !esc:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Table prints aligned columns under a heading (used for CVE / leak listings).
func (u *UI) Table(header []string, rows [][]string, colors []func(string) string) {
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = visibleLen(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(widths) && visibleLen(c) > widths[i] {
				widths[i] = min(visibleLen(c), 48)
			}
		}
	}
	var hb strings.Builder
	for i, h := range header {
		hb.WriteString(pad(h, widths[i]) + "  ")
	}
	u.println("    " + u.paint(cDim, strings.TrimRight(hb.String(), " ")))
	for _, r := range rows {
		var lb strings.Builder
		for i, c := range r {
			c = truncate(c, widths[i])
			cell := pad(c, widths[i])
			if colors != nil && i < len(colors) && colors[i] != nil {
				cell = colors[i](c) + strings.Repeat(" ", widths[i]-visibleLen(c))
			}
			lb.WriteString(cell + "  ")
		}
		u.println("    " + strings.TrimRight(lb.String(), " "))
	}
}
