package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// logo is the ShieldMon mark (docs/assets/logo-mark.svg) as a pixel grid: a shield split
// red/blue around an elephant whose trunk curls into a check mark. Two pixel rows share
// one terminal row through half-block characters. '.' is transparent.
var logo = []string{
	"..........rrbb..........",
	".......rrrrrbbbbb.......",
	"...rrrrrrrrrbbbbbbbbb...",
	"rrrrrrrrrrrrbbbbbbbbbbbb",
	"rrrrrrrrrrrrbbbbbbbbbbbb",
	"rrrrrrrrrwwwwwwbbbbbbbbb",
	"rrrwwwwrwwwwwwwwbwwwwbbb",
	"rrwwwwwrwwwwwwwwbwwwwwbb",
	"rrwwwwwrwwrwwbwwbwwwwwbb",
	"rrwwwwwrwwwwwwwwbwwwwwbb",
	"rrwwwwwrwwwwwwwwbwwwwwbb",
	"rrrwwwwwrwwwwwwbwwwwwbbb",
	"rrrrwwwwrrwwwwbbwwwwbbbb",
	"rrrrrwwrrrwwwwbbbwwbbbbb",
	"rrrrrrrrrwrwwbwbbbbbbbbb",
	"rrrrrrrrwrrwwbbwbbbbbbbb",
	".rrrrrrrrrrwwbbbbbbbbbb.",
	".rrrrrrrrrrwwbbbbbbbwwb.",
	".rrrrrrrrrrwwbbbbbbwwbb.",
	"..rrrrrrrrrwwbbbbbwwbb..",
	"..rrrrrrrrrwwbbbbwwbbb..",
	"...rrrrrrrrwwbbbwwbbb...",
	"...rrrrrrrrwwwwwbbbbb...",
	"....rrrrrrrrbbbbbbbb....",
	".....rrrrrrrbbbbbbb.....",
	"......rrrrrrbbbbbb......",
	"........rrrrbbbb........",
	"..........rrbb..........",
}

// glyphs is a 7-pixel-high font covering the wordmark.
var glyphs = map[rune][]string{
	'S': {".###", "#...", "#...", ".##.", "...#", "...#", "###."},
	'H': {"#..#", "#..#", "#..#", "####", "#..#", "#..#", "#..#"},
	'I': {"###", ".#.", ".#.", ".#.", ".#.", ".#.", "###"},
	'E': {"####", "#...", "#...", "###.", "#...", "#...", "####"},
	'L': {"#...", "#...", "#...", "#...", "#...", "#...", "####"},
	'D': {"###.", "#..#", "#..#", "#..#", "#..#", "#..#", "###."},
	'M': {"#...#", "##.##", "#.#.#", "#.#.#", "#...#", "#...#", "#...#"},
	'O': {".##.", "#..#", "#..#", "#..#", "#..#", "#..#", ".##."},
	'N': {"#...#", "##..#", "#.#.#", "#.#.#", "#..##", "#...#", "#...#"},
}

// inks are the brand colours, with the closest xterm-256 index for terminals without
// 24-bit colour. 'k' (not listed) is the terminal's default foreground.
var inks = map[byte]struct{ r, g, b, x256 int }{
	'r': {230, 57, 70, 167},
	'b': {47, 128, 237, 33},
	'w': {255, 255, 255, 231},
}

type painter struct {
	color     bool // false renders a silhouette in the default foreground (NO_COLOR)
	truecolor bool
}

// bannerPainter reports whether w is a terminal that should get the banner, and how to
// draw it. Pipes, files and TERM=dumb get plain help.
func bannerPainter(w io.Writer) (painter, bool) {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("TERM") == "dumb" {
		return painter{}, false
	}
	if fi, err := f.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return painter{}, false
	}
	ct := os.Getenv("COLORTERM")
	return painter{
		color:     os.Getenv("NO_COLOR") == "",
		truecolor: ct == "truecolor" || ct == "24bit",
	}, true
}

// writeBanner prints the logo with the wordmark and tagline beside it, within 80 columns.
func writeBanner(w io.Writer, p painter) {
	art := p.rows(logo)
	side := make([]string, len(art))
	copy(side[3:], p.rows(wordmark()))
	side[8] = p.style("1", "Continuous vulnerability monitoring for containers")
	side[10] = p.style("2", "SBOM-first · digest-pinned · evidence-closed")
	side[11] = p.style("2", "version "+Version)
	for i, a := range art {
		fmt.Fprintln(w, strings.TrimRight(a+"   "+side[i], " "))
	}
	fmt.Fprintln(w)
}

// wordmark lays out SHIELDMON as a pixel grid: SHIELD in the default foreground, MON in
// blue. A blank first row centres the glyphs in four terminal rows.
func wordmark() []string {
	rows := make([]strings.Builder, 8)
	for i, r := range "SHIELDMON" {
		ink := "k"
		if i >= len("SHIELD") {
			ink = "b"
		}
		g := glyphs[r]
		rows[0].WriteString(strings.Repeat(".", len(g[0])+1))
		for y, line := range g {
			rows[y+1].WriteString(strings.ReplaceAll(line, "#", ink) + ".")
		}
	}
	out := make([]string, len(rows))
	for i := range rows {
		out[i] = rows[i].String()
	}
	return out
}

func (p painter) rows(grid []string) []string {
	var out []string
	for y := 0; y < len(grid); y += 2 {
		var b strings.Builder
		for x := 0; x < len(grid[y]); x++ {
			top, bot := p.ink(grid[y][x]), byte('.')
			if y+1 < len(grid) {
				bot = p.ink(grid[y+1][x])
			}
			b.WriteString(p.cell(top, bot))
		}
		out = append(out, b.String())
	}
	return out
}

func (p painter) ink(c byte) byte {
	switch {
	case c == '.' || p.color:
		return c
	case c == 'w':
		return '.' // the elephant is cut out of the silhouette
	default:
		return 'k'
	}
}

func (p painter) cell(top, bot byte) string {
	switch {
	case top == '.' && bot == '.':
		return " "
	case top == bot:
		return p.paint(p.sgr(38, top), "█")
	case top == '.':
		return p.paint(p.sgr(38, bot), "▄")
	case bot == '.':
		return p.paint(p.sgr(38, top), "▀")
	case bot == 'k': // the default foreground has no background equivalent
		return p.paint(p.sgr(38, bot)+p.sgr(48, top), "▄")
	default:
		return p.paint(p.sgr(38, top)+p.sgr(48, bot), "▀")
	}
}

// sgr returns the escape sequence selecting ink on layer 38 (foreground) or 48 (background).
func (p painter) sgr(layer int, ink byte) string {
	c, ok := inks[ink]
	switch {
	case !ok || !p.color:
		return ""
	case p.truecolor:
		return fmt.Sprintf("\x1b[%d;2;%d;%d;%dm", layer, c.r, c.g, c.b)
	default:
		return fmt.Sprintf("\x1b[%d;5;%dm", layer, c.x256)
	}
}

func (p painter) style(attr, s string) string {
	if !p.color {
		return s
	}
	return p.paint("\x1b["+attr+"m", s)
}

func (p painter) paint(sgr, s string) string {
	if sgr == "" {
		return s
	}
	return sgr + s + "\x1b[0m"
}
