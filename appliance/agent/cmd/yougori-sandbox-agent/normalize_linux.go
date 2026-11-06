package main

// The normalizer (VM-W58: content normalization and preview processing inside a restricted
// VM; §5.2 line 2073: archive extraction, document parsing and HTML sanitization are attack
// surfaces): a terminal of a throwaway sandbox runs the agent's own binary as
//
//	/run/yougori/bin/yougori-probe normalize <job> <execution> <boot> <name> <version>
//	    <recipe> <declared format> <target format> <max output bytes> <input> <output>
//
// on raw bytes the host staged into that sandbox's workspace, writes the normalized bytes to
// <output> and prints one NormalizationReport (src-tauri/src/sandbox_contract/untrusted/
// normalize.rs) as a JSON line. HTML and archives are parsed here, inside the VM, never on
// the host: a malicious file can at worst subvert this sandbox, which has no network, no
// credential and no host path, and which the host stops afterwards. The host checks the
// report against the job it planned and the bytes it reads back.
//
// What it normalizes: HTML to plain text or Markdown (script, style and other non-text
// elements dropped, entities decoded, block structure kept as line breaks); an archive (zip,
// tar, gzip-compressed tar) to a listing of its entries, never extracting one; plain text to
// plain text (valid UTF-8, control characters removed). Everything else, and PNG previews,
// fails as unsupported. Normalization changes the format; a prompt injection in the content
// may survive it.

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// normalizeCommand is the normalizer's first argument.
const normalizeCommand = "normalize"

// maxNormalizeInput bounds the raw bytes read; a larger input fails as input_too_large.
const maxNormalizeInput = 64 << 20

// maxArchiveEntries bounds an archive's listing; more fail as resource_limit.
const maxArchiveEntries = 10000

// maxArchiveExpansion bounds the bytes a compressed archive may expand to while its entries
// are walked (a tar entry's data is read past to reach the next header).
const maxArchiveExpansion = 512 << 20

// errOutputBound marks an output that grew past the bound it was given.
var errOutputBound = errors.New("the output grew past its bound")

type normalizerIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Recipe  string `json:"recipe"`
}

type reportedOutput struct {
	Format    string `json:"format"`
	Content   string `json:"content"`
	SizeBytes uint64 `json:"size_bytes"`
}

type normalizationOutcome struct {
	Outcome string          `json:"outcome"`
	Output  *reportedOutput `json:"output,omitempty"`
	Failure string          `json:"failure,omitempty"`
}

type normalizationReport struct {
	Job        string               `json:"job"`
	Raw        string               `json:"raw"`
	Normalizer normalizerIdentity   `json:"normalizer"`
	Execution  string               `json:"execution"`
	Boot       uint64               `json:"boot"`
	Outcome    normalizationOutcome `json:"outcome"`
}

// failure is a NormalizerFailure (snake_case), or "" for none.
type failure string

const (
	unsupportedFormat failure = "unsupported_format"
	malformedInput    failure = "malformed_input"
	inputTooLarge     failure = "input_too_large"
	resourceLimit     failure = "resource_limit"
)

// boundedText collects normalized text up to a byte bound.
type boundedText struct {
	builder strings.Builder
	limit   int
	over    bool
}

func (text *boundedText) write(part string) {
	if text.over {
		return
	}
	if text.builder.Len()+len(part) > text.limit {
		text.over = true
		return
	}
	text.builder.WriteString(part)
}

// cleanText keeps what text displays: valid UTF-8, line breaks and tabs; every other control
// character and bidirectional override is dropped.
func cleanText(raw string) string {
	valid := strings.ToValidUTF8(raw, "�")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r == '\r':
			return -1
		case unicode.IsControl(r):
			return -1
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200E || r == 0x200F:
			return -1
		}
		return r
	}, valid)
}

// collapseSpaces turns every run of spaces and tabs into one space.
func collapseSpaces(text string) string {
	var out strings.Builder
	space := false
	for _, r := range text {
		if r == ' ' || r == '\t' || r == '\n' || r == '\f' || r == '\v' {
			space = true
			continue
		}
		if space && out.Len() > 0 {
			out.WriteByte(' ')
		}
		space = false
		out.WriteRune(r)
	}
	if space && out.Len() > 0 {
		out.WriteByte(' ')
	}
	return out.String()
}

// skippedElements hold no text a reader sees.
var skippedElements = map[string]bool{
	"script": true, "style": true, "noscript": true, "template": true, "iframe": true,
	"object": true, "svg": true, "math": true, "canvas": true,
}

// voidElements never have an end tag, so none of them may open a skipped or preformatted
// span: an <embed> written without "/>" would otherwise hide the rest of the page.
var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true, "img": true,
	"input": true, "link": true, "meta": true, "param": true, "source": true, "track": true,
	"wbr": true, "keygen": true,
}

// blockElements end a line.
var blockElements = map[string]bool{
	"p": true, "div": true, "br": true, "li": true, "ul": true, "ol": true, "tr": true,
	"table": true, "section": true, "article": true, "header": true, "footer": true,
	"blockquote": true, "pre": true, "hr": true, "h1": true, "h2": true, "h3": true,
	"h4": true, "h5": true, "h6": true, "title": true, "dt": true, "dd": true, "nav": true,
	"main": true, "aside": true, "form": true, "figure": true, "figcaption": true,
}

// htmlToText walks HTML's tokens (never building a document or running anything) and keeps
// its text, as plain text or Markdown.
func htmlToText(data []byte, markdown bool, limit int) (string, failure) {
	tokens := html.NewTokenizer(bytes.NewReader(data))
	tokens.SetMaxBuf(maxNormalizeInput)
	out := &boundedText{limit: limit}
	skip := 0
	pre := 0
	atLineStart := true
	newline := func() {
		if !atLineStart {
			out.write("\n")
			atLineStart = true
		}
	}
	for {
		kind := tokens.Next()
		switch kind {
		case html.ErrorToken:
			if errors.Is(tokens.Err(), io.EOF) {
				if out.over {
					return "", resourceLimit
				}
				return strings.TrimSpace(out.builder.String()) + "\n", ""
			}
			return "", malformedInput
		case html.StartTagToken, html.SelfClosingTagToken:
			name, _ := tokens.TagName()
			tag := string(name)
			if voidElements[tag] {
				kind = html.SelfClosingTagToken
			}
			if skippedElements[tag] {
				if kind == html.StartTagToken {
					skip++
				}
				continue
			}
			if skip > 0 {
				continue
			}
			if tag == "pre" && kind == html.StartTagToken {
				pre++
			}
			if blockElements[tag] {
				newline()
			}
			if markdown && kind == html.StartTagToken {
				switch {
				case len(tag) == 2 && tag[0] == 'h' && tag[1] >= '1' && tag[1] <= '6':
					out.write(strings.Repeat("#", int(tag[1]-'0')) + " ")
					atLineStart = false
				case tag == "li":
					out.write("- ")
					atLineStart = false
				}
			}
		case html.EndTagToken:
			name, _ := tokens.TagName()
			tag := string(name)
			if skippedElements[tag] {
				if skip > 0 {
					skip--
				}
				continue
			}
			if skip > 0 {
				continue
			}
			if tag == "pre" && pre > 0 {
				pre--
			}
			if blockElements[tag] {
				newline()
			}
		case html.TextToken:
			if skip > 0 {
				continue
			}
			text := cleanText(string(tokens.Text()))
			if pre == 0 {
				text = collapseSpaces(text)
				if atLineStart {
					text = strings.TrimLeft(text, " ")
				}
			}
			if text == "" {
				continue
			}
			out.write(text)
			atLineStart = strings.HasSuffix(text, "\n")
		}
		if out.over {
			return "", resourceLimit
		}
	}
}

// countingReader stops a decompression past its bound.
type countingReader struct {
	reader io.Reader
	left   int64
}

func (counting *countingReader) Read(buffer []byte) (int, error) {
	if counting.left <= 0 {
		return 0, errOutputBound
	}
	if int64(len(buffer)) > counting.left {
		buffer = buffer[:counting.left]
	}
	read, err := counting.reader.Read(buffer)
	counting.left -= int64(read)
	return read, err
}

// displayName writes an entry's name as text: control characters and bidirectional
// overrides as escapes, so a name cannot forge a line or reorder one.
func displayName(name string) string {
	var out strings.Builder
	for _, r := range strings.ToValidUTF8(name, "�") {
		if unicode.IsControl(r) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			fmt.Fprintf(&out, "\\u{%x}", r)
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

// archiveListing lists a zip, tar or gzip-compressed tar's entries without extracting any:
// kind, size and name, one per line.
func archiveListing(data []byte, limit int) (string, failure) {
	out := &boundedText{limit: limit}
	out.write("kind\tsize_bytes\tname\n")
	entries := 0
	add := func(kind string, size int64, name string) failure {
		entries++
		if entries > maxArchiveEntries {
			return resourceLimit
		}
		out.write(fmt.Sprintf("%s\t%d\t%s\n", kind, size, displayName(name)))
		if out.over {
			return resourceLimit
		}
		return ""
	}
	switch {
	case bytes.HasPrefix(data, []byte("PK\x03\x04")) || bytes.HasPrefix(data, []byte("PK\x05\x06")):
		archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return "", malformedInput
		}
		for _, file := range archive.File {
			kind := "file"
			if file.FileInfo().IsDir() {
				kind = "directory"
			} else if file.Mode()&os.ModeSymlink != 0 {
				kind = "link"
			}
			if problem := add(kind, int64(file.UncompressedSize64), file.Name); problem != "" {
				return "", problem
			}
		}
	case bytes.HasPrefix(data, []byte{0x1f, 0x8b}) || (len(data) > 262 && string(data[257:262]) == "ustar"):
		var reader io.Reader = bytes.NewReader(data)
		if data[0] == 0x1f {
			unzipped, err := gzip.NewReader(reader)
			if err != nil {
				return "", malformedInput
			}
			reader = &countingReader{reader: unzipped, left: maxArchiveExpansion}
		}
		archive := tar.NewReader(reader)
		for {
			header, err := archive.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if errors.Is(err, errOutputBound) {
				return "", resourceLimit
			}
			if err != nil {
				return "", malformedInput
			}
			kind := "file"
			switch header.Typeflag {
			case tar.TypeDir:
				kind = "directory"
			case tar.TypeSymlink, tar.TypeLink:
				kind = "link"
			case tar.TypeReg:
			default:
				kind = "special"
			}
			if problem := add(kind, header.Size, header.Name); problem != "" {
				return "", problem
			}
		}
	default:
		return "", malformedInput
	}
	return out.builder.String(), ""
}

// plainText keeps what text displays (cleanText), with line ends as LF.
func plainText(data []byte, limit int) (string, failure) {
	text := cleanText(strings.ReplaceAll(string(data), "\r\n", "\n"))
	if len(text) > limit {
		return "", resourceLimit
	}
	return text, ""
}

// normalizeBytes picks the normalizer for a declared format and a target (module notes).
func normalizeBytes(declared, target string, data []byte, limit int) (string, failure) {
	if target != "plain_text" && target != "markdown" {
		return "", unsupportedFormat
	}
	switch declared {
	case "html":
		return htmlToText(data, target == "markdown", limit)
	case "archive":
		return archiveListing(data, limit)
	case "plain_text":
		return plainText(data, limit)
	default:
		return "", unsupportedFormat
	}
}

func isHexDigest(text string) bool {
	raw, err := hex.DecodeString(text)
	return err == nil && len(raw) == 32
}

// runNormalize is the normalizer's main: exit 0 once it printed a report (a failure is a
// report too), 2 on a bad argument, 3 when it cannot read its input or write its output.
func runNormalize(args []string) int {
	if len(args) != 11 {
		fmt.Fprintln(os.Stderr, "usage: yougori-probe normalize <job> <execution> <boot> <name> <version> <recipe> <declared> <target> <max output bytes> <input> <output>")
		return 2
	}
	job, execution, bootText, name, version, recipe := args[0], args[1], args[2], args[3], args[4], args[5]
	declared, target, maxText, inputPath, outputPath := args[6], args[7], args[8], args[9], args[10]
	boot, bootErr := strconv.ParseUint(bootText, 10, 64)
	limit, limitErr := strconv.ParseUint(maxText, 10, 32)
	if !isHexDigest(job) || !isHexDigest(recipe) || bootErr != nil || boot == 0 || limitErr != nil || limit == 0 {
		fmt.Fprintln(os.Stderr, "normalize: a digest, the boot generation or the output bound does not read")
		return 2
	}
	input, err := os.Open(inputPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "normalize:", err)
		return 3
	}
	data, err := io.ReadAll(io.LimitReader(bufio.NewReader(input), maxNormalizeInput+1))
	input.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "normalize:", err)
		return 3
	}
	report := normalizationReport{
		Job:        strings.ToLower(job),
		Raw:        contentKey(data),
		Normalizer: normalizerIdentity{Name: name, Version: version, Recipe: strings.ToLower(recipe)},
		Execution:  execution,
		Boot:       boot,
	}
	var output string
	var problem failure
	if len(data) > maxNormalizeInput {
		problem = inputTooLarge
	} else {
		output, problem = normalizeBytes(declared, target, data, int(limit))
	}
	if problem != "" {
		report.Outcome = normalizationOutcome{Outcome: "failed", Failure: string(problem)}
	} else {
		if !utf8.ValidString(output) {
			output = strings.ToValidUTF8(output, "�")
		}
		if err := os.WriteFile(outputPath, []byte(output), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "normalize:", err)
			return 3
		}
		report.Outcome = normalizationOutcome{
			Outcome: "normalized",
			Output: &reportedOutput{
				Format:    target,
				Content:   contentKey([]byte(output)),
				SizeBytes: uint64(len(output)),
			},
		}
	}
	line, err := json.Marshal(report)
	if err != nil {
		fmt.Fprintln(os.Stderr, "normalize:", err)
		return 3
	}
	fmt.Println(string(line))
	return 0
}
