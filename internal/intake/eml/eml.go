// Package eml turns one raw email message (RFC 5322, as a mail server
// or `fetchmail` hands it over) into a report.Report. Every header,
// body part and attachment is hostile input.
package eml

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"path"
	"strings"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

const (
	MaxMessageBytes = 16 << 20 // the whole raw message
	MaxBodyBytes    = 1 << 20  // report text, same cap as a report file
	MaxPoCFiles     = 64       // attachments kept as PoC files
	MaxPoCBytes     = 8 << 20  // across all attachments, decoded

	maxTitleRunes = 200
	maxParts      = 200 // MIME parts looked at in one message
	maxDepth      = 8   // nesting of multipart inside multipart
	maxRefRunes   = 300 // Message-ID kept as the source reference
)

// Options describes one message to load.
type Options struct {
	Repo string // owner/name, required: a message can't be trusted to say which project it is about
	Ref  string // commit SHA or tag, if the operator knows it
	Now  func() time.Time
	Rand io.Reader
}

// Load reads one message from r and returns it as a report. The
// report text is the message's plain-text body (or its HTML body with
// the markup removed, if there is no plain text); attachments become
// PoC files. Nothing is executed or written to disk.
func Load(r io.Reader, opts Options) (report.Report, error) {
	if err := report.ValidateRepo(opts.Repo); err != nil {
		return report.Report{}, fmt.Errorf("intake/eml: %w", err)
	}
	if opts.Ref != "" {
		if err := report.ValidateRef(opts.Ref); err != nil {
			return report.Report{}, fmt.Errorf("intake/eml: %w", err)
		}
	}
	raw, err := io.ReadAll(io.LimitReader(r, MaxMessageBytes+1))
	if err != nil {
		return report.Report{}, fmt.Errorf("intake/eml: read message: %w", err)
	}
	if len(raw) > MaxMessageBytes {
		return report.Report{}, fmt.Errorf("intake/eml: message is larger than %d bytes", MaxMessageBytes)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return report.Report{}, errors.New("intake/eml: empty message")
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return report.Report{}, fmt.Errorf("intake/eml: not a mail message: %w", err)
	}

	c := &collector{}
	if err := c.walk(header(msg.Header), msg.Body, 0); err != nil {
		return report.Report{}, fmt.Errorf("intake/eml: %w", err)
	}
	body := c.text()
	if len(body) > MaxBodyBytes {
		return report.Report{}, fmt.Errorf("intake/eml: message text is %d bytes; limit is %d", len(body), MaxBodyBytes)
	}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	rnd := io.Reader(rand.Reader)
	if opts.Rand != nil {
		rnd = opts.Rand
	}
	received := now().UTC()
	id, err := report.NewID(received, rnd)
	if err != nil {
		return report.Report{}, fmt.Errorf("intake/eml: %w", err)
	}
	return report.Report{
		ID:         id,
		Source:     report.SourceEML,
		SourceRef:  sourceRef(msg.Header.Get("Message-Id"), raw),
		Repo:       opts.Repo,
		ClaimedRef: opts.Ref,
		Title:      title(msg.Header.Get("Subject")),
		Body:       body,
		PoC:        c.attachments,
		ReceivedAt: received,
	}, nil
}

// header is the part of mail.Header and textproto.MIMEHeader that the
// walk needs; both have this method.
type header interface{ Get(string) string }

// collector gathers the text and attachments found while walking a
// message's MIME tree, and enforces the limits across the whole tree.
type collector struct {
	plain       []string
	html        []string
	attachments []report.Artifact
	parts       int
	pocBytes    int
	names       map[string]bool
}

// text prefers the plain-text parts. HTML is used only when the
// message has no plain text at all, with its markup removed.
func (c *collector) text() string {
	parts := c.plain
	if len(parts) == 0 {
		parts = c.html
	}
	return strings.TrimSpace(strings.Join(parts, "\n\n"))
}

func (c *collector) walk(h header, body io.Reader, depth int) error {
	if c.parts++; c.parts > maxParts {
		return fmt.Errorf("message has more than %d MIME parts", maxParts)
	}
	mediaType, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		// No or unparseable Content-Type: RFC 2045 says to treat it
		// as plain US-ASCII text.
		mediaType, params = "text/plain", nil
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		if depth >= maxDepth {
			return fmt.Errorf("message nests multipart sections more than %d deep", maxDepth)
		}
		boundary := params["boundary"]
		if boundary == "" {
			return errors.New("multipart section has no boundary")
		}
		mr := multipart.NewReader(body, boundary)
		for {
			// NextRawPart leaves Content-Transfer-Encoding alone, so
			// every part is decoded in one place, below.
			p, err := mr.NextRawPart()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("reading a MIME part: %w", err)
			}
			if err := c.walk(p.Header, p, depth+1); err != nil {
				return err
			}
		}
	}

	decoded := decodeTransfer(h.Get("Content-Transfer-Encoding"), body)
	name := attachmentName(h, params)
	if name != "" || !strings.HasPrefix(mediaType, "text/") {
		return c.addAttachment(name, mediaType, decoded)
	}

	// Inline text: part of the report. One byte over the cap is enough
	// to make Load refuse the message.
	data, err := io.ReadAll(io.LimitReader(decoded, MaxBodyBytes+1))
	if err != nil {
		return fmt.Errorf("decoding a text part: %w", err)
	}
	text := toUTF8(data, params["charset"])
	text = strings.ReplaceAll(text, "\r\n", "\n")
	switch mediaType {
	case "text/html":
		c.html = append(c.html, stripHTML(text))
	default:
		c.plain = append(c.plain, text)
	}
	return nil
}

func (c *collector) addAttachment(name, mediaType string, decoded io.Reader) error {
	if len(c.attachments) == MaxPoCFiles {
		return fmt.Errorf("too many attachments (limit %d)", MaxPoCFiles)
	}
	remaining := MaxPoCBytes - c.pocBytes
	data, err := io.ReadAll(io.LimitReader(decoded, int64(remaining)+1))
	if err != nil {
		return fmt.Errorf("decoding an attachment: %w", err)
	}
	if len(data) > remaining {
		return fmt.Errorf("attachments are larger than %d bytes in total", MaxPoCBytes)
	}
	c.pocBytes += len(data)
	if c.names == nil {
		c.names = map[string]bool{}
	}
	c.attachments = append(c.attachments, report.Artifact{Name: c.uniqueName(name, mediaType), Content: data})
	return nil
}

// uniqueName returns a safe, distinct file name for an attachment. A
// name from the message is reduced to its last path element, so
// "../../.ssh/authorized_keys" is just "authorized_keys": PoC files
// are data today, but the sandbox will write them to disk under these
// names.
func (c *collector) uniqueName(name, mediaType string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = path.Base(path.Clean("/" + name))
	if name == "/" {
		name = "" // nothing left: the name was empty or only dots and slashes
	}
	name = strings.ReplaceAll(report.Printable(name), "\uFFFD", "_")
	name = strings.TrimLeft(strings.TrimSpace(name), ".")
	if r := []rune(name); len(r) > 100 {
		name = string(r[len(r)-100:])
	}
	if name == "" {
		name = "attachment"
		if _, sub, ok := strings.Cut(mediaType, "/"); ok && isToken(sub) {
			name += "." + sub
		}
	}
	candidate := name
	for i := 2; c.names[candidate]; i++ {
		candidate = fmt.Sprintf("%d-%s", i, name)
	}
	c.names[candidate] = true
	return candidate
}

func isToken(s string) bool {
	if s == "" || len(s) > 20 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// attachmentName returns the file name a part declares, from
// Content-Disposition or the Content-Type "name" parameter, or "" if
// it declares none. A part marked as an attachment with no name gets
// a placeholder so it is still kept as one.
func attachmentName(h header, typeParams map[string]string) string {
	disp, params, err := mime.ParseMediaType(h.Get("Content-Disposition"))
	if err == nil {
		if n := decodeWord(params["filename"]); n != "" {
			return n
		}
	}
	if n := decodeWord(typeParams["name"]); n != "" {
		return n
	}
	if err == nil && disp == "attachment" {
		return "attachment"
	}
	return ""
}

func decodeTransfer(encoding string, r io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		// Mail wraps base64 in lines; the decoder must skip the line
		// breaks.
		return base64.NewDecoder(base64.StdEncoding, &newlineStripper{r: r})
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	}
	return r // 7bit, 8bit, binary, or something unknown: taken as is
}

// newlineStripper removes CR and LF from a stream.
type newlineStripper struct{ r io.Reader }

func (s *newlineStripper) Read(p []byte) (int, error) {
	for {
		n, err := s.r.Read(p)
		k := 0
		for _, b := range p[:n] {
			if b != '\r' && b != '\n' {
				p[k] = b
				k++
			}
		}
		if k > 0 || err != nil {
			return k, err
		}
	}
}

// toUTF8 converts text in the charsets mail still commonly uses.
// Anything else is taken as UTF-8 with invalid bytes replaced: a wrong
// guess garbles accented letters, not the ASCII identifiers and paths
// that claims are made of.
func toUTF8(data []byte, charset string) string {
	switch strings.ToLower(strings.TrimSpace(charset)) {
	case "iso-8859-1", "latin1", "iso8859-1", "windows-1252", "cp1252":
		var b strings.Builder
		b.Grow(len(data))
		for _, c := range data {
			b.WriteRune(rune(c))
		}
		return b.String()
	}
	return strings.ToValidUTF8(string(data), "�")
}

// wordDecoder decodes RFC 2047 encoded words ("=?utf-8?B?...?=") in
// headers. An unknown charset is read as bytes rather than failing.
var wordDecoder = mime.WordDecoder{
	CharsetReader: func(charset string, input io.Reader) (io.Reader, error) {
		data, err := io.ReadAll(io.LimitReader(input, 64<<10))
		if err != nil {
			return nil, err
		}
		return strings.NewReader(toUTF8(data, charset)), nil
	},
}

func decodeWord(s string) string {
	if s == "" {
		return ""
	}
	if d, err := wordDecoder.DecodeHeader(s); err == nil {
		return d
	}
	return s
}

// title is the subject as one printable line.
func title(subject string) string {
	s := strings.Join(strings.Fields(decodeWord(subject)), " ")
	r := []rune(report.Printable(s))
	if len(r) > maxTitleRunes {
		r = r[:maxTitleRunes]
	}
	return string(r)
}

// sourceRef identifies the message: its Message-ID if it has one,
// otherwise a hash of its bytes. Re-ingesting the same message gives
// the same reference, which is what keeps a report from being flagged
// as a duplicate of itself.
func sourceRef(messageID string, raw []byte) string {
	id := report.Printable(strings.TrimSpace(messageID))
	if r := []rune(id); len(r) > maxRefRunes {
		id = string(r[:maxRefRunes])
	}
	if id != "" {
		return id
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// stripHTML returns the text of an HTML document: tags, comments,
// and the contents of script and style elements are removed, block
// elements become line breaks, and the few entities that matter for
// reading code are decoded. It is a reader for report text, not a
// sanitizer: its output is never rendered as HTML.
func stripHTML(s string) string {
	// lower has the same length as s, so an offset found in one is
	// valid in the other. It is made once: lower-casing the remainder
	// for every tag would make a message full of tags quadratic.
	lower := asciiLower(s)
	var b strings.Builder
	b.Grow(len(s))
	pos := 0
	for pos < len(s) {
		i := strings.IndexByte(s[pos:], '<')
		if i < 0 {
			b.WriteString(s[pos:])
			break
		}
		b.WriteString(s[pos : pos+i])
		pos += i
		if strings.HasPrefix(s[pos:], "<!--") {
			end := strings.Index(s[pos:], "-->")
			if end < 0 {
				break
			}
			pos += end + len("-->")
			continue
		}
		end := strings.IndexByte(s[pos:], '>')
		if end < 0 {
			break // an unclosed tag: drop the rest
		}
		closing := strings.HasPrefix(s[pos:], "</")
		name := strings.TrimLeft(lower[pos+1:pos+end], "/ ")
		if j := strings.IndexAny(name, " \t\n\r/"); j >= 0 {
			name = name[:j]
		}
		pos += end + 1
		switch name {
		case "script", "style":
			if !closing {
				if j := strings.Index(lower[pos:], "</"+name); j >= 0 {
					pos += j
				} else {
					pos = len(s)
				}
			}
		case "br", "p", "div", "li", "tr", "pre", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "table", "ul", "ol":
			b.WriteByte('\n')
		}
	}
	return htmlEntities.Replace(b.String())
}

// asciiLower lower-cases A-Z only, so the result has the same byte
// length as s.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

var htmlEntities = strings.NewReplacer(
	"&nbsp;", " ", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#39;", "'", "&apos;", "'", "&amp;", "&",
)
