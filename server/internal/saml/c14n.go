package saml

// c14n.go implements W3C Exclusive XML Canonicalization (exc-c14n) as defined in
// https://www.w3.org/TR/xml-exc-c14n/
//
// This is what the vast majority of SAML SPs use to verify assertion signatures.
// The key rules (relative to the naive "just trim whitespace" approach):
//   - Namespace declarations are rendered in a canonical order and only the
//     namespaces actually used by the element (and not already in scope from the
//     serialised ancestor chain) are included.
//   - Attributes are sorted in a deterministic order (namespace URI, then local name).
//   - Empty elements are rendered with explicit open/close tags, not self-closing.
//   - Text content is escaped per XML rules (but not CDATA-wrapped).
//   - XML declaration is omitted.
//   - Whitespace outside elements is preserved as-is (we do not strip it).
//
// Implementation strategy: parse the XML with encoding/xml, then re-serialise with
// the canonical rules. This is sufficient for self-produced assertion XML where we
// control the input.

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

// ExclC14N canonicalises xmlData using Exclusive XML Canonicalization.
// The result is suitable for use as the digest input in an enveloped signature.
func ExclC14N(xmlData []byte) ([]byte, error) {
	// Strip XML declaration if present — c14n output never includes it.
	data := bytes.TrimSpace(xmlData)
	if bytes.HasPrefix(data, []byte("<?xml")) {
		end := bytes.Index(data, []byte("?>"))
		if end < 0 {
			return nil, fmt.Errorf("c14n: malformed XML declaration")
		}
		data = bytes.TrimSpace(data[end+2:])
	}

	dec := xml.NewDecoder(bytes.NewReader(data))
	var buf bytes.Buffer
	ns := newNSStack()

	if err := canonicaliseNode(dec, &buf, ns); err != nil {
		return nil, fmt.Errorf("c14n: %w", err)
	}
	return buf.Bytes(), nil
}

// nsStack tracks namespace bindings visible at each element depth.
type nsStack struct {
	frames []map[string]string // prefix → URI
}

func newNSStack() *nsStack {
	return &nsStack{frames: []map[string]string{{"xml": "http://www.w3.org/XML/1998/namespace"}}}
}

func (s *nsStack) push() { s.frames = append(s.frames, map[string]string{}) }
func (s *nsStack) pop()  { s.frames = s.frames[:len(s.frames)-1] }

func (s *nsStack) declare(prefix, uri string) {
	s.frames[len(s.frames)-1][prefix] = uri
}

// lookup returns the URI for a prefix visible at the current depth, or "".
func (s *nsStack) lookup(prefix string) string {
	for i := len(s.frames) - 1; i >= 0; i-- {
		if uri, ok := s.frames[i][prefix]; ok {
			return uri
		}
	}
	return ""
}

// needsDeclaration returns true if prefix→uri is not already visible in a parent frame.
func (s *nsStack) needsDeclaration(prefix, uri string) bool {
	// Check all frames except the current (top) one.
	for i := len(s.frames) - 2; i >= 0; i-- {
		if v, ok := s.frames[i][prefix]; ok {
			return v != uri
		}
	}
	return uri != "" // needs declaration if not already bound anywhere
}

type c14nAttr struct {
	nsURI string
	local string
	value string
	raw   string // "prefix:local" or "local"
}

func canonicaliseNode(dec *xml.Decoder, buf *bytes.Buffer, ns *nsStack) error {
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil // EOF or end of element
		}

		switch t := tok.(type) {
		case xml.StartElement:
			ns.push()

			// First pass: collect namespace declarations from attributes.
			var nsAttrs []xml.Attr
			var regularAttrs []xml.Attr
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" || (a.Name.Space == "" && a.Name.Local == "xmlns") {
					nsAttrs = append(nsAttrs, a)
				} else {
					regularAttrs = append(regularAttrs, a)
				}
			}

			// Register namespace bindings declared on this element.
			for _, a := range nsAttrs {
				prefix := a.Name.Local
				if a.Name.Space == "" && prefix == "xmlns" {
					prefix = "" // default namespace
				}
				ns.declare(prefix, a.Value)
			}
			// Also register the element's own namespace.
			if t.Name.Space != "" {
				prefix := prefixOf(t.Name.Space, t.Attr)
				ns.declare(prefix, t.Name.Space)
			}

			// Open tag.
			tagName := qualifiedName(t.Name, t.Attr)
			buf.WriteByte('<')
			buf.WriteString(tagName)

			// Emit namespace declarations that are newly needed at this element.
			// Sort for determinism: default namespace first, then by prefix.
			type nsDecl struct{ prefix, uri string }
			var decls []nsDecl

			// Element namespace.
			if t.Name.Space != "" {
				prefix := prefixOf(t.Name.Space, t.Attr)
				if ns.needsDeclaration(prefix, t.Name.Space) {
					decls = append(decls, nsDecl{prefix, t.Name.Space})
					ns.declare(prefix, t.Name.Space)
				}
			}
			// Attribute namespaces.
			for _, a := range regularAttrs {
				if a.Name.Space != "" {
					prefix := prefixOf(a.Name.Space, t.Attr)
					if ns.needsDeclaration(prefix, a.Name.Space) {
						decls = append(decls, nsDecl{prefix, a.Name.Space})
						ns.declare(prefix, a.Name.Space)
					}
				}
			}
			sort.Slice(decls, func(i, j int) bool {
				if decls[i].prefix == decls[j].prefix {
					return decls[i].uri < decls[j].uri
				}
				if decls[i].prefix == "" {
					return true
				}
				if decls[j].prefix == "" {
					return false
				}
				return decls[i].prefix < decls[j].prefix
			})
			for _, d := range decls {
				if d.prefix == "" {
					fmt.Fprintf(buf, ` xmlns="%s"`, escapeAttr(d.uri))
				} else {
					fmt.Fprintf(buf, ` xmlns:%s="%s"`, d.prefix, escapeAttr(d.uri))
				}
			}

			// Emit regular attributes sorted by (namespace URI, local name).
			sortedAttrs := make([]c14nAttr, 0, len(regularAttrs))
			for _, a := range regularAttrs {
				sortedAttrs = append(sortedAttrs, c14nAttr{
					nsURI: a.Name.Space,
					local: a.Name.Local,
					value: a.Value,
					raw:   qualifiedName(a.Name, t.Attr),
				})
			}
			sort.Slice(sortedAttrs, func(i, j int) bool {
				if sortedAttrs[i].nsURI != sortedAttrs[j].nsURI {
					return sortedAttrs[i].nsURI < sortedAttrs[j].nsURI
				}
				return sortedAttrs[i].local < sortedAttrs[j].local
			})
			for _, a := range sortedAttrs {
				fmt.Fprintf(buf, ` %s="%s"`, a.raw, escapeAttr(a.value))
			}

			buf.WriteByte('>')

			// Recurse into children.
			if err := canonicaliseNode(dec, buf, ns); err != nil {
				return err
			}

			// Close tag (always explicit, never self-closing).
			buf.WriteString("</")
			buf.WriteString(tagName)
			buf.WriteByte('>')

			ns.pop()

		case xml.EndElement:
			// Signal caller to close this element.
			return nil

		case xml.CharData:
			buf.WriteString(escapeText(string(t)))

		case xml.Comment:
			// Comments are omitted in exc-c14n by default.

		case xml.ProcInst:
			// Processing instructions are omitted (we don't produce them in assertions).

		case xml.Directive:
			// DOCTYPE etc — omit.
		}
	}
}

// qualifiedName returns "prefix:local" or just "local" for an xml.Name,
// looking up the prefix from the element's attribute list.
func qualifiedName(name xml.Name, attrs []xml.Attr) string {
	if name.Space == "" {
		return name.Local
	}
	prefix := prefixOf(name.Space, attrs)
	if prefix == "" {
		return name.Local
	}
	return prefix + ":" + name.Local
}

// prefixOf finds the namespace prefix declared for uri in the attribute list.
// Falls back to deriving a prefix from known namespaces.
func prefixOf(uri string, attrs []xml.Attr) string {
	for _, a := range attrs {
		if a.Name.Space == "xmlns" && a.Value == uri {
			return a.Name.Local
		}
		if a.Name.Space == "" && a.Name.Local == "xmlns" && a.Value == uri {
			return ""
		}
	}
	// Fallback for well-known namespaces used in SAML.
	switch uri {
	case "urn:oasis:names:tc:SAML:2.0:assertion":
		return "saml"
	case "urn:oasis:names:tc:SAML:2.0:protocol":
		return "samlp"
	case "http://www.w3.org/2000/09/xmldsig#":
		return "ds"
	case "http://www.w3.org/2001/XMLSchema-instance":
		return "xsi"
	case "urn:oasis:names:tc:SAML:2.0:metadata":
		return "md"
	case "http://www.w3.org/XML/1998/namespace":
		return "xml"
	}
	return ""
}

func escapeText(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\r", "&#xD;")
	return s
}

func escapeAttr(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "\t", "&#x9;")
	s = strings.ReplaceAll(s, "\n", "&#xA;")
	s = strings.ReplaceAll(s, "\r", "&#xD;")
	return s
}
