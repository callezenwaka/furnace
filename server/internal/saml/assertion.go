package saml

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"time"

	"authpilot/server/internal/domain"
)

// --- SAML Response / Assertion structures ---

type Response struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	Xmlns        string   `xml:"xmlns:saml,attr"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Destination  string   `xml:"Destination,attr"`
	InResponseTo string   `xml:"InResponseTo,attr,omitempty"`
	Issuer       Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Status       Status   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Assertion    Assertion
}

type Issuer struct {
	Value string `xml:",chardata"`
}

type Status struct {
	StatusCode StatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}

type StatusCode struct {
	Value string `xml:"Value,attr"`
}

type Assertion struct {
	XMLName            xml.Name           `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                 string             `xml:"ID,attr"`
	Version            string             `xml:"Version,attr"`
	IssueInstant       string             `xml:"IssueInstant,attr"`
	Issuer             Issuer             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Subject            Subject            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	Conditions         Conditions         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AuthnStatement     AuthnStatement     `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
	AttributeStatement AttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}

type Subject struct {
	NameID              NameID              `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SubjectConfirmation SubjectConfirmation `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
}

type NameID struct {
	Format string `xml:"Format,attr"`
	Value  string `xml:",chardata"`
}

type SubjectConfirmation struct {
	Method                  string                  `xml:"Method,attr"`
	SubjectConfirmationData SubjectConfirmationData `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
}

type SubjectConfirmationData struct {
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	Recipient    string `xml:"Recipient,attr"`
	InResponseTo string `xml:"InResponseTo,attr,omitempty"`
}

type Conditions struct {
	NotBefore           string              `xml:"NotBefore,attr"`
	NotOnOrAfter        string              `xml:"NotOnOrAfter,attr"`
	AudienceRestriction AudienceRestriction `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
}

type AudienceRestriction struct {
	Audience string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}

type AuthnStatement struct {
	AuthnInstant string    `xml:"AuthnInstant,attr"`
	AuthnContext AuthnContext `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext"`
}

type AuthnContext struct {
	AuthnContextClassRef string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
}

type AttributeStatement struct {
	Attributes []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

type Attribute struct {
	Name         string           `xml:"Name,attr"`
	NameFormat   string           `xml:"NameFormat,attr"`
	AttributeValues []AttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

type AttributeValue struct {
	Type  string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr,omitempty"`
	Value string `xml:",chardata"`
}

// AssertionConfig controls assertion content.
type AssertionConfig struct {
	IssuerEntityID string
	ACS            string   // AssertionConsumerServiceURL
	Audience       string   // SP EntityID — often same as ACS origin; defaults to ACS if empty
	InResponseTo   string   // AuthnRequest ID
	SessionTTL     time.Duration
}

func (c *AssertionConfig) audience() string {
	if c.Audience != "" {
		return c.Audience
	}
	return c.ACS
}

// BuildSignedResponse builds a signed SAML Response XML for the given user.
// The assertion is signed using enveloped XML DSig (RSA-SHA256, SHA-256 digest).
func BuildSignedResponse(cfg AssertionConfig, user domain.User, cm *CertManager) ([]byte, error) {
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 1 * time.Hour
	}

	now := time.Now().UTC()
	notAfter := now.Add(cfg.SessionTTL)

	assertionID, err := randomSAMLID()
	if err != nil {
		return nil, err
	}
	responseID, err := randomSAMLID()
	if err != nil {
		return nil, err
	}

	nameIDValue := user.Email
	if nameIDValue == "" {
		nameIDValue = user.ID
	}

	instant := now.Format("2006-01-02T15:04:05Z")
	expiry := notAfter.Format("2006-01-02T15:04:05Z")

	// Build attributes from user claims + standard fields.
	attrs := buildAttributes(user)

	assertion := Assertion{
		ID:           assertionID,
		Version:      "2.0",
		IssueInstant: instant,
		Issuer:       Issuer{Value: cfg.IssuerEntityID},
		Subject: Subject{
			NameID: NameID{
				Format: nameIDFormatEmailAddress,
				Value:  nameIDValue,
			},
			SubjectConfirmation: SubjectConfirmation{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: SubjectConfirmationData{
					NotOnOrAfter: expiry,
					Recipient:    cfg.ACS,
					InResponseTo: cfg.InResponseTo,
				},
			},
		},
		Conditions: Conditions{
			NotBefore:    instant,
			NotOnOrAfter: expiry,
			AudienceRestriction: AudienceRestriction{
				Audience: cfg.audience(),
			},
		},
		AuthnStatement: AuthnStatement{
			AuthnInstant: instant,
			AuthnContext: AuthnContext{
				AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			},
		},
		AttributeStatement: AttributeStatement{Attributes: attrs},
	}

	// Marshal the assertion so we can sign it.
	assertionXML, err := xml.Marshal(assertion)
	if err != nil {
		return nil, fmt.Errorf("saml: marshal assertion: %w", err)
	}

	signedAssertionXML, err := signXML(assertionXML, assertionID, cm)
	if err != nil {
		return nil, fmt.Errorf("saml: sign assertion: %w", err)
	}

	// Build the response wrapper, embedding the signed assertion as raw XML.
	resp := Response{
		Xmlns:        nsSAML,
		ID:           responseID,
		Version:      "2.0",
		IssueInstant: instant,
		Destination:  cfg.ACS,
		InResponseTo: cfg.InResponseTo,
		Issuer:       Issuer{Value: cfg.IssuerEntityID},
		Status: Status{
			StatusCode: StatusCode{Value: statusSuccess},
		},
	}

	responseXML, err := xml.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("saml: marshal response: %w", err)
	}

	// Inject the signed assertion into the response before the closing tag.
	responseXML = injectAssertion(responseXML, signedAssertionXML)

	return responseXML, nil
}

// buildAttributes converts user fields and claims into SAML attributes.
func buildAttributes(user domain.User) []Attribute {
	attrs := []Attribute{
		{
			Name:       "urn:oid:0.9.2342.19200300.100.1.3",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			AttributeValues: []AttributeValue{{Value: user.Email}},
		},
		{
			Name:       "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			AttributeValues: []AttributeValue{{Value: user.ID}},
		},
	}
	if user.DisplayName != "" {
		attrs = append(attrs, Attribute{
			Name:       "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			AttributeValues: []AttributeValue{{Value: user.DisplayName}},
		})
	}
	for k, v := range user.Claims {
		attrs = append(attrs, Attribute{
			Name:       k,
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeValues: []AttributeValue{{Value: fmt.Sprintf("%v", v)}},
		})
	}
	return attrs
}

// signXML adds an enveloped XML DSig signature to the given XML element.
// referenceID is the ID attribute of the element being signed (assertion ID).
// The signature is inserted as the first child of the element.
// Canonicalization uses W3C Exclusive XML Canonicalization (exc-c14n).
func signXML(xmlData []byte, referenceID string, cm *CertManager) ([]byte, error) {
	// Canonicalise the element for digest computation.
	canonical, err := ExclC14N(xmlData)
	if err != nil {
		return nil, fmt.Errorf("saml: c14n for digest: %w", err)
	}

	// Compute SHA-256 digest of the canonical element.
	digest := sha256.Sum256(canonical)
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	// Build the SignedInfo element using exc-c14n algorithm URI.
	signedInfo := fmt.Sprintf(
		`<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`+
			`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`+
			`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>`+
			`<ds:Reference URI="#%s">`+
			`<ds:Transforms>`+
			`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>`+
			`<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`+
			`</ds:Transforms>`+
			`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`+
			`<ds:DigestValue>%s</ds:DigestValue>`+
			`</ds:Reference>`+
			`</ds:SignedInfo>`,
		referenceID, digestB64)

	// Canonicalise SignedInfo before signing (required by XML DSig spec).
	signedInfoC14N, err := ExclC14N([]byte(signedInfo))
	if err != nil {
		return nil, fmt.Errorf("saml: c14n for SignedInfo: %w", err)
	}

	siDigest := sha256.Sum256(signedInfoC14N)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, cm.PrivateKey(), crypto.SHA256, siDigest[:])
	if err != nil {
		return nil, fmt.Errorf("saml: rsa sign: %w", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	certB64 := base64.StdEncoding.EncodeToString(cm.CertDER())

	signature := fmt.Sprintf(
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">%s<ds:SignatureValue>%s</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>`,
		signedInfo, sigB64, certB64,
	)

	// Insert signature as the first child element (after the opening tag).
	return insertAfterFirstTag(xmlData, []byte(signature)), nil
}

// insertAfterFirstTag injects content after the first XML opening tag.
func insertAfterFirstTag(data, insert []byte) []byte {
	idx := bytes.IndexByte(data, '>')
	if idx < 0 {
		return append(data, insert...)
	}
	result := make([]byte, 0, len(data)+len(insert))
	result = append(result, data[:idx+1]...)
	result = append(result, insert...)
	result = append(result, data[idx+1:]...)
	return result
}

// injectAssertion inserts the assertion XML before the closing </Response> tag.
func injectAssertion(responseXML, assertionXML []byte) []byte {
	closing := []byte("</")
	// Find the last closing tag to inject before.
	idx := bytes.LastIndex(responseXML, closing)
	if idx < 0 {
		return append(responseXML, assertionXML...)
	}
	result := make([]byte, 0, len(responseXML)+len(assertionXML))
	result = append(result, responseXML[:idx]...)
	result = append(result, assertionXML...)
	result = append(result, responseXML[idx:]...)
	return result
}

// randomSAMLID generates an ID suitable for SAML elements.
// SAML IDs must start with a letter or underscore per XML NCName rules.
func randomSAMLID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("saml: random id: %w", err)
	}
	return "_" + base64.RawURLEncoding.EncodeToString(b), nil
}
