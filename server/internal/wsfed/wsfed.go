// Package wsfed implements the WS-Federation Passive Requestor Profile
// (for legacy Azure AD / ADFS integrations).
//
// Endpoints:
//   - GET/POST /wsfed                                       — passive requestor endpoint
//   - GET /federationmetadata/2007-06/federationmetadata.xml — federation metadata
//
// # PKCE / CSRF note
//
// The WS-Federation Passive Requestor Profile (OA-WSFED-1.0) has no equivalent
// of OAuth 2.0 PKCE (RFC 7636). The protocol predates PKCE and relies on the
// wctx/wtrealm round-trip and a signed assertion posted back to the wreply URL
// for security. Consumers integrating WS-Fed via Authpilot should be aware that:
//
//  1. No code_challenge / code_verifier exchange takes place.
//  2. CSRF protection is the responsibility of the relying party (e.g. by
//     verifying the wreply origin and validating the assertion signature).
//  3. This is consistent with how Azure AD / ADFS implement the same profile.
package wsfed

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"authpilot/server/internal/domain"
	"authpilot/server/internal/saml"
	"authpilot/server/internal/store"
)

// RouterDeps are the dependencies required by the WS-Fed router.
type RouterDeps struct {
	Users    store.UserStore
	Sessions store.SessionStore
	CertMgr  *saml.CertManager
	// EntityID is the IdP entity ID (realm), e.g. "http://localhost:8026".
	EntityID string
	// IssuerURL is the base URL of the WS-Fed endpoint, e.g. "http://localhost:8026/wsfed".
	IssuerURL string
	// LoginURL is where the browser is redirected for the Authpilot login UI.
	LoginURL string
	// SessionTTL is how long WS-Fed sessions remain valid.
	SessionTTL time.Duration
}

// NewRouter returns an http.Handler serving all WS-Fed endpoints.
func NewRouter(dep RouterDeps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/wsfed", wsfedHandler(dep))
	mux.HandleFunc("/federationmetadata/2007-06/federationmetadata.xml", metadataHandler(dep))
	return mux
}

// ---------------------------------------------------------------------------
// Passive requestor endpoint
// ---------------------------------------------------------------------------

func wsfedHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		wa := q.Get("wa")

		switch wa {
		case "wsignin1.0":
			handleSignIn(w, r, dep)
		case "wsignout1.0", "wsignoutcleanup1.0":
			handleSignOut(w, r, dep)
		case "":
			// No wa — show info page.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, wsfedInfoPage, dep.EntityID, dep.IssuerURL, dep.EntityID)
		default:
			http.Error(w, "unsupported wa action: "+wa, http.StatusBadRequest)
		}
	}
}

func handleSignIn(w http.ResponseWriter, r *http.Request, dep RouterDeps) {
	q := r.URL.Query()
	wtrealm := q.Get("wtrealm")
	wreply := q.Get("wreply")
	wctx := q.Get("wctx")

	if wtrealm == "" {
		http.Error(w, "wtrealm is required", http.StatusBadRequest)
		return
	}
	if wreply == "" {
		wreply = wtrealm
	}

	// Check for a completed flow result passed back as ?wsfed_flow_id=
	// (set by the login page after the user selects a user and completes the flow).
	flowID := q.Get("wsfed_flow_id")
	if flowID != "" {
		completeSignIn(w, r, dep, flowID, wreply, wctx)
		return
	}

	// Redirect to login page, passing ourselves as the callback.
	callbackURL := dep.IssuerURL +
		"?wa=wsignin1.0" +
		"&wtrealm=" + url.QueryEscape(wtrealm) +
		"&wreply=" + url.QueryEscape(wreply)
	if wctx != "" {
		callbackURL += "&wctx=" + url.QueryEscape(wctx)
	}
	loginDest := dep.LoginURL + "?next=" + url.QueryEscape(callbackURL)
	http.Redirect(w, r, loginDest, http.StatusFound)
}

func completeSignIn(w http.ResponseWriter, r *http.Request, dep RouterDeps, flowID, wreply, wctx string) {
	_ = r
	// Look up all sessions for this flow — find the most recent one.
	sessions, err := dep.Sessions.List()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var sess *domain.Session
	for i := range sessions {
		if sessions[i].FlowID == flowID {
			sess = &sessions[i]
			break
		}
	}
	if sess == nil {
		http.Error(w, "session not found for flow", http.StatusBadRequest)
		return
	}
	user, err := dep.Users.GetByID(sess.UserID)
	if err != nil {
		http.Error(w, "user not found", http.StatusBadRequest)
		return
	}

	token, err := buildWSTrustToken(user, dep.EntityID, wreply, dep.CertMgr)
	if err != nil {
		http.Error(w, "token build error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	contextParam := ""
	if wctx != "" {
		contextParam = fmt.Sprintf(`<input type="hidden" name="wctx" value="%s"/>`, escapeAttr(wctx))
	}
	fmt.Fprintf(w, wsfedPostForm,
		wreply,
		escapeAttr(token),
		contextParam,
	)
}

func handleSignOut(w http.ResponseWriter, r *http.Request, dep RouterDeps) {
	q := r.URL.Query()
	wreply := q.Get("wreply")

	// Invalidate all sessions (simple IdP-side logout).
	sessions, _ := dep.Sessions.List()
	for _, s := range sessions {
		_ = dep.Sessions.Delete(s.ID)
	}

	if wreply != "" {
		http.Redirect(w, r, wreply, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, wsfedSignOutPage, dep.EntityID)
}

// ---------------------------------------------------------------------------
// Federation metadata
// ---------------------------------------------------------------------------

func metadataHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		certDER := dep.CertMgr.CertDER()
		certB64 := base64.StdEncoding.EncodeToString(certDER)

		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		fmt.Fprintf(w, federationMetadataXML,
			dep.EntityID, // entityID attr
			certB64,      // X509Certificate
			dep.EntityID, // ClaimType auth namespace
			dep.IssuerURL, // PassiveRequestorEndpoint Address
		)
	}
}

// ---------------------------------------------------------------------------
// WS-Trust token builder (SAML 1.1 security token)
// ---------------------------------------------------------------------------

// buildWSTrustToken constructs a WS-Trust 1.3 RSTR containing a signed SAML 1.1 assertion.
func buildWSTrustToken(user domain.User, issuer, audience string, cm *saml.CertManager) (string, error) {
	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute)
	notAfter := now.Add(1 * time.Hour)
	ts := now.Format("2006-01-02T15:04:05Z")
	nbStr := notBefore.Format("2006-01-02T15:04:05Z")
	naStr := notAfter.Format("2006-01-02T15:04:05Z")
	assertionID := randomID()

	// Build attribute statements.
	attrs := buildAttributeStatements(user)

	assertionXML := fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" `+
		`AssertionID="%s" Issuer="%s" IssueInstant="%s" `+
		`MajorVersion="1" MinorVersion="1">`+
		`<saml:Conditions NotBefore="%s" NotOnOrAfter="%s">`+
		`<saml:AudienceRestrictionCondition>`+
		`<saml:Audience>%s</saml:Audience>`+
		`</saml:AudienceRestrictionCondition>`+
		`</saml:Conditions>`+
		`<saml:AuthenticationStatement AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:unspecified" AuthenticationInstant="%s">`+
		`<saml:Subject>`+
		`<saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameIdentifier>`+
		`</saml:Subject>`+
		`</saml:AuthenticationStatement>`+
		`<saml:AttributeStatement>`+
		`<saml:Subject>`+
		`<saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameIdentifier>`+
		`</saml:Subject>`+
		`%s`+
		`</saml:AttributeStatement>`+
		`</saml:Assertion>`,
		assertionID, escapeAttr(issuer), ts,
		nbStr, naStr,
		escapeText(audience),
		ts,
		escapeText(user.Email),
		escapeText(user.Email),
		attrs,
	)

	// Sign the assertion.
	signed, err := signAssertion([]byte(assertionXML), assertionID, cm)
	if err != nil {
		return "", fmt.Errorf("sign wsfed assertion: %w", err)
	}

	// Wrap in a WS-Trust 1.3 RequestSecurityTokenResponse.
	rstr := fmt.Sprintf(`<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">`+
		`<t:Lifetime>`+
		`<wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%s</wsu:Created>`+
		`<wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%s</wsu:Expires>`+
		`</t:Lifetime>`+
		`<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">`+
		`<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">`+
		`<wsa:Address>%s</wsa:Address>`+
		`</wsa:EndpointReference>`+
		`</wsp:AppliesTo>`+
		`<t:RequestedSecurityToken>`+
		`%s`+
		`</t:RequestedSecurityToken>`+
		`<t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>`+
		`<t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>`+
		`<t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>`+
		`</t:RequestSecurityTokenResponse>`,
		ts, naStr,
		escapeText(audience),
		string(signed),
	)

	return rstr, nil
}

func buildAttributeStatements(user domain.User) string {
	var sb strings.Builder

	writeAttr := func(ns, name, value string) {
		fmt.Fprintf(&sb,
			`<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" AttributeName="%s" AttributeNamespace="%s">`,
			escapeAttr(name), escapeAttr(ns),
		)
		fmt.Fprintf(&sb, `<saml:AttributeValue>%s</saml:AttributeValue>`, escapeText(value))
		sb.WriteString(`</saml:Attribute>`)
	}

	writeAttr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims", "emailaddress", user.Email)
	writeAttr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims", "name", user.DisplayName)
	writeAttr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims", "nameidentifier", user.ID)

	for k, v := range user.Claims {
		if s, ok := v.(string); ok {
			writeAttr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims", k, s)
		}
	}
	return sb.String()
}

// signAssertion wraps the SAML 1.1 assertion XML with an enveloped XML DSig.
func signAssertion(assertionXML []byte, assertionID string, cm *saml.CertManager) ([]byte, error) {
	// Canonicalise the assertion for digest.
	canonical, err := saml.ExclC14N(assertionXML)
	if err != nil {
		return nil, fmt.Errorf("c14n assertion: %w", err)
	}
	digest := sha256.Sum256(canonical)
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	certDER := cm.CertDER()
	certB64 := base64.StdEncoding.EncodeToString(certDER)

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
		assertionID, digestB64,
	)
	siCanonical, err := saml.ExclC14N([]byte(signedInfo))
	if err != nil {
		return nil, fmt.Errorf("c14n signedinfo: %w", err)
	}
	siDigest := sha256.Sum256(siCanonical)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, cm.PrivateKey(), crypto.SHA256, siDigest[:])
	if err != nil {
		return nil, fmt.Errorf("rsa sign: %w", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	signature := fmt.Sprintf(
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`+
			`%s`+
			`<ds:SignatureValue>%s</ds:SignatureValue>`+
			`<ds:KeyInfo>`+
			`<ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data>`+
			`</ds:KeyInfo>`+
			`</ds:Signature>`,
		signedInfo, sigB64, certB64,
	)

	// Insert <ds:Signature> as the first child of the Assertion element.
	xmlStr := string(assertionXML)
	insertAfter := strings.Index(xmlStr, ">")
	if insertAfter < 0 {
		return nil, fmt.Errorf("malformed assertion XML")
	}
	result := xmlStr[:insertAfter+1] + signature + xmlStr[insertAfter+1:]
	return []byte(result), nil
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "_" + base64.RawURLEncoding.EncodeToString(b)
}

func escapeAttr(s string) string {
	var sb strings.Builder
	_ = xml.EscapeText(&sb, []byte(s))
	return sb.String()
}

func escapeText(s string) string {
	var sb strings.Builder
	_ = xml.EscapeText(&sb, []byte(s))
	return sb.String()
}

// ---------------------------------------------------------------------------
// HTML / XML templates
// ---------------------------------------------------------------------------

const wsfedInfoPage = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>WS-Federation IdP</title></head>
<body>
<h2>Authpilot WS-Federation IdP</h2>
<p>Entity ID: <code>%s</code></p>
<p>Passive Requestor Endpoint: <code>%s</code></p>
<p>Federation Metadata: <a href="/federationmetadata/2007-06/federationmetadata.xml">federationmetadata.xml</a></p>
<p>To start a sign-in, your relying party should redirect to:<br>
<code>%s?wa=wsignin1.0&amp;wtrealm=&lt;your-realm&gt;&amp;wreply=&lt;reply-url&gt;</code></p>
</body></html>`

const wsfedPostForm = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>WS-Federation Sign In</title></head>
<body onload="document.forms[0].submit()">
<form method="POST" action="%s">
  <input type="hidden" name="wa" value="wsignin1.0"/>
  <input type="hidden" name="wresult" value="%s"/>
  %s
  <noscript><button type="submit">Continue</button></noscript>
</form>
</body></html>`

const wsfedSignOutPage = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Signed Out</title></head>
<body>
<h2>Signed Out</h2>
<p>You have been signed out of <strong>%s</strong>.</p>
</body></html>`

const federationMetadataXML = `<?xml version="1.0" encoding="utf-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
  xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706"
  xmlns:wsa="http://www.w3.org/2005/08/addressing"
  xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706"
  entityID="%s">
  <RoleDescriptor
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706"
    xsi:type="fed:SecurityTokenServiceType"
    protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>%s</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <fed:TokenTypesOffered>
      <fed:TokenType Uri="urn:oasis:names:tc:SAML:1.0:assertion"/>
    </fed:TokenTypesOffered>
    <fed:ClaimTypesOffered>
      <auth:ClaimType Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" xmlns:auth="%s" Optional="true"/>
    </fed:ClaimTypesOffered>
    <fed:PassiveRequestorEndpoint>
      <wsa:EndpointReference>
        <wsa:Address>%s</wsa:Address>
      </wsa:EndpointReference>
    </fed:PassiveRequestorEndpoint>
  </RoleDescriptor>
</EntityDescriptor>`
