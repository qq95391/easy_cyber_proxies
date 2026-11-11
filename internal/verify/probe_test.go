package verify

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"easy_proxies/internal/config"
)

func TestExtHashHelpers(t *testing.T) {
	if hashBytes([]byte("abc")) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal("sha256 helper mismatch")
	}
	if tlsVersionName(tls.VersionTLS13) != "TLS1.3" {
		t.Fatal("TLS version name mismatch")
	}
}

func TestExtRenderProbeFromHTTPSServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("stable-content"))
	}))
	defer srv.Close()
	// The test server uses a self-signed certificate; use its own client so the
	// probe collection logic can be exercised without a public network call.
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	snap, err := collectProbe(context.Background(), client, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Status != 200 || snap.BodyHash == "" || snap.CertFingerprint == "" || snap.SPKIFingerprint == "" {
		t.Fatalf("incomplete probe snapshot: %+v", snap)
	}
	if snap.TLSVersion == "" || snap.Issuer == "" {
		t.Fatalf("TLS metadata missing: %+v", snap)
	}
	if string(snap.Body) != "stable-content" {
		t.Fatal("probe body not preserved for keyword checks")
	}
}

func testBaseline() *probeSnapshot {
	return &probeSnapshot{
		SPKIFingerprint: "aaa", Issuer: "CN=Trusted CA", Subject: "CN=example.com",
		TLSVersion: "TLS1.3", ALPN: "h2", BodyHash: "bbb", BodyLength: 14,
		CertFingerprint: "fff", Headers: http.Header{},
	}
}

func testMITMCfg() config.MITMConfig {
	return config.MITMConfig{
		Enabled: boolPtr(true), VerifyCertificate: true,
		CompareCertBaseline: true, CompareBodyHash: true, CheckHeaders: true,
		Action: "reject",
	}
}

func TestExtMITMCleanSampleIsNotSuspected(t *testing.T) {
	base := testBaseline()
	sample := *base
	res := Result{Reachable: true, ExitIP: "1.2.3.4"}
	compareProbeSnapshots(base, &sample, testMITMCfg(), &res)
	if res.MITMSuspected {
		t.Fatalf("identical sample flagged as MITM: %+v", res.MITMReasons)
	}
	if res.BodyHashMatch == nil || !*res.BodyHashMatch {
		t.Fatal("body hash match not recorded")
	}
}

func TestExtMITMDetectsDifferentCertificateSPKI(t *testing.T) {
	base := testBaseline()
	sample := *base
	sample.SPKIFingerprint = "ccc"
	res := Result{Reachable: true}
	compareProbeSnapshots(base, &sample, testMITMCfg(), &res)
	if !res.MITMSuspected {
		t.Fatal("SPKI mismatch must be flagged")
	}
}

func TestExtMITMDetectsBodyTamperingAndDowngrade(t *testing.T) {
	base := testBaseline()
	sample := *base
	sample.BodyHash = "tampered"
	sample.Headers = http.Header{"X-Forwarded-For": []string{"203.0.113.9"}}
	sample.Location = "http://downgrade.invalid/"
	res := Result{Reachable: true}
	compareProbeSnapshots(base, &sample, testMITMCfg(), &res)
	if !res.MITMSuspected || len(res.MITMReasons) < 3 {
		t.Fatalf("L3/L4 signals not detected: %+v", res.MITMReasons)
	}
}

func TestExtMITMAllowAndDenyLists(t *testing.T) {
	base := testBaseline()
	sample := *base
	cfg := testMITMCfg()
	cfg.TrustedFingerprints = []string{"expected-fp"}
	res := Result{Reachable: true}
	compareProbeSnapshots(base, &sample, cfg, &res)
	if !res.MITMSuspected {
		t.Fatal("untrusted fingerprint must be flagged")
	}

	cfg.TrustedFingerprints = nil
	cfg.BlacklistIPs = []string{"1.2.3.4"}
	res2 := Result{Reachable: true, ExitIP: "1.2.3.4"}
	compareProbeSnapshots(base, &sample, cfg, &res2)
	if !res2.MITMSuspected {
		t.Fatal("blacklisted exit IP must be flagged")
	}
}

func TestExtUnreachableProbeTargetDoesNotMarkProxyFake(t *testing.T) {
	cfg := config.DefaultAuthenticityConfig()
	cfg.CheckURL = "http://127.0.0.1:1/unreachable"
	cfg.RequireExitDiffers = false
	cfg.RequireDeclaredMatch = false
	v := New(config.VerificationConfig{Authenticity: cfg, MITM: config.MITMConfig{Enabled: boolPtr(false)}})
	res := Result{Reachable: true, Checks: map[string]bool{}, DirectIP: "1.1.1.1", ExitIP: "2.2.2.2"}
	v.checkAuthenticity(context.Background(), &res, config.NodeConfig{}, "http://127.0.0.1:1")
	if !res.Genuine {
		t.Fatalf("unreachable probe target must not mark proxy fake: %+v", res.GenuineReasons)
	}
	if res.Checks["genuine_probe"] {
		t.Fatal("probe should be recorded as skipped")
	}
}

func TestExtCertificateErrorClassification(t *testing.T) {
	if isCertificateError(nil) {
		t.Fatal("nil error must not be a certificate error")
	}
	if !isCertificateError(errCertificate("x509: certificate signed by unknown authority")) {
		t.Fatal("unknown authority must be detected as certificate error")
	}
	if isCertificateError(errCertificate("connection refused")) {
		t.Fatal("plain network error must not be a certificate error")
	}
}

type errCertificate string

func (e errCertificate) Error() string { return string(e) }

func TestExtScorePenalisesMITMAndFakeProxy(t *testing.T) {
	clean := Result{Reachable: true, SuccessRate: 1, LatencyMS: 100, Anonymity: "high", Handshake: "socks5", SpeedBPS: 1024, Genuine: true}
	base, grade := score(clean)
	if base < 80 || grade != "A" {
		t.Fatalf("clean proxy score = %d %s", base, grade)
	}
	mitm := clean
	mitm.MITMSuspected = true
	s, g := score(mitm)
	if s >= base || g == "A" {
		t.Fatalf("MITM proxy not penalised: %d %s", s, g)
	}
	fake := clean
	fake.Genuine = false
	fake.Checks = map[string]bool{"genuine": true}
	s2, g2 := score(fake)
	if s2 >= base || g2 == "A" {
		t.Fatalf("fake proxy not penalised: %d %s", s2, g2)
	}
}

func TestExtRedirectAndProxyHeadersAreMITMSignals(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Forwarded-For", "203.0.113.9")
		w.Header().Set("Location", "http://downgrade.invalid/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	snap, err := collectProbe(context.Background(), client, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Location == "" || !strings.HasPrefix(snap.Location, "http://") {
		t.Fatal("downgrade redirect not captured")
	}
	if snap.Headers.Get("X-Forwarded-For") == "" {
		t.Fatal("injected proxy header not captured")
	}
}

func TestExtProbeClientNeverSkipsCertificateVerification(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:1")
	tr, err := buildTransport(u, 0)
	if err != nil {
		t.Fatal(err)
	}
	client := newProbeClient(tr, 0)
	if client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Fatal("probe client must never skip certificate verification")
	}
	if client.CheckRedirect == nil {
		t.Fatal("probe client must not follow redirects")
	}
}

func boolPtr(v bool) *bool { return &v }
