package codesign

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
	"resigner/pkg/macho"
)

func TestXCTestForceReplacesMatchingProfileEntitlements(t *testing.T) {
	_, bundle, root := unzipIPAForTest(t)
	path := filepath.Join(bundle, "PlugIns", "WebDriverAgentRunner.xctest")
	key, cert := selfSignedIdentity(t)
	config := SigningConfig{Force: true, Key: key, Cert: cert,
		Chain: []*x509.Certificate{cert}, TeamID: "TEAMID12345",
		Entitlements: DefaultEntitlements("TEAMID12345", "TEAMID12345", "com.example.runner", true),
	}
	ctx, logger := context.Background(), zap.NewNop()
	// Reproduce an earlier application-style signature using the same identity.
	var signer NativeCodeSigner
	if err := signer.SignPath(ctx, logger, root, path, config); err != nil {
		t.Fatal(err)
	}
	config.Profile = &Profile{ProfileInfo: ProfileInfo{
		DeveloperCertificates: Certificates{cert}, TeamIdentifier: []string{"TEAMID12345"},
		Entitlements: ProfileEntitlements{Team: "TEAMID12345", Identifier: "TEAMID12345.com.example.runner"},
	}}
	_, info, _, err := readInfo(root, path, SigningConfig{})
	if err != nil {
		t.Fatal(err)
	}
	executablePath := filepath.Join(path, info.BundleExecutable)
	readExecutable := func() []byte {
		t.Helper()
		file, err := root.Open(executablePath)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		data, err := io.ReadAll(file)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	before := readExecutable()
	// Force must not turn verification-only into a rewrite or a false failure.
	verify := config
	verify.OnlyVerify = true
	if err := signer.SignPath(ctx, logger, root, path, verify); err != nil {
		t.Fatalf("same-profile verification failed: %v", err)
	}
	if !bytes.Equal(before, readExecutable()) {
		t.Fatal("verification changed executable bytes")
	}
	mapped := "com.example.remapped-tests"
	config.BundleIDMap = map[string]string{info.BundleIdentifier: mapped}
	if err := (xctestStrategy{}).sign(ctx, logger, root, path, config); err != nil {
		t.Fatal(err)
	}
	_, updated, _, err := readInfo(root, path, SigningConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if updated.BundleIdentifier != mapped {
		t.Errorf("force skipped bundle remapping: got %q", updated.BundleIdentifier)
	}
	file, err := root.OpenRW(executablePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	binary, err := macho.Parse(file, 0)
	if err != nil {
		t.Fatal(err)
	}
	cms := 0
	if err := binary.Visit(func(value macho.Struct, visit func() error) error {
		switch value := value.(type) {
		case *macho.CodeSignatureEntitlementsBlob, *macho.CodeSignatureEntitlementsDERBlob:
			t.Error("force retained forbidden library entitlements")
		case *macho.CodeSignatureCodeDirectoryBlob:
			if value.Identifier != mapped || value.TeamID != "TEAMID12345" {
				t.Errorf("unexpected code-directory identity: %s / %s", value.Identifier, value.TeamID)
			}
		case *macho.CodeSignatureCMSSignatureBlob:
			cms++
			if !checkSignatureMatchesProfile(value, &config) {
				t.Error("signature does not retain the parent certificate")
			}
		}
		return visit()
	}); err != nil {
		t.Fatal(err)
	}
	if cms == 0 {
		t.Fatal("missing CMS signature")
	}
}
