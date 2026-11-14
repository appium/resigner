package codesign

import (
	"context"
	"crypto/x509"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
	"resigner/pkg/macho"
)

// XCTest bundles are loaded libraries, not separate entitled applications.
func TestXCTestInheritsIdentityWithoutAppEntitlements(t *testing.T) {
	_, bundle, root := unzipIPAForTest(t)
	path := filepath.Join(bundle, "PlugIns", "WebDriverAgentRunner.xctest")
	key, cert := selfSignedIdentity(t)
	config := SigningConfig{Force: true, Key: key, Cert: cert,
		Chain: []*x509.Certificate{cert}, TeamID: "TEAMID12345",
		Entitlements: DefaultEntitlements("TEAMID12345", "TEAMID12345", "com.example.runner", true),
	}
	strategy := determineChildSigningStrategy("PlugIns/WebDriverAgentRunner.xctest", true, config)
	if err := strategy.sign(context.Background(), zap.NewNop(), root, path, config); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{path, filepath.Join(path, "Frameworks", "WebDriverAgentLib.framework")} {
		_, info, _, err := readInfo(root, dir, SigningConfig{})
		if err != nil {
			t.Fatal(err)
		}
		file, err := root.OpenRW(filepath.Join(dir, info.BundleExecutable))
		if err != nil {
			t.Fatal(err)
		}
		binary, err := macho.Parse(file, 0)
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
		directories := 0
		err = binary.Visit(func(value macho.Struct, visit func() error) error {
			switch value := value.(type) {
			case *macho.CodeSignatureEntitlementsBlob, *macho.CodeSignatureEntitlementsDERBlob:
				t.Error("loaded library contains forbidden entitlements")
			case *macho.CodeSignatureCodeDirectoryBlob:
				directories++
				if value.TeamID != "TEAMID12345" {
					t.Errorf("wrong signing team: %q", value.TeamID)
				}
			}
			return visit()
		})
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		if directories == 0 {
			t.Fatal("missing code directory")
		}
	}
}
