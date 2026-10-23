// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestPluginManifests checks the Claude Code plugin in plugin/ and the
// marketplace file that lists it: the names agree, the marketplace points
// at the plugin, and the plugin starts tern mcp with the config file the
// user chose, which has a default so that a surface that does not ask for
// values (Cowork) still starts it.
func TestPluginManifests(t *testing.T) {
	read := func(path string, v any) {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("..", path))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	var market struct {
		Name    string
		Plugins []struct{ Name, Source string }
	}
	read(".claude-plugin/marketplace.json", &market)
	var manifest struct {
		Name       string
		Version    string
		UserConfig map[string]struct{ Default string }
	}
	read("plugin/.claude-plugin/plugin.json", &manifest)
	var servers struct {
		MCPServers map[string]struct {
			Command string
			Args    []string
		}
	}
	read("plugin/.mcp.json", &servers)

	if len(market.Plugins) != 1 || market.Plugins[0].Name != manifest.Name || market.Plugins[0].Source != "./plugin" {
		t.Errorf("marketplace %q lists %+v; the plugin is %q in ./plugin", market.Name, market.Plugins, manifest.Name)
	}
	if manifest.Version == "" {
		t.Error("plugin.json has no version")
	}
	if manifest.UserConfig["config"].Default == "" {
		t.Error("the config option has no default")
	}
	tern, ok := servers.MCPServers["tern"]
	if !ok || tern.Command != "tern" || !slices.Equal(tern.Args, []string{"mcp", "--config", "${user_config.config}"}) {
		t.Errorf("tern server = %+v", servers.MCPServers)
	}
}
