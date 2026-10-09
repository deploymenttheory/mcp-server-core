package surface

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/deploymenttheory/mcp-server-core/mcpspec"
)

// ValidateCaptured checks the protocol surface actually returned to a client
// against the selected published MCP revision. It checks every advertised item,
// not a fixed list of names from the conformance suite's example server.
func ValidateCaptured(spec *mcpspec.Spec, got Captured) error {
	if got.NegotiatedVersion != spec.Version {
		return fmt.Errorf("negotiated %q, expected %q", got.NegotiatedVersion, spec.Version)
	}
	var problems []error
	check := func(name string, raw json.RawMessage) {
		if len(raw) == 0 {
			problems = append(problems, fmt.Errorf("%s was not captured", name))
			return
		}
		if err := spec.ValidateJSON(name, raw); err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", name, err))
		}
	}
	if name, ok := spec.FirstPresent("DiscoverResult", "InitializeResult"); ok {
		check(name, got.HandshakeResult)
	} else {
		problems = append(problems, fmt.Errorf("revision %s has no server handshake definition", spec.Version))
	}
	check("ServerCapabilities", got.Capabilities)
	var capabilities map[string]json.RawMessage
	if err := json.Unmarshal(got.Capabilities, &capabilities); err == nil {
		for capability := range capabilities {
			switch capability {
			case "tools", "prompts", "resources", "completions":
			default:
				problems = append(problems, fmt.Errorf("advertised capability %q has no product conformance probe", capability))
			}
		}
	}
	for _, item := range []struct {
		definition string
		field      string
		member     string
		raw        json.RawMessage
	}{
		{"ListToolsResult", "tools", "Tool", got.ToolsListResult},
		{"ListPromptsResult", "prompts", "Prompt", got.PromptsListResult},
		{"ListResourcesResult", "resources", "Resource", got.ResourcesListResult},
		{"ListResourceTemplatesResult", "resourceTemplates", "ResourceTemplate", got.ResourceTemplatesListResult},
	} {
		check(item.definition, item.raw)
		if len(item.raw) == 0 {
			continue
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(item.raw, &payload); err != nil {
			problems = append(problems, fmt.Errorf("%s: decode list: %w", item.definition, err))
			continue
		}
		var cursor string
		if len(payload["nextCursor"]) > 0 {
			if err := json.Unmarshal(payload["nextCursor"], &cursor); err != nil {
				problems = append(problems, fmt.Errorf("%s: decode nextCursor: %w", item.definition, err))
				continue
			}
			if cursor != "" {
				problems = append(problems, fmt.Errorf("%s: paginated list requires a full-page capture before it can pass the product gate", item.definition))
			}
		}
		var members []json.RawMessage
		if err := json.Unmarshal(payload[item.field], &members); err != nil {
			problems = append(problems, fmt.Errorf("%s: decode %s: %w", item.definition, item.field, err))
			continue
		}
		for index, raw := range members {
			var named struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(raw, &named)
			label := named.Name
			if label == "" {
				label = fmt.Sprintf("#%d", index)
			}
			if err := spec.ValidateJSON(item.member, raw); err != nil {
				problems = append(problems, fmt.Errorf("%s %q: %w", item.member, label, err))
			}
			if item.member == "Tool" {
				if err := validateToolSchemas(spec, raw); err != nil {
					problems = append(problems, fmt.Errorf("Tool %q: %w", label, err))
				}
			}
		}
	}
	for _, method := range []string{"tools/call", "prompts/get", "resources/read", "completion/complete"} {
		for index, raw := range got.Results[method] {
			if err := ValidateMethodResult(spec, method, raw); err != nil {
				problems = append(problems, fmt.Errorf("%s result #%d: %w", method, index+1, err))
			}
		}
	}
	return errors.Join(problems...)
}

// ValidateMethodResult checks a response shape for a supported server method.
// It also covers result constructors whose OS-backed handler cannot safely run
// on a hosted CI runner, such as screenshots and desktop-state resources.
func ValidateMethodResult(spec *mcpspec.Spec, method string, raw json.RawMessage) error {
	definition, ok := map[string]string{
		"tools/call":          "CallToolResult",
		"prompts/get":         "GetPromptResult",
		"resources/read":      "ReadResourceResult",
		"completion/complete": "CompleteResult",
	}[method]
	if !ok {
		return fmt.Errorf("no conformance definition for method %q", method)
	}
	return spec.ValidateJSON(definition, raw)
}

// RequireProbeMethods fails when an advertised operation was never exercised.
// This prevents a green schema run from meaning only that declarations parsed.
func RequireProbeMethods(got Captured, methods ...string) error {
	var missing []error
	for _, method := range methods {
		if len(got.Results[method]) == 0 {
			missing = append(missing, fmt.Errorf("%s has no successful raw response", method))
		}
	}
	return errors.Join(missing...)
}

func validateToolSchemas(spec *mcpspec.Spec, raw json.RawMessage) error {
	var tool struct {
		Input  json.RawMessage `json:"inputSchema"`
		Output json.RawMessage `json:"outputSchema"`
	}
	if err := json.Unmarshal(raw, &tool); err != nil {
		return err
	}
	for _, entry := range []struct {
		name string
		raw  json.RawMessage
	}{
		{"inputSchema", tool.Input},
		{"outputSchema", tool.Output},
	} {
		if len(entry.raw) == 0 {
			continue
		}
		var schema jsonschema.Schema
		if err := json.Unmarshal(entry.raw, &schema); err != nil {
			return fmt.Errorf("%s: %w", entry.name, err)
		}
		if schema.Schema == "" {
			schema.Schema = spec.Draft()
		}
		if _, err := schema.Resolve(&jsonschema.ResolveOptions{}); err != nil {
			return fmt.Errorf("%s: %w", entry.name, err)
		}
	}
	return nil
}
