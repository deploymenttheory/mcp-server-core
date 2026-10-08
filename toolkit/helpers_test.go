package toolkit

import (
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/mcp-server-core/inventory"
)

func inventoryToolset(id string) inventory.ToolsetMetadata {
	return inventory.ToolsetMetadata{ID: inventory.ToolsetID(id), Description: id}
}

func callReq(name, args string) *mcp.CallToolRequest {
	return &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: name, Arguments: json.RawMessage(args)}}
}
