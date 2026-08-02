/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package openaitobedrock

import (
	"encoding/json"
	"fmt"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// translateRequest converts an OpenAI Chat Completions payload into a Bedrock
// Converse request body. The model lives in the URL path, not the body, so it
// is deliberately omitted here.
func translateRequest(payload map[string]interface{}) policy.UpstreamRequestModifications {
	converse := map[string]interface{}{}

	if messages, ok := payload["messages"].([]interface{}); ok {
		system, converseMessages := convertMessages(messages)
		if len(system) > 0 {
			converse["system"] = system
		}
		if len(converseMessages) > 0 {
			converse["messages"] = converseMessages
		}
	}

	if inference := buildInferenceConfig(payload); len(inference) > 0 {
		converse["inferenceConfig"] = inference
	}

	if toolConfig := buildToolConfig(payload); toolConfig != nil {
		converse["toolConfig"] = toolConfig
	}

	newBody, err := json.Marshal(converse)
	if err != nil {
		return policy.UpstreamRequestModifications{
			Body: []byte(fmt.Sprintf(`{"error":{"message":"failed to marshal Bedrock body: %s"}}`, err.Error())),
		}
	}

	return policy.UpstreamRequestModifications{
		Body:            newBody,
		HeadersToSet:    map[string]string{"content-type": "application/json"},
		HeadersToRemove: []string{"content-length"},
	}
}

// convertMessages splits OpenAI messages into Converse system blocks and the
// role/content message list. Consecutive tool messages collapse into a single
// user message of toolResult blocks, matching how Converse groups tool output.
func convertMessages(messages []interface{}) ([]map[string]interface{}, []map[string]interface{}) {
	var system []map[string]interface{}
	var converseMessages []map[string]interface{}

	for i := 0; i < len(messages); i++ {
		message, ok := messages[i].(map[string]interface{})
		if !ok {
			continue
		}
		role, _ := message["role"].(string)

		switch role {
		case "system", "developer":
			if text := extractText(message["content"]); text != "" {
				system = append(system, map[string]interface{}{"text": text})
			}
		case "user":
			converseMessages = append(converseMessages, map[string]interface{}{
				"role":    "user",
				"content": convertUserContent(message["content"]),
			})
		case "assistant":
			converseMessages = append(converseMessages, map[string]interface{}{
				"role":    "assistant",
				"content": convertAssistantContent(message),
			})
		case "tool":
			var toolResults []interface{}
			for i < len(messages) {
				toolMessage, ok := messages[i].(map[string]interface{})
				if !ok {
					break
				}
				if r, _ := toolMessage["role"].(string); r != "tool" {
					break
				}
				toolCallID, _ := toolMessage["tool_call_id"].(string)
				toolResults = append(toolResults, map[string]interface{}{
					"toolResult": map[string]interface{}{
						"toolUseId": toolCallID,
						"content":   []interface{}{map[string]interface{}{"text": extractText(toolMessage["content"])}},
					},
				})
				i++
			}
			i-- // outer loop will re-increment
			converseMessages = append(converseMessages, map[string]interface{}{
				"role":    "user",
				"content": toolResults,
			})
		}
	}

	return system, converseMessages
}

func extractText(content interface{}) string {
	switch typed := content.(type) {
	case string:
		return typed
	case []interface{}:
		var parts []string
		for _, part := range typed {
			block, ok := part.(map[string]interface{})
			if !ok || block["type"] != "text" {
				continue
			}
			if text, ok := block["text"].(string); ok {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "")
	}
	return ""
}

func convertUserContent(content interface{}) []interface{} {
	switch typed := content.(type) {
	case string:
		return []interface{}{map[string]interface{}{"text": typed}}
	case []interface{}:
		var blocks []interface{}
		for _, part := range typed {
			block, ok := part.(map[string]interface{})
			if !ok {
				continue
			}
			switch block["type"] {
			case "text":
				if text, ok := block["text"].(string); ok {
					blocks = append(blocks, map[string]interface{}{"text": text})
				}
			case "image_url":
				if image := convertImage(block); image != nil {
					blocks = append(blocks, image)
				}
			}
		}
		if len(blocks) > 0 {
			return blocks
		}
	}
	return []interface{}{map[string]interface{}{"text": ""}}
}

func convertAssistantContent(message map[string]interface{}) []interface{} {
	var blocks []interface{}
	if text := extractText(message["content"]); text != "" {
		blocks = append(blocks, map[string]interface{}{"text": text})
	}

	toolCalls, _ := message["tool_calls"].([]interface{})
	for _, raw := range toolCalls {
		toolCall, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := toolCall["id"].(string)
		fn, _ := toolCall["function"].(map[string]interface{})
		if fn == nil {
			continue
		}
		name, _ := fn["name"].(string)
		argsString, _ := fn["arguments"].(string)

		var input interface{} = map[string]interface{}{}
		if argsString != "" {
			if err := json.Unmarshal([]byte(argsString), &input); err != nil {
				input = map[string]interface{}{}
			}
		}
		blocks = append(blocks, map[string]interface{}{
			"toolUse": map[string]interface{}{
				"toolUseId": id,
				"name":      name,
				"input":     input,
			},
		})
	}

	if len(blocks) == 0 {
		blocks = append(blocks, map[string]interface{}{"text": ""})
	}
	return blocks
}

// convertImage maps an OpenAI image_url block to a Converse image block. Only
// base64 data URIs are supported; remote URLs are dropped since the Converse
// image source expects inline bytes.
func convertImage(block map[string]interface{}) map[string]interface{} {
	imageObject, ok := block["image_url"].(map[string]interface{})
	if !ok {
		return nil
	}
	url, ok := imageObject["url"].(string)
	if !ok || !strings.HasPrefix(url, "data:") {
		return nil
	}
	parts := strings.SplitN(url, ",", 2)
	if len(parts) != 2 {
		return nil
	}
	meta := strings.TrimPrefix(parts[0], "data:")
	mediaType := strings.SplitN(meta, ";", 2)[0]
	format := strings.TrimPrefix(mediaType, "image/")
	if format == "" {
		return nil
	}
	return map[string]interface{}{
		"image": map[string]interface{}{
			"format": format,
			"source": map[string]interface{}{"bytes": parts[1]},
		},
	}
}

func buildInferenceConfig(payload map[string]interface{}) map[string]interface{} {
	inference := map[string]interface{}{}

	if v, ok := payload["max_completion_tokens"]; ok {
		inference["maxTokens"] = v
	} else if v, ok := payload["max_tokens"]; ok {
		inference["maxTokens"] = v
	}

	if v, ok := payload["temperature"]; ok {
		inference["temperature"] = v
	}
	if v, ok := payload["top_p"]; ok {
		inference["topP"] = v
	}
	if stop, ok := payload["stop"]; ok && stop != nil {
		switch s := stop.(type) {
		case string:
			inference["stopSequences"] = []string{s}
		case []interface{}:
			inference["stopSequences"] = s
		}
	}
	return inference
}

// buildToolConfig maps OpenAI tools/tool_choice to a Converse toolConfig.
// Returns nil when no tools apply (or tool_choice is "none"), in which case the
// caller omits toolConfig entirely.
func buildToolConfig(payload map[string]interface{}) map[string]interface{} {
	tools, ok := payload["tools"].([]interface{})
	if !ok || len(tools) == 0 {
		return nil
	}

	// "none" means the model may not call tools — drop the whole toolConfig.
	if choice, ok := payload["tool_choice"].(string); ok && choice == "none" {
		return nil
	}

	var converseTools []interface{}
	for _, raw := range tools {
		tool, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		fn, ok := tool["function"].(map[string]interface{})
		if !ok {
			continue
		}
		spec := map[string]interface{}{"name": fn["name"]}
		if description, ok := fn["description"]; ok {
			spec["description"] = description
		}
		schema := fn["parameters"]
		if schema == nil {
			schema = map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
		}
		spec["inputSchema"] = map[string]interface{}{"json": schema}
		converseTools = append(converseTools, map[string]interface{}{"toolSpec": spec})
	}
	if len(converseTools) == 0 {
		return nil
	}

	toolConfig := map[string]interface{}{"tools": converseTools}
	if toolChoice := convertToolChoice(payload["tool_choice"]); toolChoice != nil {
		toolConfig["toolChoice"] = toolChoice
	}
	return toolConfig
}

func convertToolChoice(toolChoice interface{}) map[string]interface{} {
	switch choice := toolChoice.(type) {
	case string:
		switch choice {
		case "required":
			return map[string]interface{}{"any": map[string]interface{}{}}
		case "auto":
			return map[string]interface{}{"auto": map[string]interface{}{}}
		}
	case map[string]interface{}:
		if fn, ok := choice["function"].(map[string]interface{}); ok {
			if name, ok := fn["name"].(string); ok {
				return map[string]interface{}{"tool": map[string]interface{}{"name": name}}
			}
		}
	}
	return nil
}
