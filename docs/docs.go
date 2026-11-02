// Package docs holds text the keystub binary prints: llms.txt is the
// setup guide `keystub help agents` shows, also published as llms.txt.
package docs

import _ "embed"

// AgentGuide is llms.txt: how a person or a coding agent sets Keystub up
// with the CLI alone.
//
//go:embed llms.txt
var AgentGuide string
