package ingest

import (
	"sort"
	"testing"
)

func TestParseImports_JSImportFrom(t *testing.T) {
	content := `
import { foo } from './utils'
import bar from '../lib/bar'
import * as baz from './components/baz.ts'
`
	got := ParseImports("src/app.ts", content)

	want := map[string]bool{
		"src/utils.ts":          true,
		"src/utils.tsx":         true,
		"src/utils.js":          true,
		"src/utils.jsx":         true,
		"src/utils/index.ts":    true,
		"src/utils/index.tsx":   true,
		"src/utils/index.js":    true,
		"src/utils/index.jsx":   true,
		"lib/bar.ts":            true,
		"lib/bar.tsx":           true,
		"lib/bar.js":            true,
		"lib/bar.jsx":           true,
		"lib/bar/index.ts":      true,
		"lib/bar/index.tsx":     true,
		"lib/bar/index.js":      true,
		"lib/bar/index.jsx":     true,
		"src/components/baz.ts": true,
	}

	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected import path: %q", p)
		}
	}

	// Check that baz.ts (with explicit extension) resolves exactly.
	found := false
	for _, p := range got {
		if p == "src/components/baz.ts" {
			found = true
		}
	}
	if !found {
		t.Error("expected src/components/baz.ts in results")
	}
}

func TestParseImports_JSRequire(t *testing.T) {
	content := `
const x = require('./config')
const y = require("../shared/types")
`
	got := ParseImports("src/index.js", content)

	hasConfig := false
	hasTypes := false
	for _, p := range got {
		if p == "src/config.js" || p == "src/config.ts" {
			hasConfig = true
		}
		if p == "shared/types.js" || p == "shared/types.ts" {
			hasTypes = true
		}
	}
	if !hasConfig {
		t.Error("expected config import candidates")
	}
	if !hasTypes {
		t.Error("expected shared/types import candidates")
	}
}

func TestParseImports_JSDynamicImport(t *testing.T) {
	content := `const mod = import('./lazy-module')`
	got := ParseImports("src/app.ts", content)

	found := false
	for _, p := range got {
		if p == "src/lazy-module.ts" {
			found = true
		}
	}
	if !found {
		t.Error("expected src/lazy-module.ts in dynamic import results")
	}
}

func TestParseImports_JSIgnoresNpmPackages(t *testing.T) {
	content := `
import React from 'react'
import { useState } from 'react'
const express = require('express')
import lodash from 'lodash/fp'
import { foo } from './local'
`
	got := ParseImports("src/app.tsx", content)

	for _, p := range got {
		if p == "react" || p == "express" || p == "lodash/fp" {
			t.Errorf("should not include npm package: %q", p)
		}
	}

	found := false
	for _, p := range got {
		if p == "src/local.ts" || p == "src/local.tsx" {
			found = true
		}
	}
	if !found {
		t.Error("expected local import candidates")
	}
}

func TestParseImports_GoReturnsEmpty(t *testing.T) {
	content := `
package main

import (
	"fmt"
	"net/http"
	"github.com/pkg/errors"
)
`
	got := ParseImports("cmd/main.go", content)

	if len(got) != 0 {
		t.Errorf("expected empty imports for Go, got %v", got)
	}
}

func TestParseImports_PythonRelativeImports(t *testing.T) {
	content := `
from . import utils
from .models import User
from ..shared import helpers
`
	got := ParseImports("src/app/views.py", content)

	want := map[string]bool{
		"src/app/__init__.py":        true,
		"src/app/models.py":          true,
		"src/app/models/__init__.py": true,
		"src/shared.py":              true,
		"src/shared/__init__.py":     true,
	}

	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected python import path: %q", p)
		}
	}

	// Verify the "from . import" yields __init__.py.
	found := false
	for _, p := range got {
		if p == "src/app/__init__.py" {
			found = true
		}
	}
	if !found {
		t.Error("expected src/app/__init__.py for 'from . import utils'")
	}
}

func TestParseImports_PythonIgnoresAbsoluteImports(t *testing.T) {
	content := `
import os
import sys
from collections import defaultdict
from .local import thing
`
	got := ParseImports("pkg/module.py", content)

	for _, p := range got {
		if p == "os" || p == "sys" || p == "collections" {
			t.Errorf("should not include stdlib import: %q", p)
		}
	}

	found := false
	for _, p := range got {
		if p == "pkg/local.py" || p == "pkg/local/__init__.py" {
			found = true
		}
	}
	if !found {
		t.Error("expected pkg/local.py or pkg/local/__init__.py")
	}
}

func TestResolveImports_FiltersToExistingPaths(t *testing.T) {
	files := []SourceFile{
		{
			Path:     "src/app.ts",
			Content:  `import { foo } from './utils'`,
			Language: "typescript",
		},
		{
			Path:     "src/utils.ts",
			Content:  `export const foo = 1`,
			Language: "typescript",
		},
		{
			Path:     "src/other.ts",
			Content:  `import { bar } from './nonexistent'`,
			Language: "typescript",
		},
	}

	result := ResolveImports(files)

	// src/app.ts imports ./utils -> src/utils.ts exists.
	appImports, ok := result["src/app.ts"]
	if !ok {
		t.Fatal("expected src/app.ts in result map")
	}
	found := false
	for _, p := range appImports {
		if p == "src/utils.ts" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected src/utils.ts in resolved imports, got %v", appImports)
	}

	// src/other.ts imports ./nonexistent -> nothing matches.
	if otherImports, ok := result["src/other.ts"]; ok {
		t.Errorf("expected no resolved imports for src/other.ts, got %v", otherImports)
	}
}

func TestResolveImports_PythonCrossFile(t *testing.T) {
	files := []SourceFile{
		{
			Path:     "pkg/views.py",
			Content:  `from .models import User`,
			Language: "python",
		},
		{
			Path:     "pkg/models.py",
			Content:  `class User: pass`,
			Language: "python",
		},
	}

	result := ResolveImports(files)

	imports, ok := result["pkg/views.py"]
	if !ok {
		t.Fatal("expected pkg/views.py in result map")
	}

	sort.Strings(imports)
	if len(imports) != 1 || imports[0] != "pkg/models.py" {
		t.Errorf("expected [pkg/models.py], got %v", imports)
	}
}

func TestParseImports_JSSideEffectImport(t *testing.T) {
	content := `import './polyfills'
import "../setup"
`
	got := ParseImports("src/main.ts", content)

	hasPolyfills := false
	hasSetup := false
	for _, p := range got {
		if p == "src/polyfills.ts" || p == "src/polyfills.js" {
			hasPolyfills = true
		}
		if p == "setup.ts" || p == "setup.js" {
			hasSetup = true
		}
	}
	if !hasPolyfills {
		t.Error("expected polyfills import candidates")
	}
	if !hasSetup {
		t.Error("expected setup import candidates")
	}
}

func TestParseImports_UnknownExtensionReturnsNil(t *testing.T) {
	got := ParseImports("readme.md", "# Hello\nSome text")
	if got != nil {
		t.Errorf("expected nil for unknown extension, got %v", got)
	}
}
