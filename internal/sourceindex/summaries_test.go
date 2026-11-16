package sourceindex

import "testing"

func TestExtractExportName(t *testing.T) {
	testCases := []struct {
		name string
		line string
		want string
	}{
		{name: "function", line: "export function foo() {", want: "foo()"},
		{name: "async_function", line: "export async function fetchData(url) {", want: "fetchData()"},
		{name: "const", line: "export const bar = 42;", want: "bar"},
		{name: "let", line: "export let mutable = true;", want: "mutable"},
		{name: "class", line: "export class Baz {", want: "Baz"},
		{name: "interface", line: "export interface Props {", want: "Props"},
		{name: "type_alias", line: "export type ID = string;", want: "ID"},
		{name: "generic_type", line: "export type Result<T> = T | Error;", want: "Result"},
		{name: "default_class", line: "export default class App {", want: "App"},
		{name: "no_keyword_match", line: "export { foo, bar };", want: ""},
		{name: "empty_after_keyword", line: "export const ", want: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractExportName(tc.line)
			if got != tc.want {
				t.Errorf("extractExportName(%q) = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}

func TestExtractPyName(t *testing.T) {
	testCases := []struct {
		name string
		line string
		want string
	}{
		{name: "def", line: "def foo():", want: "foo"},
		{name: "def_with_args", line: "def process_items(items, *, key=None):", want: "process_items"},
		{name: "class", line: "class Bar:", want: "Bar"},
		{name: "class_with_base", line: "class Child(Parent):", want: "Child"},
		{name: "class_space_before_colon", line: "class Thing :", want: "Thing"},
		{name: "no_match", line: "import os", want: ""},
		{name: "def_no_paren", line: "def ", want: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractPyName(tc.line)
			if got != tc.want {
				t.Errorf("extractPyName(%q) = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}
