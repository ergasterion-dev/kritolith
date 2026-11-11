# Heading IDs are written unescaped into the table of contents

gomarkdown/markdown at commit d0b5ea06ca81b481a9cab073610fd15323571dab: an explicit heading
ID such as `# Title {#x"><img src=x onerror=alert(1)>}` is taken as written by the parser
in `parser/block.go` and stored as `HeadingID`. An earlier fix escaped the value where the
heading itself is rendered, but not where the table of contents is built.

With the `html.TOC` flag set, `html/renderer.go` writes the ID into the `href` of the
table-of-contents link without escaping it, so the attribute can be closed and markup
injected. The `<h1 id=...>` a few lines below is escaped; the link above it is not.

This is a regression from the project this one was forked from: blackfriday v2 writes
`<a href="#toc_%d">` from a counter (`html.go:927`) and never puts user text there.

It does not affect the default `markdown.ToHTML(input, nil, nil)` call, only renderers
created with `html.RendererOptions{Flags: html.CommonFlags | html.TOC}`.

Impact: script injection in applications that render untrusted Markdown with a table of
contents and rely on `html.SkipHTML` as the safety boundary.
