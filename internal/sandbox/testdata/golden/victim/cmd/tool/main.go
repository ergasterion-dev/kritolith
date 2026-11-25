package main

import "example.com/victim/pkg"

func crash(p *pkg.Parser) { p.Parse(nil) }

func main() { crash(&pkg.Parser{}) }
