package app

import "strings"

var version string = ""

func Version() string {
	version = strings.TrimSpace(version)

	if len(version) < 1 {
		return "0.0.0"
	}

	return version
}
