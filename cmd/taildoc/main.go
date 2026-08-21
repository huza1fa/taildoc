package main

import (
	"os"

	"github.com/huza1fa/taildoc/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
