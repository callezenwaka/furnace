package main

import (
	"context"
	"flag"
	"log"

	"github.com/callezenwaka/terraform-provider-authpilot/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

// version is set by GoReleaser via ldflags at build time.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/callezenwaka/authpilot",
		Debug:   debug,
	}

	if err := providerserver.Serve(context.Background(), provider.New(version), opts); err != nil {
		log.Fatal(err)
	}
}
