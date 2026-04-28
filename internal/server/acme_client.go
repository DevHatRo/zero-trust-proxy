package server

import "golang.org/x/crypto/acme"

// autocertClient is a minimal *acme.Client carrier — autocert.Manager
// accepts a *acme.Client whose DirectoryURL is the only field we set
// for staging or alternate CAs.
type autocertClient = acme.Client
