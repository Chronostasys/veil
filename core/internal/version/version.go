// Package version carries build identity.
package version

// Version is the semantic version of the Veil core.
const Version = "1.0.0"

// Commit is injected at build time with -ldflags "-X veil/internal/version.Commit=...".
var Commit = "dev"

// Build is a compile-time stamp (ldflags -X) so the device log can prove
// exactly which binary is running.
var Build = "dev"

// UserAgent is used for subscription downloads and latency probes.
const UserAgent = "Veil/1.0 (HarmonyOS)"
