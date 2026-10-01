# AGENTS.md

- Before you commit, run `nix flake check`. This command runs the Go tests, the NixOS module check, and the promtool alert tests.
- If you change the Go module set, change `vendorHash` in nix/package.nix in the same commit. This rule also applies to imports that only tests use.
- Do not trust the node. If a response from the node is not correct, return an error. Do not let the program panic.
- Write each alert so that it gives one result for each validator.
- If you change a metric, change examples/alerts.yml, examples/alerts_test.yml, and README.md in the same commit.
- In each commit body, first write what failed and why. Then write the fix.
- Write docs, comments, and commit messages in ASD-STE100 Simplified Technical English.
