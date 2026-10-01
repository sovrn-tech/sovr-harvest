{
  description = "Validator reward claimer and restaker for SOVR, with authz signing and Prometheus metrics";

  inputs.nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.zst";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (system: rec {
        sovr-harvest = nixpkgs.legacyPackages.${system}.callPackage ./nix/package.nix {
          version = self.shortRev or self.dirtyShortRev or "dev";
        };
        default = sovr-harvest;
        docker = nixpkgs.legacyPackages.${system}.callPackage ./nix/docker.nix {
          inherit sovr-harvest;
        };
      });

      nixosModules.default = import ./nix/module.nix self;
      nixosModules.sovr-harvest = self.nixosModules.default;

      checks = forAllSystems (system: {
        # buildGoModule runs `go test ./...`.
        package = self.packages.${system}.default;
        # Evaluates the module and renders its config file.
        module =
          (nixpkgs.lib.nixosSystem {
            inherit system;
            modules = [
              self.nixosModules.default
              {
                boot.isContainer = true;
                system.stateVersion = "26.05";
                services.sovr-harvest = {
                  enable = true;
                  tokenFile = "/run/secrets/op-service-account-token";
                  settings.validator = [
                    {
                      operator_address = "sovrvaloper1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpwmje0";
                      mnemonic_ref = "op://vault/item/mnemonic";
                    }
                  ];
                };
              }
            ];
          }).config.systemd.units."sovr-harvest.service".unit;
        # Checks and unit-tests the example alert rules.
        alerts =
          nixpkgs.legacyPackages.${system}.runCommand "sovr-harvest-alerts"
            { nativeBuildInputs = [ nixpkgs.legacyPackages.${system}.prometheus.cli ]; }
            ''
              cd ${./examples}
              promtool check rules alerts.yml
              promtool test rules alerts_test.yml
              touch $out
            '';
      });

      devShells = forAllSystems (system: {
        default = nixpkgs.legacyPackages.${system}.mkShell {
          packages = with nixpkgs.legacyPackages.${system}; [
            go
            gopls
            grpcurl
          ];
          CGO_ENABLED = 0;
        };
      });
    };
}
