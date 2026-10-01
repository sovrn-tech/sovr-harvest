self:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.sovr-harvest;
  toml = pkgs.formats.toml { };
  # systemd puts a LoadCredential at $CREDENTIALS_DIRECTORY/<name>, which for
  # this unit is always this path.
  secretsCredentialPath = "/run/credentials/sovr-harvest.service/sovr-harvest-secrets";
  settings = cfg.settings // lib.optionalAttrs (cfg.secretsFile != null) {
    secrets_file.path = secretsCredentialPath;
  };
  configFile = toml.generate "sovr-harvest.toml" settings;
in
{
  options.services.sovr-harvest = {
    enable = lib.mkEnableOption "sovr-harvest, periodic SOVR validator reward claims and restakes";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "sovr-harvest.packages.\${system}.default";
    };

    tokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/run/secrets/op-service-account-token";
      description = ''
        Path to the 1Password service account token, for example a sops-nix
        secret. The service gets it through systemd LoadCredential. Thus, only
        root must be able to read the file. Give the token read-only access to
        only the vault that holds the signing mnemonic (grantee or operator).
        Set this, or secretsFile, or both.
      '';
    };

    secretsFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/run/secrets/sovr-harvest-mnemonics.toml";
      description = ''
        Path to a local secrets file, for example a sops-nix secret, as an
        alternative to 1Password. The service gets it through systemd
        LoadCredential. Thus, only root must be able to read the file. Set
        this, or tokenFile, or both.
      '';
    };

    settings = lib.mkOption {
      type = toml.type;
      default = { };
      description = ''
        sovr-harvest config, rendered to TOML. Refer to examples/config.toml.
        Do not put secrets in it. The config goes into the Nix store, which all
        users can read.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.tokenFile != null || cfg.secretsFile != null;
        message = "services.sovr-harvest: set tokenFile, secretsFile, or both.";
      }
      {
        assertion = !(cfg.settings ? onepassword && cfg.settings.onepassword ? token_file);
        message = "services.sovr-harvest: set tokenFile, not settings.onepassword.token_file.";
      }
      {
        assertion = !(cfg.settings ? secrets_file);
        message = "services.sovr-harvest: set secretsFile, not settings.secrets_file.";
      }
    ];

    systemd.services.sovr-harvest = {
      description = "SOVR validator reward harvester";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} run -config ${configFile}";
        LoadCredential =
          lib.optional (cfg.tokenFile != null) "op-service-account-token:${cfg.tokenFile}"
          ++ lib.optional (cfg.secretsFile != null) "sovr-harvest-secrets:${cfg.secretsFile}";
        Restart = "on-failure";
        RestartSec = 30;
        DynamicUser = true;

        # mlockall keeps key material out of swap. Core dumps are off.
        LimitMEMLOCK = "infinity";
        LimitCORE = 0;

        CapabilityBoundingSet = "";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        PrivateUsers = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "@memlock"
        ];
        UMask = "0077";
        # MemoryDenyWriteExecute is off on purpose. The 1Password SDK runs its
        # core as WebAssembly in wazero. wazero JIT-compiles the code to
        # executable memory.
      };
    };
  };
}
