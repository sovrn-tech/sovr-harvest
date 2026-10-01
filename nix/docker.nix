{
  lib,
  dockerTools,
  sovr-harvest,
}:

# An OCI image that holds only the static binary and the CA certificates.
# The CA certificates are necessary for TLS to 1Password and to the gRPC node.
dockerTools.buildLayeredImage {
  name = "sovr-harvest";
  tag = sovr-harvest.version;
  contents = [ dockerTools.caCertificates ];
  # The image has no /tmp by default. Some libraries write temporary files.
  extraCommands = ''
    mkdir -p tmp etc/sovr-harvest
    chmod 1777 tmp
  '';
  config = {
    Entrypoint = [ (lib.getExe sovr-harvest) ];
    Cmd = [
      "run"
      "-config"
      "/etc/sovr-harvest/config.toml"
    ];
    # nobody:nogroup. The process does not need root.
    User = "65534:65534";
    ExposedPorts."9657/tcp" = { };
    Labels = {
      "org.opencontainers.image.title" = "sovr-harvest";
      "org.opencontainers.image.description" = sovr-harvest.meta.description;
      "org.opencontainers.image.licenses" = "MIT";
      "org.opencontainers.image.version" = sovr-harvest.version;
    };
  };
}
