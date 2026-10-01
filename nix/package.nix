{
  lib,
  stdenvNoCC,
  buildGoModule,
  go,
  version,
}:

let
  # A Go build cache for the vendored dependencies. This derivation uses only
  # go.mod, go.sum, and the vendor directory. Thus a change to the project
  # code does not cause Nix to build it again. The package copies it into
  # GOCACHE, and then Go compiles only the project code.
  goCache = stdenvNoCC.mkDerivation {
    pname = "sovr-harvest-go-cache";
    version = "0";
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../go.mod
        ../go.sum
      ];
    };
    nativeBuildInputs = [ go ];
    env = {
      inherit (go) GOOS GOARCH;
      GOTOOLCHAIN = "local";
      CGO_ENABLED = 0;
      GOPROXY = "off";
      GOSUMDB = "off";
    };
    buildPhase = ''
      runHook preBuild
      export HOME=$TMPDIR GOPATH=$TMPDIR/go GOCACHE=$out
      # The unpack phase puts us in /build/source, the same directory as in
      # buildGoModule. The tests do not use -trimpath, thus their cache keys
      # include the source path.
      cp -r --reflink=auto ${package.goModules} vendor
      pkgs=$(go list -mod=vendor -e \
        -f '{{if and (not .Error) (not .DepsErrors)}}{{.ImportPath}}{{end}}' \
        $(grep -v '^#' vendor/modules.txt))
      # The build uses -trimpath. The tests do not. Some vendored packages do
      # not compile for all architectures. Go continues to compile the other
      # packages, so ignore these errors. A missing cache entry only makes the
      # package build slower.
      go build -mod=vendor -trimpath -p $NIX_BUILD_CORES $pkgs 2>/dev/null || true
      go build -mod=vendor -p $NIX_BUILD_CORES $pkgs 2>/dev/null || true
      runHook postBuild
    '';
    dontInstall = true;
    dontFixup = true;
  };

  package = buildGoModule {
    pname = "sovr-harvest";
    inherit version;
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../go.mod
        ../go.sum
        ../cmd
        ../internal
      ];
    };
    vendorHash = "sha256-f+bNg3v33Gxx4HPkWX7scL7JnR+hlRTbBWYE6hJcteA=";
    # Without subPackages, buildGoModule runs dirname once for each .go file
    # in the vendor directory to find the packages. That takes approximately
    # 16 seconds for each phase. "./..." does not include the vendor directory.
    # Go also builds and tests all packages in one command.
    subPackages = [ "..." ];
    env.CGO_ENABLED = 0;
    ldflags = [
      "-s"
      "-w"
      "-X main.version=${version}"
    ];
    preBuild = ''
      cp -r --reflink=auto --no-preserve=mode ${goCache}/. "$GOCACHE"
    '';
    overrideModAttrs = _: _: {
      # The default name includes the version. Then each Git revision gives a
      # new vendor path, and Nix downloads the modules and builds goCache again.
      name = "sovr-harvest-go-modules";
      # The vendor derivation also runs preBuild. It must not use the cache.
      preBuild = "";
    };
    passthru = { inherit goCache; };
    meta = {
      description = "Validator reward claimer and restaker for SOVR, with authz signing and Prometheus metrics";
      license = lib.licenses.mit;
      mainProgram = "sovr-harvest";
      platforms = lib.platforms.linux;
    };
  };
in
package
