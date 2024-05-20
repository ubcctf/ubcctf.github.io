{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      out = system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };

          gems = pkgs.bundlerEnv {
            name = "your-package";
            inherit (pkgs) ruby;
            gemdir = ./.;
          };

          lock-gems = pkgs.writeShellScriptBin "lock-gems" ''
            bundle lock
            bundix -l
          '';
        in
        {
          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [
              bundler
              ruby
              bundix
              gems
              lock-gems

              # in case you choose to `bundle install` manually (you do not
              # need to do this)
              zlib
              libxml2
              lzma
              pkg-config
              libxslt
            ];
            env = {
              # evil hack to make ruby not think it is 1970 and utf-8 does not exist
              LOCALE_ARCHIVE = "${pkgs.glibcLocales}/lib/locale/locale-archive";

              # make nokogiri compile way faster because we have good system libs
              BUNDLE_BUILD__NOKOGIRI = "--use-system-libraries";

              # bundle please don't put x86_64-linux in the lock file >:(
              BUNDLE_FORCE_RUBY_PLATFORM = "true";
            };
          };

        };
    in
    flake-utils.lib.eachDefaultSystem out;

}
