{
  description = "The robmuxinator script serves as a command-line tool to manage and control tmux sessions on multiple hosts of your robot.";
  outputs = { self, nixpkgs, ... }@inputs:
    let
      forAllSystems = nixpkgs.lib.genAttrs nixpkgs.lib.platforms.unix;

      nixpkgsFor = forAllSystems (system: import nixpkgs {
        inherit system;
      });
    in
      {
        packages = forAllSystems (system:
          let pkgs = nixpkgsFor.${system}; in
          {
            default = self.packages.${system}.robmuxinator;

            robmuxinator = pkgs.python3Packages.buildPythonPackage rec {
              name = "robmuxinator";
              src = self;

              preCheck = ''
                export HOME=$(mktemp -d)
              '';

              propagatedBuildInputs = with pkgs; [
                python3Packages.argcomplete
                python3Packages.colorama
                python3Packages.paramiko
                python3Packages.pyyaml
              ];
            };
          });

        apps = forAllSystems (system:
          let apps = nixpkgsFor.${system}; in
          {
            default = self.apps.${system}.robmuxinator;

            robmuxinator = {
              type = "app";
              program = "${self.packages.${system}.robmuxinator}/bin/robmuxinator";
            };
          });
      };
}
