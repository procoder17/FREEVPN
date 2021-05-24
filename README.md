# FREEVPN

VPN SOFTWARE FOR PERSONAL USE

FREEVPN is a cross-platform light GUI-VPN software which makes it easy for users to install and use personally.

# FEATURES

- Sign In with JWT authentication using SSL
- Packet Filtering including https packets using Hashing and B-Tree Search
- Software NAT with Mayaqua of SoftetherVPN (Implemented, but is not using for now)
- Encrypted Connection between VPN client and VPN Server.

# Compilation and Build

- Client

FREEVPN requires the [Ultimate++](https://www.ultimatepp.org/) to compile and function.
Ultimate++ supports all platforms, but currently FRREVPN client has been tested only on Windows and Mac OS X.

- Server

For windows, Microsoft Visul Studio 2017 is required for build.
For Linux, CMake and g++ library is required.

- Authentication Server

FREEVPN uses JWT token for user verification when signing in.
Sign up is not implemented yet.
This functionality is now on testing.

# Execution

- Windows Client
  Install Windows Tap Driver using OpenVpn for Windows Client.
  After that, just run executable file on Client. That's it.
  No need to configure for running.
- Mac OS X Client
  No extra configuration.
  Just run the executable binary file.
- Server(Both Windows and Linux)
  No extra configuration.
  Just run the executable binary file.

# references

- [N2N](https://github.com/ntop/n2n)
- [SoftetherVPN](https://github.com/SoftEtherVPN/SoftEtherVPN)
- [Jansson](https://github.com/akheron/jansson)
- [libjwt](https://github.com/benmcollins/libjwt)
- [curve25519-donna](https://github.com/agl/curve25519-donna)
