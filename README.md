# Node JS Messenger Client

## Overview

The Client is written in Node JS with the intention of being ran directly with node or dropped into an electron app. 

## Primary Capabilities

| Capability                 | Support Status                                         |
|----------------------------|--------------------------------------------------------|
| Transports                 | WebSockets                                             |
| Encryption                 | AES-256-CBC with random IV prefix.                     |
| Reconnection procedure     | Defaults to five (5) attempts over sixty (60) seconds. |
| SOCKS5 TCP                 | Supported                                              |
| SOCKS5 UDP                 | Not Supported                                          |

## Quick Start

```
operator~# ./builder.py --encryption-key test
Wrote Node JS client to 'client.js'

C:\Users\operator> npm install ws
added 1 package in 245ms

C:\Users\operator> node client.js
[+] Connected to http://localhost:8080/socketio/?EIO=4&transport=websocket
```

## Usage

To build the client, execute `builder.py` or `messenger-builder` from the [Messenger Repository](https://github.com/skylerknecht/messenger).

Both scripts accept the same options and will generate a Python Messenger Client. If provided options, the builder scripts
will hard-code the options into the script. Once built, the operator can specify command-line arguments that will override
the hardcoded options. Those options and their definitions are shown below. 

## Client Options

| Option                                        | Flag                      | Default Value           |
|-----------------------------------------------|---------------------------|-------------------------|
| [Server URL](#server-url)                     | `--server-url`            | ws://localhost:8080     |
| [Encryption Key](#encryption-key)             | `--encryption-key`        | None                    |
| [User Agent](#user-agent)                     | `--user-agent`            | [Specified Here](https://github.com/skylerknecht/messenger-client-nodejs/blob/f3d0202723d6347590332577a5c64a198fcdf209/builder.py#L6)      | 
| [Remote Port Forwards](#remote-port-forwards) | `--remote-port-forwards`  | None                    |
| [Retry Duration](#retry-duration)             | `--retry-duration`        | One Minute              |
| [Retry Attempts](#retry-attempts)             | `--retry-attempts`        | Five                    |
| [Name](#name)                                 | `--name`                  | client.py               |

### Server URL

Once the Messenger Server is running, the operator will be provided a server URL that can be set with `--server-url`. 

```
builder.py --server-url http://localhost:8080
```

The client will attempt to establish a connection to the server based on the protocol specified in the server URL. For HTTP, leave the protocol as 
`http://`, for websockets use `ws://`. Given that the server is listening with SSL encryption, provide the SSL 
alternative to each protocol. 

#### Encryption Key

Messenger Server will also provide an encryption key upon startup that can be hardcoded.

```
builder.py --encryption-key SuP3rs_crEtk3y
```

Since the server expects encryption, the default will likely cause issues; therefore, the client outputs an 
error.

```
[!] No encryption key provided, please specify one with --encryption-key.
```

#### User Agent

For HTTP-based protocols, the operator can control the user-agent header. 

```
builder.py --user-agent "Test User Agent"
```

#### Remote Port Forwards

Messenger expects clients to attempt to set up remote port forwards on the client side. The operator can specify multiple port forwards 
with the schema `LISTENING-HOST:LISTENING-PORT:DESTINATION-HOST:DESTINATION-PORT`. 

```
builder.py --remote-port-forwards localhost:8080:remotehost:8080
```

This will forward all local connections on 8080 to a remote host on 8080. Given that the operator has not permitted the connection server-side, 
they will see the following message.

```
[!] Messenger `test` has no Remote Port Forwarder configured for remotehost:8080, denying forward!
```

#### Retry Duration

Clients will disconnect for various reasons. Given that the client does not completely exit, it will attempt to reconnect. Operators can 
control how long the client will attempt to reconnect by specifying a retry duration. This value is expected to be in seconds. For example,
if the retry duration is set to 120, then the client will attempt to reconnect for two minutes. 

```
builder.py --retry-duration 100
```

To disable reconnection attempts, set the retry attempts option to 0. 

#### Retry Attempts

In combination with the retry duration, retry attempts determine the minimum time the client waits between reconnection attempts. 

```
builder.py --retry-attempts 100
```

#### Name

The build process outputs an artifact, and operators can control its name.

```
builder.py --name output.py
```
