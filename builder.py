import argparse
import json
import shutil
import subprocess
import tempfile

from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

WEBPACK_CONFIG = """\
const path = require('path');
module.exports = {
  entry: './client.js',
  output: { filename: 'client.js', path: path.resolve(__dirname, 'dist'), pathinfo: false },
  target: 'node',
  mode: 'production',
  devtool: false,
};
"""

def add_arguments(parser):
    builder = parser.add_argument_group("Builder options")
    builder.add_argument("--name", default="client.js",
                     help="Name of the output.")
    builder.add_argument("--electron", action="store_true",
                     help="Build for Electron (uses fetch and native WebSocket for proxy awareness).")
    builder.add_argument("--no-compile", action="store_true",
                     help="Skip webpack bundling and output raw source.")
    builder.add_argument("--no-print", action="store_true",
                     help="Strip all console output from the generated client.")

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

    behavior = parser.add_argument_group("Behavior")
    behavior.add_argument("--exit-on-close", action="store_true", default=False,
                          help="Call process.exit() when the client stops instead of returning.")


def _webpack_bundle(source_path):
    tmp = Path(tempfile.mkdtemp())
    try:
        shutil.copy2(source_path, tmp / "client.js")

        pkg = {
            "private": True,
            "dependencies": {"ws": "^8.0.0"},
            "devDependencies": {"webpack": "^5.0.0", "webpack-cli": "^5.0.0"},
        }
        (tmp / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
        (tmp / "webpack.config.js").write_text(WEBPACK_CONFIG, encoding="utf-8")

        print("[*] Installing dependencies...")
        subprocess.run(
            ["npm", "install", "--no-audit", "--no-fund"],
            cwd=tmp, check=True, capture_output=True,
        )

        print("[*] Bundling with webpack...")
        result = subprocess.run(
            ["npx", "webpack-cli", "--config", "webpack.config.js"],
            cwd=tmp, capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"[!] Webpack failed:\n{result.stderr}")
            return False

        bundle = tmp / "dist" / "client.js"
        if not bundle.is_file():
            print("[!] Webpack did not produce output")
            return False

        shutil.copy2(bundle, source_path)
        return True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


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

    template = env.get_template("messenger-client.js")
    rendered = template.render(**vars(args))

    out_path = Path(args.name)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")

    compiled = False
    if not args.no_compile and not args.electron:
        node = shutil.which("node")
        npm = shutil.which("npm")
        if not node or not npm:
            from builder.its import install_cmd
            print("[!] Node.js/npm not found, run the following to install:")
            print(f"    {install_cmd('node')}")
        else:
            compiled = _webpack_bundle(out_path)

    if compiled:
        print(f"[+] Bundled Node.js client to '{out_path}'")
    else:
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage=argparse.SUPPRESS)
    add_arguments(parser)
    parsed_args = parser.parse_args()
    build(parsed_args)
