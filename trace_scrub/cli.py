import argparse
import sys

from .core import Invalid, encode, export, verify


def main(argv=None):
    parser = argparse.ArgumentParser(description="Export structured traces under an explicit field policy.")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("export")
    create.add_argument("source")
    create.add_argument("--policy", required=True)
    create.add_argument("--out", required=True)
    check = commands.add_parser("verify")
    check.add_argument("bundle")
    check.add_argument("--source", help="Also reproduce the transformation from the original input")
    check.add_argument("--policy", help="Require the embedded policy to match a separately approved policy")
    args = parser.parse_args(argv)
    try:
        result = export(args.source, args.policy, args.out) if args.command == "export" else verify(args.bundle, args.source, args.policy)
        print(encode(result).decode(), end="")
        return 0
    except Invalid as error:
        print(encode({"error": str(error)}).decode(), end="", file=sys.stderr)
        return 2
    except OSError:
        # Paths and OS exception details can themselves contain private identifiers.
        print('{"error":"filesystem operation failed; check permissions and use a new output directory"}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
