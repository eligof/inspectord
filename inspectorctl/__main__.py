"""inspectorctl entry point."""

from __future__ import annotations

from inspectorctl.cli.app import app


def main() -> None:
    app()


if __name__ == "__main__":
    main()
