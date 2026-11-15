"""Containers subcommand — remove nightwing-managed pentest containers."""


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "containers", help="Stop and remove nightwing pentest containers (Kali/Parrot)"
    )
    return parser


def handle(cli, args):
    """Stop and remove all nightwing pentest containers."""
    from nightwing.agent.tools.ops.pentest_container import cleanup_all

    for distro, status in cleanup_all().items():
        color = "green" if status == "removed" else "dim"
        cli.console.print(f"[{color}]{distro}: {status}[/{color}]")
