"""Containers subcommand — manage nightwing pentest containers (Kali/Parrot)."""

from __future__ import annotations


def add_parser(subparsers):
    parser = subparsers.add_parser("containers", help="Manage nightwing-managed pentest containers")
    parser.add_argument(
        "action",
        nargs="?",
        default="cleanup",
        choices=["cleanup", "status"],
        help="Action: cleanup (stop+remove) or status (default: cleanup)",
    )
    return parser


def handle(cli, args):
    """Run container management actions."""
    from nightwing.agent.tools.ops.pentest_container import _DISTRO_MANAGERS, cleanup_all

    if args.action == "cleanup":
        results = cleanup_all()
        for distro, status in results.items():
            color = "green" if status == "removed" else "dim"
            cli.console.print(f"[{color}]{distro}: {status}[/{color}]")
        return

    # status
    for name, manager in _DISTRO_MANAGERS.items():
        try:
            client = manager._get_client()
            container = client.containers.get(manager._cfg.container_name)
            cli.console.print(f"[green]{name}: {container.status}[/green] ({container.short_id})")
        except Exception:
            cli.console.print(f"[dim]{name}: not found[/dim]")
