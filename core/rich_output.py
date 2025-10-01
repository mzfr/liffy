"""Rich-based output formatting module"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
import os
import yaml

# Global console instance
console = Console()

# Configuration for output control
_config = {"disable_colors": False, "disable_banner": False}


def load_config():
    """Load configuration from YAML file"""
    config_file = "liffy_config.yaml"
    if os.path.exists(config_file):
        try:
            with open(config_file, "r") as f:
                user_config = yaml.safe_load(f) or {}
                _config.update(user_config)
        except Exception:
            pass  # Use defaults if config file is invalid


def create_default_config():
    """Create default YAML configuration file if it doesn't exist"""
    config_file = "liffy_config.yaml"
    if os.path.exists(config_file):
        return False  # Config already exists

    default_config = {
        "disable_colors": False,
        "disable_banner": False,
        "rate_limit_delay": 0.1,
        "user_agent_rotation": True,
        "max_threads": 5,
        "detection_timeout": 30,
    }

    with open(config_file, "w") as f:
        yaml.dump(default_config, f, default_flow_style=False, indent=2)

    return True  # Config was created


def rich_print(text, style=None, end="\n"):
    """Print text with Rich formatting, respecting color settings"""
    if _config.get("disable_colors", False):
        # Strip any markup and print plain text
        console.print(text, style=None, highlight=False, markup=False, end=end)
    else:
        console.print(text, style=style, end=end)


def print_banner():
    """Print the application banner"""
    if _config.get("disable_banner", False):
        return

    banner_text = """
    ╦  ┬┌─┐┌─┐┬ ┬  ┬  ┬┌─┐┌─┐
    ║  │├┤ ├┤ └┬┘  └┐┌┘┌─┘┌─┘
    ╩═╝┴└  └   ┴    └┘ └─┘└─┘
    """

    if not _config.get("disable_colors", False):
        rich_print(
            Panel(
                Text(banner_text, style="bold green"),
                title="[bold cyan]Liffy v2.0 - LFI Exploitation Tool[/bold cyan]",
                border_style="bright_blue",
            )
        )
    else:
        print("Liffy v2.0 - LFI Exploitation Tool")
        print(banner_text)


# Color mapping for backward compatibility
def colors(text, color_code=None):
    """Backward compatible color function using Rich"""
    if _config.get("disable_colors", False):
        return str(text)

    # Map old color codes to Rich styles
    color_map = {
        91: "red",  # Error/Warning
        92: "green",  # Success
        93: "yellow",  # Info
        94: "blue",  # Debug/Details
        95: "magenta",  # Special
        96: "cyan",  # Highlights
        97: "white",  # Default
    }

    style = color_map.get(color_code, "white")
    return f"[{style}]{text}[/{style}]"


# Rich-specific functions
def print_success(message):
    """Print success message"""
    rich_print(f"[green][+][/green] {message}")


def print_error(message):
    """Print error message"""
    rich_print(f"[red][!][/red] {message}")


def print_info(message):
    """Print info message"""
    rich_print(f"[yellow][~][/yellow] {message}")


def print_debug(message):
    """Print debug message"""
    rich_print(f"[blue][*][/blue] {message}")


def print_warning(message):
    """Print warning message"""
    rich_print(f"[orange1][!][/orange1] {message}")


def print_vulnerable(url):
    """Print vulnerability found message"""
    rich_print(
        Panel(
            f"[bold green]LFI Vulnerability Detected![/bold green]\n[cyan]{url}[/cyan]",
            border_style="green",
            title="[bold]VULNERABLE[/bold]",
        )
    )


def print_technique_header(technique_name):
    """Print technique testing header"""
    rich_print(f"\n[bold cyan]Testing {technique_name}[/bold cyan]")
    rich_print("─" * 50, style="dim")


def print_payload_test(payload, encoding_variants=None):
    """Print payload testing information"""
    if encoding_variants:
        rich_print(
            f"[dim]Testing payload with {len(encoding_variants)} encoding variants[/dim]"
        )
    rich_print(f"[blue]Payload:[/blue] {payload}")


def configure_output(disable_colors=False, disable_banner=False):
    """Configure output settings - CLI args override config file settings"""
    if disable_colors:
        _config["disable_colors"] = True
    if disable_banner:
        _config["disable_banner"] = True
