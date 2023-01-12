#!/usr/bin/env python3

"""results_to_html - Convert JSON results to a simple HTML file

Copyright (C) 2023 Peter Mosmans [Go Forward]
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import ipaddress
import json
import sys
from jinja2 import Environment, FileSystemLoader
import typer

app = typer.Typer()


def sorted_hosts(unsorted):
    """Return a list of hosts sorted on IP address (when possible)."""
    try:
        results = map(str, sorted([ipaddress.ip_address(x) for x in unsorted]))
    except:
        results = sorted(unsorted)
    return results


@app.command()
def convert(filename: str, templates="/usr/share/templates"):
    """Convert JSON results to HTML."""
    try:
        with open(filename, encoding="utf-8") as handle:
            results = json.load(handle)
        hosts = sorted_hosts(results["results"])
        environment = Environment(loader=FileSystemLoader(templates))
        template = environment.get_template("results.html")
        print(template.render(results=results, hosts=hosts))
    except Exception as e:
        print(f"Something went wrong: {e}", file=sys.stderr)
        sys.exit(-1)


if __name__ == "__main__":
    app()
