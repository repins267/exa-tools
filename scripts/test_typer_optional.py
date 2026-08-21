"""Test @click.option nargs='?' with Typer via kwargs."""
import sys
import click
import typer
from typing import Optional, Annotated

# Approach: @click.option with nargs='?' and receive via **kwargs
app = typer.Typer()

@app.command()
@click.option("--output-pdf", "output_pdf", default=None, nargs='?', const='', help="PDF output path (auto if no arg)")
def test(**kwargs):
    output_pdf = kwargs.get("output_pdf")
    sys.stderr.write(f"output_pdf={output_pdf!r}\n")

from typer.testing import CliRunner
runner = CliRunner()

for args in [["--output-pdf"], ["--output-pdf", "myfile.pdf"], []]:
    r = runner.invoke(app, args)
    sys.stderr.write(f"args={args!r}: exit={r.exit_code}\n")
    if r.exception:
        import traceback
        traceback.print_exception(type(r.exception), r.exception, r.exception.__traceback__, file=sys.stderr)
