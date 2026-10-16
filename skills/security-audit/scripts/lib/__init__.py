"""What every audit step shares: the workspace, the config, YAML/TSV files and templates."""
from pathlib import Path

import pandas as pd
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

A = Path(".security-audit")  # what the reader keeps: the .md files (reports, coverage, recon, rankings)
W = A / "work"  # what agents and steps pass to each other; audit.py clean removes it
LIB = Path(__file__).parent
CONFIG = yaml.safe_load((LIB / "config.yaml").read_text())

jinja = Environment(loader=FileSystemLoader(LIB / "templates"), trim_blocks=True, lstrip_blocks=True,
                    keep_trailing_newline=True, undefined=StrictUndefined)
jinja.globals.update(A=A, W=W, severities=CONFIG["severities"])
jinja.filters.update(
    rows=lambda df, limit=None: df.head(limit).itertuples(),
    where=lambda df, **equal: df.loc[(df[list(equal)] == list(equal.values())).all(axis=1)],
    cell=lambda text: str(text).replace("|", "\\|").replace("\n", " "))


def render(template, path, **context):
    path.write_text(jinja.get_template(template).render(**context))


def say(message, **context):
    """Print one of the console.j2 macros."""
    print(getattr(jinja.get_template("console.j2").make_module(), message)(**context), end="")


def load(path):
    """A YAML file's contents; None when it is missing or not valid YAML."""
    try:
        return yaml.safe_load(Path(path).read_text())
    except (OSError, yaml.YAMLError):
        return None


class Dumper(yaml.SafeDumper):
    """Writes multi-line strings (code excerpts) as readable | blocks."""


Dumper.add_representer(str, lambda d, s: d.represent_scalar("tag:yaml.org,2002:str", s, style="|" if "\n" in s else None))


def dump(data, path):
    Path(path).write_text(yaml.dump(data, Dumper=Dumper, sort_keys=False, allow_unicode=True, width=120))


def read_tsv(name, columns):
    path = W / name
    if not path.exists() or not path.stat().st_size:
        return pd.DataFrame(columns=columns)
    return pd.read_csv(path, sep="\t", names=columns, dtype=str, keep_default_na=False).fillna("")


def write_tsv(df, name):
    df.to_csv(W / name, sep="\t", index=False, header=False)
