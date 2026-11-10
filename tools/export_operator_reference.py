"""Export source-aligned operator indexes without importing application modules.

These indexes supplement the procedural manual. They enumerate declared code,
not verified runtime coverage, enabled preferences or successful test results.
"""
from __future__ import annotations

import argparse
import ast
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "reference"


def _text(value):
    return str(value).replace("|", "\\|").replace("\r", "").replace("\n", " ").strip()


def _literal(node, default=None):
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return default


def _expression(node):
    return ast.unparse(node) if node is not None else ""


def _link(path, line):
    relative = path.relative_to(ROOT).as_posix()
    return f"[{relative}:{line}](../../{relative}#L{line})"


def _read(path):
    source = path.read_text(encoding="utf-8-sig")
    return source, ast.parse(source, filename=str(path))


def _assignments(node):
    result = {}
    for statement in node.body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    result[target.id] = statement.value
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            result[statement.target.id] = statement.value
    return result


def _setting_names(tree):
    names = set()
    owners = {"self.config", "config", "self.cfg", "cfg", "self._config"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and _expression(node.value) in owners:
            names.add(node.attr)
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
              and node.func.id in {"getattr", "setattr"} and len(node.args) >= 2
              and _expression(node.args[0]) in owners):
            name = _literal(node.args[1])
            if isinstance(name, str):
                names.add(name)
    return names


def _modules():
    rows = []
    _, config_tree = _read(ROOT / "src/angerona/core/config.py")
    config = next(node for node in config_tree.body if isinstance(node, ast.ClassDef) and node.name == "Config")
    settings_schema = set(_assignments(config))
    for path in sorted((ROOT / "src/angerona/modules").glob("*.py")):
        _, tree = _read(path)
        for node in tree.body:
            if not isinstance(node, ast.ClassDef) or not any(_expression(base) == "BaseModule" for base in node.bases):
                continue
            attributes = _assignments(node)
            name = _literal(attributes.get("name"), node.name)
            description = _literal(attributes.get("description"), ast.get_docstring(node) or ast.get_docstring(tree) or "See the source contract.")
            category = _literal(attributes.get("category"), "Undeclared")
            methods = {item.name: item for item in node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))}
            check = methods.get("self_test")
            rows.append((str(name), description, category, path, node.lineno,
                         sorted(_setting_names(node) & settings_schema), check))
    rows.sort(key=lambda row: row[0].casefold())
    lines = ["# Module reference", "", "This source index lists every built-in `BaseModule` declaration. "
        "A declaration, self-test method or capability contract does not establish live collection, "
        "detection or containment. Runtime coverage depends on platform, permissions, policy and fresh evidence.",
        "", "Open a module's inspector for its current lifecycle, configured selection, assurance, dependencies "
        "and individual diagnostic results. A healthy worker can remain idle when its separate response policy is off.",
        "", f"Declared modules: **{len(rows)}**.", ""]
    for name, description, category, path, line, settings, check in rows:
        lines += [f"## {_text(name)}", "", _text(description), "",
                  f"Category: {_text(category)}. Source: {_link(path, line)}.", ""]
        if settings:
            lines += ["Referenced settings: " + ", ".join(f"`{_text(setting)}`" for setting in settings) + ".", ""]
        if check is not None:
            explanation = ast.get_docstring(check) or "This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions."
            lines += [f"Individual test: {_link(path, check.lineno)}. {_text(explanation)}", ""]
        else:
            lines += ["Individual test: inherited diagnostic; inspect Self-Test coverage details for supported sample checks and gaps.", ""]
    return "\n".join(lines).rstrip() + "\n"


def _settings():
    path = ROOT / "src/angerona/core/config.py"
    source, tree = _read(path)
    config = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Config")
    fields = [node for node in config.body if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)]
    lines = ["# Configuration reference", "", "This index enumerates the stored Config schema and its code defaults. "
        "It never opens a user's settings or secret store. Defaults are not current saved values; platform validation "
        "and separate policy gates may change effective behavior.", "", "Use Settings or Full Setup for supported edits. "
        "Credentials belong in their protected stores. Editing a sandbox copy does not activate it or bypass privileged consent.",
        "", f"Declared fields: **{len(fields)}**.", "", "| Setting | Type | Code default | Source note |",
        "| --- | --- | --- | --- |"]
    source_lines = source.splitlines()
    for node in fields:
        default = _expression(node.value)
        note = source_lines[node.lineno - 1].partition("#")[2].strip()
        lines.append(f"| [`{node.target.id}`](../../src/angerona/core/config.py#L{node.lineno}) | "
                     f"`{_text(_expression(node.annotation))}` | `{_text(default)}` | {_text(note)} |")
    return "\n".join(lines) + "\n"


class _Controls(ast.NodeVisitor):
    TYPES = {"QPushButton", "QToolButton", "QAction", "QCheckBox", "QRadioButton", "HeaderActionButton"}

    def __init__(self):
        self.scope = []
        self.rows = []
        self.handlers = {}
        self.variables = {}

    def visit_ClassDef(self, node):
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node):
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Call):
            self.variables[id(node.value)] = ", ".join(_expression(target) for target in node.targets)
        self.generic_visit(node)

    def visit_Call(self, node):
        scope = ".".join(self.scope)
        if (isinstance(node.func, ast.Attribute) and node.func.attr == "connect" and node.args
                and isinstance(node.func.value, ast.Attribute)):
            signal = node.func.value
            if signal.attr in {"clicked", "triggered", "toggled", "pressed", "activated"}:
                self.handlers.setdefault((scope, _expression(signal.value)), []).append(_expression(node.args[0]))
        kind = node.func.id if isinstance(node.func, ast.Name) else ""
        if kind in self.TYPES:
            label = next((value for argument in node.args if isinstance(value := _literal(argument), str)), "")
            variable = self.variables.get(id(node), "inline control")
            self.rows.append((node.lineno, scope, kind, label or "Generated label or icon", variable))
        elif isinstance(node.func, ast.Attribute) and node.func.attr in {"addTab", "addMenu"}:
            kind = "Tab" if node.func.attr == "addTab" else "Menu"
            label = next((value for argument in reversed(node.args) if isinstance(value := _literal(argument), str)), "Generated label")
            self.rows.append((node.lineno, scope, kind, label, _expression(node.func.value)))
        self.generic_visit(node)


def _interfaces():
    lines = ["# Interface control reference", "", "This source index lists declared buttons, actions, checkboxes, "
        "radio buttons, tabs and menus in every GUI source file. Generated labels and context-dependent controls "
        "are identified by their declaration and handler instead of guessing their current contents. Shared builders "
        "can create several runtime controls from one declaration.", "", "The linked source gives the exact handler. "
        "The master manual explains supported workflows and authority; a visible control does not imply that a "
        "provider is configured or that an action is authorized.", ""]
    total = 0
    for path in sorted((ROOT / "src/angerona/gui").glob("*.py")):
        _, tree = _read(path)
        visitor = _Controls()
        visitor.visit(tree)
        if not visitor.rows:
            continue
        total += len(visitor.rows)
        title = re.sub(r"[_-]+", " ", path.stem).strip().capitalize()
        lines += [f"## {title}", "", "| Control | Kind | Owning function | Handler or source |", "| --- | --- | --- | --- |"]
        for line, scope, kind, label, variable in sorted(visitor.rows):
            handlers = visitor.handlers.get((scope, variable), [])
            destination = ", ".join(f"`{_text(handler)}`" for handler in handlers)
            lines.append(f"| {_text(label)} | {kind} | `{_text(scope)}` | {destination + ' · ' if destination else ''}{_link(path, line)} |")
        lines.append("")
    lines.insert(4, f"Declared control sites: **{total}**.\n")
    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Require current deterministic exports")
    args = parser.parse_args()
    outputs = {"modules.md": _modules(), "settings.md": _settings(), "interface-controls.md": _interfaces()}
    stale = []
    if not args.check:
        OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, text in outputs.items():
        destination = OUTPUT / name
        if args.check:
            if not destination.is_file() or destination.read_text(encoding="utf-8") != text:
                stale.append(name)
        else:
            destination.write_text(text, encoding="utf-8", newline="\n")
    if stale:
        parser.exit(1, "Outdated operator reference: " + ", ".join(stale) + "\n")
    print("PASS: deterministic module, configuration and interface source indexes" + (" verified" if args.check else " exported"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
