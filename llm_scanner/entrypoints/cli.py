from __future__ import annotations

from pathlib import Path
from typing import Annotated, Final

import typer

from clients.neo4j import Neo4jClient, Neo4jConfig
from loaders.graph_loader import GraphLoader
from loaders.yaml_loader import YamlLoader
from models.edge import Edge
from models.node import Node
from pipeline import GeneralPipeline
from .base import ParserType, parse_file_to_cpg

app = typer.Typer(
    name="llm-scanner",
    add_completion=False,
    no_args_is_help=True,
    help="Unified CLI for generating and loading code property graphs.",
)

ROOT_DIR: Final[Path] = Path(__file__).resolve().parents[2]
DEFAULT_TESTS_DIR: Final[Path] = ROOT_DIR / "tests"
DEFAULT_SAMPLE_FILE: Final[Path] = DEFAULT_TESTS_DIR / "sample.py"
DEFAULT_OUTPUT_FILE: Final[Path] = ROOT_DIR / "output.yaml"


def _build_client(
    uri: str, user: str, password: str, /, *, cfg: Neo4jConfig | None = None
) -> Neo4jClient:
    """Create a Neo4j client with provided or environment-backed config.

    Args:
        uri: Bolt URI for the Neo4j instance.
        user: Username for authentication.
        password: Password for authentication.
        cfg: Optional pre-built configuration to reuse.

    Returns:
        Neo4jClient: Configured Neo4j client ready for queries.
    """
    if cfg is None:
        cfg = Neo4jConfig(uri=uri, user=user, password=password)
    return Neo4jClient(cfg)


@app.command("load-sample")
def load_sample(
    sample_path: Annotated[
        Path,
        typer.Argument(
            help="Path to the Python file to load into Neo4j.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ] = DEFAULT_SAMPLE_FILE,
    parser_type: Annotated[
        ParserType,
        typer.Option(
            "--parser",
            case_sensitive=False,
            help="Parser implementation to use (ast or tree_sitter).",
        ),
    ] = ParserType.AST,
    ignore_magic: Annotated[
        bool,
        typer.Option(
            "--ignore-magic/--include-magic",
            help="Whether to skip magic dunder methods while parsing.",
        ),
    ] = True,
    neo4j_uri: Annotated[
        str,
        typer.Option(
            "--neo4j-uri",
            help="Neo4j bolt URI.",
            envvar="NEO4J_URI",
            show_default=True,
        ),
    ] = Neo4jConfig().uri,
    neo4j_user: Annotated[
        str,
        typer.Option(
            "--neo4j-user",
            help="Neo4j username.",
            envvar="NEO4J_USER",
            show_default=True,
        ),
    ] = Neo4jConfig().user,
    neo4j_password: Annotated[
        str,
        typer.Option(
            "--neo4j-password",
            help="Neo4j password.",
            envvar="NEO4J_PASSWORD",
            show_default=False,
        ),
    ] = Neo4jConfig().password,
) -> None:
    """Parse a single file and load its CPG into Neo4j.

    Args:
        sample_path: Path to the Python file to parse.
        parser_type: Parser implementation to use.
        ignore_magic: Whether to skip magic dunder methods.
        neo4j_uri: Bolt URI of the target Neo4j instance.
        neo4j_user: Username for the Neo4j instance.
        neo4j_password: Password for the Neo4j instance.
    """
    nodes: dict[str, Node]
    edges: list[Edge]
    nodes, edges = parse_file_to_cpg(
        sample_path, ignore_magic=ignore_magic, parser_type=parser_type
    )

    client = _build_client(neo4j_uri, neo4j_user, neo4j_password)
    try:
        loader = GraphLoader(client)
        loader.load(nodes, edges)
    finally:
        client.close()

    typer.secho(
        f"Loaded {len(nodes)} nodes and {len(edges)} edges from {sample_path}",
        fg=typer.colors.GREEN,
    )


@app.command("load-all-samples")
def load_all_samples(
    tests_dir: Annotated[
        Path,
        typer.Argument(
            help="Directory containing sample .py files.",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            resolve_path=True,
        ),
    ] = DEFAULT_TESTS_DIR,
    output_path: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Path to write the aggregated YAML graph.",
            file_okay=True,
            dir_okay=False,
            writable=True,
            resolve_path=True,
        ),
    ] = DEFAULT_OUTPUT_FILE,
    parser_type: Annotated[
        ParserType,
        typer.Option(
            "--parser",
            case_sensitive=False,
            help="Parser implementation to use (ast or tree_sitter).",
        ),
    ] = ParserType.AST,
    ignore_magic: Annotated[
        bool,
        typer.Option(
            "--ignore-magic/--include-magic",
            help="Whether to skip magic dunder methods while parsing.",
        ),
    ] = True,
) -> None:
    """Parse all test samples and persist their CPG as YAML.

    Args:
        tests_dir: Directory containing Python files to parse.
        output_path: Destination path for the generated YAML graph.
        parser_type: Parser implementation to use.
        ignore_magic: Whether to skip magic dunder methods.
    """
    files: list[Path] = sorted(
        p for p in tests_dir.glob("*.py") if p.name != "__init__.py"
    )
    if not files:
        typer.secho("No Python files found to process.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    total_nodes: int = 0
    total_edges: int = 0
    result_nodes: dict[str, Node] = {}
    result_edges: list[Edge] = []

    for path in files:
        nodes: dict[str, Node]
        edges: list[Edge]
        nodes, edges = parse_file_to_cpg(
            path, ignore_magic=ignore_magic, parser_type=parser_type
        )
        result_edges.extend(edges)
        result_nodes.update(nodes)
        total_nodes += len(nodes)
        total_edges += len(edges)

    loader = YamlLoader(output_path)
    loader.load(result_nodes, result_edges)

    typer.secho(
        f"Loaded {total_nodes} nodes and {total_edges} edges from {len(files)} files "
        f"into {output_path}",
        fg=typer.colors.GREEN,
    )


@app.command("run-pipeline")
def run_pipeline(
    src: Annotated[
        Path,
        typer.Argument(
            help="Path to the project root to scan.",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            resolve_path=True,
        ),
    ],
) -> None:
    """Run the full analysis pipeline against a project directory.

    Args:
        src: Project root to scan and load into Neo4j.
    """
    pipeline = GeneralPipeline(src=src)
    pipeline.run()
    typer.secho(f"Pipeline completed for {src}", fg=typer.colors.GREEN)


def main() -> None:
    """Entry point for executing the Typer application."""
    app()


if __name__ == "__main__":
    main()
