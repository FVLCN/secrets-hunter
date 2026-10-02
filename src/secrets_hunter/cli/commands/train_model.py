import argparse
import sys

from secrets_hunter.detection.semantics.concept_model import DEFAULT_CONCEPT_SMOOTHING
from secrets_hunter.detection.semantics.concept_model.training import (
    ConceptModelTrainingResult,
    train_model,
)

from ..protocols import SubparserRegistry


NAME = "train-model"


def register(subparsers: SubparserRegistry) -> None:
    parser = subparsers.add_parser(
        NAME,
        help="train the semantic concept model",
        description="Train the semantic concept model from the packaged catalogs.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="output JSON path",
    )
    parser.add_argument(
        "--smoothing",
        type=float,
        default=DEFAULT_CONCEPT_SMOOTHING,
        help=f"classifier smoothing value (default: {DEFAULT_CONCEPT_SMOOTHING})",
    )
    parser.set_defaults(command_handler=run, command_validator=validate)


def validate(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.smoothing <= 0:
        parser.error("--smoothing must be greater than zero")


def _print_summary(summary: ConceptModelTrainingResult) -> None:
    print(f"Concepts: {summary.concept_count}")
    print(f"Training examples: {summary.training_example_count}")
    print(f"Concept label assignments: {summary.label_assignment_count}")
    print(f"Wrote model to {summary.output_path}")
    print(f"Model SHA-256: {summary.model_sha256}")


def run(args: argparse.Namespace) -> int:
    try:
        summary = train_model(output=args.output, smoothing=args.smoothing)
    except (OSError, ValueError) as exc:
        print(f"Could not train semantic concept model: {exc}", file=sys.stderr)
        return 1

    _print_summary(summary)
    return 0
