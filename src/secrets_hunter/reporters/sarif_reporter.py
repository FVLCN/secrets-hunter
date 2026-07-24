import json
import logging

from secrets_hunter import __version__
from secrets_hunter.reporters.finding_view import FindingView
from secrets_hunter.reporters.source_location import (
    source_location_kind,
    source_location_to_dict
)

logger = logging.getLogger(__name__)


class SARIFReporter:
    @staticmethod
    def export(findings: list[FindingView], output_file: str) -> None:
        logger.info(f"Exporting results to {output_file}...")

        results = []
        for finding in findings:
            location = finding.location
            serialized_location = source_location_to_dict(location)
            result = {
                "ruleId": finding.kind.id,
                "message": {
                    "text": (
                        f"{finding.kind.display_name} found in "
                        f"{location.locator}"
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": location.locator
                        },
                        "region": {
                            "startLine": location.line,
                            "snippet": {
                                "text": finding.context
                            }
                        }
                    }
                }],
                "properties": {
                    "title": finding.title,
                    "finding_kind": {
                        "id": finding.kind.id,
                        "display_name": finding.kind.display_name
                    },
                    "match": finding.match,
                    "detection_method": finding.detection_method,
                    "confidence": finding.confidence,
                    "disposition": finding.disposition.value,
                    "context_var": finding.context_var,
                    "location": {
                        "kind": source_location_kind(location),
                        **serialized_location
                    },
                    "severity": finding.severity,
                    "confidence_reasoning": finding.confidence_reasoning,
                    "decision_trace": [
                        activation.to_dict()
                        for activation in finding.decision_trace
                    ],
                }
            }
            results.append(result)

        sarif_output = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "fvlcn_secrets_hunter",
                        "informationUri": "https://github.com/FVLCN/secrets-hunter",
                        "version": __version__
                    }
                },
                "results": results
            }]
        }

        with open(output_file, 'w') as f:
            json.dump(sarif_output, f, indent=4)

        logger.info(f"Results exported to {output_file}")
