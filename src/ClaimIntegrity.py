# -*- coding: utf-8 -*-
# Autopsy Jython 2.7 data-source ingest module skeleton
# Claim and Evidence Integrity Assessment
#
# IMPORTANT:
# - This is Jython 2.7 code executed inside Autopsy, not CPython 3.
# - Run standard ingest modules first, then run this module in a second pass.
# - The first version queries selected existing Blackboard artifacts and creates
#   a custom result artifact. Artifact availability depends on the Autopsy version
#   and which standard ingest modules were run.

import inspect
from datetime import datetime
from java.lang import Class
from java.util.logging import Level

from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.ingest import (
    DataSourceIngestModule,
    IngestModuleFactoryAdapter,
    IngestMessage,
    IngestServices,
    ModuleDataEvent
)
from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute


MODULE_NAME = "Claim and Evidence Integrity Assessment"
MODULE_VERSION = "0.1.0"


class ClaimIntegrityFactory(IngestModuleFactoryAdapter):
    """Factory discovered by Autopsy when the module folder is loaded."""

    moduleName = MODULE_NAME

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return ("Evaluates a structured no-user-activity claim against existing "
                "Autopsy artifacts and reports possible evidence-integrity concerns.")

    def getModuleVersionNumber(self):
        return MODULE_VERSION

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ClaimIntegrityDataSourceIngestModule()


class ClaimIntegrityDataSourceIngestModule(DataSourceIngestModule):
    """Runs once for a data source and correlates already-extracted artifacts."""

    _logger = Logger.getLogger(MODULE_NAME)

    def __init__(self):
        self.context = None

    def log(self, level, message):
        self._logger.logp(level, self.__class__.__name__,
                          inspect.stack()[1][3], message)

    def startUp(self, context):
        self.context = context
        self.log(Level.INFO, "Claim Integrity module started")

    def process(self, dataSource, progressBar):
        progressBar.switchToIndeterminate()

        try:
            if self.context is not None and self.context.isJobCancelled():
                return DataSourceIngestModule.ProcessResult.OK

            claim = self._load_claim()
            events = self._collect_existing_artifacts(dataSource, claim)
            assessment = self._assess_claim(claim, events)
            self._assess_integrity(assessment, events)
            self._publish_result(dataSource, assessment)

            text = ("Claim {0}: {1}; contradiction score={2}; "
                    "integrity score={3}; matching events={4}").format(
                        claim["claim_id"], assessment["status"],
                        assessment["contradiction_score"],
                        assessment["integrity_score"], len(assessment["events"]))

            IngestServices.getInstance().postMessage(
                IngestMessage.createDataMessage(MODULE_NAME,
                                                "Claim assessment completed",
                                                text))
            self.log(Level.INFO, text)
            return DataSourceIngestModule.ProcessResult.OK

        except Exception as ex:
            self.log(Level.SEVERE, "Module failed: {0}".format(str(ex)))
            return DataSourceIngestModule.ProcessResult.ERROR

    # ------------------------------------------------------------------
    # Claim input
    # ------------------------------------------------------------------
    def _load_claim(self):
        """
        MVP claim. Replace this method later with a settings panel or JSON file.
        Epoch values are UTC seconds.
        Example local period: 2026-09-20 22:00 to 23:00 at UTC+05:30.
        """
        return {
    "claim_id": "CLM-EXAMPLE-001",
    "claim_type": "NO_USER_ACTIVITY",
    "username": "ExampleUser",
    "start_epoch": 1700000000,
    "end_epoch": 1700003600
}

    # ------------------------------------------------------------------
    # Artifact collection
    # ------------------------------------------------------------------
    def _collect_existing_artifacts(self, dataSource, claim):
        """
        Queries artifacts already produced by standard Autopsy ingest modules.

        Start with web history and downloads because they are commonly generated
        by Recent Activity. Login/file/USN mappings vary by parser and version,
        so add those only after inspecting the actual artifacts in your test case.
        """
        case = Case.getCurrentCase()
        sk_case = case.getSleuthkitCase()
        events = []

        artifact_types = [
            (BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_HISTORY,
             "BROWSER"),
            (BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_DOWNLOAD,
             "BROWSER")
        ]

        for artifact_type, event_type in artifact_types:
            if self.context is not None and self.context.isJobCancelled():
                break

            artifacts = sk_case.getBlackboardArtifacts(artifact_type)
            for artifact in artifacts:
                # Keep only artifacts owned by this data source where possible.
                try:
                    source = artifact.getParent()
                    if source is not None and source.getDataSource() is not None:
                        if source.getDataSource().getId() != dataSource.getId():
                            continue
                except Exception:
                    pass

                timestamp = self._first_timestamp(artifact)
                if timestamp is None:
                    continue

                if timestamp < claim["start_epoch"] or timestamp > claim["end_epoch"]:
                    continue

                event = {
                    "type": event_type,
                    "timestamp": timestamp,
                    "artifact_id": artifact.getArtifactID(),
                    "description": artifact.getDisplayName(),
                    "username": self._string_attribute(
                        artifact,
                        BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME)
                }
                events.append(event)

        return events

    def _first_timestamp(self, artifact):
        """Returns the first usable common timestamp attribute in UTC epoch seconds."""
        candidates = [
            BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED,
            BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED,
            BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_MODIFIED,
            BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME
        ]
        for attr_type in candidates:
            try:
                attr = artifact.getAttribute(attr_type)
                if attr is not None:
                    value = attr.getValueLong()
                    if value > 0:
                        return value
            except Exception:
                pass
        return None

    def _string_attribute(self, artifact, attr_type):
        try:
            attr = artifact.getAttribute(attr_type)
            if attr is not None:
                return attr.getValueString()
        except Exception:
            pass
        return ""

    # ------------------------------------------------------------------
    # Deterministic assessment rules
    # ------------------------------------------------------------------
    def _assess_claim(self, claim, events):
        categories = set([event["type"] for event in events])
        score = 0

        if "LOGIN" in categories:
            score += 30
        if "BROWSER" in categories:
            score += 25
        if "FILE_ACTIVITY" in categories:
            score += 20
        if len(categories) >= 2:
            score += 15
        if len(events) > 0:
            score += 10

        score = min(score, 100)
        status = "POSSIBLY_CONTRADICTED" if events else "NOT_CONTRADICTED"
        rules = []
        if events:
            rules.append("CA-01: Relevant activity inside claimed inactivity window")
        if len(categories) >= 2:
            rules.append("CA-02: Multiple independent activity categories")

        return {
            "claim": claim,
            "status": status,
            "contradiction_score": score,
            "integrity_score": 0,
            "events": events,
            "rules": rules
        }

    def _assess_integrity(self, assessment, events):
        """
        Initial integrity check. Extend later with SI/FN/USN comparisons.
        This skeleton only looks for an event explicitly mapped as LOG_CLEARING.
        """
        score = 0
        for event in events:
            if event["type"] == "LOG_CLEARING":
                score += 20
                assessment["rules"].append(
                    "EI-04: Windows event-log clearing indicator")
        assessment["integrity_score"] = min(score, 100)

    # ------------------------------------------------------------------
    # Blackboard output
    # ------------------------------------------------------------------
    def _publish_result(self, dataSource, assessment):
        case = Case.getCurrentCase()
        sk_case = case.getSleuthkitCase()
        blackboard = sk_case.getBlackboard()

        artifact_type = sk_case.getOrAddBlackboardArtifactType(
            "TSK_CLAIM_ASSESSMENT",
            "Claim Assessment")

        attr_claim_id = sk_case.getOrAddBlackboardAttributeType(
            "TSK_CLAIM_ID",
            BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
            "Claim ID")
        attr_status = sk_case.getOrAddBlackboardAttributeType(
            "TSK_CLAIM_STATUS",
            BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
            "Claim Status")
        attr_contradiction = sk_case.getOrAddBlackboardAttributeType(
            "TSK_CONTRADICTION_SCORE",
            BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER,
            "Contradiction Score")
        attr_integrity = sk_case.getOrAddBlackboardAttributeType(
            "TSK_INTEGRITY_SCORE",
            BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER,
            "Integrity Concern Score")
        attr_rules = sk_case.getOrAddBlackboardAttributeType(
            "TSK_TRIGGERED_RULES",
            BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
            "Triggered Rules")
        attr_sources = sk_case.getOrAddBlackboardAttributeType(
            "TSK_SOURCE_ARTIFACT_IDS",
            BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
            "Source Artifact IDs")

        artifact = dataSource.newDataArtifact(artifact_type.getTypeID())
        source_name = MODULE_NAME
        source_ids = ",".join(
            [str(event["artifact_id"]) for event in assessment["events"]])

        attributes = [
            BlackboardAttribute(attr_claim_id, source_name,
                                assessment["claim"]["claim_id"]),
            BlackboardAttribute(attr_status, source_name,
                                assessment["status"]),
            BlackboardAttribute(attr_contradiction, source_name,
                                assessment["contradiction_score"]),
            BlackboardAttribute(attr_integrity, source_name,
                                assessment["integrity_score"]),
            BlackboardAttribute(attr_rules, source_name,
                                " | ".join(assessment["rules"])),
            BlackboardAttribute(attr_sources, source_name, source_ids)
        ]

        artifact.addAttributes(attributes)
        blackboard.indexArtifact(artifact)
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(MODULE_NAME, artifact_type, None))
