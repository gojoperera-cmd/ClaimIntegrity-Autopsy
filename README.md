Explainable Claim Assessment and Evidence Integrity Module for Autopsy
Project Overview
This repository contains a proof-of-concept Python/Jython data-source ingest module for Autopsy. The module evaluates a structured Windows user-inactivity claim against selected forensic artifacts extracted into an Autopsy case.

Research Problem
Autopsy extracts and presents forensic artifacts, but investigators normally compare these artifacts with case-related claims manually. This project introduces a lightweight, deterministic, and explainable claim-assessment layer within the existing Autopsy workflow.

Current Features
Python/Jython data-source ingest module
Support for the NO_USER_ACTIVITY claim type
Time-window filtering
Browser-history artifact assessment
Browser-download artifact assessment
Deterministic indicator-strength scoring
Triggered-rule reporting
Source artifact traceability
Framework for evidence-integrity indicators
Limitations
Proof-of-concept implementation
The claim is currently configured within the module
Only selected artifact categories are supported
No graphical claim-entry panel is currently included
The module does not prove deception or intentional evidence manipulation
Installation
Install Autopsy 4.23.1.
Open Tools > Python Plugins.
Copy the module folder into the Python plugin directory.
Restart Autopsy.
Run standard ingest modules against the evidence source.
Run Claim and Evidence Integrity Assessment as a second ingest pass.
Evidence Notice
Forensic VMDK evidence files are not included in this repository due to privacy, evidential, and storage constraints. The repository contains only source code, documentation, synthetic examples, and selected screenshots.

Author
Nirmal Peiris