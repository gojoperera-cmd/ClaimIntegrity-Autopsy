# Claim Integrity Python Ingest Module

This is an Autopsy **Jython 2.7** data-source ingest module, not a normal Python 3 program.

## Install

1. Create a folder named `ClaimIntegrity`.
2. Put `ClaimIntegrity.py` inside it.
3. In Autopsy, open **Tools > Python Plugins** to locate the Python module library directory.
4. Copy the entire `ClaimIntegrity` folder into that directory.
5. Restart Autopsy.
6. Run standard ingest modules first, especially Recent Activity.
7. Rerun ingest and select only **Claim and Evidence Integrity Assessment**.

## First test

Edit `_load_claim()` so its UTC epoch start and end times cover known browser activity in your test image. The module initially queries web-history and web-download artifacts. It then publishes a custom `Claim Assessment` artifact.

## Important

Autopsy APIs can differ by release. If `newDataArtifact()` or an artifact-type call differs in your installed version, use the sample Python modules shipped with that exact Autopsy release as the final API reference.

## Next steps

1. Add a settings panel or JSON claim loader.
2. Inspect your case database artifacts and map login events.
3. Add relevant file activity.
4. Map EVTX log-clearing indicators.
5. Add SI/FN/USN timestamp consistency checks for files linked to the claim period.
