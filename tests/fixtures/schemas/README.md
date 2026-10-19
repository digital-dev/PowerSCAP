# Schemas for validating PowerSCAP's output

Unmodified copies of the official XML schemas that `tools\Test-ScapSchema.ps1` and `tests\Schema.Tests.ps1` validate
XCCDF results, OVAL results and ARF reports against. They were copied from the `Resources\Schemas` folder of SCAP
Compliance Checker 5.15, which ships the published versions:

| Files | Standard | Publisher and terms |
|---|---|---|
| `xccdf_1.2.xsd`, `cpe-language_2.3.xsd`, `cpe-naming_2.3.xsd` | XCCDF 1.2, CPE 2.3 | NIST (U.S. Government work, not subject to copyright) |
| `asset-reporting-format_1.1.0.xsd`, `reporting-core_1.1.0.xsd`, `asset-identification_1.1.0.xsd` | ARF 1.1, AI 1.1 | NIST (U.S. Government work, not subject to copyright) |
| `oval_5.12.3\*` (except `xmldsig-core-schema.xsd`) | OVAL 5.12.3 | OVAL Community; the terms of use in each file grant a royalty-free license to use and reproduce them, provided those terms are kept |
| `oval_5.12.3\xmldsig-core-schema.xsd` | XML Signature | W3C Software License (notice in the file) |
| `xAL.xsd`, `xNL.xsd` | OASIS CIQ 2.0 | OASIS (copyright notice in the file) |
| `xlink.xsd`, `xml.xsd` | XLink, XML namespace | W3C |

Each file keeps its original notice, if it has one. They are test data only and are not part of the PowerSCAP module.
