# DOCX and ODT: A Standards-First Technical Research Report (as of August 2026)

## Executive summary

DOCX and ODT are both ZIP-packaged, XML-vocabulary word-processing formats, but they descend from different standardization cultures and encode different engineering trade-offs. DOCX is the WordprocessingML member of the Office Open XML (OOXML) family, standardized as ECMA-376 and ISO/IEC 29500, whose stated design goal is "to be capable of faithfully representing the pre-existing corpus of word-processing documents, spreadsheets and presentations that had been produced by the Microsoft Office applications (from Microsoft Office 97 to Microsoft Office 2008, inclusive)" ([ISO/IEC 29500-1:2016](https://www.iso.org/standard/71691.html)). ODT is the text-document member of the OpenDocument Format (ODF) family, standardized by OASIS and as ISO/IEC 26300, designed as an "XML-based, application-independent and platform-independent" format for authoring, editing, viewing, exchange and archiving ([ODF 1.4 Part 1](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part1-introduction.html)).

Six facts frame everything else in this report:

1. **The OOXML base standard is effectively frozen but under ISO revision.** ECMA-376 lists Part 1 (5th ed., December 2016), Part 2 (5th ed., December 2021), Part 3 (5th ed., December 2015) and Part 4 (5th ed., December 2016), and notes that "only part 2 has been adopted in the last edition of the Standard" ([Ecma International](https://ecma-international.org/publications-and-standards/standards/ecma-376/)). ISO/IEC 29500-1:2016 (4th edition, 5,024 pages) is at stage 90.92 "To be revised" and will be replaced by ISO/IEC DIS 29500-1 ([ISO](https://www.iso.org/standard/71691.html)).
2. **ODF moved forward in 2025.** OpenDocument 1.4 was approved as an OASIS Standard on 2025-12-03 ([OpenDocument standardization](https://en.wikipedia.org/wiki/OpenDocument_standardization); [The Document Foundation](https://blog.documentfoundation.org/blog/2025/12/03/tdf-announces-odf-v14-as-oasis-standard/)), while the ISO track still stands at ISO/IEC 26300-1:2015 (ODF 1.2), stage 90.92 ([ISO](https://www.iso.org/standard/66363.html)).
3. **Vendor implementation documentation, not the base standard, is where the hard interoperability truth lives.** [MS-OI29500] is still being revised — published version 23.0 dated 2/18/2025 ([Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/office_standards/ms-oi29500/1fd4a662-8623-49c0-82f0-18fa91b413b8)) — and [MS-OFFCRYPTO] reached revision 14.0 (Major) on 2026-02-17 ([Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/3c34d72a-1a61-4b52-a893-196f9157f083)).
4. **ODF's package rules are more normatively constrained than OPC's.** An ODF package "shall be a Zip file", all entries "shall be non compressed (`STORED`) or compressed using the 'deflate' (`DEFLATED`) algorithm", and `mimetype` "shall be the first file of the Zip file", uncompressed, with no extra field ([ODF 1.4 Part 2](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)). OPC, by contrast, is described as "a file technology for designing file formats with a shared, base architecture" that maps package concepts onto ZIP ([Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)).
5. **Both ecosystems remain live attack surfaces in 2026.** LibreOffice published advisories in June 2026 including a heap use-after-free in ODF number-format parsing (CVE-2026-6040) and an out-of-bounds write via "crafted OOXML documents with mismatched encryption salt parameters" (CVE-2026-4430, CVSS 4.0 base 5.4) ([LibreOffice security advisories](https://www.libreoffice.org/security/); [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-4430)).
6. **Tooling is healthy but unevenly maintained.** Apache POI released 5.5.1 on 30 November 2025 ([Apache POI](https://poi.apache.org/)), the ODF Toolkit released 0.13.0 on 2026-01-23 with ODF 1.4 support ([ODF Toolkit](https://odftoolkit.org/); [TDF dev blog](https://dev.blog.documentfoundation.org/2026/01/22/validating-odf-and-ooxml-files/)), while WebODF's last release notes date from 2015 ([webodf.org](https://webodf.org/)) and its repository was last pushed on 2020-02-04 ([repository metadata](https://api.github.com/repos/webodf/WebODF)).

---

## 1. History and standards lineage

### 1.1 OOXML / ECMA-376 / ISO/IEC 29500

OOXML was designed by Microsoft "to match the functionality of the proprietary binary formats used as the default formats in Microsoft Office applications—Word, Excel, and PowerPoint—through Office 2003" and to be "fully compatible with the existing corpus of documents"; ECMA TC45 was established in December 2005, the resulting document was approved as ECMA-376 in December 2006, submitted through ISO/IEC JTC 1 in early 2007, and approved as ISO/IEC 29500 in early 2008 ([Library of Congress, OOXML family](https://www.loc.gov/preservation/digital/formats/fdd/fdd000395.shtml)).

| Edition | Date | Notes |
|---|---|---|
| ECMA-376 1st edition | December 2006 | Archived edition ([Ecma](https://ecma-international.org/publications-and-standards/standards/ecma-376/)) |
| ECMA-376 2nd edition | December 2008 | Archived edition (same source) |
| ECMA-376 3rd edition | June 2011 | Archived edition |
| ECMA-376 4th edition | December 2012 | Archived edition |
| ECMA-376 Part 1, 5th ed. | December 2016 | "Fundamentals And Markup Language Reference" |
| ECMA-376 Part 2, 5th ed. | December 2021 | "Open Packaging Conventions"; the only part "adopted in the last edition of the Standard" |
| ECMA-376 Part 3, 5th ed. | December 2015 | "Markup Compatibility and Extensibility" |
| ECMA-376 Part 4, 5th ed. | December 2016 | "Transitional Migration Features" |
| ISO/IEC 29500-1:2016 | 2016-11 | Edition 4, 5,024 pages, stage 90.92 "To be revised"; will be replaced by ISO/IEC DIS 29500-1 ([ISO](https://www.iso.org/standard/71691.html)) |

**Strict vs Transitional.** ISO/IEC 29500-1:2016 "specifies concepts for documents and applications of both strict and transitional conformance" ([ISO](https://www.iso.org/standard/71691.html)). The restructuring at ISO separated markup supporting functional requirements from markup supporting backwards compatibility and legacy formats, which was moved into a part titled *Transitional Migration Features*; consequently "[f]iles that comply with ISO/IEC 29500 Part 1 are termed 'Strict' and files that comply with Part 4 (which is structured as textual modifications to Part 1) are termed 'Transitional'" ([Library of Congress](https://www.loc.gov/preservation/digital/formats/fdd/fdd000395.shtml)). The Strict variant "disallows legacy markup as specified in Part 4" and therefore "has less support for backwards compatibility when converting documents from older formats"; the split "eliminated all use of VML from the Strict specification", while VML "remains available in Transitional OOXML for backwards compatibility" and DrawingML is "a newer and richer markup language intended to support the same functionality as VML and more" ([Library of Congress, PPTX FDD](https://www.loc.gov/preservation/digital/formats/fdd/fdd000399.shtml)).

In products, Strict is a distinct save target sharing the same extension: Word lists both "Word Document (`.docx`)" and "Strict Open XML document (`.docx`)", the latter conforming "to the Strict profile of the Open XML standard (ISO/IEC 29500)", a profile that "doesn't allow a set of features that were designed specifically for backward-compatibility with existing binary documents, as specified in Part 4 of ISO/IEC 29500" ([Microsoft Learn](https://learn.microsoft.com/en-us/office/compatibility/xml-file-name-extension-reference-for-office)).

DOCX-family extensions and their macro semantics are normatively distinguished by Microsoft as follows ([same source](https://learn.microsoft.com/en-us/office/compatibility/xml-file-name-extension-reference-for-office)):

| Extension | Meaning | Macros |
|---|---|---|
| `.docx` | Default Word format | "Can't store VBA macro code" |
| `.docx` (Strict) | Strict Open XML document | Same XML family; Part-4 features disallowed |
| `.docm` | Word Macro-Enabled Document | "can store VBA macro code"; created when VBA code is present |
| `.dotx` | Word Template | "Can't store VBA macro code" |
| `.dotm` | Word Macro-Enabled Template | Stores macro code; documents created from it "do not inherit the VBAProject part of the template" |

### 1.2 ODF / OASIS / ISO/IEC 26300

OpenDocument "was based on OpenOffice.org XML as used in OpenOffice.org version 1", chosen because it "was already an XML format with most of the desired properties" and "had been in use since 2000 as the program's primary storage format" — though "OpenDocument is not the same as the older OpenOffice.org XML format" ([OpenDocument standardization](https://en.wikipedia.org/wiki/OpenDocument_standardization)).

| Version | OASIS status | ISO/IEC status |
|---|---|---|
| ODF 1.0 | OASIS Standard 2005-05-01 | ISO/IEC 26300:2006, published 2006-11-30 ([Wikipedia](https://en.wikipedia.org/wiki/OpenDocument_standardization)) |
| ODF 1.1 | OASIS Standard 2007-02-01 (announced 2007-02-13) | ISO/IEC 26300:2006/Amd 1:2012, March 2012 (same source) |
| ODF 1.2 | CS 17 March 2011; OASIS Standard 29 September 2011 | ISO/IEC 26300-1/-2/-3:2015, published 17 June 2015 ([Wikipedia](https://en.wikipedia.org/wiki/OpenDocument_standardization); [OASIS](https://www.oasis-open.org/standard/opendocumentv1-2/)) |
| ODF 1.3 | OASIS Standard 2021-04-27 | "Draft International Standard" stage as of March 2024 ([Wikipedia](https://en.wikipedia.org/wiki/OpenDocument_standardization)) |
| ODF 1.4 | OASIS Standard 2025-12-03 | "not submitted yet" (same source); TDF announcement 3 December 2025 ([TDF](https://blog.documentfoundation.org/blog/2025/12/03/tdf-announces-odf-v14-as-oasis-standard/)) |

ODF 1.4's four Committee Specification 01 parts are all dated 2 August 2024 — Part 1 Introduction, Part 2 Packages, Part 3 OpenDocument Schema, Part 4 Recalculated Formula (OpenFormula) — and the 60-day public review closed "7 September 2025 at 23:59 UTC" before the call for consent as an OASIS Standard ([OASIS](https://www.oasis-open.org/2025/07/07/13016/)). ODF 1.2's three-part structure (Schema / OpenFormula / Packages) was mapped to ISO/IEC 26300-1:2015, -2:2015 and -3:2015 ([OASIS](https://www.oasis-open.org/standard/opendocumentv1-2/)); ISO's own life-cycle listing shows ISO/IEC 26300-1:2015 as published with ISO/IEC CD 26300-3 under development ([ISO](https://www.iso.org/standard/66363.html)).

ODF 1.3's substantive additions, per The Document Foundation, were formal digital-signature specification with **XAdES** support (including signing whole documents, individual parts, or multiple sections), optional **OpenPGP-based encryption** alongside the traditional Blowfish method, finer-grained change management including change tracking in tables, and RDF-based custom metadata improvements; ODF 1.3 also introduced two compliance modes, **Strict** ("clean documents that comply with the specifications") and **Extended** ("allows specific enhancements by a company for broader feature support") ([TDF blog](https://blog.documentfoundation.org/blog/2025/08/01/whats-new-in-odf-1-3-and-1-4/)). The same (secondary, vendor-authored) source describes ODF 1.4 goals as style-change tracking, change IDs, chart flexibility, accessibility semantics, and richer form controls. As of the January 2026 LibreOffice developer blog, "ODF 1.4 … is not yet implemented in LibreOffice" ([TDF dev blog](https://dev.blog.documentfoundation.org/2026/01/22/validating-odf-and-ooxml-files/)).

### 1.3 Current status through 2026 — summary table

| Question | Answer (as of August 2026) | Source |
|---|---|---|
| Latest OOXML ECMA edition | 5th edition parts, Part 2 dated December 2021 | [Ecma](https://ecma-international.org/publications-and-standards/standards/ecma-376/) |
| Latest OOXML ISO edition | ISO/IEC 29500-1:2016 (ed. 4), stage 90.92, DIS in progress | [ISO](https://www.iso.org/standard/71691.html) |
| Latest ODF OASIS Standard | ODF 1.4, approved 2025-12-03 | [Wikipedia](https://en.wikipedia.org/wiki/OpenDocument_standardization) |
| Latest ODF ISO edition | ISO/IEC 26300-1:2015 (ODF 1.2), stage 90.92 | [ISO](https://www.iso.org/standard/66363.html) |
| Latest Microsoft OOXML variance doc | [MS-OI29500] rev. 23.0, 2/18/2025 | [Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/office_standards/ms-oi29500/1fd4a662-8623-49c0-82f0-18fa91b413b8) |
| Latest Office cryptography doc | [MS-OFFCRYPTO] rev. 14.0 Major, 2026-02-17 | [Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/3c34d72a-1a61-4b52-a893-196f9157f083) |

---

## 2. Physical and package architecture

### 2.1 OPC (DOCX)

OPC is "[r]ather than a specific file format … a file technology for designing file formats with a shared, base architecture", integrating "Zip, XML, and Web technologies", and is documented in ISO/IEC 29500 and ECMA-376 ([Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)). Logically a package is "an aggregate of data structured as a directed graph" whose vertices are "[a]ll URI-addressable resources" and whose edges are relationships; a relationship source "must be either the package itself or a data component called a part inside the package", while a target "can be any URI-addressable resource inside or outside of the package" (same source). Parts consist of "a byte stream of data and properties", with a content type expressed as "a MIME-style media type" (same source).

Concretely, in the ZIP physical mapping: "[a] file called `[Content_Types].xml` and a folder called `_rels` are mandatory in the ZIP-based OPC container"; `[Content_Types].xml` "contains a list of the MIME types and extensions for all the other parts in the package"; "[a]ll parts of the package must be discoverable by following relationships"; `_rels/.rels` "defines a relationship to the main part"; and "[e]ach part can have an associated `.rels` file with relationships to embedded or associated files" ([Library of Congress, OPC FDD](https://www.loc.gov/preservation/digital/formats/fdd/fdd000363.shtml)). The same FDD records OPC's PRONOM PUID as `fmt/189`, that OPC is a subtype of "ZIP File Format, Version 6.2.0 (PKWARE)", that it incorporates schemas for relationships, content types, digital signatures and "core properties", and that the Core Properties schema "uses selected Dublin Core metadata elements in addition to OPC-specific elements".

**Part naming and URI/IRI rules.** The most significant difference between ECMA-376 Part 2 1st edition (December 2006) and all later ISO/IEC 29500-2 versions through 2012 "relates to permitting part names in the package to be IRIs" (RFC 3987), whereas "[t]he first edition permitted part names as URIs as defined in RFC 3986" ([Library of Congress](https://www.loc.gov/preservation/digital/formats/fdd/fdd000363.shtml)). The .NET packaging model mirrors the abstraction: parts "are addressed by URIs", relationships are created at package level (`Package.CreateRelationship`) or part level, and each may target a part inside the package or "a target resource outside of the package" ([System.IO.Packaging.Package](https://learn.microsoft.com/en-us/dotnet/api/system.io.packaging.package)). That API also documents that ZIP "is the primary physical format for a `Package`" while other implementations "might use other physical formats, including an XML document, a database, or a Web service", and that parts can be created with an explicit `CompressionOption` (same source).

**Annotated DOCX package tree** (part names and roles as documented):

```text
mydoc.docx  (ZIP / OPC package)
├── [Content_Types].xml          # mandatory; MIME types + extensions for all parts
├── _rels/
│   └── .rels                    # package-level relationships → main document, docProps
├── docProps/
│   ├── core.xml                 # OPC core properties (Dublin Core based)
│   └── app.xml                  # application/extended properties
└── word/
    ├── document.xml             # main document part; root <w:document>
    ├── styles.xml               # style definitions part
    ├── numbering.xml            # numbering definitions
    ├── settings.xml             # document settings part
    ├── fontTable.xml            # font preferences
    ├── header1.xml / footer1.xml
    ├── footnotes.xml / endnotes.xml / comments.xml
    ├── media/…                  # embedded images and binaries
    └── _rels/
        └── document.xml.rels    # part-level relationships ("a catalog with all further files")
```

The part inventory and roles above are documented in Microsoft's WordprocessingML structure page — which enumerates package parts and their root elements (`document`, `comments`, `settings`, `endnotes`, `ftr`, `footnotes`, `glossaryDocument`, `hdr`, `styles`) and states that a minimal document requires only the main document part, whose file is `document.xml` "under the `word` folder of the `.zip` package" ([Microsoft Learn](https://learn.microsoft.com/en-us/office/open-xml/word/structure-of-a-wordprocessingml-document)) — and in a peer-reviewed analysis of the package layout, which lists `_rels/.rels`, `docProps/app.xml`, `docProps/core.xml`, `word/document.xml`, `word/_rels/document.xml.rels` as "a catalog with all further files", `word/styles.xml`, and `word/fontTable.xml`, and notes that "[g]raphics can be external resources. In that case, only the URL of the graphic is stored in the document and the graphic is automatically reloaded when the document is opened" ([USENIX Security 2023, Rohlmann et al.](https://www.usenix.org/system/files/sec23summer_235-rohlmann-prepub.pdf)).

Minimal `document.xml` as published by Microsoft:

```xml
<?xml version="1.0" encoding="utf-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>The text passed as the second parameter goes here</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>
```
([Microsoft Learn](https://learn.microsoft.com/en-us/office/open-xml/word/structure-of-a-wordprocessingml-document))

### 2.2 ODF package (ODT)

ODF's package layer is normatively tighter. From ODF 1.4 Part 2 ([OASIS](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)):

- "An OpenDocument Package **shall be a Zip file**, as defined by [ZIP]" — identified as PKWARE Zip APPNOTE Version 6.2.0.
- "All files contained in the Zip file **shall be non compressed (`STORED`) or compressed using the 'deflate' (`DEFLATED`) algorithm**."
- A package "may contain multiple sub documents, but **only a single document can be contained in the root of the package**"; "[a] directory has no corresponding file entry within the Zip file."
- `mimetype`: "should contain" it when a MIME media type exists; content "shall be the ASCII encoded MIME media type associated with the document"; it "shall be the first file of the Zip file"; it "shall not be compressed"; it "shall not use an 'extra field' in its header". If `META-INF/manifest.xml` has a `<manifest:file-entry>` with `manifest:full-path="/"`, a `mimetype` file "shall exist" and its content "shall be equal to the value of that entry's `manifest:media-type` attribute".
- Byte-offset discovery: `PK` at position 0, `mimetype` beginning at position 30, and the media type itself beginning at position 38.
- "Every OpenDocument Package **shall contain** `META-INF/manifest.xml`", it "shall be a well-formed XML document", its root "shall be `<manifest:manifest>`", and it "shall be valid with respect to the manifest schema".
- `content.xml` "shall be a well-formed XML 1.0 document" whose root "shall be `<office:document-content>` or `<math:math>`"; "[a] conforming package shall contain at least one of `content.xml` and `styles.xml`"; "[a] package may contain additional files" ([ODF 1.4 Part 3](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part3-schema.html)).

LibreOffice's user documentation confirms the practical file set: documents "are stored as compressed ZIP archives" containing XML files, with `content.xml` holding "the text content of the document", `meta.xml` holding "the meta information … which can be entered under File - Properties", and `settings.xml` holding further information ([LibreOffice Help](https://help.libreoffice.org/latest/en-GB/text/shared/00/00000021.html?DbPAR=SHARED)).

**Annotated ODT package tree:**

```text
mydoc.odt  (ZIP; APPNOTE 6.2.0; STORED or DEFLATED only)
├── mimetype                     # first entry, STORED, no extra field; ASCII media type
├── META-INF/
│   ├── manifest.xml             # mandatory; root <manifest:manifest>; lists every file entry
│   ├── documentsignatures.xml   # recommended filename for document signature
│   └── macrosignatures.xml      # recommended filename for macro signature
├── content.xml                  # root <office:document-content>; body + automatic styles
├── styles.xml                   # common/master/page styles
├── meta.xml                     # document metadata (root <office:document-meta>)
├── settings.xml                 # application settings (root <office:document-settings>)
├── Thumbnails/thumbnail.png     # preview image
├── Pictures/…                   # embedded binaries
├── Basic/                       # Basic macro libraries (Standard/Module1.xml, script-lb/lc.xml)
└── Scripts/                     # Python, JavaScript or BeanShell macros
```

The signature filenames and macro directory layout above are documented in the peer-reviewed ODF security analysis, which states that document signatures are "recommended" to use `documentsignatures.xml`, macro signatures "should use" `macrosignatures.xml`, that both files have the same internal structure, and that `Basic` is used for Basic macros while `Scripts` is used for "Python, JavaScript, or BeanShell macros" ([USENIX Security 2022, Rohlmann et al.](https://www.usenix.org/system/files/sec22-rohlmann.pdf)). The root-element/part mapping (`office:document-content`, `office:document-styles`, `office:document-meta`, `office:document-settings`, plus the single-file `office:document` root) is tabulated in ODF 1.4 Part 3 ([OASIS](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part3-schema.html)).

### 2.3 ZIP mechanics, ZIP64, streaming, random access, canonicalization

- **ZIP64.** Neither the OPC overview nor the ODF Part 2 text fetched here states ZIP64 requirements: the OPC page "does not mention ZIP64 or specify any ZIP64 requirements" ([Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)), and ODF Part 2 normatively references APPNOTE 6.2.0 without ZIP64-specific statements in the extracted text ([OASIS](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)). Practical evidence of the 32-bit boundary comes from Apache POI, whose `ZipSecureFile.setMaxEntrySize` default is "`4GB`, the 32-bit ZIP format maximum", a limit POI 5.1.0 removed from the setting itself ([Apache POI configuration](https://poi.apache.org/components/configuration.html)). Low-level libraries do support ZIP64 explicitly — libzip lists "Zip64 large archives" among its capabilities ([libzip](https://libzip.org/)). Whether a specific consumer accepts ZIP64 DOCX/ODT packages: **n.a.** (not verified from primary specification text in this session).
- **Streaming vs random access.** ODF Part 2 describes the sequential ZIP layout ("[a] Zip file starts with a sequence of files. Each file has a local header immediately before its data … followed by a central directory at the end of the Zip archive"), which is what makes both streaming reads and central-directory-driven random access possible ([OASIS](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)). The `mimetype`-at-offset-30 rule is the ODF-specific concession to sniffing without full directory parsing (same source). Implementation-level streaming controls exist in POI: `ZipInputStreamZipEntrySource.setThresholdBytesForTempFiles` (added in POI 5.1.0; default `-1` meaning no temp files, in which case entries with more than 2 GB of decompressed data fail; "[a] threshold such as `50000000` (approximately `50Mb`) is recommended") ([Apache POI configuration](https://poi.apache.org/components/configuration.html)).
- **Canonicalization / deterministic output.** No canonicalization requirement for either package format was found in the fetched specification text (**n.a.**). Practically, reproducible output requires controlling the ZIP layer: archives "will, by default, record file last modification times" and entry order follows filesystem order, "likely to be different on every run", so producers must normalize timestamps and sort entries (e.g. locale-independent name sorting in the C locale) and control recorded ownership and permissions ([Reproducible Builds](https://reproducible-builds.org/docs/archives/)). For ODF, deterministic generation additionally has to preserve the fixed first-entry/STORED constraint for `mimetype`; WebODF explicitly documents having had to guarantee "that the mimetype file is not compressed within the ZIP container" ([webodf.org](https://webodf.org/)). Note also an ODF encryption interaction: encrypted entries "shall be flagged as `'STORED'` rather than `'DEFLATED'`" even though they were deflated before encryption, with the plaintext size carried in `manifest:size` ([ODF 1.4 Part 2](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)).
- **Duplicate entry names** are a real corruption/ambiguity class: POI 5.4.0+ "checks for duplicate ZIP entry names and throws an exception when found" ([Apache POI](https://poi.apache.org/)).

---

## 3. Document object models and XML vocabularies

### 3.1 WordprocessingML (DOCX)

The minimum content model is `document` → `body` → `p` (paragraph) → `r` (run) → `t` (text range) ([Microsoft Learn](https://learn.microsoft.com/en-us/office/open-xml/word/structure-of-a-wordprocessingml-document)). Content is organized into *stories*: "comment, endnote, footer, footnote, frame, glossary document, header, main story, subdocument, text box", and "[n]ot all stories must be present in a valid WordprocessingML document" (same source).

**Styles.** Paragraph-level rich formatting lives in `w:pPr`; `w:pStyle/@w:val` carries the style identifier; the styles part is represented by `StyleDefinitionsPart` with a `Styles` root element; crucially "[t]he styles part is not required for a document to be considered valid", is created automatically by Word but **not** by the Open XML SDK, which requires explicit creation ([Microsoft Learn](https://learn.microsoft.com/en-us/office/open-xml/word/how-to-apply-a-style-to-a-paragraph-in-a-word-processing-document)).

```xml
<w:p xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:pPr>
    <w:pStyle w:val="OverdueAmount" />
  </w:pPr>
  ...
</w:p>
```
([same source](https://learn.microsoft.com/en-us/office/open-xml/word/how-to-apply-a-style-to-a-paragraph-in-a-word-processing-document))

**Numbering.** `w:numPr` "[s]pecifies that the current paragraph references a *numbering definition instance* in the current document"; its presence means the paragraph "inherits the properties specified by the numbering definition in the `num` element (§17.9.16), at the level specified by the `lvl` element (§17.9.7), and shall have an associated number positioned before the beginning of the text flow". A subtle inheritance rule: "[w]hen `numPr` appears as part of the paragraph formatting for a paragraph style, any numbering level defined using `ilvl` shall be ignored, and the `pStyle` element (§17.9.24) on the associated abstract numbering definition shall be used instead" ([Microsoft Learn, NumberingProperties](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.numberingproperties?view=openxml-3.0.1)).

```xml
<w:pPr>
  <w:numPr>
    <w:ilvl w:val="4" />
    <w:numId w:val="0" />
  </w:numPr>
</w:pPr>
```
([same source](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.numberingproperties?view=openxml-3.0.1))

**Content controls (SDTs) and custom XML.** Content controls are containers that "[f]ix the position of content", "[s]pecify the kind of content", "[r]estrict or enable editing" and "[a]dd semantic meaning to content"; Word 2010 offered Rich Text, Plain Text, Picture, Building Block Gallery, Combo Box, Drop-Down List, Date, Checkbox and Group controls, and Word 2013 added improved visualization, XML mapping for rich-text controls, and a repeating-content control. Appearance states are Bounding box, Start/End tags, or None (`wdContentControlBoundingBox`, `wdContentControlTags`, `wdContentControlHidden`). For XML mapping, "[t]he custom XML is stored as flat Open XML markup" within the custom XML part ([Microsoft Learn](https://learn.microsoft.com/en-us/office/client-developer/word/content-controls-in-word)).

**altChunk (imported external content).** `w:altChunk` may appear under `body`, `comment`, `docPartBody`, `endnote`, `footnote`, `ftr`, `hdr`, `tc`, and takes one child, `altChunkPr`; the class has been available since Office 2007 ([Microsoft Learn, AltChunk](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.altchunk?view=openxml-3.0.1)). Microsoft documents two variances from the standard: Word uses the relationship type `http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk` rather than `…/afChunk`, and while "the standard specifies that applications can support any set of content types", Word supports a specific list: WordprocessingML document/template main parts (including macro-enabled variants), `message/rfc822`, `application/xml`, `application/rtf`, `application/xhtml+xml`, `text/html`, `text/plain` ([MS-OI29500 §2.1.527](https://learn.microsoft.com/en-us/openspecs/office_standards/ms-oi29500/c391c28f-1b03-4a21-a4f8-4d9cddd4a95c)). This is architecturally important — and a security-relevant surface, since it lets a DOCX embed RTF or HTML for the consumer to import.

Other WordprocessingML areas (fields, bookmarks, tracked revisions, drawings/charts, OMML equations, OLE embeddings, macros/signatures) are addressed where evidence was obtained: parts and root elements in §2.1; macros and signatures in §6–§7; fields/revisions behavior in §5 and §8. Exhaustive element-level enumeration of field-code grammar and OMML from primary text: **n.a.** in this session.

### 3.2 ODF text model (ODT)

Namespaces used by ODF 1.4 Part 3 include `office` (`urn:oasis:names:tc:opendocument:xmlns:office:1.0`), `text`, `style`, `table`, `draw` (`urn:oasis:names:tc:opendocument:xmlns:drawing:1.0`), `form`, `script`, `math` (`http://www.w3.org/1998/Math/MathML`), `xlink` (`http://www.w3.org/1999/xlink`), `xhtml`, and `grddl` (`http://www.w3.org/2003/g/data-view#`); implementors "may use any prefix if a namespace declaration binds that prefix to the IRI of the corresponding namespace" ([ODF 1.4 Part 3](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part3-schema.html)).

Structural facts from the same source:

- `<office:document-content>` is the root element of `content.xml`, carrying `grddl:transformation` and `office:version`, with children `<office:automatic-styles>`, `<office:body>`, `<office:font-face-decls>`, `<office:scripts>`.
- Style containers are partitioned across roots: `<office:styles>` and `<office:master-styles>` appear in `office:document-styles`, `<office:automatic-styles>` in both content and styles roots — i.e. **automatic (direct-formatting) styles live with the content, common styles live with `styles.xml`**.
- `<office:text>` "[r]epresents the content of a text document", with attributes `text:global` and `text:use-soft-page-breaks`, and children spanning the entire text/table/draw vocabulary: `<text:p>`, `<text:h>`, `<text:list>`, `<text:numbered-paragraph>`, `<text:section>`, `<table:table>`, `<text:tracked-changes>`, `<text:change>`, `<text:change-start>`, `<text:change-end>`, `<text:soft-page-break>`, `<office:forms>`, indices (`<text:table-of-content>`, `<text:alphabetical-index>`, `<text:illustration-index>`, `<text:object-index>`, `<text:table-index>`, `<text:user-index>`, `<text:bibliography>`), declarations (`<text:variable-decls>`, `<text:user-field-decls>`, `<text:sequence-decls>`, `<text:dde-connection-decls>`), and drawing shapes (`<draw:frame>`, `<draw:g>`, `<draw:custom-shape>`, `<dr3d:scene>`, etc.).
- `<text:h>` "[r]epresents a heading"; headings "define the division structure for a document. A chapter or section begins with a heading and extends to the next heading at the same or higher level"; `<text:h>` and `<text:p>` "are collectively referred to as paragraph elements".
- Extensibility: "[f]oreign elements and attributes shall not use a namespace listed in Tables 1, 2, or 3 of section 1.5", and deprecated names "should not be used any longer, and may be removed from future versions".

Note the structural contrast with WordprocessingML: ODF encodes lists as real containers (`<text:list>` with list styles) and tracked changes as a document-level `<text:tracked-changes>` region referenced by in-flow `<text:change-start>`/`<text:change-end>` markers, whereas WordprocessingML expresses revisions as attributes/wrappers around runs and paragraphs, and lists as paragraph properties referencing numbering definitions ([ODF 1.4 Part 3](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part3-schema.html); [NumberingProperties](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.numberingproperties?view=openxml-3.0.1)). Scripting/macro containers (`office:scripts`, `Basic/`, `Scripts/`) are documented above ([USENIX 2022](https://www.usenix.org/system/files/sec22-rohlmann.pdf)); MathML embedding is standardized by the `math:math` root being permitted for `content.xml` ([ODF 1.4 Part 3](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part3-schema.html)), and the ODF Validator confirms MathML handling in practice by auto-selecting "the MathML 1.01 DTD or the MathML 3 schema … for formula documents" ([ODF Toolkit](https://odftoolkit.org/conformance/ODFValidator.html)). RDF metadata support in ODF 1.2 is evidenced by the published "OpenDocument v1.2 Metadata Manifest Ontology" and "Package Metadata Manifest Ontology" ([OASIS](https://www.oasis-open.org/standard/opendocumentv1-2/)); ODF 1.3 "[i]mproved management of custom metadata fields using RDF" ([TDF](https://blog.documentfoundation.org/blog/2025/08/01/whats-new-in-odf-1-3-and-1-4/)).

---

## 4. Namespaces, MCE, version negotiation and unknown markup

### 4.1 OOXML: Markup Compatibility and Extensibility

MCE is standardized as ISO/IEC 29500-3 (approved in 2008; the FDD identifies ISO/IEC 29500-3:2015 as the latest version as of March 2020) with namespace `http://schemas.openxmlformats.org/markup-compatibility/2006`, typically bound to prefix `mc:` or `mce:`; it "defines a set of conventions for forward compatibility of markup specifications", applicable beyond OOXML, and is also used in ECMA-388 OpenXPS. Notably, "[a] file may contain a namespace declaration linking the MCE namespace identifier to a prefix even if the file does not incorporate elements and attributes not defined by Parts 1, 2, and 4 of ISO 29500", and Microsoft Office may declare the MCE namespace and list newer feature namespaces as ignorable regardless ([Library of Congress, MCE FDD](https://www.loc.gov/preservation/digital/formats/fdd/fdd000396.shtml)). Typical processing "involves pre-processing documents containing MCE elements and attributes to produce a document understood by the consuming application" (same source).

The normative processing model for alternate content ([ECMA-376 Part on MCE, reference rendering](https://c-rex.net/samples/ooxml/e1/Part5/OOXML_P5_Markup_Compatibility_and_Extensibility_AlternateContent_topic_ID0E4GBG.html)):

- `<AlternateContent>` contains all alternatives; each alternative is in a `<Choice>` or `<Fallback>`; there "shall" be one or more `<Choice>` children; at most one `<Fallback>`, which "shall follow all `<Choice>` elements"; `<AlternateContent>` "shall not be the child of an `<AlternateContent>` element".
- "Markup consumers shall rely solely on the namespaces identified by the `<Choice>` element, rather than on the alternate content markup itself, to decide which content to use."
- Unselected branches: "[a]ll child and descendant elements … shall be treated as if they did not exist", and no error may be raised for `@MustUnderstand` inside them.
- Errors: a consumer "shall generate an error when encountering an attribute or child element of the `<AlternateContent>` element that belongs to a namespace that is neither understood nor ignorable", and "shall generate an error if it encounters a `@MustUnderstand` attribute included on a `<Choice>` or `<Fallback>` element that identifies a namespace that it does not understand".
- The MCE attributes recognized on `<AlternateContent>` are `@Ignorable`, `@MustUnderstand`, `@ProcessContent`, `@PreserveElements`, `@PreserveAttributes`; their qualified names "shall be prefixed" there, and an unprefixed attribute name "shall" cause an error.
- Attribute inheritance: namespace declarations and compatibility-rule attributes on `<AlternateContent>` or the selected branch "shall be processed as though they appeared on every child element of the selected `<Choice>` or `<Fallback>` element".

Microsoft's developer-facing summary confirms `Ignorable` "specifies namespaces that can be ignored when they are not understood by the consuming application", that alternate content lets applications choose at run time, and — importantly for interoperability planning — that "[i]nteroperability is a function of support both in the file format and by applications" ([Microsoft Learn](https://learn.microsoft.com/en-us/office/open-xml/general/introduction-to-markup-compatibility)). Toolchains expose MCE pre-processing as a policy decision: the Open XML SDK's `MarkupCompatibilityProcessSettings.ProcessMode` offers `NoProcess` (default — "[t]he application must be able to understand and handle any elements and attributes present in the document markup, including elements and attributes in the Markup Compatibility namespace"), `ProcessLoadedPartsOnly` ("ensuring minimal modification to the file"), and `ProcessAllParts`, with `TargetFileFormatVersions` supplying the version context (same source).

### 4.2 ODF: conformance, foreign markup and versions

ODF's negotiation model is version-attribute plus conformance-class based rather than in-document fallback markup. `office:version` appears on document roots ([ODF 1.4 Part 3](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part3-schema.html)); foreign elements/attributes must not reuse ODF namespaces (same source); and packages are graded: alternative encryption algorithms and key-derivation IRIs "may be specified by extended conforming packages only. They shall not be specified by conforming packages" ([ODF 1.4 Part 2](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)). Note that the ODF 1.4 Part 1 introduction fetched here does **not** itself enumerate conformance classes (**n.a.** from that source) ([ODF 1.4 Part 1](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part1-introduction.html)); TDF describes the ODF 1.3-era modes as Strict and Extended ([TDF](https://blog.documentfoundation.org/blog/2025/08/01/whats-new-in-odf-1-3-and-1-4/)).

The best operational statement of unknown-markup behavior comes from the reference validator: "[f]or ODF 1.0/1.1, unknown markup is ignored when ODF conformance rules are selected. For ODF 1.2 or later, unknown markup is ignored when extended ODF conformance rules are selected. With regular schemas, errors are reported for unknown markup, except when it appears in styles or metadata of ODF 1.0/1.1 documents" ([ODF Validator](https://odftoolkit.org/conformance/ODFValidator.html)). Producer-specific extension in the wild is visible in LibreOffice's save targets, which include "ODF 1.2 Extended (compatibility mode)", "ODF 1.2 Extended" and "ODF 1.3 Extended" alongside plain ODF versions, with ODF 1.3/1.3 Extended first supported in LibreOffice 7.0 ([LibreOffice Help](https://help.libreoffice.org/latest/en-GB/text/shared/00/00000021.html?DbPAR=SHARED)).

### 4.3 Comparison table: architecture and extensibility

| Dimension | DOCX (OOXML/WordprocessingML) | ODT (ODF text) |
|---|---|---|
| Container | OPC over ZIP; "nearly all package formats are based on ZIP archives" ([MS](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)) | "shall be a Zip file" per APPNOTE 6.2.0, STORED/DEFLATED only ([OASIS](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)) |
| Mandatory index | `[Content_Types].xml` + `_rels` folder ([LoC](https://www.loc.gov/preservation/digital/formats/fdd/fdd000363.shtml)) | `META-INF/manifest.xml` ([OASIS](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)) |
| Type discovery | Content types declared per extension/part in `[Content_Types].xml` ([LoC](https://www.loc.gov/preservation/digital/formats/fdd/fdd000363.shtml)) | `mimetype` first entry, uncompressed, media type at byte 38 ([OASIS](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)) |
| Linking model | Relationship parts (`.rels`), IDs resolved from markup; internal or external targets ([MS](https://learn.microsoft.com/en-us/dotnet/api/system.io.packaging.package)) | Manifest file entries + `xlink:href` references in content ([OASIS](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part3-schema.html)) |
| Extensibility | MCE `AlternateContent`/`Choice`/`Fallback`, `Ignorable`, `MustUnderstand`, `ProcessContent` ([ECMA MCE](https://c-rex.net/samples/ooxml/e1/Part5/OOXML_P5_Markup_Compatibility_and_Extensibility_AlternateContent_topic_ID0E4GBG.html)) | Foreign elements outside ODF namespaces; conforming vs extended conforming ([OASIS Part 3](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part3-schema.html), [Part 2](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)) |
| Profiles | Strict (Part 1) vs Transitional (Part 4) ([LoC](https://www.loc.gov/preservation/digital/formats/fdd/fdd000395.shtml)) | Version attribute + conformance mode; "Extended" save targets in LibreOffice ([LibreOffice](https://help.libreoffice.org/latest/en-GB/text/shared/00/00000021.html?DbPAR=SHARED)) |
| Foreign-content import | `altChunk` with implementation-defined content types (Word: RTF/HTML/XHTML/plain text/rfc822…) ([MS-OI29500](https://learn.microsoft.com/en-us/openspecs/office_standards/ms-oi29500/c391c28f-1b03-4a21-a4f8-4d9cddd4a95c)) | Sub-documents in package; only one document at package root ([OASIS](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)) |

---

## 5. Semantics that make editing hard

The following difficulties are grounded in the documented models above and in vendor-documented behavior; where a mechanism is well known but was not confirmable from a fetched primary source in this session, it is marked **n.a.**

- **Run fragmentation.** Text lives in `w:t` inside `w:r` inside `w:p`; any formatting or revision boundary forces a new run, so logical strings are physically split across siblings ([Microsoft Learn](https://learn.microsoft.com/en-us/office/open-xml/word/structure-of-a-wordprocessingml-document)). Real-world consequence: template placeholders are frequently split, which is why templating engines expose "inspection APIs [to] list placeholders and compiled document data" before rendering ([docxtemplater FAQ](https://docxtemplater.com/docs/faq/)).
- **Style inheritance and cascade.** DOCX style resolution depends on the optional styles part and `pStyle` ids ([Microsoft Learn](https://learn.microsoft.com/en-us/office/open-xml/word/how-to-apply-a-style-to-a-paragraph-in-a-word-processing-document)); ODF splits automatic styles (with content) from common/master styles (in `styles.xml`), so a faithful edit must touch both roots ([ODF 1.4 Part 3](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part3-schema.html)). Cross-format conversion multiplies style objects: Word notes "an increase in the number of styles after you save the document in .odt format, and all formatting in ODF is style based" ([Microsoft Support](https://support.microsoft.com/en-us/word/differences-between-the-opendocument-text-odt-format-and-the-word-docx-format-used-by-word-for-the-w)).
- **Numbering/list identity.** `numId`/`ilvl` are indirections into numbering definition instances and abstract definitions, with the style-level override rule described in §3.1, meaning list identity is not a property of the paragraph text at all ([Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.numberingproperties?view=openxml-3.0.1)). Round-trip artifacts are documented: bullets and numbering are "Supported" but "[s]pacing between number/bullet and text might be slightly different", spacing between list items is "increased to match line spacing of document", and "[d]efault bullets in OpenOffice change appearance when .odt file is opened" ([Microsoft Support](https://support.microsoft.com/en-us/word/differences-between-the-opendocument-text-odt-format-and-the-word-docx-format-used-by-word-for-the-w)).
- **Fields and computed content.** Field-driven content is a documented loss vector: a table of contents "loses items labeled with a **SEQ** field" in the ODT round trip, and mail-merge connections require that "[t]he connection to the data source must be established again if the document is edited by another ODF application" (same source). Rendering-dependent field values are simply outside pure-XML tooling: docxtemplater states it "[c]annot convert DOCX to PDF or render DOCX for page numbers, total pages, element height, or regenerating a table of contents" ([docxtemplater FAQ](https://docxtemplater.com/docs/faq/)).
- **Section breaks and page geometry.** "Continuous section breaks might lose some properties, such as top/bottom margins, headers/footers, borders, and line numbering" ([Microsoft Support](https://support.microsoft.com/en-us/word/differences-between-the-opendocument-text-odt-format-and-the-word-docx-format-used-by-word-for-the-w)).
- **Floating shapes and anchoring.** Drop caps are supported but "[a]nchors to some regions of the margin are not supported"; text boxes are only partially supported because "[t]ext boxes cannot be nested" (same source). In the ODF model, anchored graphics are `draw:*` shapes and `draw:frame` children of `office:text` ([ODF 1.4 Part 3](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part3-schema.html)).
- **Tables.** Hard capacity/structural limits appear in conversion: "[t]ables with more than 64 columns are not supported" in the ODT path ([Microsoft Support](https://support.microsoft.com/en-us/word/differences-between-the-opendocument-text-odt-format-and-the-word-docx-format-used-by-word-for-the-w)); accessibility tooling separately penalizes complex tables, warning when tables are not "simple rectangles with no split cells, merged cells, or nesting" ([Microsoft Support, Accessibility Checker rules](https://support.microsoft.com/en-us/office/rules-for-the-accessibility-checker-651e08f2-0fc3-4e10-aaca-74b4a67101c1)).
- **Revisions/tracked changes.** ODF models revisions in `<text:tracked-changes>` plus `<text:change-start>`/`<text:change-end>` ([ODF 1.4 Part 3](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part3-schema.html)); ODF 1.3 improved change management including "change tracking in tables", previously "a weak point", and ODF 1.4 targets style-change tracking and change IDs ([TDF](https://blog.documentfoundation.org/blog/2025/08/01/whats-new-in-odf-1-3-and-1-4/)). Tracked-change import is also a real memory-safety hazard: a heap buffer overflow existed in LibreOffice Calc "when a document reused the same change identifier for two different kinds of change" (CVE-2026-8358) ([LibreOffice](https://www.libreoffice.org/security/)).
- **Formatting semantics that shift meaning.** Highlighting "is converted to character background color when you save the document"; shading patterns and picture border styles are unsupported and picture borders are "converted to a solid line"; positional tabs are unsupported; custom footnote/endnote separators are unsupported; multi-column indices are unsupported; and "[p]ictures from a document created in OpenOffice are not displayed" ([Microsoft Support](https://support.microsoft.com/en-us/word/differences-between-the-opendocument-text-odt-format-and-the-word-docx-format-used-by-word-for-the-w)).
- **Whitespace, bidi/international text, fonts, hyphenation, locale.** Paragraph properties include "[t]ext direction" and "[h]yphenation override" in WordprocessingML ([Microsoft Learn](https://learn.microsoft.com/en-us/office/open-xml/word/how-to-apply-a-style-to-a-paragraph-in-a-word-processing-document)); font resources are carried in `word/fontTable.xml` and embedded fonts may be referenced through nested relationship parts ([USENIX 2023](https://www.usenix.org/system/files/sec23summer_235-rohlmann-prepub.pdf)); font substitution and embedded-font use are explicit library features (docx4j documents "font substitution and use of embedded fonts") ([docx4j](https://github.com/plutext/docx4j)). Locale-sensitive number formatting is a documented ODF parsing risk area: CVE-2026-6040 involved "ODF number-format blank-width parsing" ([LibreOffice](https://www.libreoffice.org/security/)). Exact normative whitespace-preservation and bidi algorithm text from ISO/IEC 29500 or ODF Part 3: **n.a.** in this session.

---

## 6. Security and privacy

### 6.1 Threat model table

| Threat | DOCX / DOCM specifics | ODT specifics | Evidence |
|---|---|---|---|
| ZIP decompression bomb | POI enforces a minimum inflate ratio; default `1%` (`0.01d`) — "[w]hen the compression is better than `1%` for any given read package part, parsing fails and indicates a Zip-Bomb"; max entry size default 4 GB; max extracted text default ~10 million chars | Same ZIP substrate; ODF requires STORED/DEFLATED only, which bounds algorithms but not ratios | [Apache POI configuration](https://poi.apache.org/components/configuration.html); [ZipSecureFile](https://poi.apache.org/apidocs/dev/org/apache/poi/openxml4j/util/ZipSecureFile.html); [ODF 1.4 Part 2](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html) |
| Path traversal on extraction ("Zip Slip") | Applies to any code extracting package entries to disk; "a form of directory traversal that can be exploited by extracting files from an archive", enabling overwrite of executables/config and remote command execution; especially prevalent in Java | Identical exposure | [Snyk research](https://security.snyk.io/research/zip-slip-vulnerability) |
| Duplicate/ambiguous entries | POI 5.4.0+ "checks for duplicate ZIP entry names and throws an exception" | Manifest/actual-entry mismatch is used offensively against signatures | [Apache POI](https://poi.apache.org/); [USENIX 2022](https://www.usenix.org/system/files/sec22-rohlmann.pdf) |
| XXE / entity expansion | POI 5.1.0 disallows DocType parsing by default in embedded XML (`DEFAULT_XML_OPTIONS.setDisallowDocTypeDeclaration(false)` reverts) | Same XML substrate; hardening is parser-level | [Apache POI configuration](https://poi.apache.org/components/configuration.html); [OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) |
| External references / SSRF | External graphics store only the URL and are "automatically reloaded when the document is opened" | Floating frames linked to external files were loaded "without prompt" (CVE-2023-2255) | [USENIX 2023](https://www.usenix.org/system/files/sec23summer_235-rohlmann-prepub.pdf); [NVD CVE-2023-2255](https://nvd.nist.gov/vuln/detail/cve-2023-2255) |
| Macros | `.docm`/`.dotm` carry VBA; internet-sourced macro files are blocked by default | `Basic/` and `Scripts/` hold Basic/Python/JavaScript/BeanShell macros, separately signable | [Microsoft Learn](https://learn.microsoft.com/en-us/office/compatibility/xml-file-name-extension-reference-for-office); [Microsoft Learn, macro blocking](https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked); [USENIX 2022](https://www.usenix.org/system/files/sec22-rohlmann.pdf) |
| ActiveX / OLE | ActiveX controls are "disabled by default in Microsoft 365 and Office 2024": you "will not be able to create new ActiveX objects" or "interact with existing ActiveX objects" across Word/Excel/PowerPoint/Visio | n.a. | [Microsoft Support](https://support.microsoft.com/en-us/office/vba/activex-controls-are-disabled-by-default-in-microsoft-365-and-office-2024) |
| Protocol/handler abuse | "A remote code execution vulnerability exists when MSDT is called using the URL protocol from a calling application such as Word" (CVE-2022-30190, published 06/01/2022) | n.a. | [NVD](https://nvd.nist.gov/vuln/detail/cve-2022-30190) |
| Foreign-content import chains | `altChunk` lets a DOCX pull in RTF/HTML/XHTML/rfc822 content for the consumer to parse | Sub-documents/embedded objects in package | [MS-OI29500](https://learn.microsoft.com/en-us/openspecs/office_standards/ms-oi29500/c391c28f-1b03-4a21-a4f8-4d9cddd4a95c) |
| Memory-safety bugs in importers | CVE-2026-4430: out-of-bounds write "via crafted OOXML documents with mismatched encryption salt parameters" (CVSS 4.0 5.4; LibreOffice 26.2 < 26.2.3, 25.8 < 25.8.7) | CVE-2026-6040: heap use-after-free in ODF number-format blank-width parsing (fixed 26.2.3 / 25.8.7) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-4430); [LibreOffice](https://www.libreoffice.org/security/) |
| Signature forgery / manipulation | Attack chain wraps a legacy `.doc` signature into an OOXML package as `_xmlsignatures/sig1.xml` with `_xmlsignatures/origin.sigs` and `_xmlsignatures/_rels` | "Content Manipulation with Signature Upgrade" abuses renaming `macrosignatures.xml` to `documentsignatures.xml`; only those two names are processed as signature files | [USENIX 2023](https://www.usenix.org/system/files/sec23summer_235-rohlmann-prepub.pdf); [USENIX 2022](https://www.usenix.org/system/files/sec22-rohlmann.pdf) |
| Metadata/revision leakage | `docProps/core.xml` and `docProps/app.xml` contain "the author, creation time, Office version, creator, last modifier, and associated timestamps" | `meta.xml` carries document metadata | [USENIX 2023](https://www.usenix.org/system/files/sec23summer_235-rohlmann-prepub.pdf); [LibreOffice Help](https://help.libreoffice.org/latest/en-GB/text/shared/00/00000021.html?DbPAR=SHARED) |
| Antivirus/type-confusion at the gateway | ClamAV types OOXML by container inspection: `CL_TYPE_OOXML_WORD` ("Microsoft Office Open Word 2007+") "may be assigned to a Zip file containing files with specific names"; OLE2 is Target Type 2, "including specific macros" | No ODF-specific `CL_TYPE` is listed on the file-types page | [ClamAV docs](https://docs.clamav.net/appendix/FileTypes.html) |

### 6.2 Hardening guidance that is actually documented

**Parser configuration.** The safest XXE posture is to "disable DTDs (External Entities) completely" — e.g. `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` — which "also makes the parser secure against denial-of-service attacks such as Billion Laughs"; the minimal rule set is: disable DOCTYPE, disable external entities, disable external DTD loading, enable secure processing, disable XInclude, limit entity expansion, avoid legacy parsers, and "[n]ever parse untrusted XML with default settings". Java parsers historically have XXE enabled by default, and the `DocumentBuilderFactory`/`SAXParserFactory` countermeasures "require Java 7 update 67, Java 8 update 20, or later because earlier Java versions are affected by CVE-2014-6517" ([OWASP](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)).

**Process architecture.** Apache POI's security guidance is unusually candid and generalizes well to any document pipeline: "never parsing files from untrusted or unknown sources"; POI "cannot fully protect against some documents causing impact on the current process"; expect `StackOverflowError`, `OutOfMemoryError`, index errors and integer overflows, which POI "typically does not classify … as security vulnerabilities"; use "a broad catch statement"; expect "prolonged CPU usage and long parsing times" and provide a way to stop processing; for sensitive environments "extract[] document-parsing logic into a separate process", bound its memory, time it out, and restart it on crash; secure the temp-file directory; clear sensitive heap data (e.g. `Biff8EncryptionKey` `ThreadLocal`s); and never run POI code "in a JVM where untrusted users have access to heap memory" ([Apache POI security guidance](https://poi.apache.org/security.html)).

**Application-layer controls.** Office blocks VBA macros in files carrying Mark of the Web across Access, Excel, PowerPoint, Project, Publisher, Visio and Word on Windows (not Mac/Android/iOS/web), rolled out from Current Channel (Preview) Version 2203 on April 12, 2022 through Semi-Annual Enterprise Channel Version 2208 on January 10, 2023, with separate Publisher (February 14, 2023) and Project (August 13, 2024) timelines; macro-enabled templates (`.dot`, `.dotm`, `.pot`, `.potm`, `.xlt`, `.xltm`) and add-ins (`.ppa`, `.ppam`, `.xla`, `.xlam`) are covered ([Microsoft Learn](https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked)). ActiveX is disabled by default in Microsoft 365 and Office 2024 ([Microsoft Support](https://support.microsoft.com/en-us/office/vba/activex-controls-are-disabled-by-default-in-microsoft-365-and-office-2024)).

**Sanitization caveat.** Converters are not sanitizers: Mammoth explicitly documents "[n]o source sanitization; untrusted input requires extreme care", though "[e]xternal-file access is disabled by default" ([mammoth.js](https://github.com/mwilliamson/mammoth.js)); Pandoc warns that "[g]enerated HTML is not guaranteed safe" ([Pandoc manual](https://pandoc.org/MANUAL.html)).

### 6.3 Signature and encryption capability distinctions

| Package class | Macros | Encryption | Signatures |
|---|---|---|---|
| `.docx` | Cannot store VBA ([MS](https://learn.microsoft.com/en-us/office/compatibility/xml-file-name-extension-reference-for-office)) | ECMA-376 standard/agile via [MS-OFFCRYPTO] envelope ([MS-OFFCRYPTO](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/cab78f5c-9c17-495e-bea9-032c63f02ad8)) | OPC package signatures with Digital Signature Origin part ([MS](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/digital-signatures-overview)) |
| `.docm` / `.dotm` | Stores VBA; `.docm` created when VBA present; documents from `.dotm` "do not inherit the VBAProject part" ([MS](https://learn.microsoft.com/en-us/office/compatibility/xml-file-name-extension-reference-for-office)) | Same as `.docx` | Same as `.docx` |
| `.odt` | Basic macros in `Basic/`, scripting languages in `Scripts/` ([USENIX 2022](https://www.usenix.org/system/files/sec22-rohlmann.pdf)) | Per-entry package encryption declared in the manifest; manifest itself "shall not be encrypted" ([OASIS](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)) | `META-INF/documentsignatures.xml` (documents) and `META-INF/macrosignatures.xml` (macros); a single-XML-file ODF document "cannot be digitally signed" ([USENIX 2022](https://www.usenix.org/system/files/sec22-rohlmann.pdf)) |

---

## 7. Encryption and digital signatures in detail

### 7.1 OOXML / MS-OFFCRYPTO

[MS-OFFCRYPTO] "[s]pecifies the Office Document Cryptography Structure, which is the file format for documents with Information Rights Management policies applied", currently at revision 14.0 (2026-02-17) ([Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/3c34d72a-1a61-4b52-a893-196f9157f083)). On ECMA-376 document encryption:

- "ECMA-376 document encryption using standard encryption does not support CBC" and "does not have a provision for detecting corruption"; "[a] block cipher—specifically, AES—is not known to be subject to bit-flipping attacks."
- "ECMA-376 documents using agile encryption are required to use CBC and corruption detection" and "are not subject to the issues noted for standard encryption."
- "Passwords are limited to 255 Unicode code points."
- Algorithm guidance: "the SHA-2 series of hashing algorithms is preferred"; "MD2, MD4, and MD5 are not recommended"; "[o]lder cipher algorithms, such as DES, are also not recommended" ([MS-OFFCRYPTO, ECMA-376 Document Encryption](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/cab78f5c-9c17-495e-bea9-032c63f02ad8)).

Agile key derivation is specified as a PKCS#5-derived iterated hash ([MS-OFFCRYPTO §2.3.4.11](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/74d60145-a0f0-44be-99ce-c65d211b4eb7)):

```text
H0     = H(salt + password)                    # salt MUST be random, stored in
                                               # PasswordKeyEncryptor.saltValue in \EncryptionInfo
Hn     = H(iterator + Hn-1)                    # iterator: unsigned 32-bit, starts 0x00000000,
                                               # incremented monotonically to spinCount iterations
Hfinal = H(Hn + blockKey)                      # blockKey prevents identical ciphertext across blocks
# If |Hfinal| < keyBits: pad by appending bytes of value 0x36; if larger: truncate.
```

Note the specification pages fetched here define the *mechanism* (hash `H()` determined by `PasswordKeyEncryptor.hashAlgorithm`, key size by `keyBits`) rather than mandating SHA-512/AES on that page; the concrete algorithm identifiers live in the `\EncryptionInfo` descriptor (same source). The compound-file envelope structure (`EncryptionInfo` / `EncryptedPackage` streams) is not described on the pages fetched (**n.a.** here), but is implemented in practice: msoffcrypto-tool supports "ECMA-376 Agile Encryption", "ECMA-376 Standard Encryption", "ECMA-376 Extensible Encryption", legacy "Office Binary Document RC4 CryptoAPI"/"RC4", "XOR Obfuscation" and Office 95-era schemes, with keys supplied as passwords, intermediate keys, or private keys for escrow certificates; `verify_password=True` works "only for ECMA-376 Agile/Standard Encryption" and HMAC payload verification (`verify_integrity=True`) "only for ECMA-376 Agile Encryption" ([msoffcrypto-tool docs](https://msoffcrypto-tool.readthedocs.io/)).

**OPC signatures.** A package signature is composed of references to signed parts (`IOpcSignaturePartReference`), signed relationships grouped per Relationships part (`IOpcSignatureRelationshipReference`), references to application data in the signature markup (`IOpcSignatureReference`), custom objects, and X.509 certificates; on signing, "[e]ach item to be signed has its cryptographic hash value, or digest value, computed", stored in the signature markup along with "the encrypted hash value computed for the entire signature, called the signature value"; the **Digital Signature Origin part** "does not contain signature markup" but "serves as the starting point for locating all signatures in the package" ([Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/digital-signatures-overview)).

**Interoperability limits are documented as exploitable.** The USENIX 2023 analysis of Microsoft Office's OOXML signatures documents an attack that takes a signature file from a signed legacy `.doc` (stored in an `_xmlsignatures` folder under a random numeric name), renames it `sig1.xml`, and inserts it into an OOXML package together with `_xmlsignatures/origin.sigs` and `_xmlsignatures/_rels` ([USENIX Security 2023](https://www.usenix.org/system/files/sec23summer_235-rohlmann-prepub.pdf)).

### 7.2 ODF encryption, checksums and signatures

ODF encryption is per-file-entry and manifest-declared ([ODF 1.4 Part 2](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)):

- Stages: "[a] single start key is generated and used for all of the keys that will be derived", "[t]he derived key is generated based on the start key", then "[t]he files are encrypted based on the derived key and the encryption algorithm".
- "The manifest shall not be encrypted." Each encrypted entry "shall be compressed with the `\"deflate\"` algorithm before being encrypted", "shall be flagged as `'STORED'`", and the plaintext size "shall be contained in the `manifest:size` attribute".
- Legacy process: 20-byte SHA-1 digest of the UTF-8 password as start key; "PBKDF2 algorithm based on the HMAC-SHA-1 function" for derivation; per-file 16-byte random salt; unique 128-bit derived key per file; "[t]he default iteration count for the algorithm is 1024"; 8-byte IV; "Blowfish algorithm in 8-bit cipher feedback (8-bit CFB) mode".
- `<manifest:encryption-data>` is usable within `<manifest:file-entry>`, carries `manifest:checksum` and `manifest:checksum-type`, and contains `<manifest:algorithm>`, `<manifest:key-derivation>` and `<manifest:start-key-generation>`.
- `manifest:checksum-type` values include `SHA1/1K` — "SHA1 algorithm … applied to the first `1024` bytes of the compressed unencrypted file" — and the URN form `urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha1-1k`. The checksum "is used to confirm that a decryption is successful. It should not be regarded as a security feature."
- Algorithm identifiers: `manifest:algorithm-name` accepts an IRI listed in §5.2 of [xmlenc-core], `Blowfish CFB`, or `urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#blowfish`; producers supporting encryption "shall support the value `Blowfish CFB`" and consumers "shall support" both Blowfish forms; implementation-defined alternatives "may be specified by extended conforming packages only".
- `manifest:key-derivation-name` accepts `PBKDF2` ("with HMAC-SHA-1 for the Pseudo-Random Function"), its URN form, implementation-defined IRIs (extended packages only), and `PGP`; when PBKDF2 is used, `<manifest:encryption-data>` "shall contain a `<manifest:start-key-generation>` child element".
- `manifest:start-key-generation-name` accepts `SHA1` or an IRI listed in §5.7 of [xmlenc-core].

**Argon2 support in ODF: n.a.** — not found in the fetched Part 2 text, and TDF's ODF 1.3/1.4 feature article explicitly does not mention Argon2 ([TDF](https://blog.documentfoundation.org/blog/2025/08/01/whats-new-in-odf-1-3-and-1-4/)). Implementation-level reality per TDF: content is compressed, a random salt and IV are generated, "[a] key is derived from the password using PBKDF2", and AES — "typically … with a 256-bit key" — encrypts the content; "[n]ot all applications supporting ODF implement encryption in the same way", which "may have repercussions on interoperability" ([TDF, ODF format security](https://blog.documentfoundation.org/blog/2025/10/31/odf-format-security/)).

**ODF signatures** are XML digital signatures over a content hash signed with the signer's private key, stored in `META-INF/documentsignatures.xml` ([TDF](https://blog.documentfoundation.org/blog/2025/10/31/odf-format-security/)); ODF 1.3 formalized signatures with XAdES support and part-level signing ([TDF](https://blog.documentfoundation.org/blog/2025/08/01/whats-new-in-odf-1-3-and-1-4/)). Their documented weaknesses: applications "always include all existing files of the ODF package as references in the signature, except for the signature file itself"; the hash of `META-INF/manifest.xml` participates in the signature; "[a]ll applications except Microsoft Office consider the ODF file corrupt when the package contains files that are not referenced within `META-INF/manifest.xml`"; files whose names contain "signatures" in `META-INF` are excluded from ordinary package checks but only the two canonical names are processed, so an extra pseudo-signature file yields a "partial signature" rather than corruption — and "the ODF specifications do not precisely define the treatment of signature-file naming in this situation" ([USENIX Security 2022](https://www.usenix.org/system/files/sec22-rohlmann.pdf)).

---

## 8. Interoperability and conversion

### 8.1 Strict/Transitional and profile mismatch

Because Strict forbids Part-4 legacy markup — most visibly VML — Strict↔Transitional conversion is asymmetric: producing Strict from legacy content requires re-expressing graphics in DrawingML and dropping backwards-compatibility constructs, and Strict "has less support for backwards compatibility when converting documents from older formats" ([Library of Congress](https://www.loc.gov/preservation/digital/formats/fdd/fdd000399.shtml)). Since both profiles use the `.docx` extension, profile identity must be detected from markup, not filename ([Microsoft Learn](https://learn.microsoft.com/en-us/office/compatibility/xml-file-name-extension-reference-for-office)).

### 8.2 DOCX ↔ ODT loss modes (authoritative vendor table)

Microsoft classifies ODT support as "Supported" ("[c]ontent, formatting, and usability will not be lost") or "Partially Supported" ("[n]o text or data is lost, but formatting and how you work with text or graphics might be different") ([Microsoft Support](https://support.microsoft.com/en-us/word/differences-between-the-opendocument-text-odt-format-and-the-word-docx-format-used-by-word-for-the-w)). Selected rows:

| Area | Feature | Level | Documented caveat |
|---|---|---|---|
| Content | Insert Break | Partially Supported | Continuous section breaks may lose top/bottom margins, headers/footers, borders, line numbering |
| Content | Tables | Partially Supported | ">64 columns not supported" |
| Content | Text boxes | Partially Supported | "Text boxes cannot be nested" |
| Content | Table of Contents | Partially Supported | "TOC loses items labeled with a SEQ field" |
| Content | Footnotes-Endnotes | Supported | "Custom separators not supported" |
| Content | Index | Supported | "Multiple columns indices not supported" |
| Content | Pictures | Supported | "Pictures from a document created in OpenOffice are not displayed" |
| Formatting | Styles | Supported | Style count increases after ODT save; "all formatting in ODF is style based" |
| Formatting | Borders and Shading | Supported | Shading patterns unsupported; picture borders converted to solid lines |
| Formatting | Highlighter | Supported | Highlighting converted to character background color |
| Formatting | Tabs | Supported | "Positional tabs are not supported" |
| Formatting | Bullets and Numbering | Supported | Spacing differences; OpenOffice default bullets change appearance |
| Collaboration | Mail Merge | Supported | Data-source connection must be re-established after editing in another ODF application |

All rows: ([Microsoft Support](https://support.microsoft.com/en-us/word/differences-between-the-opendocument-text-odt-format-and-the-word-docx-format-used-by-word-for-the-w)). Note this table is scoped to Word for the web and ODT; the page provided "ODT support tables only" and no rows labeled "Not supported" (same source).

### 8.3 Application behaviors with authoritative evidence

- **LibreOffice** loads and saves ODF by default, exposes ODF 1.0/1.1 for backwards compatibility, and offers Extended variants; ODF 1.3/1.3 Extended arrived in LibreOffice 7.0 ([LibreOffice Help](https://help.libreoffice.org/latest/en-GB/text/shared/00/00000021.html?DbPAR=SHARED)). ODF 1.4 is "not yet implemented in LibreOffice" as of January 2026 ([TDF dev blog](https://dev.blog.documentfoundation.org/2026/01/22/validating-odf-and-ooxml-files/)). LibreOffice's own OOXML validation tooling of choice is Office-o-tron 0.8.8 (same source).
- **Google Docs**: as of May 19, 2025, viewing/editing client-side encrypted Word files is in beta, limited to "`.docx` Microsoft Word file types" with a 20 MB maximum, saving "in the original Word format"; Google warns users "may encounter incompatibilities for certain features", that some features "may not be displayed" or "may not be editable" yet "will be preserved in the document and viewable in Microsoft Office", while "[o]ther features may be lost or altered", with an in-document notification when editing will cause loss ([Google Workspace Updates](https://workspaceupdates.googleblog.com/2025/05/edit-client-side-encrypted-microsoft-word-files-with-google-docs.html)).
- **Conversion engines.** LibreOffice-based conversion remains the pragmatic high-fidelity path: `libreoffice --headless --convert-to pdf …` is documented, and unoserver keeps LibreOffice resident in listener mode, lowering CPU load "somewhere between 50% and 75%", i.e. "between two and four times as many documents" per unit time; only LibreOffice is officially supported and filters can be pinned (`--input-filter 'writer8'`) ([unoserver](https://github.com/unoconv/unoserver)). Pandoc converts among many formats including `docx` and ODT/OpenDocument but warns that "[c]onversions may be lossy" and "formatting details and complex tables may not survive" ([Pandoc manual](https://pandoc.org/MANUAL.html)). Gotenberg wraps Chromium/LibreOffice/fonts into an API that converts documents and URLs to PDF and manipulates PDFs (merge, split, encrypt, watermark, metadata, Factur-X/ZUGFeRD) ([Gotenberg docs](https://gotenberg.dev/docs/getting-started/introduction)).
- **Round-trip hazards specific to templating/HTML paths.** Mammoth ignores table formatting including borders, renders text-box content "as a separate paragraph afterward", ignores underlines and comments by default, and describes its document-transform API as unstable ([mammoth.js](https://github.com/mwilliamson/mammoth.js)). docxcompose merges documents but "[h]eaders and footers from other documents are ignored; the first document's header and footer are used throughout the merged file" ([docxcompose](https://github.com/4teamwork/docxcompose)).
- **Macros, content controls, formulas, signatures across conversion:** no authoritative cross-application fidelity matrix was located in this session (**n.a.**). Treat macro, content-control and signature preservation across DOCX↔ODT conversion as unverified and test-driven.

---

## 9. Accessibility, metadata, localization, archival and preservation

**Accessibility.** Microsoft's Accessibility Checker encodes the practical structural contract for DOCX: the error-level rule "All non-text content has alternative text (alt text)" verifies "[a]ll objects have alt text and the alt text doesn't contain image names or file extensions"; "Tables specify column header information" is also error-level; "Table has a simple structure" warns on split/merged/nested cells; "Documents use heading styles" is a tip verifying "[c]ontent is organized with headings and/or a Table of Contents (TOC)"; and AI-generated alt text appears as "Suggested alternative text" for review ([Microsoft Support](https://support.microsoft.com/en-us/office/rules-for-the-accessibility-checker-651e08f2-0fc3-4e10-aaca-74b4a67101c1)). On the ODF side, ODF 1.3 claims "[i]mproved compliance with accessibility standards" and ODF 1.4 targets "[c]learer semantics for assistive technologies" and structural tags for headings, lists and tables ([TDF](https://blog.documentfoundation.org/blog/2025/08/01/whats-new-in-odf-1-3-and-1-4/)); ODF's heading model natively encodes division structure via `<text:h>` ([ODF 1.4 Part 3](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part3-schema.html)). Exact WCAG/EN 301 549/PDF-UA interaction requirements: **n.a.** in this session.

**Metadata models.** DOCX uses OPC core properties (Dublin Core based, plus OPC-specific elements) in `docProps/core.xml` with application properties in `docProps/app.xml` ([Library of Congress](https://www.loc.gov/preservation/digital/formats/fdd/fdd000363.shtml); [USENIX 2023](https://www.usenix.org/system/files/sec23summer_235-rohlmann-prepub.pdf)). ODF uses `meta.xml` plus RDF-based metadata with published ontologies for document and package metadata manifests ([LibreOffice Help](https://help.libreoffice.org/latest/en-GB/text/shared/00/00000021.html?DbPAR=SHARED); [OASIS](https://www.oasis-open.org/standard/opendocumentv1-2/)).

**Preservation assessments.**

- DOCX Transitional: LoC records PUID-level identity and relationships (subtype of the OOXML family and of OPC/ZIP 6.2.0; "[m]ay contain" MCE markup; modified version DOCX Strict; associated `.dotx`, `.docm`, `.dotm`), notes that since 2006 the specification "has had very few changes other than clarifications and corrections", that the Library "has over 2 TB of DOCX files in its digital collections in 2024", and that DOCX is "listed as an Acceptable format for Textual Works – Digital and Textual Works – Electronic Serials" ([LoC DOCX FDD](https://www.loc.gov/preservation/digital/formats/fdd/fdd000397.shtml)).
- ODT: LoC describes ODF text as "[f]ormat for editable textual documents", notes that "[v]arious features of the ZIP File Format are not permitted in ODF", that the manifest "is mandatory in all ODF packages", that the ODF package spec defines the manifest form plus "[o]ptions for embedded metadata", "[o]ptions for digital signatures" and "[o]ptions for encryption", and that markup changes from ODF 1.1 to 1.2 were "few", mainly lists/tables/references formatting ([LoC ODT FDD](https://www.loc.gov/preservation/digital/formats/fdd/fdd000427.shtml)).
- Both FDDs note the workflow reality that editable office formats are typically "converted to a static format rather than an editing format for final publication or archiving" ([LoC ODF family](https://www.loc.gov/preservation/digital/formats/fdd/fdd000247.shtml); [LoC ODT](https://www.loc.gov/preservation/digital/formats/fdd/fdd000427.shtml)).
- The Library's Recommended Formats Statement imposes a hard technical-protection constraint on digital textual works: "Files must contain no measures (such as digital rights management [DRM] technologies or encryption) that control access to or prevent use of the digital work" ([LoC RFS, Textual Works](https://www.loc.gov/preservation/resources/rfs/text.html)). Specific named format preference lists were not present in the fetched page text (**n.a.**).

**Practical archival risk register** (each grounded above): encryption blocks ingest and validation; macros are both a security and a rendering dependency; external image/frame links break or leak ([USENIX 2023](https://www.usenix.org/system/files/sec23summer_235-rohlmann-prepub.pdf); [NVD CVE-2023-2255](https://nvd.nist.gov/vuln/detail/cve-2023-2255)); embedded/substituted fonts change layout ([docx4j](https://github.com/plutext/docx4j)); MCE-ignored namespaces mean archived bytes may contain features no current consumer renders ([LoC MCE FDD](https://www.loc.gov/preservation/digital/formats/fdd/fdd000396.shtml)); and metadata carries authorship/timestamp trails that may need scrubbing before release ([USENIX 2023](https://www.usenix.org/system/files/sec23summer_235-rohlmann-prepub.pdf)). PDF/A conversion specifics (ISO 19005 conformance levels, veraPDF profiles): **n.a.** — not verified in this session.

---

## 10. Performance and engineering

**Parsing strategy.** The dominant industry shift is toward streaming/pull parsing for extraction workloads: Apache Tika 3.3.2 (16 July 2026) "[p]orted the 4.x SAX-based OOXML parsers for `docx`, `pptx`, `xlsx`, and `vsdx` to 3.x" and "made SAX the default" ([Apache Tika](https://tika.apache.org/)). Apache POI similarly recommends its streaming APIs for large workloads: "[t]he core POI APIs are not optimized to avoid excessive memory use. POI provides streaming APIs for reading and writing XLSX files" ([Apache POI security guidance](https://poi.apache.org/security.html)). Xerces-C++ offers DOM, SAX and SAX2 APIs with "[o]n-the-fly validation for creating XML editors" ([Xerces-C++](https://xerces.apache.org/xerces-c/)), and Apache Santuario provides both "a mature DOM-based implementation of XML Signature and XML Encryption" and "a more recent StAX-based (streaming) implementation" ([Apache Santuario](https://santuario.apache.org/)).

**Selective part loading and memory behavior.** OPC/ODF's part granularity is the lever: load only `document.xml`/`content.xml` for text extraction, and only styles/numbering when formatting matters. Open XML SDK supports opening read-only (`Open(String, false)` — "[c]hanges made to the document will not be saved") and notes AutoSave is on by default when opened for editing ([Microsoft Learn](https://learn.microsoft.com/en-us/office/open-xml/word/how-to-open-and-add-text-to-a-word-processing-document)). MCE pre-processing can be limited to loaded parts via `ProcessLoadedPartsOnly` "when working on specific document parts while leaving the rest untouched, such as when ensuring minimal modification to the file" ([Microsoft Learn](https://learn.microsoft.com/en-us/office/open-xml/general/introduction-to-markup-compatibility)). POI adds memory controls: temp-file thresholds for large ZIP entries, optional temp-file encryption (`setEncryptTempFiles`, default `false`), temp-file-backed package parts (`ZipPackage.setUseTempFilePackageParts`, default `false`), and per-allocation byte-array override (`IOUtils.setByteArrayMaxOverride`, `-1` to use per-record limits) ([Apache POI configuration](https://poi.apache.org/components/configuration.html)).

**Validation and schema versions.** For ODF, the ODF Toolkit validator validates `meta.xml`, `content.xml`, `styles.xml`, `settings.xml`, `manifest.xml` and signature files against version-detected schemas (ODF 1.0–1.3 bundled, forced via `-1.0`…`-1.3`), can use the strict schema or externally supplied schemas, and auto-selects MathML 1.01 DTD vs MathML 3 schema ([ODF Validator](https://odftoolkit.org/conformance/ODFValidator.html)); version 0.13.0 adds ODF 1.4 support and is invoked as `java -jar odfvalidator-0.13.0-jar-with-dependencies.jar test.odt`, while OOXML validation uses `java -jar officeotron-0.8.8.jar ~/test.docx` ([TDF dev blog](https://dev.blog.documentfoundation.org/2026/01/22/validating-odf-and-ooxml-files/)). For DOCX, Open-Xml-PowerTools documents the ability to "validate Open XML and retrieve validation errors" ([Open-Xml-PowerTools](https://github.com/EricWhiteDev/Open-Xml-PowerTools)), and odfpy performs producer-side checks that "prevent invalid documents and raise exceptions for invalid elements, unknown grammar attributes, missing required attributes, or text in elements that do not allow it" ([odfpy on PyPI](https://pypi.org/project/odfpy/)).

**Diff/merge and semantic normalization.** Evidence-backed capabilities: Open-Xml-PowerTools can "compare DOCX files with revision tracking", "manage and accept tracked revisions", "split DOCX/PPTX", "search and replace with regular expressions" and "retrieve revision lists" ([Open-Xml-PowerTools](https://github.com/EricWhiteDev/Open-Xml-PowerTools)); the Open XML SDK can "[s]earch and replace content using regular expressions", "[s]plit one file into multiple files and combine multiple files into one file" and "[u]pdate cached data and embedded spreadsheets for charts" ([Open XML SDK](https://github.com/dotnet/Open-XML-SDK)); unoserver's `unocompare` "compares an older file with a newer file and produces the comparison result as a converted output file" ([unoserver](https://github.com/unoconv/unoserver)). Run-level normalization before diffing is a practical necessity given run fragmentation (§5).

**Repair/recovery and corpus design.** POI's guidance to expect arbitrary exceptions, cap CPU time, and sandbox parsing is effectively a repair/recovery architecture ([Apache POI security guidance](https://poi.apache.org/security.html)); duplicate-entry detection (POI 5.4.0+) is an example of format-level repair checks ([Apache POI](https://poi.apache.org/)). For corpora, both LoC FDD families provide the format-variant taxonomy to sample against (Transitional vs Strict, ODF 1.1/1.2/1.3/1.4, MCE-bearing files) ([LoC OOXML family](https://www.loc.gov/preservation/digital/formats/fdd/fdd000395.shtml); [LoC ODF family](https://www.loc.gov/preservation/digital/formats/fdd/fdd000247.shtml)), and docxcompose's "blackbox whole-file comparison tests using `FixtureDocument` and `ComposedDocument`" is a concrete fixture-based testing pattern ([docxcompose](https://github.com/4teamwork/docxcompose)).

**Reproducible generation.** Normalize ZIP metadata (timestamps, entry order in C-locale name order, ownership, permissions) as per Reproducible Builds guidance ([Reproducible Builds](https://reproducible-builds.org/docs/archives/)); for ODT additionally keep `mimetype` first and STORED ([ODF 1.4 Part 2](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html); [webodf.org](https://webodf.org/)).

---

## 11. Open-source ecosystem inventory

Activity dates below are last-push timestamps from repository metadata retrieved in this session; licenses are as stated by the project or its license file.

### 11.1 Native object-model libraries (read/write the XML directly)

| Project | Language | License | Latest / activity | Capabilities & notes | Primary URL |
|---|---|---|---|---|---|
| Apache POI (XWPF/OOXML4J) | Java (requires Java 1.8+) | Apache-2.0 (per project site; GitHub mirror metadata shows no SPDX field) | 5.5.1 released 30 Nov 2025; repo pushed 2026-08-13 | Read/write DOC/DOCX/XLS/XLSX/PPT/PPTX, OLE2 + OOXML; components HWPF/XWPF, HSSF/XSSF/SXSSF, HSLF/XSLF, HSMF/HMEF, HDGF/XDGF, HPBF, POIFS, HPSF; duplicate ZIP entry checks in 5.4.0+; zip-bomb/XXE/memory controls; documented security guidance | [poi.apache.org](https://poi.apache.org/), [repo metadata](https://api.github.com/repos/apache/poi), [configuration](https://poi.apache.org/components/configuration.html) |
| docx4j | Java (98.2%) | Apache-2.0 | 69 tags; repo pushed 2026-07-30 | JAXB-based; open/create/edit/save OOXML packages (docx, pptx, xlsx, Word 2007 `pkg`); export HTML, export PDF "using 3 strategies", import XHTML; content-control data binding, MERGEFIELD, OpenDoPE repeats/conditionals; font substitution and embedded fonts | [github.com/plutext/docx4j](https://github.com/plutext/docx4j), [repo metadata](https://api.github.com/repos/plutext/docx4j) |
| Open XML SDK | C# | MIT | 3.3.0 (Mar 5, 2025); repo pushed 2026-08-12 | Strongly typed OOXML API over System.IO.Packaging; OPC packages, Flat OPC, Open XML markup; regex search/replace; split/combine; chart cached-data updates; MCE processing settings | [github.com/dotnet/Open-XML-SDK](https://github.com/dotnet/Open-XML-SDK), [repo metadata](https://api.github.com/repos/dotnet/Open-XML-SDK) |
| python-docx | Python | MIT | v1.2.0 (date not shown); repo pushed 2026-08-01 | Create/update `.docx`: headings, paragraphs, runs, lists, pictures, tables, page breaks | [python-docx docs](https://python-docx.readthedocs.io/en/latest/), [repo metadata](https://api.github.com/repos/python-openxml/python-docx) |
| PHPWord | PHP | LGPL-3.0 (per LICENSE: "GNU Lesser General Public License version 3") | repo pushed 2026-08-12 | "pure PHP library for reading and writing word processing documents" | [LICENSE](https://raw.githubusercontent.com/PHPOffice/PHPWord/master/LICENSE), [repo metadata](https://api.github.com/repos/PHPOffice/PHPWord) |
| docx (dolanmiu) | TypeScript | MIT | 9.7.1 (May 27, 2026); repo pushed 2026-08-07 | Declarative generation/modification of `.docx` in Node and browser: paragraphs, bullets, tables, images, margins, headers/footers | [github.com/dolanmiu/docx](https://github.com/dolanmiu/docx) |
| docx (Ruby) | Ruby (2.6+) | MIT | v0.10.0 (Sept 12, 2025) | Read paragraphs/bookmarks/tables; render paragraphs as HTML; insert at bookmarks; substitute text; copy/insert table rows; exposes Nokogiri nodes/XPath; TODOs include inherited-formatting computation | [github.com/ruby-docx/docx](https://github.com/ruby-docx/docx) |
| Caracal | Ruby | MIT | v1.4.0 (date not stated) | Generates OOXML from HTML-style DSL; styles, tables, images, nested lists, bookmarks; "[n]ot an HTML-to-Word translator"; requires OOXML units; pre-Word-2010 unsupported; experimental `iframe` external inclusion | [github.com/urvin-compliance/caracal](https://github.com/urvin-compliance/caracal) |
| docx-rs | Rust | MIT | repo pushed 2026-07-28 | "A .docx file writer with Rust/WebAssembly" | [repo metadata](https://api.github.com/repos/bokuweb/docx-rs) |
| ODF Toolkit (ODFDOM, validator, XSLT runner) | Java (67.9%) | Apache-2.0 | 0.13.0 (2026-01-23); repo pushed 2026-04-18 | Create/scan/manipulate ODF (ISO/IEC 26300); ODF Validator for conformance; XSLT over package streams without extraction; Simple API deprecated | [odftoolkit.org](https://odftoolkit.org/), [github.com/tdf/odftoolkit](https://github.com/tdf/odftoolkit), [repo metadata](https://api.github.com/repos/tdf/odftoolkit) |
| odfpy | Python | Listed on PyPI as "Apache Software License, GNU General Public License (GPL), GNU Library or Lesser General Public License (LGPL)"; GitHub metadata reports GPL-2.0 | 1.4.1; repo pushed 2026-04-07 | Read/write ODF 1.2; CSV→spreadsheet; ODF→(X)HTML; package↔flat XML; metadata list/change; outline; validity checks; API generated from RELAX NG grammar | [PyPI](https://pypi.org/project/odfpy/), [repo metadata](https://api.github.com/repos/eea/odfpy) |
| ezodf | Python (CPython 2.7/3.2+) | MIT (per PyPI) | 0.3.2; latest NEWS entry 0.3.1 Dec 2015; repo pushed 2022-11-22 | Create/open ODT/ODS/ODP/ODG and templates; extract/add/modify/delete; spreadsheet cell APIs; 0.2.5 notes "development stopped - for now" | [PyPI](https://pypi.org/project/ezodf/), [repo metadata](https://api.github.com/repos/T0ha/ezodf) |
| lpod-python (lpOD) | Python | not stated in repo README | Branches `legacy`/`current`/`master`; documentation "currently inaccurate" | Implements ISO/IEC 26300 API | [github.com/lpod/lpod-python](https://github.com/lpod/lpod-python) |
| UniOffice | Go (pure Go, no CGO) | Commercial subscription ("[o]ne commercial license covers your whole team"); repo metadata shows NOASSERTION | repo pushed 2026-08-13 | Create/read/edit DOCX, XLSX, PPTX; PDF export via UniPDF; formula evaluation and data validation | [unidoc.io/unioffice](https://unidoc.io/unioffice/), [repo metadata](https://api.github.com/repos/unidoc/unioffice) |

### 11.2 Templating and document assembly

| Project | Language | License | Activity | Notes | URL |
|---|---|---|---|---|---|
| docxtemplater | JavaScript | Dual: "MIT license *or* the GPLv3 license" | repo pushed 2026-08-04 | DOCX/PPTX (since 3.0.4) and TXT (since 3.33.0) templating; loops, conditions, filters, HTML module, styling module; placeholder inspection APIs; cannot convert to PDF or recompute page numbers/TOC; encryption handled externally (`msoffcrypto`) | [LICENSE.md](https://raw.githubusercontent.com/open-xml-templating/docxtemplater/master/LICENSE.md), [FAQ](https://docxtemplater.com/docs/faq/), [repo metadata](https://api.github.com/repos/open-xml-templating/docxtemplater) |
| docxtpl (python-docx-template) | Python | LGPL-2.1 | repo pushed 2026-07-07 | Jinja2 templating over a `.docx`; uses python-docx for subdocuments; notes python-docx is "not [powerful] for modifying" documents | [github.com/elapouya/python-docx-template](https://github.com/elapouya/python-docx-template) |
| docxcompose | Python | MIT | repo pushed 2026-06-02 | Append/concatenate DOCX; CLI + `Composer` API; headers/footers of non-first documents ignored | [github.com/4teamwork/docxcompose](https://github.com/4teamwork/docxcompose) |
| Open-Xml-PowerTools | C# | MIT | 4.6.0 / "Version 4.6", November 16, 2020 (canonical repo redirected when queried via API) | DOCX↔HTML/CSS, Flat OPC, template population from XML, document comparison with revision tracking, revision accept/manage, validation with error retrieval, split/combine, chart updates | [github.com/EricWhiteDev/Open-Xml-PowerTools](https://github.com/EricWhiteDev/Open-Xml-PowerTools) |
| Caracal | Ruby | MIT | see §11.1 | Also functions as "a `:docx` templating engine"; Tilt/Rails integration | [github.com/urvin-compliance/caracal](https://github.com/urvin-compliance/caracal) |

### 11.3 Extraction and conversion

| Project | Language | License | Activity | Notes | URL |
|---|---|---|---|---|---|
| Apache Tika | Java (3.x requires Java 11) | Apache-2.0 (repo metadata) | 3.3.2 (16 July 2026); 4.0.0-beta-1 (3 July 2026); repo pushed 2026-08-13 | Detection + text/metadata extraction from "over a thousand" file types; SAX-based OOXML parsers now default; Flat ODF detection/parser since 1.25; tightened `tika-server` defaults requiring `enableUnsecureFeatures=true` for `/pipes`, `/async`, `/status` | [tika.apache.org](https://tika.apache.org/), [repo metadata](https://api.github.com/repos/apache/tika) |
| Mammoth (JS) | JavaScript | BSD-2-Clause | repo pushed 2026-08-09 | DOCX→semantic HTML and raw text; style-map customization; ignores table borders; underlines/comments ignored by default; no sanitization; external file access disabled by default; Markdown support deprecated | [github.com/mwilliamson/mammoth.js](https://github.com/mwilliamson/mammoth.js) |
| python-mammoth | Python | BSD-2-Clause | repo pushed 2026-08-09 | Python port of Mammoth | [repo metadata](https://api.github.com/repos/mwilliamson/python-mammoth) |
| docx2python | Python | MIT | repo pushed 2026-08-10 | "Extract docx headers, footers, (formatted) text, footnotes, endnotes, properties, and images" | [repo metadata](https://api.github.com/repos/ShayHill/docx2python) |
| Pandoc | Haskell (+Lua) | "GPL, version 2 or greater" | repo pushed 2026-08-13 | Reader/writer AST conversion across docx, ODT/OpenDocument, HTML, LaTeX, PDF, PPTX, EPUB and many more; filters; explicit lossiness warnings; `wkhtmltopdf` deprecated; generated HTML not guaranteed safe | [Pandoc manual](https://pandoc.org/MANUAL.html), [repo metadata](https://api.github.com/repos/jgm/pandoc) |
| unoserver | Python 3 | MIT | repo pushed 2026-06-10 | LibreOffice listener-mode conversion server (`unoserver`, `unoconvert`, `unocompare`); 50–75% CPU reduction vs per-file headless; filter/option control; stdin/stdout support; only LibreOffice officially supported | [github.com/unoconv/unoserver](https://github.com/unoconv/unoserver) |
| unoconv | Python | GPL-2.0 | **Archived** (archived=true); last push 2023-04-19 | Legacy universal converter via LibreOffice/OpenOffice; superseded in practice by unoserver | [repo metadata](https://api.github.com/repos/unoconv/unoconv) |
| Gotenberg | Go | MIT | repo pushed 2026-08-13 | Docker API: documents/URLs → PDF; PDF merge/split/encrypt/watermark/metadata; Factur-X/ZUGFeRD; bundles Chromium/LibreOffice/fonts | [Gotenberg docs](https://gotenberg.dev/docs/getting-started/introduction), [repo metadata](https://api.github.com/repos/gotenberg/gotenberg) |

### 11.4 Server engines and browser editors

| Project | Language | License | Activity | Notes | URL |
|---|---|---|---|---|---|
| Collabora Online | Shell/C++/JS (repo metadata NOASSERTION) | MPL-2.0 (COPYING: "Mozilla Public License, v. 2.0"); site: "primarily licensed under the MPLv2", some parts other OSS licenses | repo pushed 2026-08-11 (GitHub is "[i]ssue tracker only. Active development is on Gerrit") | Browser-based viewing/editing of text, spreadsheets, presentations; components `wsd/` (web services daemon), `kit/` (renders documents in chroot), `browser/` (JS client) | [COPYING](https://raw.githubusercontent.com/CollaboraOnline/online/master/COPYING), [collaboraoffice.org/online](https://www.collaboraoffice.org/online/), [repo metadata](https://api.github.com/repos/CollaboraOnline/online) |
| ONLYOFFICE Docs (Document Server) | Shell/C++/JS | AGPL-3.0 | repo pushed 2026-07-22 | Community Edition limited to "20 simultaneous document editing connections", no clustering/SLA/white-labeling; commercial license required for proprietary integration or branding removal | [repo metadata](https://api.github.com/repos/ONLYOFFICE/DocumentServer), [licensing FAQ](https://helpcenter.onlyoffice.com/docs/faq/docs-community.aspx) |
| WebODF | JavaScript | AGPL (site); repo metadata shows no SPDX license | Last release notes 0.5.9 (2015-09-04); repo pushed 2020-02-04 | ODF rendering/editing in browser via HTML/CSS; Wodo.TextEditor and Wodo.CollabTextEditor; uses JSZip; guarantees uncompressed `mimetype`; commercial licensing via KO GmbH | [webodf.org](https://webodf.org/), [repo metadata](https://api.github.com/repos/webodf/WebODF) |
| LibreOffice (headless/UNO) | C++/Java/Python bindings | n.a. (license not fetched this session) | 26.2.x branch current per 2026 advisories | `libreoffice --headless --convert-to pdf …`; listener mode for servers; default ODF save; extended ODF variants | [unoserver](https://github.com/unoconv/unoserver), [LibreOffice Help](https://help.libreoffice.org/latest/en-GB/text/shared/00/00000021.html?DbPAR=SHARED), [advisories](https://www.libreoffice.org/security/) |

"ODF.js" as a project distinct from WebODF: **n.a.** (no distinct project verified). AbiWord libraries: **n.a.** (not verified in this session). LibreOfficeKit as a separately documented API: **n.a.** here (Collabora's `kit/` component is documented as the rendering client) ([collaboraoffice.org](https://www.collaboraoffice.org/online/)).

### 11.5 Low-level ZIP / XML / security tooling

| Project | Language | License | Activity | Notes | URL |
|---|---|---|---|---|---|
| libzip | C | BSD ("BSD license" allowing commercial use) | 1.11.4, May 23, 2025; repo pushed 2026-08-12 | Read/create/modify ZIP; Zip64; deflate/bzip2/LZMA/zstd; WinZip AES and legacy PKWARE encryption; memory-buffer input; revert unsaved changes | [libzip.org](https://libzip.org/), [repo metadata](https://api.github.com/repos/nih-at/libzip) |
| minizip-ng | C | zlib-style ("Condition of use and distribution are the same as zlib") | repo pushed 2026-08-07 | Fork of the zlib minizip ZIP manipulation library | [LICENSE](https://raw.githubusercontent.com/zlib-ng/minizip-ng/develop/LICENSE), [repo metadata](https://api.github.com/repos/zlib-ng/minizip-ng) |
| libarchive | C | Per-file BSD-style; COPYING summarizes per-file copyright status | repo pushed 2026-08-12 | Multi-format archive and compression library | [COPYING](https://raw.githubusercontent.com/libarchive/libarchive/master/COPYING), [repo metadata](https://api.github.com/repos/libarchive/libarchive) |
| JSZip | JavaScript | Dual: "MIT license *or* the GPLv3 license" | repo pushed 2025-03-28 | Create/read/edit ZIP in JS (asynchronous) | [LICENSE](https://raw.githubusercontent.com/Stuk/jszip/master/LICENSE.markdown), [repo metadata](https://api.github.com/repos/Stuk/jszip) |
| PizZip | JavaScript | Dual MIT or GPLv3 | repo pushed 2026-07-24 | Fork of JSZip 2.x "because it provides a synchronous Zip library" — the synchronous model docxtemplater depends on | [LICENSE](https://raw.githubusercontent.com/open-xml-templating/pizzip/master/LICENSE.markdown), [npm](https://www.npmjs.com/package/pizzip) |
| lxml | Python | BSD-3-Clause | repo pushed 2026-08-13 | XML toolkit underpinning python-docx/odfpy/ezodf workflows | [repo metadata](https://api.github.com/repos/lxml/lxml) |
| Xerces-C++ | C++ | Apache-2.0 | Version 3.3.0, source-only distribution | Validating parser with DOM/SAX/SAX2, XML Schema, XInclude; **"Xerces-C++ currently lacks active maintainers"** and may not promptly address bugs or security risks | [xerces.apache.org/xerces-c](https://xerces.apache.org/xerces-c/) |
| Apache Santuario (XML Security for Java) | Java | Apache-2.0 (repo metadata; site does not state license name) | 4.0.4 and 3.0.6 (April 2025); repo pushed 2026-08-10 | JSR-105 API; DOM and StAX implementations of XML Signature and XML Encryption; C++ version "officially retired as an Apache Project", forked to Shibboleth, "estimated to be fully retired sometime before 2030"; CVE-2023-44483 fixed October 2023 | [santuario.apache.org](https://santuario.apache.org/), [repo metadata](https://api.github.com/repos/apache/santuario-xml-security-java) |
| msoffcrypto-tool | Python | MIT | repo pushed 2026-01-12 | Decrypt/encrypt Office files; ECMA-376 agile/standard/extensible, RC4 CryptoAPI, RC4, XOR obfuscation, Office 95 schemes; password and integrity verification flags; CLI encryption "OOXML-only and experimental" | [docs](https://msoffcrypto-tool.readthedocs.io/), [repo metadata](https://api.github.com/repos/nolze/msoffcrypto-tool) |
| oletools | Python | BSD-style (LICENSE.txt: "Redistribution and use in source and binary forms…"; thirdparty folder separately licensed); repo metadata NOASSERTION | repo pushed 2026-02-14 | "python tools to analyze MS OLE2 files (Structured Storage, Compound File Binary Format) and MS Office" documents | [LICENSE.txt](https://raw.githubusercontent.com/decalage2/oletools/master/oletools/LICENSE.txt), [repo metadata](https://api.github.com/repos/decalage2/oletools) |
| ClamAV | C | GPL-2.0 | repo pushed 2026-08-12 | Container-aware typing: `CL_TYPE_OOXML_WORD/XL/PPT`, `CL_TYPE_MSOLE2`, `CL_TYPE_ZIP`, `CL_TYPE_ZIPSFX`; Target Type 2 = "OLE2 containers, including specific macros"; no ODF-specific type listed | [repo metadata](https://api.github.com/repos/Cisco-Talos/clamav), [file types](https://docs.clamav.net/appendix/FileTypes.html) |

### 11.6 Validators and conformance tools

| Tool | Scope | Version | Invocation / notes | URL |
|---|---|---|---|---|
| ODF Toolkit `odfvalidator` | ODF/ODT conformance | 0.13.0 (release 0.13 published 23 January 2026, "contains ODF 1.4 support"); 0.14.0-SNAPSHOT from source | `java -jar odfvalidator-0.13.0-jar-with-dependencies.jar test.odt`; validates meta/content/styles/settings/manifest/signature parts; strict schema mode; MathML DTD/schema auto-selection; unknown-markup behavior depends on conformance mode | [TDF dev blog](https://dev.blog.documentfoundation.org/2026/01/22/validating-odf-and-ooxml-files/), [ODF Validator](https://odftoolkit.org/conformance/ODFValidator.html) |
| odfvalidator.org | Online ODF validation | not stated | Subject to disclaimer; "does not cover all ODF conformance criteria" | [TDF dev blog](https://dev.blog.documentfoundation.org/2026/01/22/validating-odf-and-ooxml-files/) |
| Office-o-tron | OOXML (and can validate ODT) | 0.8.8 ("currently the latest version") | `java -jar officeotron-0.8.8.jar ~/test.docx`; distributed from LibreOffice's dev-www server | [TDF dev blog](https://dev.blog.documentfoundation.org/2026/01/22/validating-odf-and-ooxml-files/) |
| Open XML SDK / PowerTools validation | OOXML schema validation | see §11.1–11.2 | "validate Open XML and retrieve validation errors" | [Open-Xml-PowerTools](https://github.com/EricWhiteDev/Open-Xml-PowerTools) |

### 11.7 Excluded, commercial, or legacy

- **GemBox.Document** — excluded as not open source: the vendor sells per-developer licenses ("1 developer: $356 before expiration; up to 10 developers: $1,780; up to 50 developers: $5,340") and no open-source license is stated ([GemBox pricing](https://www.gemboxsoftware.com/document/pricing)).
- **UniOffice** — commercially licensed Go library ("[o]ne commercial license covers your whole team"; "no per-document or per-server metering") ([unidoc.io](https://unidoc.io/unioffice/)); repository license metadata is NOASSERTION ([repo metadata](https://api.github.com/repos/unidoc/unioffice)). Do not assume OSS terms from its public repository.
- **unoconv** — archived on 2023-04-19 ([repo metadata](https://api.github.com/repos/unoconv/unoconv)); use unoserver.
- **WebODF** — last release notes 2015, repository idle since 2020 ([webodf.org](https://webodf.org/); [repo metadata](https://api.github.com/repos/webodf/WebODF)).
- **ezodf** — 0.3.1 NEWS entry dated December 2015 and a historical "development stopped - for now" note ([PyPI](https://pypi.org/project/ezodf/)); repository idle since 2022 ([repo metadata](https://api.github.com/repos/T0ha/ezodf)).
- **Open-Xml-PowerTools** — canonical repository URL redirected when queried through the GitHub API in this session, and the newest release visible on the fetched repository page is 4.6.0 / "Version 4.6", dated **November 16, 2020** ([repository page](https://github.com/EricWhiteDev/Open-Xml-PowerTools)). Treat as legacy/unmaintained for new work; its DOCX→HTML, comparison and revision-management code remains valuable as reference.
- **Xerces-C++** — "Xerces-C++ currently lacks active maintainers", and because of that it "may not be able to promptly address" bugs and security risks ([Apache Xerces-C++](https://xerces.apache.org/xerces-c/)). Prefer maintained parsers for untrusted input in C/C++.
- **Apache Santuario C++** — "officially retired as an Apache Project"; the code base forked to the Shibboleth Project, is "frozen at Apache", "will not be supported for third-party use", and was "estimated to be fully retired sometime before 2030" ([Apache Santuario](https://santuario.apache.org/)). Java (`4.0.4`/`3.0.6`, April 2025) remains actively developed.
- **lpOD / lpod-python** — no license statement in the fetched README and documentation described as "currently inaccurate" ([lpod-python](https://github.com/lpod/lpod-python)); treat as historical.
- **"ODF.js"** as a project distinct from WebODF: **n.a.** — not verified in this session.
- **AbiWord libraries**: **n.a.** — not verified in this session.

---

## 12. Per-tool capability matrix (consolidated)

Read the matrix with the licensing and activity evidence in §11; capability columns record only what the fetched sources state. `n.a.` = not verified in this session (which is not the same as "unsupported").

| Tool | Runtime | License | Formats | Read | Write | Convert/Render | Validate | Macro | Encrypt | Sign |
|---|---|---|---|---|---|---|---|---|---|---|
| Apache POI | Java 8+ | Apache-2.0 ([poi.apache.org](https://poi.apache.org/)) | DOC/DOCX/XLS/XLSX/PPT/PPTX/OLE2/TNEF/Visio ([repo](https://github.com/apache/poi)) | yes | yes | XSSFExportToXml only | duplicate-ZIP-entry check in 5.4.0+ ([site](https://poi.apache.org/)) | n.a. | `Biff8EncryptionKey` handling implies key material in memory ([security](https://poi.apache.org/security.html)) | n.a. |
| docx4j | Java/JAXB | Apache-2.0 | DOCX/PPTX/XLSX, Word 2007 `pkg`, HTML, PDF, XHTML | yes | yes | HTML + PDF export (3 strategies), XHTML import | n.a. | n.a. | n.a. | n.a. |
| Open XML SDK | .NET | MIT | OOXML, OPC packages, Flat OPC | via typed API | "high-performance generation"; add/update/remove content and metadata | n.a. | n.a. | n.a. | n.a. | n.a. |
| Open-Xml-PowerTools | .NET | MIT | DOCX/XLSX/PPTX/HTML/Flat OPC | yes | yes | DOCX↔HTML/CSS | "validate Open XML and retrieve validation errors" | n.a. | n.a. | n.a. |
| python-docx | Python | MIT | `.docx` | yes | yes | no | n.a. | n.a. | n.a. | n.a. |
| PHPWord | PHP | LGPL-3.0 | word-processing documents | yes | yes | n.a. | n.a. | n.a. | n.a. | n.a. |
| docx (dolanmiu) | Node/browser TS | MIT | `.docx` | modify | generate | no | n.a. | n.a. | n.a. | n.a. |
| docxtemplater | JS | MIT **or** GPLv3 | DOCX/PPTX/TXT | template parse | render/write | explicitly **cannot** convert to PDF | placeholder inspection APIs | n.a. | delegates to `msoffcrypto` | n.a. |
| docxtpl | Python | LGPL-2.1 | `.docx` | via python-docx | yes | no | n.a. | n.a. | n.a. | n.a. |
| docxcompose | Python | MIT | `.docx` | yes | append/merge | no | n.a. | n.a. | n.a. | n.a. |
| Mammoth | JS / Python | BSD-2-Clause | DOCX → HTML/text | yes | no | yes (HTML) | no | n.a. | n.a. | n.a. |
| docx2python | Python | MIT | DOCX extraction | yes | no | text/format extraction | n.a. | n.a. | n.a. | n.a. |
| Apache Tika | Java 11+ | Apache-2.0 | 1000+ types incl. DOCX/PPTX/XLSX/VSDX, flat ODF | yes | no | text+metadata extraction | detection | n.a. | n.a. | n.a. |
| Pandoc | Haskell | GPL-2.0+ | DOCX, ODT, HTML, LaTeX, PDF, PPTX, EPUB… | yes | yes | yes (lossy) | no | LaTeX macros only | n.a. | n.a. |
| unoserver | Python 3 + LibreOffice | MIT | LibreOffice import/export filters (PDF, PNG, CSV, HTML, ODF, XLSX, ODT named) | via LO | via LO | yes; also `unocompare` | n.a. | n.a. | n.a. | n.a. |
| Gotenberg | Go/Docker | MIT | documents/URLs → PDF | n.a. | n.a. | yes | n.a. | n.a. | PDF encryption | n.a. |
| ODF Toolkit | Java | Apache-2.0 | ODF/ODT | yes | yes | XSLT runner | ODF conformance validator | n.a. | n.a. | validates signature files |
| odfpy | Python | mixed (Apache/GPL/LGPL as listed) | ODF 1.2, ODF XML, CSV, (X)HTML | yes | yes | ODF↔(X)HTML, flat XML↔package | schema-driven checks that raise on invalid markup | n.a. | n.a. | n.a. |
| msoffcrypto-tool | Python | MIT | OOXML + legacy binary | decrypt | experimental OOXML encryption | no | password + HMAC integrity verification | n.a. | yes | n.a. |
| oletools | Python | BSD-style | OLE2 / Office | analysis | no | no | macro/IOC analysis | yes (analysis) | n.a. | n.a. |
| ClamAV | C | GPL-2.0 | container-aware typing incl. `CL_TYPE_OOXML_WORD` | scan | no | no | signature matching | OLE2 target type 2 "including specific macros" | n.a. | n.a. |
| libzip / minizip-ng / libarchive | C | BSD / zlib / per-file BSD | ZIP (+ more) | yes | yes | n.a. | n.a. | n.a. | libzip: WinZip AES + legacy PKWARE | n.a. |
| Apache Santuario (Java) | Java | Apache-2.0 | XML Signature/Encryption (DOM + StAX) | yes | yes | n.a. | signature verification | n.a. | XML Encryption | yes |

---

## 13. Decision guidance

### 13.1 Architecture matrix by use case

| Use case | Recommended approach | Why (evidence) | Anti-pattern |
|---|---|---|---|
| **Generate new documents** | Object-model library in your host language: Open XML SDK (.NET, MIT, 3.3.0), python-docx, docx4j, dolanmiu/docx, Caracal | These libraries are explicitly write-oriented ("high-performance generation"; "Create and modify Word documents"; "dynamically creating … .docx documents") | Producing DOCX by string-concatenating XML without `[Content_Types].xml`/`_rels` — both are mandatory in an OPC container ([LoC OPC](https://www.loc.gov/preservation/digital/formats/fdd/fdd000363.shtml)) |
| **Template merge / mail-merge** | docxtemplater (JS), docxtpl (Python), docx4j data-binding/OpenDoPE (Java) | docx4j documents "content-control data binding or MERGEFIELD", "OpenDoPE repeats and conditionals" ([docx4j](https://github.com/plutext/docx4j)); docxtemplater documents loops/conditions/inspection APIs ([FAQ](https://docxtemplater.com/docs/faq/)) | Expecting the templating layer to repaginate: docxtemplater cannot render page numbers, total pages or regenerate a TOC ([FAQ](https://docxtemplater.com/docs/faq/)) |
| **Precise surgical editing of existing files** | Load only the parts you need through an OPC-aware API (Open XML SDK / POI OOXML4J / docx4j); keep MCE preservation semantics intact | MCE preprocessing is configurable per part (`ProcessLoadedPartsOnly` exists "when ensuring minimal modification to the file") ([Microsoft Learn](https://learn.microsoft.com/en-us/office/open-xml/general/introduction-to-markup-compatibility)) | Round-tripping through HTML/Markdown: Pandoc warns conversions "may be lossy" and complex tables may not survive ([Pandoc](https://pandoc.org/MANUAL.html)) |
| **High-fidelity conversion / rendering / PDF** | LibreOffice-based engine: unoserver (listener mode), Gotenberg, Collabora Online | unoserver's listener mode lowers CPU load "somewhere between 50% and 75%" versus per-file headless launches ([unoserver](https://github.com/unoconv/unoserver)) | unoconv (archived 2023-04-19) ([metadata](https://api.github.com/repos/unoconv/unoconv)) |
| **Bulk text/metadata extraction** | Apache Tika (SAX OOXML parsers are default in 3.3.2), docx2python, Mammoth for semantic HTML | Tika 3.3.2 "[p]orted the 4.x SAX-based OOXML parsers … made SAX the default" ([Tika](https://tika.apache.org/)) | DOM-parsing whole packages for text; POI's core APIs "are not optimized to avoid excessive memory use" ([POI security](https://poi.apache.org/security.html)) |
| **Diff / merge / redline** | Open-Xml-PowerTools (compare DOCX with revision tracking; "manage and accept tracked revisions") for .NET; `unocompare` in unoserver for engine-grade compare | Both capabilities are documented in the fetched sources | Text-level diffing of `document.xml`: run fragmentation makes textually identical documents differ structurally (§5) |
| **Server-side SaaS at scale** | Stateless converter pool (unoserver/Gotenberg) + object-model libs for structured edits; process isolation and timeouts | POI advises extracting "document-parsing logic into a separate process", memory-bounded, timeout-killed and auto-restarted ([POI security](https://poi.apache.org/security.html)) | One long-lived JVM shared with untrusted tenants — POI explicitly says do not run in a JVM where untrusted users can read heap memory |
| **Untrusted input** | Hard limits + sandbox + AV + macro/relationship stripping | POI ships zip-bomb ratio (default 1%/`0.01d`), max entry size (4GB default), max text size (~10M chars) and DocType-disallowed defaults ([POI configuration](https://poi.apache.org/components/configuration.html)); OWASP: disable DTDs entirely, which "also makes the parser secure against … Billion Laughs" ([OWASP](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)) | Naïve archive extraction — Zip Slip is "a form of directory traversal … exploited by extracting files from an archive" ([Snyk](https://security.snyk.io/research/zip-slip-vulnerability)) |
| **Browser-only** | dolanmiu/docx or docxtemplater + PizZip/JSZip | PizZip is a synchronous fork of JSZip 2.x ([npm](https://www.npmjs.com/package/pizzip)); JSZip is dual MIT/GPLv3 ([LICENSE](https://raw.githubusercontent.com/Stuk/jszip/master/LICENSE.markdown)) | WebODF for new browser ODT editing (idle since 2020; AGPL) ([webodf.org](https://webodf.org/)) |

### 13.2 Recommended stacks by language

| Language | DOCX | ODT | Conversion/render | Security layer |
|---|---|---|---|---|
| **Java** | POI XWPF (Apache-2.0) or docx4j (Apache-2.0) | ODF Toolkit / ODFDOM 0.13.0 | unoserver/Gotenberg over HTTP; Tika for extraction | Santuario for XML signatures; POI `ZipSecureFile` limits; disallow DOCTYPE |
| **.NET** | Open XML SDK 3.3.0 (MIT); PowerTools for HTML/compare (legacy) | n.a. (no maintained OSS ODT object model verified) | Gotenberg/unoserver service | `System.IO.Packaging` OPC model; OWASP .NET XXE guidance |
| **Python** | python-docx + docxtpl + docxcompose; docx2python for extraction | odfpy (mixed license); ezodf legacy | unoserver (MIT); Pandoc | msoffcrypto-tool for encrypted input; `lxml` configured against XXE; oletools for macro triage |
| **JS/TS** | dolanmiu/docx; docxtemplater; Mammoth for HTML | n.a. (no maintained OSS ODT library verified) | Gotenberg | JSZip/PizZip with explicit path validation |
| **PHP** | PHPWord (LGPL-3.0) | n.a. | Gotenberg/unoserver | LGPL obligations if distributing modifications |
| **Ruby** | ruby-docx/docx (read/edit, MIT); Caracal (generate, MIT) | n.a. | external engine | note Caracal's stated validation weakness |
| **Rust** | docx-rs (MIT, writer-oriented) | n.a. | external engine | Rust ZIP crate + explicit entry-name checks |
| **Go** | UniOffice is **commercial**, not OSS | n.a. | Gotenberg (Go, MIT) | Gotenberg as an isolated container |

### 13.3 Build vs engine

Build on an object model when you own the document's semantics (generation, templating, structured edits, extraction) — it is deterministic, cheap and horizontally scalable. Delegate to an engine (LibreOffice/Collabora/ONLYOFFICE) whenever the requirement mentions *layout*: pagination, page numbers, TOC regeneration, PDF fidelity, or interactive co-editing. This split is forced by the format: templating libraries explicitly disclaim layout ("cannot convert docx to PDF… render docx for page numbers, total pages… regenerating a table of contents") ([docxtemplater](https://docxtemplater.com/docs/faq/)), while engines carry the licensing weight — MPL-2.0 for Collabora Online ([COPYING](https://raw.githubusercontent.com/CollaboraOnline/online/master/COPYING)) and AGPL-3.0 with a 20-connection cap plus branding restrictions for ONLYOFFICE Docs Community ([ONLYOFFICE FAQ](https://helpcenter.onlyoffice.com/docs/faq/docs-community.aspx)).

---

## 14. Implementation checklists

### 14.1 Producer checklist — DOCX

- [ ] Emit `[Content_Types].xml` (Default + Override entries) and `_rels/.rels`; both the file and the `_rels` folder are mandatory in the ZIP-based OPC container ([LoC](https://www.loc.gov/preservation/digital/formats/fdd/fdd000363.shtml)).
- [ ] Ensure every part is reachable by following relationships ("[a]ll parts of the package must be discoverable by following relationships") ([LoC](https://www.loc.gov/preservation/digital/formats/fdd/fdd000363.shtml)).
- [ ] Match relationship IDs in `document.xml` to entries in `word/_rels/document.xml.rels` ([USENIX'23](https://www.usenix.org/system/files/sec23summer_235-rohlmann-prepub.pdf)).
- [ ] Decide Strict vs Transitional deliberately: Strict = Part 1 only; Transitional applies Part 4 deltas and retains VML ([LoC](https://www.loc.gov/preservation/digital/formats/fdd/fdd000399.shtml)).
- [ ] Create the styles part explicitly when generating programmatically — the SDK does not create it for you ([Microsoft Learn](https://learn.microsoft.com/en-us/office/open-xml/word/how-to-apply-a-style-to-a-paragraph-in-a-word-processing-document)).
- [ ] For lists, emit `w:numPr` with `w:ilvl` + `w:numId`, and remember that a `pStyle` on the abstract numbering definition overrides `ilvl` ([Open XML SDK](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.numberingproperties?view=openxml-3.0.1)).
- [ ] If you use extension namespaces, declare them `Ignorable` and wrap alternatives in `AlternateContent`/`Choice`/`Fallback` with prefixed MCE attributes ([c-rex ECMA-376 Part 3 text](https://c-rex.net/samples/ooxml/e1/Part5/OOXML_P5_Markup_Compatibility_and_Extensibility_AlternateContent_topic_ID0E4GBG.html)).
- [ ] Do not write duplicate ZIP entry names (POI 5.4.0+ rejects them) ([Apache POI](https://poi.apache.org/)).
- [ ] For reproducible output: normalize entry timestamps, sort entries deterministically in the C locale, and normalize ownership/permissions ([Reproducible Builds](https://reproducible-builds.org/docs/archives/)).

### 14.2 Producer checklist — ODT

- [ ] `mimetype` must be the **first** ZIP entry, **STORED**, with **no extra field**; its content must equal the root `manifest:media-type` when a `/` file entry exists ([ODF 1.4 Part 2](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)).
- [ ] Use only STORED or DEFLATED for every entry ([ODF 1.4 Part 2](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)).
- [ ] Emit `META-INF/manifest.xml` listing every file entry; it is mandatory and schema-validated ([ODF 1.4 Part 2](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)); consumers other than Microsoft Office treat unreferenced files as corruption ([USENIX'22](https://www.usenix.org/system/files/sec22-rohlmann.pdf)).
- [ ] Provide at least one of `content.xml` / `styles.xml`; `content.xml`'s root must be `office:document-content` (or `math:math`) ([ODF 1.4 Part 3](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part3-schema.html)).
- [ ] Keep foreign markup out of the reserved ODF namespaces ([ODF 1.4 Part 3](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part3-schema.html)).
- [ ] When encrypting, deflate first, then encrypt, flag entries STORED in the central directory, and record the plaintext size in `manifest:size`; never encrypt the manifest ([ODF 1.4 Part 2](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)).
- [ ] Validate with `odfvalidator` 0.13.0 (ODF 1.4-aware) before shipping ([TDF dev blog](https://dev.blog.documentfoundation.org/2026/01/22/validating-odf-and-ooxml-files/)).

### 14.3 Untrusted-input intake checklist (both formats)

- [ ] Reject archives failing an inflate-ratio threshold (POI default 1%), a per-entry size cap and a text-size cap ([POI configuration](https://poi.apache.org/components/configuration.html)).
- [ ] Canonicalize and validate every entry name against the extraction root before writing anything (Zip Slip) ([Snyk](https://security.snyk.io/research/zip-slip-vulnerability)).
- [ ] Disable DOCTYPE/DTDs, external entities, external DTD loading and XInclude; enable secure processing; cap entity expansion ([OWASP](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)). POI 5.1.0+ disallows DocType in embedded XML by default ([POI configuration](https://poi.apache.org/components/configuration.html)).
- [ ] Enumerate and strip/queue for review: external relationships, `altChunk` imports (Word accepts `text/html`, `application/rtf`, `message/rfc822`, `text/plain` and more) ([MS-OI29500](https://learn.microsoft.com/en-us/openspecs/office_standards/ms-oi29500/c391c28f-1b03-4a21-a4f8-4d9cddd4a95c)), VBA parts in `.docm`/`.dotm` ([Microsoft Learn](https://learn.microsoft.com/en-us/office/compatibility/xml-file-name-extension-reference-for-office)), and ODF `Basic/`/`Scripts/` macro trees ([USENIX'22](https://www.usenix.org/system/files/sec22-rohlmann.pdf)).
- [ ] Scan with container-aware AV (`CL_TYPE_OOXML_WORD`, `CL_TYPE_MSOLE2`, `CL_TYPE_ZIP`) ([ClamAV](https://docs.clamav.net/appendix/FileTypes.html)) and triage OLE/VBA with oletools ([repo](https://api.github.com/repos/decalage2/oletools)).
- [ ] Parse in a separate, memory-capped, timeout-killed, auto-restarting process; expect `StackOverflowError`, OOM and arbitrary runtime exceptions ([POI security](https://poi.apache.org/security.html)).
- [ ] Keep the temp directory unreadable/unwritable by untrusted users; consider encrypted temp files and package parts (POI 5.1.0+ options) ([POI configuration](https://poi.apache.org/components/configuration.html)).
- [ ] Treat password prompts as a decryption path, not a trust boundary: for ODF, `manifest:checksum` "should not be regarded as a security feature" ([ODF 1.4 Part 2](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)); crafted OOXML encryption parameters have caused memory-safety bugs (CVE-2026-4430) ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-4430)).
- [ ] Never rely on a rendered "signed" badge alone: both ecosystems have documented signature-spoofing classes ([USENIX'23](https://www.usenix.org/system/files/sec23summer_235-rohlmann-prepub.pdf); [USENIX'22](https://www.usenix.org/system/files/sec22-rohlmann.pdf)).

### 14.4 Privacy/metadata-hygiene checklist

- [ ] Strip or review `docProps/core.xml` and `docProps/app.xml`, which carry author, creation time, Office version, creator, last modifier and timestamps ([USENIX'23](https://www.usenix.org/system/files/sec23summer_235-rohlmann-prepub.pdf)).
- [ ] Strip ODF `meta.xml` (File ▸ Properties data) and `settings.xml` view/application state ([LibreOffice Help](https://help.libreoffice.org/latest/en-GB/text/shared/00/00000021.html?DbPAR=SHARED)).
- [ ] Accept or reject tracked changes before release: `w:*` revision markup in DOCX; `text:tracked-changes`, `text:change-start`/`text:change-end` in ODT ([ODF 1.4 Part 3](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part3-schema.html)); PowerTools can "manage and accept tracked revisions" programmatically ([repo](https://github.com/EricWhiteDev/Open-Xml-PowerTools)).
- [ ] Remove comments/annotations (`comments.xml`; `office:annotation`) and check custom XML parts, which can hold the full data behind mapped rich-text content controls ([Microsoft Learn](https://learn.microsoft.com/en-us/office/client-developer/word/content-controls-in-word)).
- [ ] For archival transfer, remember institutional deposit rules: files "must contain no measures (such as digital rights management [DRM] technologies or encryption) that control access to or prevent use of the digital work" ([LoC RFS](https://www.loc.gov/preservation/resources/rfs/text.html)).

### 14.5 Accessibility checklist

- [ ] Alt text on every non-text object, without image names or file extensions — Accessibility Checker **error**: "All non-text content has alternative text (alt text)" ([Microsoft](https://support.microsoft.com/en-us/office/rules-for-the-accessibility-checker-651e08f2-0fc3-4e10-aaca-74b4a67101c1)).
- [ ] Table column headers present — **error**: "Tables specify column header information"; keep tables simple rectangles (no split/merged/nested cells) — **warning**: "Table has a simple structure" ([Microsoft](https://support.microsoft.com/en-us/office/rules-for-the-accessibility-checker-651e08f2-0fc3-4e10-aaca-74b4a67101c1)).
- [ ] Use heading styles / a TOC — **tip**: "Documents use heading styles" ([Microsoft](https://support.microsoft.com/en-us/office/rules-for-the-accessibility-checker-651e08f2-0fc3-4e10-aaca-74b4a67101c1)).
- [ ] Review machine-generated alt text ("Suggested alternative text") rather than shipping it blind ([Microsoft](https://support.microsoft.com/en-us/office/rules-for-the-accessibility-checker-651e08f2-0fc3-4e10-aaca-74b4a67101c1)).
- [ ] On the ODF side, target ODF 1.3/1.4-era structure semantics: ODF 1.3 improved "compliance with accessibility standards" and ODF 1.4 adds "[c]learer semantics for assistive technologies" with "[s]tructural tags for [h]eadings, [l]ists, [t]ables" ([TDF](https://blog.documentfoundation.org/blog/2025/08/01/whats-new-in-odf-1-3-and-1-4/)).

---

## 15. Gaps, obsolete projects, misleading names and unverified claims

**Explicit `n.a.` items (searched, not confirmable from fetched primary sources in this session):**

| Claim/topic | Status |
|---|---|
| ZIP64 requirements or prohibitions in OPC and in the ODF package | **n.a.** — the OPC overview "does not mention ZIP64" ([Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)) and no ZIP64 rule was located in the fetched ODF Part 2 text ([OASIS](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)) |
| A normative canonicalization/deterministic-serialization requirement for either package | **n.a.** — none found; treat reproducibility as an engineering discipline ([Reproducible Builds](https://reproducible-builds.org/docs/archives/)) |
| Argon2 (or Argon2id) key derivation in ODF | **n.a.** — ODF 1.4 Part 2 defines `PBKDF2`, its URN form and `PGP`, plus legacy Blowfish CFB ([OASIS](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part2-packages.html)); the TDF ODF 1.3/1.4 feature article does not mention Argon2 ([TDF](https://blog.documentfoundation.org/blog/2025/08/01/whats-new-in-odf-1-3-and-1-4/)) |
| ODF 1.4 ISO/IEC submission or publication | **n.a. / not submitted** — the version-history table states ODF 1.4 is "not submitted yet" to ISO ([Wikipedia, secondary](https://en.wikipedia.org/wiki/OpenDocument_standardization)); ISO's current ODF entry remains 26300-1:2015 (ODF 1.2) with `ISO/IEC CD 26300-3` under development ([ISO](https://www.iso.org/standard/66363.html)) |
| ODF 1.4 conformance classes in Part 1 | **n.a.** — Part 1 "does not define or list conformance clauses or conformance classes"; the operative distinction (conforming vs *extended* conforming) appears in the Part 2/Part 3 text and in validator behavior ([OASIS Part 1](https://docs.oasis-open.org/office/OpenDocument/v1.4/OpenDocument-v1.4-part1-introduction.html); [ODF Validator](https://odftoolkit.org/conformance/ODFValidator.html)) |
| ISO/IEC 29500 next edition timing | **n.a.** — status is only "International Standard to be revised [90.92]" with `ISO/IEC DIS 29500-1` listed as the replacement under development ([ISO](https://www.iso.org/standard/71691.html)) |
| Google Docs' general DOCX/ODT fidelity behavior | **partially n.a.** — the only authoritative statement located is the client-side-encrypted `.docx` beta: `.docx` only, 20 MB limit, "[o]ther features may be lost or altered" with an in-document notification ([Google Workspace Updates](https://workspaceupdates.googleblog.com/2025/05/edit-client-side-encrypted-microsoft-word-files-with-google-docs.html)) |
| LibreOffice license and UNO/LibreOfficeKit API details | **n.a.** — not fetched in this session; Collabora Online's own page does not mention LibreOfficeKit ([Collabora](https://www.collaboraoffice.org/online/)) |
| "ODF.js" as a project distinct from WebODF; AbiWord libraries | **n.a.** — not verified |
| POI `ZipSecureFile` defaults from the Javadoc alone | The Javadoc "does not state a default numeric value" ([Javadoc](https://poi.apache.org/apidocs/dev/org/apache/poi/openxml4j/util/ZipSecureFile.html)); the numbers cited in this report come from the Configuration page ([POI configuration](https://poi.apache.org/components/configuration.html)) |
| Apache POI license via GitHub metadata | GitHub metadata returns no SPDX license for the mirror ([metadata](https://api.github.com/repos/apache/poi)); Apache-2.0 comes from the project site ([poi.apache.org](https://poi.apache.org/)) |
| CVSS scores for CVE-2022-30190 and CVE-2023-2255 | **n.a.** — "NVD assessment not yet provided" on both records ([NVD 2022-30190](https://nvd.nist.gov/vuln/detail/cve-2022-30190); [NVD 2023-2255](https://nvd.nist.gov/vuln/detail/cve-2023-2255)) |

**Obsolete or frozen projects:** unoconv (archived), WebODF (2015 releases; repo idle since 2020), ezodf (2015-era releases; repo idle since 2022), Open-Xml-PowerTools (4.6, 2020), lpod-python (unlicensed README, "inaccurate" docs), Xerces-C++ (no active maintainers), Apache Santuario C++ (retired, moving to Shibboleth), Mammoth's Markdown support (deprecated), and Pandoc's `wkhtmltopdf` engine (deprecated).

**Misleading names and licence traps:**

- **`docx` is three different projects** — `dolanmiu/docx` (TypeScript, MIT), `ruby-docx/docx` (Ruby, MIT) and the Python package `python-docx`. Pin by repository, not by name.
- **PizZip vs JSZip** — PizZip is a fork of JSZip **2.x** chosen for synchronous behavior; both are dual MIT/GPLv3, so "MIT" is a choice you must document ([PizZip LICENSE](https://raw.githubusercontent.com/open-xml-templating/pizzip/master/LICENSE.markdown); [JSZip LICENSE](https://raw.githubusercontent.com/Stuk/jszip/master/LICENSE.markdown)).
- **docxtemplater** is likewise dual MIT/GPLv3, with paid modules layered on top ([LICENSE.md](https://raw.githubusercontent.com/open-xml-templating/docxtemplater/master/LICENSE.md)).
- **odfpy** advertises three license families simultaneously on PyPI ("Apache Software License, GNU General Public License (GPL), GNU Library or Lesser General Public License (LGPL)") — resolve it against the shipped LICENSE before redistribution ([PyPI](https://pypi.org/project/odfpy/)).
- **Copyleft in the toolchain**: docxtpl is LGPL-2.1, PHPWord LGPL-3.0, Pandoc GPL-2.0+, ClamAV GPL-2.0, ONLYOFFICE Docs AGPL-3.0 with branding retention and a 20-connection cap, WebODF AGPL. Server-side use of AGPL components triggers source-availability obligations by design ([ONLYOFFICE FAQ](https://helpcenter.onlyoffice.com/docs/faq/docs-community.aspx)).
- **UniOffice** looks like an OSS Go library on GitHub but is sold as a commercial subscription ([unidoc.io](https://unidoc.io/unioffice/); [metadata](https://api.github.com/repos/unidoc/unioffice)); **GemBox.Document** is straightforwardly commercial ([pricing](https://www.gemboxsoftware.com/document/pricing)).
- **"Strict Open XML document" and "Word Document" share the `.docx` extension** — the profile is invisible in the filename ([Microsoft Learn](https://learn.microsoft.com/en-us/office/compatibility/xml-file-name-extension-reference-for-office)).
- **`.dotm` ≠ macros present**: it "[d]oes not always contain macro code, but is configured to support the storage of macro code", and documents created from it default to `.docx` without inheriting the VBAProject part ([Microsoft Learn](https://learn.microsoft.com/en-us/office/compatibility/xml-file-name-extension-reference-for-office)).
- **Vendor "supported" ≠ lossless**: Microsoft's own ODT table marks features "Supported" while noting behavior changes such as highlighting converting to character background color and style counts increasing ([Microsoft](https://support.microsoft.com/en-us/word/differences-between-the-opendocument-text-odt-format-and-the-word-docx-format-used-by-word-for-the-w)).

**Ecosystem gaps worth noting for architects:** there is no maintained open-source ODT object model for .NET, JavaScript/TypeScript, PHP, Ruby or Rust verified in this session — ODT work outside Java (ODF Toolkit) and Python (odfpy) effectively means driving a LibreOffice-based engine. Conversely, there is no open-source, non-engine renderer that reproduces Word's or Writer's pagination; every high-fidelity path in this report routes through LibreOffice-derived code.

