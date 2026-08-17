# src/ — agent guide

No modules live here. Add code under [`docxplus/`](docxplus/AGENTS.md), inside the
package, and import siblings relatively (`from .crypto import digest`) so the package
is relocatable and works identically installed or from a checkout.

Never reintroduce a flat top-level module beside `docxplus/`. It would be importable
from a checkout, absent from every wheel, and the difference would not show up until
somebody installed the package and found it empty.
