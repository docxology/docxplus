# src/ — the import root

This directory holds no modules of its own. It exists so that `src/docxplus/` is on
the path as a *package*, which is what makes `import docxplus` mean the same thing
from a checkout and from an install.

The code is one level down: [`docxplus/`](docxplus/README.md).

Until v1.0.1 the modules sat directly here and were imported flat — `import crypto`,
`import container`. That works from a checkout and nowhere else: a wheel built from
it shipped no modules at all, so `pip install docxplus` succeeded and left nothing
importable. Namespacing them fixed the install and cost the flat imports, which is
the trade a public package has to make.
