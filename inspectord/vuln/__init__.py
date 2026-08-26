"""Pure vulnerability-scanning logic (vuln-scanner design §3-§4).

Everything importable from here is side-effect-free and takes bytes/strings,
so the vuln_scanner worker stays a thin scheduling shell around it. The only
subprocess in the package is the injectable `vercmp` wrapper in `matching`.
"""
