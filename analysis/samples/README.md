<!-- threatscan:allow-signatures -->
# Samples

Live malware samples are **not** kept in this repository: every colleague who
installs ThreatScan from git would receive them, Windows Defender flags them as
`Trojan:JS/PolinRider.DB!MTB`, and the scanner itself would (correctly) offer
to delete them.

The stage-2 implant analysed in `analysis-report.txt` is identified by:

```
SHA-256  517c92cb4139a1b840108c2dc08ae2966f1b3e8f9453fd88a06e491b6d4c111b
size     4818 bytes
marker   global.i="A10-*23650"
```

It remains in git history (commit 9a2a5b9) for forensics.  To work on a sample,
copy it into an isolated directory (see `../docker-compose.yml`, network
disabled) and keep it out of any path the guard watches, or the guard will
prompt to delete it.
