{.experimental: "codeReordering".}
import zip/zipfiles
import streams
import std/sha1
import base64
import strutils
import tables
import nimcrypto
import os, osproc
import parseopt

when defined windows:
  {.passl: "-lz".}

const
  apkIn = "demo.apk"
  apkOut = "demo-signed.apk"
  signKey = "test.key.pem"
  signCert = "test.cert.pem"
  tmpFile = "tmp"
  usage = """
USAGE: apksign -i=DIRECTORY -o=FILE.apk -c=cert.pem -k=key.pem"""

type
  Signer = object
    manifest: string
    certSf: string
    certRsa: string
    manifestHash: string
    entryHash: Table[string, string]

main()

proc main() =
  # Parse flags
  var
    input: string
    output: string
    cert: string
    key: string
  for kind, flag, val in getopt():
    case flag
    of "i":
      if val == "": die "flag `-i` requires a directory parameter, e.g.: -i=apk/"
      if not dirExists val: die "flag `-i` requires a directory as a parameter, got: " & val
      input = val
    of "o":
      if val == "": die "flag `-o` requires a filename parameter, e.g.: -o=myapp.apk"
      output = val
    of "c":
      if val == "": die "flag `-c` requires a filename parameter, e.g.: -c=cert.pem"
      cert = val
    of "k":
      if val == "": die "flag `-k` requires a filename parameter, e.g.: -k=key.pem"
      key = val
    else:
      die "unknown flag: " & $kind & flag & "\n" & usage
  if input == "":  die "missing `-i` flag\n" & usage
  if output == "": die "missing `-o` flag\n" & usage
  if cert == "":   die "missing `-c` flag\n" & usage
  if key == "":    die "missing `-k` flag\n" & usage
  if fileExists(input & "/META-INF/MANIFEST.MF"):
    die "modifying existing META-INF/MANIFEST.MF file not yet implemented"

  # TODO: take files from apk/ directory (flag -i)
  # TODO: calculate manifest.mf, cert.sf, cert.rsa
  # TODO: add manifest & cert.{sf,rsa} to .zip file (flag -o)
  # TODO: add remaining files to .zip file

  var src: ZipArchive
  doAssert src.open(apkIn, fmRead)

  # FIXME: manifest.mf & cert.sf lines must be wrapped at 72 bytes (70 + CR + LF)
  # FIXME: files in cert.sf (or manifest.mf? or both?) must be sorted
  var signer = Signer(entryHash: initTable[string, string]())
  signer.buildManifestMf(src)
  signer.buildCertSf(src)
  signer.buildCertRsa()
  signer.buildSignedAPK(src)


proc buildManifestMf(signer: var Signer, src: var ZipArchive) =

  echo "- Building MANIFEST.MF"

  signer.manifest.add joinCrLf([
     "Manifest-Version: 1.0",
     "Built-By: Generated-by-ADT",
     "Created-By: Android Gradle 3.3.2",
  ])

  for f in src.walkFiles:
    if not f.skipFile:
      let s = src.getStream(f)
      let entry = joinCrLf([
        "Name: " & f,
        "SHA-256-Digest: " & s.readAll().base64sha1,
      ])
      signer.manifest.add entry
      signer.entryHash[f] = base64sha1(entry)
      s.close()

  signer.manifestHash = base64sha1(signer.manifest)

proc buildCertSf(signer: var Signer, src: var ZipArchive) =

  echo "- Building CERT.SF"

  signer.certSf.add joinCrLf [
    "Signature-Version: 1.0",
    "Created-By: 1.0 (Android)",
    "SHA-256-Digest-Manifest: " & signer.manifestHash,
  ]

  for f in src.walkFiles:
    if not f.skipFile:
      signer.certSf.add joinCrLf [
        "Name: " & f,
        "SHA-256-Digest: " & signer.entryHash[f],
      ]


proc buildCertRsa(signer: var Signer) =

  echo "- Building CERT.RSA"

  writeFile(tmpFile & ".in", signer.certSf)
  let cmd = "openssl smime" &
               " -sign -inkey " & signKey & 
               " -signer " & signCert & 
               " -binary -outform DER" &
               " -noattr" &
               " -in " & tmpFile & ".in" &
               " -out " & tmpFile & ".out" 

  let (stdout, rv) = execCmdEx(cmd)
  doAssert rv == 0
  signer.certRsa = readFile(tmpFile & ".out")
  removeFile(tmpFile & ".in")
  removeFile(tmpFile & ".out")


proc buildSignedApk(signer: var Signer, src: var ZipArchive) =

  echo "- Building signed APK"
  
  var dst: ZipArchive
  doAssert dst.open(apkOut, fmWrite)

  dst.addFile("META-INF/MANIFEST.MF", newStringStream(signer.manifest))
  dst.addFile("META-INF/CERT.SF", newStringStream(signer.certSf))
  dst.addFile("META-INF/CERT.RSA", newStringStream(signer.certRsa))

  for f in src.walkFiles:
    if not f.skipFile:
      let s = src.getStream(f)
      dst.addFile(f, s)

  dst.close()


proc `$`(kind: CmdLineKind): string =
  case kind
  of cmdLongOption: "--"
  of cmdShortOption: "-"
  of cmdArgument, cmdEnd: ""

proc die(s: string) =
  stderr.write("apksign: " & s & "\n")
  quit(1)

proc skipFile(s: string): bool =
  let (dir, name, ext) = s.splitFile
  return dir == "META-INF" and ext in [ ".MF", ".SF", ".RSA", ".DSA", ".EC" ]

proc joinCrLf(ss: openarray[string]): string =
  ss.join("\r\n") & "\r\n\r\n"

proc base64sha1(s: string): string =
  base64.encode(sha256.digest(s).data)





