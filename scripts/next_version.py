import semver
import sys

versionStr = sys.argv[1]
if versionStr[:1] == "v":
    versionStr = versionStr[1:]
oldVersion = semver.VersionInfo.parse(versionStr)
newVersion = oldVersion.bump_patch()

print("v" + str(newVersion))
