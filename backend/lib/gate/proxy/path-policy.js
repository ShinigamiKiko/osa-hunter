'use strict';

const ARTIFACT_EXT = /\.(?:tgz|whl|tar\.gz|zip|mod|info|jar|pom|module|nupkg|crate|gem|deb|apk|rpm)$/i;

function metadataAllowed(ecosystem, value) {
  const p = value.replace(/^\/+/, '');

  if (ecosystem.startsWith('Alpine')) {
    return /^(?:[^/]+\/)*APKINDEX\.tar\.gz$/i.test(p);
  }

  if (ecosystem.startsWith('Debian') || ecosystem.startsWith('Ubuntu')) {
    // Do not allow the whole dists/ tree: it can contain arbitrary files.
    // Allowed families (all signed / hash-listed in (In)Release):
    //   InRelease, Release(.gpg), Contents-*, <comp>/binary-<arch>/Packages*,
    //   command-not-found (cnf/Commands-*), appstream (dep11/*), i18n
    //   (Translation-*), and their by-hash variants.
    const hash = '(?:by-hash\\/(?:SHA256|SHA512)\\/[a-f0-9]+)';
    const gz = '(?:\\.(?:gz|xz|bz2))?';
    return new RegExp(`^dists\\/[^/]+\\/(?:`
      + `InRelease|Release(?:\\.gpg)?`
      + `|Contents-[^/]+${gz}`
      + `|${hash}`
      + `|[^/]+\\/(?:`
        + `binary-[^/]+\\/(?:Packages${gz}|Release|${hash})`
        + `|Contents-[^/]+${gz}`
        + `|cnf\\/(?:Commands-[^/]+${gz}|${hash})`               // command-not-found
        + `|dep11\\/(?:(?:Components|icons)-[^/]+\\.[^/]+|${hash})` // appstream DEP-11
        + `|i18n\\/(?:Translation-[^/]+${gz}|${hash})`            // translations
      + `)`
      + `)$`, 'i').test(p);
  }

  if (ecosystem === 'Go') {
    return /^(?:.+)\/\@v\/(?:list|latest)$/i.test(p);
  }

  if (ecosystem === 'Maven') {
    return /^(?:.+)\/maven-metadata\.xml$/i.test(p)
      || /\/[^/]+\.(?:jar|pom|module)(?:\.(?:sha1|sha256|sha512|md5|asc))?$/i.test(p)
      || /\/maven-metadata\.xml\.(?:sha1|sha256|sha512|md5|asc)$/i.test(p);
  }

  if (ecosystem === 'NuGet') {
    return /^(?:[^/]+\/)*index\.json$/i.test(p) || /^[^/]+\/[^/]+\/[^/]+\.nuspec$/i.test(p);
  }

  if (ecosystem === 'crates.io') {
    return /^(?:[^/]+\/){2}[^/]+$/i.test(p) || /^config\.json$/i.test(p);
  }

  if (ecosystem === 'RubyGems') {
    return /^(?:versions|latest_specs\.4\.8\.gz|specs\.4\.8\.gz|prerelease_specs\.4\.8\.gz)$/i.test(p)
      || /^info\/[^/]+$/i.test(p)
      || /^quick\/Marshal\.4\.8\/[^/]+\.gemspec\.rz$/i.test(p)
      || /^api\/v1\/dependencies$/i.test(p);
  }

  if (/^(Rocky Linux|AlmaLinux|Red Hat|CentOS|openSUSE|SUSE)\b/.test(ecosystem)) {
    // repomd.xml (+ its detached signature/key) and the index files it lists:
    // primary/filelists/other/comps/updateinfo/modules, as xml|yaml|sqlite with
    // any of the compressions dnf uses (gz, xz, bz2, zst, zck). Flat names only
    // ([^/]+) - no nesting, no traversal, nothing outside repodata/.
    return /^repodata\/(?:repomd\.xml(?:\.(?:asc|key|sig))?|[^/]+\.(?:xml|yaml|sqlite)(?:\.(?:gz|xz|bz2|zst|zck))?)$/i.test(p);
  }

  return false;
}

module.exports = { ARTIFACT_EXT, metadataAllowed };
