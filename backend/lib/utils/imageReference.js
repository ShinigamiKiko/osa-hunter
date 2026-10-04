'use strict';

const DEFAULT_REGISTRIES = 'docker.io,ghcr.io,quay.io,registry.k8s.io,mcr.microsoft.com,gcr.io,public.ecr.aws';
const dockerAliases = new Set(['docker.io', 'index.docker.io', 'registry-1.docker.io']);
const canonicalRegistry = host => dockerAliases.has(host.toLowerCase()) ? 'docker.io' : host.toLowerCase();
const component = /^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$/;

function imageReference(image, tag = '', registries = process.env.TRIVY_ALLOWED_REGISTRIES ?? DEFAULT_REGISTRIES) {
  if (typeof image !== 'string' || !image || image.length >= 512 || typeof tag !== 'string')
    throw new Error('Invalid image name');
  const parts = image.split('/');
  const first = parts[0];
  if (first.toLowerCase() === 'localhost') throw new Error('Use localhost with an explicit registry port');
  const explicit = parts.length > 1 && (first.includes('.') || first.includes(':') || first.toLowerCase() === 'localhost');
  const registry = explicit ? canonicalRegistry(first) : 'docker.io';
  const repository = explicit ? parts.slice(1) : parts;
  if ((explicit && !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[1-9][0-9]{0,4})?$/i.test(first))
      || (explicit && first.includes(':') && Number(first.split(':')[1]) > 65535)
      || !repository.every(part => component.test(part)))
    throw new Error('Use an image repository name and provide its tag separately');
  const allowed = new Set(registries.split(',').map(s => canonicalRegistry(s.trim())).filter(Boolean));
  if (!allowed.has(registry)) throw new Error('Image registry is not allowed; configure TRIVY_ALLOWED_REGISTRIES');
  const actualTag = tag || 'latest';
  if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(actualTag)) throw new Error('Invalid tag');
  return `${image}:${actualTag}`;
}

module.exports = { imageReference };
