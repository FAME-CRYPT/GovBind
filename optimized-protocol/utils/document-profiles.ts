export const documentProfiles = {
  'military-service': {
    documentType: 'military-service',
    displayName: 'Military Service',
    tlsProfile: 'edevlet-military-service-pdf-v1',
    recordVersion: 'zk-devlet-proof-record-v3',
    noirProgram: 'zk-devlet-military-service-noir-v1',
    circuitDirectory: 'military-service',
    artifactName: 'zk_devlet_military_service_v2.json',
    witnessBuilderName: 'prepare-military-service-witness.js',
    maximumCompressedLength: 1536,
    privateRangeKinds: ['barcode', 'qr-image', 'content-stream', 'document-id'],
  },
  residence: {
    documentType: 'residence',
    displayName: 'Residence City',
    tlsProfile: 'edevlet-residence-pdf-v1',
    recordVersion: 'zk-devlet-proof-record-v4',
    noirProgram: 'zk-devlet-residence-noir-v2',
    circuitDirectory: 'residence',
    artifactName: 'zk_devlet_residence_v2.json',
    witnessBuilderName: 'prepare-residence-witness.js',
    maximumCompressedLength: 5504,
    privateRangeKinds: ['content-stream', 'document-id'],
  },
  'criminal-record': {
    documentType: 'criminal-record',
    displayName: 'Criminal Record',
    tlsProfile: 'edevlet-criminal-record-pdf-v1',
    recordVersion: 'zk-devlet-proof-record-v5',
    noirProgram: 'zk-devlet-criminal-record-noir-v1',
    circuitDirectory: 'criminal-record',
    artifactName: 'zk_devlet_criminal_record_v1.json',
    witnessBuilderName: 'prepare-criminal-record-witness.js',
    maximumCompressedLength: 1024,
    privateRangeKinds: [
      'barcode', 'qr-image', 'content-stream', 'creation-date',
      'modification-date', 'document-id',
    ],
  },
  'driver-license': {
    documentType: 'driver-license',
    displayName: 'Driver License Traffic Penalties',
    tlsProfile: 'edevlet-driver-license-traffic-penalties-pdf-v1',
    recordVersion: 'zk-devlet-proof-record-v6',
    noirProgram: 'zk-devlet-driver-license-traffic-penalties-noir-v2',
    circuitDirectory: 'driver-license',
    artifactName: 'zk_devlet_driver_license_v2.json',
    witnessBuilderName: 'prepare-driver-license-witness.js',
    maximumCompressedLength: 4096,
    privateRangeKinds: [
      'barcode', 'qr-image', 'content-stream', 'creation-date',
    ],
  },
  'tax-debt': {
    documentType: 'tax-debt',
    displayName: 'Overdue Tax Debt',
    tlsProfile: 'gib-tax-debt-status-pdf-v1',
    recordVersion: 'zk-devlet-proof-record-v7',
    noirProgram: 'zk-devlet-tax-debt-status-noir-v2',
    circuitDirectory: 'tax-debt',
    artifactName: 'zk_devlet_tax_debt_v2.json',
    witnessBuilderName: 'prepare-tax-debt-witness.js',
    maximumCompressedLength: 2304,
    privateRangeKinds: [
      'qr-image', 'content-stream', 'creation-date', 'modification-date',
      'document-id',
    ],
  },
} as const;

export type DocumentType = keyof typeof documentProfiles;
export type DocumentProfile = (typeof documentProfiles)[DocumentType];
export type TlsPdfProfile = DocumentProfile['tlsProfile'];
export type NoirProgram = DocumentProfile['noirProgram'];
export type PrivateRangeKind = DocumentProfile['privateRangeKinds'][number];

const profiles = Object.values(documentProfiles);
for (const [documentType, profile] of Object.entries(documentProfiles)) {
  if (profile.documentType !== documentType ||
      profile.maximumCompressedLength < 1 ||
      profile.privateRangeKinds.filter((kind) => kind === 'content-stream').length !== 1 ||
      new Set(profile.privateRangeKinds).size !== profile.privateRangeKinds.length) {
    throw new Error(`Invalid document profile definition: ${documentType}`);
  }
}
for (const field of ['tlsProfile', 'recordVersion', 'noirProgram'] as const) {
  if (new Set(profiles.map((profile) => profile[field])).size !== profiles.length) {
    throw new Error(`Document profile ${field} values must be unique.`);
  }
}

export function getDocumentProfile(documentType: DocumentType): DocumentProfile {
  return documentProfiles[documentType];
}

export function getDocumentProfileByTlsProfile(
  tlsProfile: TlsPdfProfile,
): DocumentProfile {
  const profile = Object.values(documentProfiles).find(
    (candidate) => candidate.tlsProfile === tlsProfile,
  );
  if (!profile) throw new Error('The selected PDF profile is not supported.');
  return profile;
}
