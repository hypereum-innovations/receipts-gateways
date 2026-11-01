// SPDX-License-Identifier: Apache-2.0
/**
 * RFC 3161 time-stamping. Request builder (DER), HTTP client for real
 * (qualified) TSAs, a local TSA producing conforming CMS tokens for tests and
 * self-hosting, and a token verifier that checks the CMS signature, the
 * message imprint and the genTime — no trust in Hypereum's clock. Every hour
 * the current checkpoint root is stamped by two independent authorities in
 * production; in development the local TSA stands in behind the same API.
 */
import {
  createHash,
  createSign,
  createVerify,
  randomBytes,
  X509Certificate,
  createPrivateKey,
  createPublicKey,
  type KeyObject,
} from 'node:crypto';
import {
  der,
  derExplicit,
  derGeneralizedTime,
  derInt,
  derNull,
  derOctetString,
  derOid,
  derSeq,
  derSet,
  oidToString,
  parseDer,
  parseGeneralizedTime,
  type DerNode,
} from './asn1.js';
import { sha256 } from './keys.js';

const OID_SHA1 = '1.3.14.3.2.26';
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_SHA384 = '2.16.840.1.101.3.4.2.2';
const OID_SHA512 = '2.16.840.1.101.3.4.2.3';
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_DATA = '1.2.840.113549.1.7.1';
export const OID_TSTINFO = '1.2.840.113549.1.9.16.1.4';
const OID_TSTINFO_PKCS9 = '1.2.840.113549.1.9.16.1.4';
const OID_SIGNING_TIME = '1.2.840.113549.1.9.5';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_CONTENT_TYPE_ATTR = '1.2.840.113549.1.9.3';
const OID_RSA_SHA256 = '1.2.840.113549.1.1.11';

function digestByOid(oid: string, data: Uint8Array): Buffer {
  switch (oid) {
    case OID_SHA256:
      return sha256(data);
    case OID_SHA384:
      return createHash('sha384').update(data).digest();
    case OID_SHA512:
      return createHash('sha512').update(data).digest();
    case OID_SHA1:
      return createHash('sha1').update(data).digest();
    default:
      throw new Error(`RFC3161: unsupported digest algorithm OID ${oid}`);
  }
}

function verifyAlgByDigestOid(oid: string): string {
  switch (oid) {
    case OID_SHA256:
      return 'RSA-SHA256';
    case OID_SHA384:
      return 'RSA-SHA384';
    case OID_SHA512:
      return 'RSA-SHA512';
    case OID_SHA1:
      return 'RSA-SHA1';
    default:
      throw new Error(`RFC3161: unsupported signature digest algorithm OID ${oid}`);
  }
}

function algId(oid: string, params: Buffer | null = derNull()): Buffer {
  return derSeq(params ? [derOid(oid), params] : [derOid(oid)]);
}

export function buildTimestampRequest(messageImprintDigest: Buffer, nonce = randomBytes(8)): Buffer {
  const imprint = derSeq([algId(OID_SHA256), derOctetString(messageImprintDigest)]);
  return derSeq([
    derInt(1),
    imprint,
    derInt(BigInt('0x' + nonce.toString('hex'))),
    der(0x01, Buffer.from([0xff])), // certReq = true
  ]);
}

export interface TimestampTokenInfo {
  imprint: Buffer;
  genTime: Date;
  policy: string;
  serial: Buffer;
  tokenDer: Buffer;
  signerCertPem: string | null;
}

function expectSeq(node: DerNode, what: string): DerNode[] {
  if (node.tag !== 0x30 || !node.children) throw new Error(`RFC3161: expected SEQUENCE for ${what}`);
  return node.children;
}

/** Parse a TimeStampResp; returns the token (ContentInfo) DER or throws with the PKIStatus. */
export function extractTokenFromResponse(respDer: Buffer): Buffer {
  const resp = expectSeq(parseDer(respDer), 'TimeStampResp');
  const statusInfo = expectSeq(resp[0]!, 'PKIStatusInfo');
  const status = statusInfo[0]!.content.readUIntBE(0, Math.min(4, statusInfo[0]!.content.length));
  if (status !== 0 && status !== 1) throw new Error(`RFC3161: TSA refused with PKIStatus ${status}`);
  if (!resp[1]) throw new Error('RFC3161: response has no token');
  return resp[1].raw;
}

/** Dig into CMS SignedData (or outer TimeStampResp) and return TSTInfo fields + signer material. */
export function parseTimestampToken(inputDer: Buffer): TimestampTokenInfo & {
  eContent: Buffer;
  signedAttrs: DerNode | null;
  signature: Buffer;
  digestAlg: string;
  hashAlgorithmOid: string;
  hashedMessage: Buffer;
} {
  let tokenDer: Buffer = Buffer.from(inputDer);
  let outerSeq = expectSeq(parseDer(tokenDer), 'ContentInfo');
  // Auto-unwrap TimeStampResp (starts with PKIStatusInfo SEQUENCE 0x30 instead of OID 0x06)
  if (outerSeq[0]?.tag === 0x30) {
    tokenDer = Buffer.from(extractTokenFromResponse(tokenDer));
    outerSeq = expectSeq(parseDer(tokenDer), 'ContentInfo');
  }
  const contentInfo = outerSeq;
  if (oidToString(contentInfo[0]!.content) !== OID_SIGNED_DATA) throw new Error('token is not SignedData');
  const signedData = expectSeq(contentInfo[1]!.children![0]!, 'SignedData');
  // signedData: version, digestAlgorithms SET, encapContentInfo, [0] certs?, signerInfos SET
  let idx = 2;
  const encap = expectSeq(signedData[idx++]!, 'EncapsulatedContentInfo');
  const encapOid = oidToString(encap[0]!.content);
  if (encapOid !== OID_TSTINFO_PKCS9 && encapOid !== OID_TSTINFO) {
    throw new Error('eContentType is not TSTInfo');
  }
  const eContent = encap[1]!.children![0]!.content; // OCTET STRING content (TSTInfo DER)
  let signerCertPem: string | null = null;
  if (signedData[idx]?.tag === 0xa0) {
    const certDer = signedData[idx]!.children![0]!.raw;
    signerCertPem =
      '-----BEGIN CERTIFICATE-----\n' +
      certDer.toString('base64').replace(/(.{64})/g, '$1\n') +
      '\n-----END CERTIFICATE-----';
    idx++;
  }
  const signerInfos = signedData[idx]!;
  const signerInfo = expectSeq(signerInfos.children![0]!, 'SignerInfo');
  // SignerInfo v1: version, issuerAndSerial, digestAlg, [0] signedAttrs?, sigAlg, signature
  let si = 2;
  const digestAlgNode = expectSeq(signerInfo[si++]!, 'digestAlgorithm');
  const digestAlg = oidToString(digestAlgNode[0]!.content);
  let signedAttrs: DerNode | null = null;
  if (signerInfo[si]?.tag === 0xa0) signedAttrs = signerInfo[si++]!;
  si++; // signatureAlgorithm
  const signature = signerInfo[si]!.content;

  const tst = expectSeq(parseDer(Buffer.from(eContent)), 'TSTInfo');
  // TSTInfo: version, policy OID, messageImprint, serial, genTime, ...
  const policy = oidToString(tst[1]!.content);
  const imprintSeq = expectSeq(tst[2]!, 'MessageImprint');
  const imprintAlgNode = expectSeq(imprintSeq[0]!, 'MessageImprint.hashAlgorithm');
  const hashAlgorithmOid = oidToString(imprintAlgNode[0]!.content);
  const imprint = Buffer.from(imprintSeq[1]!.content);
  const serial = Buffer.from(tst[3]!.content);
  const genTime = parseGeneralizedTime(tst[4]!.content);
  return {
    imprint,
    hashedMessage: imprint,
    hashAlgorithmOid,
    genTime,
    policy,
    serial,
    tokenDer,
    signerCertPem,
    eContent: Buffer.from(eContent),
    signedAttrs,
    signature: Buffer.from(signature),
    digestAlg,
  };
}

/**
 * Verify a token over an expected imprint. Checks: messageDigest signed
 * attribute (when present) equals the eContent digest (supporting SHA-256,
 * SHA-384, SHA-512, SHA-1), the CMS signature verifies with the embedded
 * (or supplied) TSA certificate, and the certificate chains to a pinned TSA
 * root or matches a pinned TSA certificate when supplied.
 */
export function verifyTimestampToken(
  tokenDer: Buffer,
  expectedImprint: Buffer,
  opts: { trustedTsaCertPems?: string[] } = {},
): { valid: boolean; genTime: Date | null; detail: string } {
  try {
    const t = parseTimestampToken(tokenDer);
    const imprintMatches =
      t.imprint.equals(expectedImprint) ||
      digestByOid(t.hashAlgorithmOid, expectedImprint).equals(t.imprint);
    if (!imprintMatches) {
      return { valid: false, genTime: t.genTime, detail: 'message imprint mismatch' };
    }
    const pemBlocks: string[] = [];
    for (const entry of opts.trustedTsaCertPems ?? []) {
      const matches = entry.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
      if (matches) pemBlocks.push(...matches);
      else if (entry.trim()) pemBlocks.push(entry.trim());
    }
    if (!t.signerCertPem && pemBlocks.length === 0) {
      return { valid: false, genTime: t.genTime, detail: 'token carries no signer certificate' };
    }
    const signerCertPem = t.signerCertPem ?? pemBlocks[0]!;
    const cert = new X509Certificate(signerCertPem);
    if (pemBlocks.length > 0) {
      const trusted = pemBlocks.some((pem) => {
        const root = new X509Certificate(pem);
        return root.raw.equals(cert.raw) || cert.verify(root.publicKey);
      });
      if (!trusted) {
        return {
          valid: false,
          genTime: t.genTime,
          detail: 'TSA certificate does not chain to a pinned root',
        };
      }
    }
    let signedData: Buffer;
    if (t.signedAttrs) {
      // messageDigest attribute must equal digest of eContent under SignerInfo.digestAlg
      let md: Buffer | null = null;
      for (const attr of t.signedAttrs.children!) {
        const parts = expectSeq(attr, 'Attribute');
        if (oidToString(parts[0]!.content) === OID_MESSAGE_DIGEST) {
          md = Buffer.from(parts[1]!.children![0]!.content);
        }
      }
      const expectedMd = digestByOid(t.digestAlg, t.eContent);
      if (!md || !md.equals(expectedMd)) {
        return { valid: false, genTime: t.genTime, detail: 'messageDigest attribute mismatch' };
      }
      // Signature is over the DER SET encoding of the attributes (tag 0x31, not [0]).
      signedData = Buffer.concat([Buffer.from([0x31]), t.signedAttrs.raw.subarray(1)]);
    } else {
      signedData = t.eContent;
    }
    const verifyAlg = verifyAlgByDigestOid(t.digestAlg);
    const v = createVerify(verifyAlg);
    v.update(signedData);
    v.end();
    const ok = v.verify(cert.publicKey, t.signature);
    return {
      valid: ok,
      genTime: t.genTime,
      detail: ok ? `TSA token verified, genTime ${t.genTime.toISOString()}` : 'CMS signature does not verify',
    };
  } catch (e) {
    return { valid: false, genTime: null, detail: (e as Error).message };
  }
}

export interface TsaClient {
  stamp(digest: Buffer): Promise<Buffer>;
}

export class HttpTsaClient implements TsaClient {
  constructor(
    private readonly url: string,
    private readonly fetchFn: typeof fetch = fetch,
  ) {}
  async stamp(digest: Buffer): Promise<Buffer> {
    const req = buildTimestampRequest(digest);
    const res = await this.fetchFn(this.url, {
      method: 'POST',
      headers: { 'content-type': 'application/timestamp-query' },
      body: new Uint8Array(req),
    });
    if (!res.ok) throw new Error(`TSA ${this.url} answered ${res.status}`);
    return extractTokenFromResponse(Buffer.from(await res.arrayBuffer()));
  }
}

/** A local RFC 3161 TSA (RSA) for development, tests and self-hosted witnesses of time. */
export class LocalTsa implements TsaClient {
  private serial = 1;
  private key: KeyObject;
  constructor(
    private readonly certPem: string,
    keyPem: string,
    private readonly policy = '1.3.6.1.4.1.99999.1',
    private readonly now: () => Date = () => new Date(),
  ) {
    this.key = createPrivateKey(keyPem);
  }

  async stamp(digest: Buffer): Promise<Buffer> {
    const genTime = this.now();
    const cert = new X509Certificate(this.certPem);
    const tstInfo = derSeq([
      derInt(1),
      derOid(this.policy),
      derSeq([algId(OID_SHA256), derOctetString(digest)]),
      derInt(this.serial++),
      derGeneralizedTime(genTime),
      derSeq([derInt(1)]), // accuracy: 1 second
    ]);
    const eContentDigest = sha256(tstInfo);
    const utcTime = der(
      0x17,
      Buffer.from(
        genTime.toISOString().slice(2).replace(/[-:]/g, '').replace('T', '').replace(/\.\d{3}/, ''),
        'ascii',
      ),
    );
    const signedAttrsContent = Buffer.concat(
      [
        derSeq([derOid(OID_CONTENT_TYPE_ATTR), derSet([derOid(OID_TSTINFO)])]),
        derSeq([derOid(OID_SIGNING_TIME), derSet([utcTime])]),
        derSeq([derOid(OID_MESSAGE_DIGEST), derSet([derOctetString(eContentDigest)])]),
      ].sort((a, b) => Buffer.compare(a as never, b as never)),
    );
    const attrsForSigning = der(0x31, signedAttrsContent);
    const signer = createSign('RSA-SHA256');
    signer.update(attrsForSigning);
    signer.end();
    const signature = signer.sign(this.key);
    const certDer = cert.raw;
    const issuerAndSerial = derSeq([
      // Reuse the certificate's issuer Name DER from the TBS — extracted positionally.
      extractIssuerName(certDer),
      derInt(Buffer.from(cert.serialNumber.replace(/:/g, ''), 'hex')),
    ]);
    const signerInfo = derSeq([
      derInt(1),
      issuerAndSerial,
      algId(OID_SHA256),
      der(0xa0, signedAttrsContent),
      algId(OID_RSA_SHA256),
      derOctetString(signature),
    ]);
    const encap = derSeq([derOid(OID_TSTINFO), derExplicit(0, derOctetString(tstInfo))]);
    const signedData = derSeq([
      derInt(3),
      derSet([algId(OID_SHA256)]),
      encap,
      derExplicit(0, certDer),
      derSet([signerInfo]),
    ]);
    return derSeq([derOid(OID_SIGNED_DATA), derExplicit(0, signedData)]);
  }
}

function extractIssuerName(certDer: Buffer): Buffer {
  const cert = parseDer(certDer);
  const tbs = cert.children![0]!;
  // TBSCertificate: [0] version?, serial, signature, issuer, ...
  let i = tbs.children![0]!.tag === 0xa0 ? 1 : 0;
  i += 2; // serial, signature alg
  return tbs.children![i]!.raw;
}

/** Dev TSA identity: self-signed RSA cert with timeStamping EKU, via node-forge. */
export async function createDevTsaIdentity(): Promise<{ certPem: string; keyPem: string }> {
  const forge = (await import('node-forge')).default;
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '02';
  cert.validity.notBefore = new Date(Date.now() - 3600_000);
  cert.validity.notAfter = new Date(Date.now() + 365 * 24 * 3600_000);
  const attrs = [{ name: 'commonName', value: 'Hivemind Receipts Dev TSA' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true },
    { name: 'extKeyUsage', timeStamping: true },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { certPem: forge.pki.certificateToPem(cert), keyPem: forge.pki.privateKeyToPem(keys.privateKey) };
}

export function tsaPublicKey(certPem: string): KeyObject {
  return createPublicKey(new X509Certificate(certPem).publicKey);
}
