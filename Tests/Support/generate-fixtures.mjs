// Development-only fixture generator. Requires npm install in the sibling js checkout.
// Never runs as part of Swift builds, CI, or registry maintenance.
import { createRequire } from 'node:module';
import { readFile, writeFile, readdir } from 'node:fs/promises';
const jsRoot = new URL('../../../js/', import.meta.url);
const require = createRequire(new URL('package.json', jsRoot));
const asn1 = await import(require.resolve('asn1js'));
const pki = await import(require.resolve('pkijs'));
const { default: canonical } = await import(require.resolve('canonical-json'));
const sdk = await import(new URL('scripts/trusted-issuer-registry.js', jsRoot));
const helpers = await import(new URL('scripts/certificate-helper.js', jsRoot));
const { REGISTRY_URL_BASE } = await import(new URL('scripts/constants.js', jsRoot));
helpers.ensurePKIjsCryptoEngine();
const NativeDate = Date;
const NOW = '2026-10-08T00:00:00Z';
globalThis.Date = class extends NativeDate {
    constructor(...args) { super(...(args.length ? args : [NOW])); }
    static now() { return new NativeDate(NOW).getTime(); }
};
const time = value => new pki.Time({ type: 1, value: new Date(value) });
const ext = (oid, value, critical = false) => new pki.Extension({ extnID: oid, critical,
    extnValue: value.toSchema ? value.toSchema().toBER() : value.toBER() });
const identifier = new Uint8Array([1, 2, 3, 4]);
const crlURL = 'https://example.test/issuer.crl';
const name = value => new pki.RelativeDistinguishedNames({ typesAndValues: [
    new pki.AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1.Utf8String({ value }) }),
    new pki.AttributeTypeAndValue({ type: '2.5.4.6', value: new asn1.PrintableString({ value: 'US' }) }),
    new pki.AttributeTypeAndValue({ type: '2.5.4.8', value: new asn1.Utf8String({ value: 'US-VA' }) }),
].sort((a, b) => Buffer.compare(Buffer.from(a.toSchema().toBER()), Buffer.from(b.toSchema().toBER()))) });
const keys = () => crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const issuerKeys = await keys();
const leafKeys = await keys();
const certificates = {};
async function certificate(label, { issuer = false, keyPair = issuer ? issuerKeys : leafKeys,
    signer = issuerKeys, before = '2000-01-01', after = '2100-01-01', serial = issuer ? 1 : 100,
    aki = !issuer, ski = issuer, points, usage = issuer, subject = issuer ? 'Test issuer' : 'Document signer',
    issuerName = 'Test issuer', hash = 'SHA-256', ca = issuer } = {}) {
    const extensions = [];
    if(ski) extensions.push(ext('2.5.29.14', new asn1.OctetString({ valueHex: identifier })));
    if(aki) extensions.push(ext('2.5.29.35', new pki.AuthorityKeyIdentifier({ keyIdentifier: new asn1.OctetString({ valueHex: identifier }) })));
    if(ca) extensions.push(ext('2.5.29.19', new pki.BasicConstraints({ cA: true }), true));
    if(usage) extensions.push(ext('2.5.29.15', new asn1.BitString({ valueHex: new Uint8Array([6]), unusedBits: 1 }), true));
    if(!issuer && points !== false) extensions.push(ext('2.5.29.31', new pki.CRLDistributionPoints({ distributionPoints: points ?? [
        new pki.DistributionPoint({ distributionPoint: [new pki.GeneralName({ type: 6, value: crlURL })] }),
    ] })));
    const cert = new pki.Certificate({ version: 2, serialNumber: new asn1.Integer({ value: serial }),
        subject: name(subject), issuer: name(issuerName), notBefore: time(before), notAfter: time(after), extensions });
    await cert.subjectPublicKeyInfo.importKey(keyPair.publicKey);
    await cert.sign(signer.privateKey, hash);
    certificates[label] = sdk.certificateToPem(cert);
    return cert;
}
const issuer = await certificate('issuer', { issuer: true });
await certificate('renewed', { issuer: true, serial: 2, before: '2001-01-01' });
await certificate('expiredIssuer', { issuer: true, serial: 3, after: '2001-01-01' });
await certificate('futureIssuer', { issuer: true, serial: 4, before: '2090-01-01' });
await certificate('wrongIssuer', { issuer: true, serial: 5, keyPair: await keys(), signer: await keys() });
await certificate('wrongName', { issuer: true, subject: 'Other issuer' });
await certificate('noSKI', { issuer: true, ski: false });
await certificate('noUsage', { issuer: true, usage: false });
const leaf = await certificate('leaf');
// Keep these signed malformed inputs outside parity cases: Swift rejects ambiguous TBS fields.
async function certificateWithTBSFields(label, transform) {
    const fields = asn1.fromBER(leaf.encodeTBS().toBER()).result.valueBlock.value;
    const tbs = new asn1.Sequence({ value: transform(fields) });
    const signature = pki.createCMSECDSASignature(await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' }, issuerKeys.privateKey, tbs.toBER()));
    const der = new asn1.Sequence({ value: [tbs, leaf.signatureAlgorithm.toSchema(), new asn1.BitString({ valueHex: signature })] }).toBER();
    certificates[label] = '-----BEGIN CERTIFICATE-----\n' + Buffer.from(der).toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----';
}
const uniqueID = tagNumber => new asn1.Primitive({ idBlock: { tagClass: 3, tagNumber }, valueHex: new Uint8Array([0, 0xA5]) });
await certificateWithTBSFields('uniqueIDs', fields => [...fields.slice(0, -1), uniqueID(1), uniqueID(2), fields.at(-1)]);
for(const tag of [1, 2]) await certificateWithTBSFields(`duplicateUniqueID${tag}`, fields => [...fields.slice(0, -1), uniqueID(tag), uniqueID(tag), fields.at(-1)]);
await certificateWithTBSFields('duplicateExtensions', fields => [...fields, fields.at(-1)]);
await certificateWithTBSFields('reorderedUniqueIDs', fields => [...fields.slice(0, -1), uniqueID(2), uniqueID(1), fields.at(-1)]);
await certificateWithTBSFields('extensionsBeforeUniqueID', fields => [...fields, uniqueID(1)]);
await certificateWithTBSFields('constructedUniqueID', fields => [...fields.slice(0, -1), new asn1.Constructed({ idBlock: { tagClass: 3, tagNumber: 1 }, value: [new asn1.BitString({ valueHex: new Uint8Array([1]) })] }), fields.at(-1)]);
await certificateWithTBSFields('invalidUniqueIDPadding', fields => [...fields.slice(0, -1), new asn1.Primitive({ idBlock: { tagClass: 3, tagNumber: 1 }, valueHex: new Uint8Array([8, 0]) }), fields.at(-1)]);
await certificateWithTBSFields('v1UniqueID', fields => [...fields.slice(1, -1), uniqueID(1)]);
await certificateWithTBSFields('v2Extensions', fields => [new asn1.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [new asn1.Integer({ value: 1 })] }), ...fields.slice(1)]);
await certificate('expiredLeaf', { after: '2001-01-01' });
await certificate('futureLeaf', { before: '2090-01-01' });
await certificate('boundaryLeaf', { before: NOW, after: NOW });
await certificate('noAKI', { aki: false, after: '2001-01-01' });
await certificate('noCRL', { points: false });
await certificate('caLeaf', { ca: true });
const fullName = url => [new pki.GeneralName({ type: 6, value: url })];
await certificate('delegated', { points: [new pki.DistributionPoint({ distributionPoint: fullName(crlURL), cRLIssuer: fullName('https://example.test/delegated') })] });
const reasonBits = byte => new asn1.BitString({ valueHex: new Uint8Array([byte]), unusedBits: 0 });
await certificate('partialReasons', { points: [new pki.DistributionPoint({ distributionPoint: fullName(crlURL), reasons: reasonBits(0x40) })] });
await certificate('twoReasons', { points: [
    new pki.DistributionPoint({ distributionPoint: fullName(crlURL), reasons: reasonBits(0x40) }),
    new pki.DistributionPoint({ distributionPoint: fullName('https://example.test/second.crl'), reasons: new asn1.BitString({ valueHex: new Uint8Array([0x3F, 0x80]), unusedBits: 7 }) }),
] });
const crls = {};
async function crl(label, { revoked = false, reason, delta = false, before = '2000-01-01', after = '2100-01-01',
    idp, signer = issuerKeys, issuerName = 'Test issuer', nextUpdate = true, hash = 'SHA-256', extraExtensions = [] } = {}) {
    const extensions = [...extraExtensions];
    if(delta) extensions.push(ext('2.5.29.27', new asn1.Integer({ value: 1 }), true));
    if(idp) extensions.push(ext('2.5.29.28', new pki.IssuingDistributionPoint(idp), true));
    const value = new pki.CertificateRevocationList({ version: 1, issuer: name(issuerName), thisUpdate: time(before),
        ...(nextUpdate && { nextUpdate: time(after) }),
        ...(extensions.length && { crlExtensions: new pki.Extensions({ extensions }) }),
        revokedCertificates: revoked ? [new pki.RevokedCertificate({ userCertificate: leaf.serialNumber, revocationDate: time('2000-01-01'),
            ...(reason !== undefined && { crlEntryExtensions: new pki.Extensions({ extensions: [ext('2.5.29.21', new asn1.Enumerated({ value: reason }))] }) }) })] : [] });
    await value.sign(signer.privateKey, hash);
    crls[label] = Buffer.from(value.toSchema().toBER()).toString('base64');
    return value;
}
await crl('valid');
await crl('revoked', { revoked: true });
await crl('stale', { after: '2001-01-01' });
await crl('staleRevoked', { revoked: true, after: '2001-01-01' });
await crl('future', { before: '2090-01-01' });
await crl('delta', { delta: true });
await crl('deltaRevoked', { delta: true, revoked: true });
await crl('remove', { revoked: true, reason: 8 });
await crl('deltaRemove', { delta: true, revoked: true, reason: 8 });
await crl('badSignature', { signer: await keys() });
await crl('wrongIssuer', { issuerName: 'Other issuer' });
await crl('indirect', { idp: { indirectCRL: true } });
await crl('attribute', { idp: { onlyContainsAttributeCerts: true } });
await crl('caOnly', { idp: { onlyContainsCACerts: true } });
await crl('userOnly', { idp: { onlyContainsUserCerts: true } });
await crl('wrongPoint', { idp: { distributionPoint: fullName('https://example.test/other.crl') } });
await crl('matchingPoint', { idp: { distributionPoint: fullName(crlURL) } });
await crl('partial', { idp: { onlySomeReasons: 0x40 } });
await crl('noNextUpdate', { nextUpdate: false });
await crl('soon', { after: '2026-10-08T00:00:05Z' });
for(const critical of [false, true]) {
    for(const revoked of [false, true]) await crl(`unknown${critical ? 'Critical' : 'Noncritical'}${revoked ? 'Revoked' : ''}`, {
        revoked, extraExtensions: [ext('1.2.3.4', new asn1.OctetString({ valueHex: new Uint8Array([1]) }), critical)],
    });
}
await crl('knownCritical', { extraExtensions: [ext('2.5.29.20', new asn1.Integer({ value: 1 }), true)] });
const aki = helpers.getSubjectKeyIdentifier(issuer);
const signingKeys = await keys();
await certificate('testSigning', { issuer: true, keyPair: signingKeys, signer: signingKeys });
async function signIssuer(value) {
    const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signingKeys.privateKey, Buffer.from(canonical(value)));
    return { ...value, signature: Buffer.from(pki.createCMSECDSASignature(signature)).toString('base64') };
}
const unsignedIssuer = { issuer_id: `x509_aki:${aki}`, entity_type: 'government', entity_metadata: { country: 'US', region: 'VA' },
    display: { name: 'Registry issuer', logo: 'https://example.test/logo.png', description: 'Issuer é\u2028description' },
    trust_scopes: ['government_issued_id'], certificates: [
        { data: certificates.renewed, format: 'pem', trust_lists: ['uv'] },
        { data: certificates.issuer, format: 'pem', trust_lists: ['aamva_dts'] },
    ] };
const registryIssuers = { normal: await signIssuer(unsignedIssuer), empty: await signIssuer({ ...unsignedIssuer, certificates: [] }) };
// Store the raw JSON as text: decoding into Swift models would discard the unknown signed fields.
const signedJSON = [];
for(const [label, extra] of [
    ['unicodeKeys', { 'é': 'composed', 'e\u0301': 'decomposed', nested: { 'Å': 1, 'A\u030A': 2 },
        array: [{ 'ö': 'first', 'o\u0308': 'second' }], escaped: '😀\u2028\u0000' }],
    ['optionalNulls', { null: null, boolean: true, list: [false, null, 0, -1.25, 'quote"/slash\\'] }],
    ['loneSurrogateInUnknownField', { surrogate: '\ud800' }],
]) {
    const unsigned = { ...unsignedIssuer, extra };
    if(label === 'optionalNulls') {
        unsigned.entity_metadata = { country: null };
        unsigned.display = { name: 'Nullable metadata', logo: null, description: null };
    }
    const value = await signIssuer(unsigned);
    const canonicalBytes = Buffer.from(canonical(unsigned));
    if(!await sdk.verifySignatureWithPem(certificates.testSigning, value.signature, canonicalBytes)) {
        throw new Error(`Invalid signed JSON fixture: ${label}`);
    }
    signedJSON.push({ label, input: JSON.stringify(value),
        reordered: '{' + Object.entries(value).reverse().map(([key, data]) => JSON.stringify(key) + ':' + JSON.stringify(data)).join(',') + '}',
        canonicalBytes: canonicalBytes.toString('base64'), expected: value });
}
const cases = [];
const originalFetch = globalThis.fetch;
async function scenario(label, { input = 'leaf', custom = ['issuer'], mode = 'skip', trustLists = [], scope,
    registry, status = 404, crl = 'valid', secondCRL = 'valid' } = {}) {
    const options = { trustedIssuerCertificates: custom.map(value => typeof value === 'string' ? certificates[value] : { ...value, data: certificates[value.data] }), revocationCheckMode: mode };
    const client = new sdk.Registry(options);
    if(registry) client._cachedFetcher._set('issuer', `${REGISTRY_URL_BASE}/issuers/x509_aki/${aki}.json`,
        { ok: true, status: 200, issuer: registryIssuers[registry] });
    globalThis.fetch = async url => {
        if(url.includes('/issuers/')) return new Response('', { status });
        if(crl === 'unavailable') return new Response('', { status: 503 });
        if(crl === 'malformed') return new Response('bad CRL');
        return new Response(Buffer.from(crls[url.endsWith('second.crl') ? secondCRL : crl], 'base64'));
    };
    const expected = await client.resolveCertificateTrust(input === null ? null : certificates[input], { trustLists, trustScope: scope });
    const normalize = result => ({ ...result, untrustedReasons: result.untrustedReasons ?? [],
        ...(result.issuer && { issuer: { ...result.issuer, certificates: result.issuer.certificates.map(cert => ({ ...cert, untrustedReasons: cert.untrustedReasons ?? [] })) } }) });
    cases.push({ label, input, custom, mode, trustLists, ...(scope && { scope }), registry, status, crl, secondCRL, expected: normalize(expected) });
}
await scenario('custom only');
await scenario('ordered unique IDs', { input: 'uniqueIDs' });
await scenario('parsed validity boundary', { input: 'boundaryLeaf' });
await scenario('missing', { input: null });
await scenario('no AKI', { input: 'noAKI', trustLists: ['uv'] });
await scenario('expired leaf', { input: 'expiredLeaf' });
await scenario('future leaf', { input: 'futureLeaf' });
await scenario('expired issuer', { custom: ['expiredIssuer'] });
await scenario('future issuer', { custom: ['futureIssuer'] });
await scenario('wrong issuer signature', { custom: ['wrongIssuer'] });
await scenario('wrong issuer name', { custom: ['wrongName'] });
await scenario('scope missing', { scope: 'document_signing' });
await scenario('scope supplied', { scope: 'document_signing', custom: [{ data: 'issuer', trust_scopes: ['document_signing'] }] });
await scenario('missing issuer', { custom: [] });
await scenario('registry 404', { custom: [], trustLists: ['uv'] });
await scenario('registry failure', { custom: [], trustLists: ['uv'], status: 503 });
await scenario('custom fallback', { trustLists: ['uv'], status: 503 });
await scenario('failed custom and CDN', { custom: ['wrongIssuer'], trustLists: ['uv'], status: 503 });
await scenario('registry only', { custom: [], trustLists: ['uv'], registry: 'normal' });
await scenario('registry list mismatch', { custom: [], trustLists: ['uv'], registry: 'normal', scope: 'document_signing' });
await scenario('empty registry issuer', { custom: [], trustLists: ['uv'], registry: 'empty' });
await scenario('merge custom and registry', { custom: [{ data: 'issuer', trust_scopes: ['document_signing'], entity_type: 'educational_institution',
    entity_metadata: { country: 'CA' }, display: { name: 'User name' } }], trustLists: ['uv'], registry: 'normal' });
await scenario('user order and tie breaking', { custom: ['expiredIssuer', 'futureIssuer'] });
await scenario('duplicates', { custom: ['issuer', 'issuer', 'renewed'] });
for(const mode of ['skip', 'best_effort', 'required']) {
    for(const value of ['valid', 'revoked', 'stale', 'staleRevoked', 'future', 'delta', 'deltaRevoked', 'remove', 'deltaRemove',
        'badSignature', 'wrongIssuer', 'indirect', 'attribute', 'caOnly', 'userOnly', 'wrongPoint', 'matchingPoint', 'partial',
        'noNextUpdate', 'unavailable', 'malformed', 'unknownCritical', 'unknownCriticalRevoked',
        'unknownNoncritical', 'unknownNoncriticalRevoked', 'knownCritical']) await scenario(`${mode} CRL ${value}`, { mode, crl: value });
}
await scenario('required no distribution point', { input: 'noCRL', mode: 'required' });
await scenario('best effort no distribution point', { input: 'noCRL', mode: 'best_effort' });
await scenario('delegated CRL', { input: 'delegated', mode: 'required' });
await scenario('partial reason coverage', { input: 'partialReasons', mode: 'required' });
await scenario('combined reason coverage', { input: 'twoReasons', mode: 'required' });
await scenario('CA leaf versus user CRL', { input: 'caLeaf', mode: 'required', crl: 'userOnly' });
await scenario('CA leaf versus CA CRL', { input: 'caLeaf', mode: 'required', crl: 'caOnly' });
await scenario('issuer missing CRL usage', { custom: ['noUsage'], mode: 'required' });
await scenario('signature failure avoids CRL', { custom: ['wrongIssuer'], mode: 'required' });
const signatureData = Buffer.from('Signature verification regression test');
// JS supports these keys; Swift Certificates' importer requires at least 2048 bits.
const rsa1024 = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', modulusLength: 1024,
    publicExponent: new Uint8Array([1, 0, 1]) }, true, ['sign', 'verify']);
await certificate('rsa1024', { issuer: true, keyPair: rsa1024, signer: rsa1024 });
await certificate('rsa1024-leaf', { signer: rsa1024 });
if(!await sdk.verifyCertificateSignature(certificates['rsa1024-leaf'], certificates.rsa1024)) throw new Error('RSA 1024 fixture must verify in JavaScript');
const signatures = [];
for(const [curve, hash, override] of [['P-256', 'SHA-256', 'SHA-384'], ['P-384', 'SHA-384', 'SHA-512'], ['P-521', 'SHA-512', 'SHA-256']]) {
    const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: curve }, true, ['sign', 'verify']);
    const label = `ec-${curve}`;
    await certificate(label, { issuer: true, keyPair, signer: keyPair });
    await certificate(`${label}-leaf`, { signer: keyPair });
    await crl(`${label}-crl`, { signer: keyPair });
    await scenario(`${curve} certificate and CRL`, { custom: [label], input: `${label}-leaf`, mode: 'required', crl: `${label}-crl` });
    for(const chosen of [hash, override, 'SHA-1']) {
        const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: chosen }, keyPair.privateKey, signatureData);
        signatures.push({ certificate: label, hash: chosen, algorithm: 'ecdsa', useDefault: chosen === hash,
            signature: Buffer.from(pki.createCMSECDSASignature(signature)).toString('base64') });
    }
}
for(const algorithm of ['RSASSA-PKCS1-v1_5', 'RSA-PSS']) {
    for(const hash of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
        const keyPair = await crypto.subtle.generateKey({ name: algorithm, hash, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }, true, ['sign', 'verify']);
        const label = `${algorithm}-${hash}`;
        const cert = await certificate(label, { issuer: true, keyPair, signer: keyPair, hash });
        await certificate(`${label}-leaf`, { signer: keyPair, hash });
        await crl(`${label}-crl`, { signer: keyPair, hash });
        await scenario(`${label} certificate and CRL`, { custom: [label], input: `${label}-leaf`, mode: 'required', crl: `${label}-crl` });
        const salts = algorithm === 'RSA-PSS' ? [hash === 'SHA-1' ? 20 : Number(hash.slice(4)) / 8, 0, 20, 80] : [null];
        for(const saltLength of [...new Set(salts)]) {
            const options = { name: algorithm, ...(saltLength !== null && { saltLength }) };
            const signature = await crypto.subtle.sign(options, keyPair.privateKey, signatureData);
            signatures.push({ certificate: label, hash, algorithm: algorithm === 'RSA-PSS' ? 'rsaPSS' : 'rsaPKCS1v15',
                ...(saltLength !== null && { saltLength }), signature: Buffer.from(signature).toString('base64') });
        }
        if(algorithm === 'RSA-PSS' && hash === 'SHA-256') {
            const hashAlgorithm = new pki.AlgorithmIdentifier({ algorithmId: '2.16.840.1.101.3.4.2.1', algorithmParams: new asn1.Null() });
            const mgf = new pki.AlgorithmIdentifier({ algorithmId: '1.2.840.113549.1.1.8', algorithmParams: hashAlgorithm.toSchema() });
            for(const [suffix, changes] of [
                ['badMGF', { maskGenAlgorithm: new pki.AlgorithmIdentifier({ algorithmId: '1.2.840.113549.1.1.8', algorithmParams: new pki.AlgorithmIdentifier({ algorithmId: '2.16.840.1.101.3.4.2.2', algorithmParams: new asn1.Null() }).toSchema() }) }],
                ['badTrailer', { trailerField: 2 }],
                ['zeroSalt', { saltLength: 0 }],
            ]) {
                const algorithmIdentifier = new pki.AlgorithmIdentifier({ algorithmId: '1.2.840.113549.1.1.10',
                    algorithmParams: new pki.RSASSAPSSParams({ hashAlgorithm, maskGenAlgorithm: mgf, saltLength: 32, ...changes }).toSchema() });
                const value = await crl(suffix, { signer: keyPair, hash });
                value.signature = algorithmIdentifier;
                value.signatureAlgorithm = algorithmIdentifier;
                value.tbsView = new Uint8Array(value.encodeTBS().toBER());
                value.signatureValue = new asn1.BitString({ valueHex: await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: changes.saltLength ?? 32 }, keyPair.privateKey, value.tbsView) });
                crls[suffix] = Buffer.from(value.toSchema().toBER()).toString('base64');
                if(suffix !== 'zeroSalt') await scenario(`unsupported PSS CRL ${suffix}`, { custom: [label], input: `${label}-leaf`, mode: 'required', crl: suffix });
            }
            cert.subjectPublicKeyInfo.algorithm = new pki.AlgorithmIdentifier({ algorithmId: '1.2.840.113549.1.1.10' });
            cert.tbsView = new Uint8Array(cert.encodeTBS().toBER());
            certificates.pssOnly = sdk.certificateToPem(cert);
        }
    }
}
for(const fixture of signatures) {
    fixture.expected = await sdk.verifySignatureWithPem(certificates[fixture.certificate], fixture.signature, signatureData,
        fixture.algorithm === 'ecdsa' ? (fixture.useDefault ? {} : { hash: fixture.hash }) :
            { name: fixture.algorithm === 'rsaPSS' ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5', hash: fixture.hash, saltLength: fixture.saltLength });
}
const canonicalValues = [
    { z: ['é', '\u2028', '\u0000', '😀', '\u007f'], a: { second: 'line\nslash/quote"', first: '\u00ad\ufeff' } },
    { bool: true, false: false, null: null, numbers: [0, -0, 1, -1.25, 1e-7, 1e-6, 1e20, 1e21, 1.234e30] },
    { '\uffff': 'last', '😀': 'UTF-16 first', nested: { b: [], a: {} } },
    { 'é': 'composed', 'e\u0301': 'decomposed', nested: { 'Å': 1, 'A\u030A': 2 } },
];
const actualFile = (await readdir(new URL('issuers/x509_aki/', jsRoot))).sort()[0];
const actualIssuerJSON = await readFile(new URL(`issuers/x509_aki/${actualFile}`, jsRoot), 'utf8');
const { verifyIssuer } = await import(new URL('scripts/issuer-helper.js', jsRoot));
if(!await verifyIssuer(JSON.parse(actualIssuerJSON))) throw new Error('Pinned signing certificate does not verify real issuer fixture');
globalThis.fetch = originalFetch;
const output = { now: NOW, aki, certificates, crls, registryIssuers, actualIssuerJSON, signedJSON,
    signatureData: signatureData.toString('base64'), signatures, cases,
    canonical: canonicalValues.map(value => ({ input: JSON.stringify(value), expected: canonical(value) })) };
await writeFile(new URL('../TrustedIssuerRegistryTests/Fixtures/runtime.json', import.meta.url), JSON.stringify(output, null, 2) + '\n');
console.log(`Wrote ${cases.length} trust cases, ${signatures.length} signatures, and ${Object.keys(crls).length} CRLs.`);
