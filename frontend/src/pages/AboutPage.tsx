import { useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Breadcrumbs, EvidenceTag, PageTitle, Panel } from '../components/ui';

const Section = ({ id, title, children }: { id: string; title: string; children: React.ReactNode }) => (
  <section id={id} aria-labelledby={`${id}-h`} className="scroll-mt-4">
    <Panel title={<span id={`${id}-h`}>{title}</span>}><div className="space-y-2 text-sm text-ink max-w-[90ch]">{children}</div></Panel>
  </section>
);

export const AboutPage = () => {
  const { hash } = useLocation();
  useEffect(() => {
    if (hash) document.getElementById(hash.slice(1))?.scrollIntoView({ block: 'start' });
  }, [hash]);
  return (
    <>
      <Breadcrumbs items={[{ label: 'About and limitations' }]} />
      <PageTitle title="About SecureMailScope"
        lead="A passive analysis workstation for the cryptographic security of email traffic (SMTP, IMAP, POP3) in stored packet captures." />

      <Section id="method" title="1. Method">
        <p>A capture is analysed offline. SecureMailScope never contacts a mail server, never generates traffic and never decrypts anything.</p>
        <ol className="list-decimal pl-5 space-y-1">
          <li>TCP streams are reassembled by sequence number (out-of-order, retransmitted and overlapping segments handled).</li>
          <li>SMTP, IMAP and POP3 are identified from greetings, commands and ports, including STARTTLS/STLS and implicit TLS (465, 993, 995).</li>
          <li>TLS handshakes are parsed: version, cipher suite, key exchange and group, forward secrecy, alerts.</li>
          <li>X.509 certificates are extracted where the protocol exposes them, and analysed at capture time.</li>
          <li>Deterministic rules produce findings; a posture score is computed from findings only.</li>
          <li>A supplementary ML stage ranks sessions that are weaker than the capture's own norm.</li>
        </ol>
      </Section>

      <Section id="findings-vs-ml" title="2. Deterministic findings and ML anomalies">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="border border-line rounded p-3">
            <div className="font-semibold">Deterministic finding</div>
            <p className="mt-1">A defined security rule was triggered by observed values (for example TLS 1.0 was negotiated). Findings carry an evidence class, capture frame numbers and a recommendation, and they determine the posture score. This is the primary security assessment.</p>
          </div>
          <div className="border border-ml/60 rounded p-3">
            <div className="font-semibold">ML anomaly <EvidenceTag value="ML_ANOMALY" /></div>
            <p className="mt-1">This session's security configuration is weaker than, and unusual relative to, the rest of this capture. It requires investigation. It is not an attack, compromise or malicious-session verdict, and it never changes findings or the score.</p>
          </div>
        </div>
        <p><strong>Model:</strong> unsupervised Isolation Forest that ranks sessions weaker than the capture's norm; evaluated on labelled lab sessions; supplementary to deterministic rules.</p>
        <ul className="list-disc pl-5 space-y-1" id="ml-limitations">
          <li>Evaluated only on lab-generated labelled sessions (80 real TLS sessions from 20 server configurations). No real-world accuracy is claimed.</li>
          <li>Uncommon but healthy configurations (TLS 1.3, ECDSA keys, stronger keys) are not penalised.</li>
          <li>A weakness shared by most sessions of a capture defines the norm and is not reported as an ML anomaly; the rules still report it.</li>
          <li>On the evaluation data the forest adds a ranking, not detection beyond the rules.</li>
        </ul>
      </Section>

      <Section id="limitations" title="3. What passive analysis cannot establish">
        <ul className="list-disc pl-5 space-y-1">
          <li><EvidenceTag value="NOT_OBSERVABLE" /> Certificates in TLS 1.3 sessions: the Certificate message is encrypted by the protocol.</li>
          <li><EvidenceTag value="NOT_EVALUATED" /> Certificate trust: no trust-anchor store, CRL or OCSP is consulted. Chain linkage (each certificate signed by the next) is verified cryptographically.</li>
          <li><EvidenceTag value="NOT_OBSERVED" /> Server capabilities that were not exercised in the capture (for example whether a server would also accept TLS 1.0).</li>
          <li><EvidenceTag value="POTENTIAL_INDICATOR" /> Whether a STARTTLS rejection was an attack or a misconfiguration.</li>
          <li>Anything inside TLS (commands, authentication, message content), DANE, MTA-STS and DNSSEC policy.</li>
          <li>Scoring weights and policy profiles are documented policy choices, not calibrated risk models.</li>
        </ul>
      </Section>

      <Section id="evidence-classes" title="4. Evidence classes">
        <dl className="kv">
          <dt><EvidenceTag value="OBSERVED" /></dt><dd>Directly visible in the capture bytes.</dd>
          <dt><EvidenceTag value="INFERRED" /></dt><dd>Derived from observed values (for example no forward secrecy from a static-RSA suite).</dd>
          <dt><EvidenceTag value="POTENTIAL_INDICATOR" /></dt><dd>Consistent with an attack or a misconfiguration; not proof.</dd>
          <dt><EvidenceTag value="NOT_OBSERVED" /></dt><dd>Absent from this capture.</dd>
          <dt><EvidenceTag value="NOT_OBSERVABLE" /></dt><dd>Hidden from any passive observer by the protocol.</dd>
        </dl>
      </Section>

      <Section id="validation" title="5. Validation data">
        <ul className="list-disc pl-5 space-y-1">
          <li>28 fixture captures with real OpenSSL TLS handshakes in synthesised TCP framing, each with ground truth.</li>
          <li>Real mail server/client sessions generated in a controlled local lab: SMTP (Mailpit, aiosmtpd), IMAP (pymap), POP3 (Mailpit) with Python clients. Application bytes and timing are real; TCP/IP headers are reconstructed by a recording relay because no raw capture driver was available.</li>
          <li>Five independently produced public captures (Wireshark wiki sample captures: IMAP, POP3 and SMTP with STARTTLS, and plaintext SMTP), downloaded and verified by SHA-256 at test time.</li>
        </ul>
      </Section>

      <Section id="data-handling" title="6. Data handling">
        <ul className="list-disc pl-5 space-y-1">
          <li>The API and dashboard run on this machine (the API binds to 127.0.0.1) and have no authentication; do not expose them.</li>
          <li>Uploaded captures are stored under a random name; credentials seen in plaintext authentication are never stored, only the mechanism name.</li>
          <li>Redacted outputs replace addresses, host names, organisation names, e-mail addresses and the file name with pseudonyms. Fingerprints and serial numbers are kept and can be looked up in public Certificate Transparency logs.</li>
          <li>Analyst notes are stored with the analysis. Only notes you select appear in reports; in redacted reports addresses and host names inside notes are pseudonymised, other free text is not.</li>
        </ul>
      </Section>

      <Section id="independence" title="7. Independence">
        <p>SecureMailScope is an independent academic project for Smart India Hackathon 2026 (problem statement SIH26159). It is not affiliated with, endorsed by or a product of any government agency. Its restrained presentation follows public accessibility guidance (GIGW 3.0); it uses no government emblem, seal or branding.</p>
        <p><Link to="/captures" className="link">Start with step 1: Capture</Link></p>
      </Section>
    </>
  );
};
