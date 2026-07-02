# OCM Technical Primitives: For Non-Technical Deck Discussions

**Purpose.** Enough OCM technical grounding for a deck-discussion session to talk about primitives without going back to the spec every time. If you need the spec's precision, go to `~/github/github.com/morri-son/ocm-spec/doc/`, this file is for framing decisions, not for engineering.

## The four moves: the deck's central mnemonic

Every OCM lifecycle move maps to one of four verbs. Slide 7 of every architect deck sets this. Slides 8–11 walk them.

**Pack**, bundle your artifacts into a component. YAML input (constructor). Produces a signed descriptor + resources.

**Sign**, one signature over the canonicalized descriptor. Covers every resource digest. Three schemes (CLI): RSA, OpenPGP, Sigstore. K8s controller today: RSA only.

**Transport**, move the component across boundaries. Three patterns, one command:
- Registry → Registry (promotion, cross-cloud)
- Registry → CTF (archive out)
- CTF → Registry (air-gap import)

**Deploy**, verify at destination, unpack, apply. K8s: four-CR chain (Repository → Component → Resource → Deployer).

## What's actually signed: the trick

OCM signs the **canonical descriptor hash**, not the artifacts.

- Each resource has a SHA-256 digest of its bytes.
- The descriptor lists every resource's digest.
- The descriptor is canonicalized (deterministic serialization).
- The canonicalized descriptor's SHA-256 is what gets signed.
- **Access fields are EXCLUDED from canonicalization**, this is why transport can rewrite them freely without invalidating the signature.

So: one signature, over the canonical descriptor, covers every resource by digest. Sign once, verify anywhere, transport freely.

## Composition: service vs product

- **Service**, a component with `resources:`. Carries the actual artifacts.
- **Product**, a component with `componentReferences:`. Carries pointers to other components.

The product's signature covers each reference's descriptor digest, so re-signing or re-publishing a referenced service breaks the product signature. This is transitive trust: the product signature is only valid if every referenced service is unchanged.

**Day-2 mechanic:** bump one service's version in the product's `componentReferences:`, re-sign the product. Product goes from v1.4.2 to v1.4.3. Two lines changed; one signature re-computed. Downstream picks up the new descriptor.

## Verification

Verification is **opt-in on each Component CR** via the `verify:` field. Structure:

```yaml
verify:
  - signature: acme-release-key   # signature NAME to look for
    value: <base64 PEM>            # OR secretRef: to a K8s Secret
```

- No `verify:` entries → controller resolves and pulls, does NOT check signatures.
- `verify:` entries present → controller matches signatures by name, verifies against the provided key.
- Scheme is derived from the descriptor's `algorithm` field per signature. Cannot pin scheme on CR.
- K8s controller v1alpha1 implements RSA only. Non-RSA algorithms rejected with error ("unsupported signature algorithm").

For **global enforcement**, there is no OCM-shipping admission webhook. Bring your own (Kyverno, Gatekeeper, custom).

## Air-gap semantics

**Sigstore in air-gap:** requires the trusted-root file (Fulcio CA + Rekor public key for the OIDC issuer) to be distributed once, out of band. After that, `ocm verify cv` runs locally without contacting Rekor or Fulcio. RSA and OpenPGP need only their pinned public keys.

**`ocm transfer` default footgun:** default `ocm transfer` copies only the descriptor. Access fields still point back at the source registry. For actual air-gap (CTF → Registry), MUST pass `--copy-resources` to copy the bytes. Named as a trim edge on Slide 14 of every architect deck.

## What OCM is NOT

- OCM is NOT a replacement for OCI, Helm, cosign, sigstore, or SBOM tooling. It **wraps** them.
- OCM is NOT a policy engine. Kyverno/Gatekeeper enforce policy; OCM gives you the object to enforce about.
- OCM is NOT a registry. It uses existing OCI-compliant registries.
- OCM is NOT a build system. It packs what your build already produces.
- OCM is NOT (today) a scheme-pinning mechanism on the K8s controller. See verify semantics.

## Vocabulary discipline

If the user or a slide says "component," they mean the OCM component (identity + descriptor + resources).
If they say "descriptor," they mean the machine-readable YAML/JSON (also called SBOD in marketing).
If they say "resource," they mean an artifact inside a component.
If they say "digest," they mean SHA-256 of bytes.
If they say "identity," they mean DNS-style name + SemVer.
Do not conflate these in slide text or speaker notes.

## Where to check when unsure

- Spec: `~/github/github.com/morri-son/ocm-spec/doc/`
- Website docs: `./website/content/docs/`
- Go implementation: `bindings/go/`
- K8s controllers: `kubernetes/controller/`
- The four decks in this folder: `decks/*/speaker-notes.md`

If a session claims a technical fact that isn't backed by one of these, treat as suspicious and verify.
