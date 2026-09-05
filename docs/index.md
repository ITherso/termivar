<div class="tmv-home">
  <section class="tmv-hero" aria-labelledby="termivar-home-title">
    <div class="tmv-hero-copy">
      <p class="tmv-eyebrow"><span>Development preview</span> Rust security assessment</p>
      <h1 id="termivar-home-title">Evidence before verdicts.</h1>
      <p class="tmv-hero-lede">
        Run bounded web assessments. Understand the evidence. Compare what changed.
        Termivar produces readable HTML and JSON reports and compares their
        observations offline without treating disappearance as verified remediation.
      </p>
      <div class="tmv-actions" aria-label="Primary documentation links">
        <a class="tmv-button tmv-button-primary" href="GETTING_STARTED/">Get started</a>
        <a class="tmv-button tmv-button-secondary" href="examples/first-use/assessment.html">View example report</a>
        <a class="tmv-text-link" href="architecture/">Explore architecture <span aria-hidden="true">&rarr;</span></a>
      </div>
      <ul class="tmv-hero-facts" aria-label="Core runtime boundaries">
        <li>Exact-origin authority</li>
        <li>Bounded request budgets</li>
        <li>One composed web runtime</li>
      </ul>
    </div>
    <div class="tmv-hero-visual" aria-label="Termivar product identity">
      <div class="tmv-logo-surface">
        <img src="assets/brand/termivar-lockup.png" alt="Termivar" width="1128" height="296">
      </div>
      <div class="tmv-runtime-card" aria-label="Runtime principles">
        <div><span>authority</span><strong>explicit</strong></div>
        <div><span>execution</span><strong>deterministic</strong></div>
        <div><span>claims</span><strong>evidence-scoped</strong></div>
      </div>
    </div>
  </section>

  <aside class="tmv-preview-note" aria-label="Development status">
    <span class="tmv-status-dot" aria-hidden="true"></span>
    <div>
      <strong>Experimental alpha.</strong>
      Current <code>main</code> is the unreleased <code>0.10.0-alpha.2</code>
      development line and is not production-ready. The published
      <a href="https://github.com/ITherso/termivar/releases/tag/v0.10.0-alpha.1"><code>v0.10.0-alpha.1</code> prerelease</a>
      does not include later source changes. Use only on systems you own or are
      explicitly authorized to test.
    </div>
  </aside>

  <section class="tmv-section" aria-labelledby="principles-title">
    <div class="tmv-section-heading">
      <p class="tmv-kicker">Why Termivar</p>
      <h2 id="principles-title">A deliberately narrow trust model</h2>
      <p>Observation, execution, and conclusion remain separate so a successful action cannot silently become a vulnerability verdict.</p>
    </div>
    <div class="tmv-card-grid tmv-card-grid-three">
      <article class="tmv-card">
        <span class="tmv-card-index">01</span>
        <h3>Explicit boundaries</h3>
        <p>Exact-origin authority, shared budgets, cancellation, and deadlines constrain every supported web assessment.</p>
      </article>
      <article class="tmv-card">
        <span class="tmv-card-index">02</span>
        <h3>Typed evidence</h3>
        <p>Observations, hypotheses, verification outcomes, and report items retain distinct identities and authority.</p>
      </article>
      <article class="tmv-card">
        <span class="tmv-card-index">03</span>
        <h3>Claim-safe reports</h3>
        <p>Informational, NeedsReview, and Confirmed are not interchangeable. Incomplete execution stays visibly incomplete.</p>
      </article>
    </div>
  </section>

  <section class="tmv-section tmv-capabilities" aria-labelledby="capabilities-title">
    <div class="tmv-section-heading">
      <p class="tmv-kicker">Current preview</p>
      <h2 id="capabilities-title">Useful surfaces, constrained execution</h2>
      <p>Capabilities are opt-in where documented. Structural knowledge does not automatically grant network or finding authority.</p>
    </div>
    <div class="tmv-card-grid tmv-card-grid-two">
      <article class="tmv-feature-card">
        <div class="tmv-feature-icon" aria-hidden="true">&gt;_</div>
        <div>
          <h3>Bounded web review</h3>
          <p>One <code>WebAssessmentRuntime</code> composes evidence, reasoning, shared transport accounting, and the final report.</p>
          <a href="internals/web-runtime/">Runtime contract <span aria-hidden="true">&rarr;</span></a>
        </div>
      </article>
      <article class="tmv-feature-card">
        <div class="tmv-feature-icon" aria-hidden="true">{ }</div>
        <div>
          <h3>API surface intelligence</h3>
          <p>GraphQL, OpenAPI, bounded REST read-only, and selected-resource authorization reviews preserve their own strict limits.</p>
          <a href="internals/api-evidence/">API evidence model <span aria-hidden="true">&rarr;</span></a>
        </div>
      </article>
      <article class="tmv-feature-card">
        <div class="tmv-feature-icon" aria-hidden="true">==</div>
        <div>
          <h3>Reports and comparison</h3>
          <p>Readable assessment reports and offline comparison keep disappearance distinct from verified remediation.</p>
          <a href="reporting/">Reporting contract <span aria-hidden="true">&rarr;</span></a>
        </div>
      </article>
      <article class="tmv-feature-card">
        <div class="tmv-feature-icon" aria-hidden="true">[ ]</div>
        <div>
          <h3>Local artifact review</h3>
          <p>An explicit local-file path supports bounded signature review without turning artifact input into web authority.</p>
          <a href="artifact-signatures/">Artifact boundary <span aria-hidden="true">&rarr;</span></a>
        </div>
      </article>
    </div>
  </section>

  <section class="tmv-section tmv-flow-section" aria-labelledby="flow-title">
    <div class="tmv-section-heading">
      <p class="tmv-kicker">Operator flow</p>
      <h2 id="flow-title">Start with authority. End with evidence.</h2>
    </div>
    <ol class="tmv-flow">
      <li><span>01</span><div><strong>Choose a reviewed build</strong><p>Use the checksum-verified published archive or build a pinned source commit.</p></div></li>
      <li><span>02</span><div><strong>Declare the exact scope</strong><p>Select the authorized origin and only the profile or capabilities you intend to run.</p></div></li>
      <li><span>03</span><div><strong>Run within shared limits</strong><p>The runtime accounts for requests, bytes, deadlines, and verification work.</p></div></li>
      <li><span>04</span><div><strong>Read the claim basis</strong><p>Interpret each item with its disposition, completeness, and evidence boundary intact.</p></div></li>
    </ol>
  </section>

  <section class="tmv-start-panel" aria-labelledby="start-title">
    <div>
      <p class="tmv-kicker">Start locally</p>
      <h2 id="start-title">Run the documented, credential-free walkthrough</h2>
      <p>The repository-owned fixture stays on numeric loopback and demonstrates CLI wiring and report reading—not detection accuracy.</p>
      <div class="tmv-actions">
        <a class="tmv-button tmv-button-primary" href="GETTING_STARTED/">Open the walkthrough</a>
        <a class="tmv-button tmv-button-secondary" href="examples/first-use/">Read a real example</a>
      </div>
    </div>
    <pre aria-label="Termivar command example"><code><span class="tmv-prompt">$</span> termivar scan &lt;AUTHORIZED_ORIGIN&gt; \
  --profile web-review \
  --report-format html \
  --report-output assessment.html</code></pre>
  </section>

  <nav class="tmv-resource-strip" aria-label="Additional Termivar resources">
    <a href="internals/runtime-map/"><span>Runtime map</span><small>What actually executes</small></a>
    <a href="examples/report-compare/"><span>Compare reports</span><small>Offline, four-group diff</small></a>
    <a href="https://itherso.github.io/termivar/rust/termivar_scanner/"><span>Rust API</span><small>Source-level contracts</small></a>
    <a href="https://github.com/ITherso/termivar/blob/main/SECURITY.md"><span>Security policy</span><small>Report issues privately</small></a>
  </nav>
</div>
