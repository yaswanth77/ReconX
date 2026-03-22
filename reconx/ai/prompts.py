"""
AI prompt templates — all prompts in one place, versioned and tunable.

Each function builds a prompt for a specific AI task.
Keep prompts tight — every token costs money and latency.
"""


def target_analysis_prompt(tech_stack: dict, headers: dict, title: str) -> tuple[str, str]:
    """After fingerprinting: analyze tech stack and suggest attack vectors."""
    system = (
        "You are an expert penetration tester. Analyze the target's technology stack "
        "and provide actionable security recommendations. Be specific and concise. "
        "Respond in JSON format."
    )
    user = f"""Analyze this web target's technology stack and provide security recommendations.

Tech fingerprint:
- Title: {title}
- Server: {headers.get('server', 'unknown')}
- X-Powered-By: {headers.get('x-powered-by', 'unknown')}
- Technologies detected: {', '.join(tech_stack.get('tech', []))}
- Headers: {dict(list(headers.items())[:10])}

Return JSON with:
{{
    "identified_technologies": ["list of specific tech with versions if possible"],
    "recommended_nuclei_tags": ["relevant nuclei template tags"],
    "potential_attack_vectors": ["specific attack vectors to test"],
    "interesting_headers": ["headers that reveal security issues"],
    "priority_checks": ["top 5 things to check first"],
    "risk_level": "low|medium|high|critical"
}}"""
    return system, user


def dynamic_wordlist_prompt(tech_stack: list[str], existing_paths: list[str]) -> tuple[str, str]:
    """Generate context-aware paths based on detected tech."""
    system = (
        "You are a web security expert. Generate likely hidden paths for a web application "
        "based on the detected technology stack. Only suggest paths that are commonly present "
        "but not linked in the application. Respond in JSON format."
    )
    user = f"""Generate hidden directory/file paths for a target with this tech stack:

Technologies: {', '.join(tech_stack)}
Already discovered paths (don't repeat): {', '.join(existing_paths[:20])}

Return JSON:
{{
    "paths": ["/path1", "/path2", "..."],
    "reasoning": "brief explanation"
}}

Generate 20-50 high-signal paths. Focus on:
- Admin panels for the specific CMS/framework
- Config files specific to the detected tech
- Debug/development endpoints
- API documentation endpoints
- Backup files with common naming
- Version-specific known paths"""
    return system, user


def param_risk_scoring_prompt(params: list[dict]) -> tuple[str, str]:
    """Score parameters by injection risk."""
    system = (
        "You are a vulnerability researcher. Analyze HTTP parameters and score their "
        "likelihood of being vulnerable to different injection types. Be precise. "
        "Respond in JSON format."
    )

    param_summary = []
    for p in params[:30]:  # Limit to avoid token explosion
        param_summary.append({
            "endpoint": p.get("endpoint", ""),
            "params": p.get("params", []),
            "method": p.get("method", "GET"),
        })

    user = f"""Analyze these HTTP parameters for potential vulnerabilities:

{param_summary}

For each parameter, return JSON:
{{
    "scored_params": [
        {{
            "endpoint": "/path",
            "param": "param_name",
            "idor_score": 0.0-1.0,
            "sqli_score": 0.0-1.0,
            "xss_score": 0.0-1.0,
            "ssrf_score": 0.0-1.0,
            "open_redirect_score": 0.0-1.0,
            "reasoning": "brief reason"
        }}
    ]
}}

Scoring guide:
- 0.8+ = strong signal (param name like 'id', 'user_id', 'redirect')
- 0.5-0.8 = moderate signal
- 0.0-0.5 = weak signal"""
    return system, user


def finding_triage_prompt(findings: list[dict]) -> tuple[str, str]:
    """Triage raw findings: real vs false positive, severity."""
    system = (
        "You are a senior security analyst triaging vulnerability findings. "
        "Evaluate each finding for likely severity and false-positive probability. "
        "Respond in JSON format."
    )

    findings_summary = []
    for f in findings[:20]:
        findings_summary.append({
            "type": f.get("type", ""),
            "url": f.get("url", ""),
            "evidence": str(f.get("evidence", ""))[:200],
        })

    user = f"""Triage these security findings:

{findings_summary}

Return JSON:
{{
    "triaged": [
        {{
            "type": "finding type",
            "url": "url",
            "severity": "info|low|medium|high|critical",
            "confidence": 0.0-1.0,
            "likely_false_positive": true/false,
            "reasoning": "brief",
            "recommended_action": "what to do next"
        }}
    ]
}}"""
    return system, user


def nuclei_template_selection_prompt(tech_stack: list[str], services: list[dict]) -> tuple[str, str]:
    """Select relevant Nuclei template tags based on fingerprint."""
    system = (
        "You are a security automation expert. Based on the detected technology stack, "
        "select the most relevant Nuclei template tags to scan. Be selective — don't scan "
        "everything, only what's likely to yield results. Respond in JSON format."
    )
    user = f"""Select Nuclei template tags for these targets:

Technologies detected: {', '.join(tech_stack)}
Number of alive services: {len(services)}

Common Nuclei tags: cve, exposure, misconfig, default-login, takeover, 
file, xss, sqli, ssrf, lfi, rfi, rce, redirect, cors, crlf, 
wordpress, joomla, drupal, apache, nginx, iis, tomcat, spring, 
django, laravel, nodejs, php, java, python, ruby, aws, azure, gcp

Return JSON:
{{
    "selected_tags": ["tag1", "tag2"],
    "excluded_tags": ["tag3"],
    "reasoning": "why these tags",
    "estimated_template_count": "approximate number"
}}

Be selective. More tags = slower scan. Pick only high-signal ones."""
    return system, user


def recon_summary_prompt(data_summary: dict, key_findings: list[dict]) -> tuple[str, str]:
    """Generate an AI attack narrative from structured data."""
    system = (
        "You are a penetration tester writing a recon summary for a client report. "
        "Write a professional, concise narrative of the attack surface discovered. "
        "Highlight the most interesting findings and suggest next steps."
    )
    user = f"""Write a recon summary from this data:

Data collected:
{data_summary}

Key findings:
{key_findings[:15]}

Write a professional 2-3 paragraph summary covering:
1. Attack surface overview (what was found)
2. Key risks and interesting findings
3. Recommended next steps for manual testing

Keep it concise and actionable. Use markdown formatting."""
    return system, user


def subdomain_generation_prompt(domain: str, known_subs: list[str]) -> tuple[str, str]:
    """Generate context-aware subdomain candidates."""
    system = (
        "You are a DNS expert. Based on known subdomain patterns for a domain, "
        "generate additional likely subdomains. Respond in JSON format."
    )
    user = f"""Generate likely subdomains for: {domain}

Known subdomains found so far:
{', '.join(known_subs[:30])}

Based on the naming patterns (e.g., if 'api' exists, 'api-v2', 'api-staging' might too),
generate additional likely subdomains.

Return JSON:
{{
    "candidates": ["sub1", "sub2", ...],
    "reasoning": "pattern analysis"
}}

Generate 20-40 candidates. Focus on:
- Variations of existing names (staging, dev, test, old, new, v2)
- Common infrastructure subdomains
- Patterns visible in the existing list"""
    return system, user
