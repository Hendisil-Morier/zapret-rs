//! JSON and human-readable CLI output formatters for `strat_finder` [`ScanReport`] summaries.

/// Scan summary types serialized to `--json` or stdout tables.
use crate::tools::strat::runner::ScanReport;

/// Escapes a string literal for JSON output using `serde_json`.
fn json_quote(raw: &str) -> String
{
    serde_json::to_string(raw).unwrap_or_else(|_| "\"\"".to_owned())
}

/// Formats `report` as JSON printed to stdout when `--json` is set.
pub fn format_report_json(report: &ScanReport) -> String
{
    let mut out = format!("{{\n  \"interrupted\": {},\n  \"targets\": [\n", report.interrupted);
    for (i, t) in report
        .targets
        .iter()
        .enumerate()
    {
        let sep = if i + 1
            < report
                .targets
                .len()
        {
            ","
        }
        else
        {
            ""
        };
        let best = t
            .matches
            .first()
            .map_or_else(
                || "null".to_owned(),
                |m| {
                    json_quote(
                        &m.strategy
                            .id,
                    )
                },
            );
        out.push_str(&format!(
            "    {{\"domain\": {}, \"proto\": {}, \"ipv\": {}, \"baseline\": {}, \"skipped_unblocked\": {}, \"tested\": {}, \"matches\": {}, \"best\": {}}}{sep}\n",
            json_quote(&t.domain), json_quote(t.proto.as_str()), json_quote(t.ipv.as_str()),
            json_quote(&t.baseline.summary()), t.skipped_unblocked, t.tested_count, t.matches.len(), best,
        ));
    }
    out.push_str("  ],\n  \"cover\": [\n");
    for (i, c) in report
        .cover
        .iter()
        .enumerate()
    {
        let sep = if i + 1
            < report
                .cover
                .len()
        {
            ","
        }
        else
        {
            ""
        };
        let doms: Vec<String> = c
            .domains
            .iter()
            .map(|d| json_quote(d))
            .collect();
        out.push_str(&format!(
            "    {{\"strategy\": {}, \"weight\": {}, \"avg_latency_ms\": {}, \"domains\": [{}]}}{sep}\n",
            json_quote(
                &c.strategy
                    .id
            ),
            c.strategy
                .weight,
            c.avg_latency_ms,
            doms.join(", "),
        ));
    }
    out.push_str("  ]\n}\n");
    out
}

/// Prints a concise human-readable scan summary to stdout.
pub fn print_report_summary(report: &ScanReport)
{
    println!("\n=== strat_finder summary ===");
    if report.interrupted
    {
        println!("Note: scan interrupted early; showing partial results.");
    }
    for t in &report.targets
    {
        if t.skipped_unblocked
        {
            println!(
                "- {} ({}/{}): reachable directly [{}]",
                t.domain,
                t.proto,
                t.ipv,
                t.baseline
                    .summary()
            );
        }
        else if let Some(best) = t
            .matches
            .first()
        {
            println!(
                "- {} ({}/{}): {} working (best: {}, {} ms; tested {})",
                t.domain,
                t.proto,
                t.ipv,
                t.matches
                    .len(),
                best.strategy
                    .id,
                best.latency_ms,
                t.tested_count
            );
        }
        else
        {
            println!(
                "- {} ({}/{}): no working strategy found (baseline: {}; tested {})",
                t.domain,
                t.proto,
                t.ipv,
                t.baseline
                    .summary(),
                t.tested_count
            );
        }
    }
    if !report
        .cover
        .is_empty()
    {
        println!(
            "\nSelected minimal profile set ({}):",
            report
                .cover
                .len()
        );
        for c in &report.cover
        {
            println!(
                "  * {} (weight {}, avg {} ms) -> {}",
                c.strategy
                    .id,
                c.strategy
                    .weight,
                c.avg_latency_ms,
                c.domains
                    .join(", ")
            );
        }
    }
}
