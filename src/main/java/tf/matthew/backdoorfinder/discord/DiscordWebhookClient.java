package tf.matthew.backdoorfinder.discord;

import tf.matthew.backdoorfinder.PluginConfiguration;
import tf.matthew.backdoorfinder.scanner.ScanResult;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.logging.Logger;

public final class DiscordWebhookClient {
    private static final int MAX_EMBED_DESCRIPTION_LENGTH = 4096;
    private static final int MAX_FIELD_VALUE_LENGTH = 1024;
    private static final int CLEAN_COLOR = 0x3BA55D;
    private static final int SUSPICIOUS_COLOR = 0xED4245;
    private static final int SUMMARY_COLOR = 0x5865F2;

    private final Logger logger;
    private final PluginConfiguration configuration;

    public DiscordWebhookClient(PluginConfiguration configuration, Logger logger) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.logger = Objects.requireNonNull(logger, "logger");
    }

    public void sendScanResult(ScanResult result) {
        if (!shouldSend(result)) {
            return;
        }
        postJson(buildScanPayload(result));
    }

    public void sendSummary(String reason, List<ScanResult> results) {
        if (!configuration.hasWebhook()) {
            return;
        }

        long suspiciousCount = results.stream().filter(ScanResult::suspicious).count();
        int highestScore = results.stream().mapToInt(ScanResult::score).max().orElse(0);
        String topFindings = summarizeTopResults(results);

        StringBuilder payload = new StringBuilder(1024);
        payload.append("{\"username\":\"BackdoorFinder\",\"embeds\":[{")
                .append("\"title\":\"BackdoorFinder Summary\",")
                .append("\"color\":").append(SUMMARY_COLOR).append(',')
                .append("\"timestamp\":\"").append(Instant.now()).append("\",")
                .append("\"fields\":[");

        appendField(payload, "Reason", reason, true, false);
        appendField(payload, "Scanned", Integer.toString(results.size()), true, true);
        appendField(payload, "Suspicious", Long.toString(suspiciousCount), true, true);
        appendField(payload, "Highest score", Integer.toString(highestScore), true, true);
        if (topFindings != null && !topFindings.trim().isEmpty()) {
            appendField(payload, "Top hits", topFindings, false, true);
        }
        payload.append("]}]}");
        postJson(payload.toString());
    }

    private boolean shouldSend(ScanResult result) {
        if (!configuration.hasWebhook()) return false;
        if (result.score() < configuration.minScoreToSend()) return false;
        if (result.suspicious()) return true;
        return configuration.includeCleanResults();
    }

    private void postJson(String jsonPayload) {
        try {
            URL url = new URL(configuration.webhookUrl());
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("User-Agent", "BackdoorFinder-Java8");
            connection.setDoOutput(true);
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);

            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = jsonPayload.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
                os.flush();
            }

            int responseCode = connection.getResponseCode();
            if (responseCode < 200 || responseCode >= 300) {
                logger.warning("Discord Webhook endpoint returned status code: " + responseCode);
            }
            connection.disconnect();
        } catch (Exception e) {
            logger.severe("An error occurred while dispatching Discord Webhook payload: " + e.getMessage());
        }
    }

    private String buildScanPayload(ScanResult result) {
        int color = result.suspicious() ? SUSPICIOUS_COLOR : CLEAN_COLOR;
        StringBuilder payload = new StringBuilder(1024);
        payload.append("{\"username\":\"BackdoorFinder\",\"embeds\":[{")
                .append("\"title\":\"Scan Analysis: ").append(escapeJson(result.pluginName())).append("\",")
                .append("\"color\":").append(color).append(',')
                .append("\"timestamp\":\"").append(Instant.now()).append("\",")
                .append("\"fields\":[");

        appendField(payload, "File", result.jarPath().getFileName().toString(), true, false);
        if (result.version() != null && !result.version().trim().isEmpty()) {
            appendField(payload, "Version", result.version(), true, true);
        }
        if (result.mainClass() != null && !result.mainClass().trim().isEmpty()) {
            appendField(payload, "Main Class", result.mainClass(), false, true);
        }
        appendField(payload, "Malware Threat Score", Integer.toString(result.score()), true, true);
        appendField(payload, "Flagged Status", result.suspicious() ? "SUSPICIOUS" : "CLEAN", true, true);

        if (!result.findings().isEmpty()) {
            StringBuilder findingsBuilder = new StringBuilder();
            int counter = 0;
            for (ScanResult.ScanFinding finding : result.findings()) {
                if (counter++ >= 10) {
                    findingsBuilder.append("... and more findings hidden.");
                    break;
                }
                findingsBuilder.append("**[").append(finding.score()).append("] ").append(finding.title()).append("**\\n");
                if (!finding.evidence().isEmpty()) {
                    int evCount = 0;
                    for (String ev : finding.evidence()) {
                        if (evCount++ >= configuration.maxEvidencePerRule()) {
                            findingsBuilder.append("  - *and more evidence hidden*\\n");
                            break;
                        }
                        findingsBuilder.append("  - `").append(escapeJson(truncate(ev, 120))).append("`\\n");
                    }
                }
            }
            appendField(payload, "Triggered Indicators", truncate(findingsBuilder.toString(), MAX_EMBED_DESCRIPTION_LENGTH), false, true);
        }

        if (!result.notes().isEmpty()) {
            StringBuilder notesBuilder = new StringBuilder();
            for (String note : result.notes()) {
                notesBuilder.append("- ").append(escapeJson(note)).append("\\n");
            }
            appendField(payload, "Scanner Notes", truncate(notesBuilder.toString(), 1024), false, true);
        }

        payload.append("]}]}");
        return payload.toString();
    }

    private String summarizeTopResults(List<ScanResult> results) {
        List<ScanResult> problematic = new ArrayList<>();
        for (ScanResult r : results) {
            if (r.score() > 0) problematic.add(r);
        }
        problematic.sort((a, b) -> Integer.compare(b.score(), a.score()));

        if (problematic.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (ScanResult r : problematic) {
            if (count++ >= 8) {
                sb.append("... and more files omitted.");
                break;
            }
            sb.append("`").append(escapeJson(r.jarPath().getFileName().toString()))
              .append("` — Score: **").append(r.score()).append("** (")
              .append(r.suspicious() ? "SUSPICIOUS" : "CLEAN").append(")\\n");
        }
        return sb.toString();
    }

    private void appendField(StringBuilder builder, String name, String value, boolean inline, boolean appendComma) {
        if (appendComma) builder.append(',');
        builder.append("{\"name\":\"").append(escapeJson(name))
                .append("\",\"value\":\"").append(escapeJson(limit(value, MAX_FIELD_VALUE_LENGTH)))
                .append("\",\"inline\":").append(inline)
                .append('}');
    }

    private String truncate(String value, int maxLength) {
        if (value.length() <= maxLength) return value;
        return value.substring(0, Math.max(0, maxLength - 3)) + "...";
    }

    private String limit(String value, int maxLength) {
        if (value.length() <= maxLength) return value;
        return value.substring(0, Math.max(0, maxLength - 3)) + "...";
    }

    private String escapeJson(String input) {
        StringBuilder builder = new StringBuilder(input.length() + 32);
        for (int i = 0; i < input.length(); i++) {
            char character = input.charAt(i);
            switch (character) {
                case '\\': builder.append("\\\\"); break;
                case '"': builder.append("\\\""); break;
                case '\n': builder.append("\\n"); break;
                case '\r': builder.append("\\r"); break;
                case '\t': builder.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        builder.append(String.format("\\u%04x", (int) character));
                    } else {
                        builder.append(character);
                    }
                    break;
            }
        }
        return builder.toString();
    }
}