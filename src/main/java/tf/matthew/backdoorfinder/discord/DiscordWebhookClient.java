package tf.matthew.backdoorfinder.discord;

import tf.matthew.backdoorfinder.PluginConfiguration;
import tf.matthew.backdoorfinder.scanner.ScanResult;
import tf.matthew.backdoorfinder.scanner.ScanResult.ScanFinding;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
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

    private final HttpClient httpClient;
    private final Logger logger;
    private final PluginConfiguration configuration;

    public DiscordWebhookClient(PluginConfiguration configuration, Logger logger) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.logger = Objects.requireNonNull(logger, "logger");
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
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
        if (!topFindings.isBlank()) {
            appendField(payload, "Top hits", topFindings, false, true);
        }

        payload.append("]}]}");
        postJson(payload.toString());
    }

    private boolean shouldSend(ScanResult result) {
        if (!configuration.hasWebhook()) {
            return false;
        }
        if (result.suspicious()) {
            return result.score() >= configuration.minScoreToSend();
        }
        return configuration.includeCleanResults();
    }

    private String buildScanPayload(ScanResult result) {
        StringBuilder payload = new StringBuilder(2048);
        payload.append("{\"username\":\"BackdoorFinder\",\"embeds\":[{")
                .append("\"title\":\"").append(escapeJson(result.pluginName())).append("\",")
                .append("\"description\":\"")
                .append(escapeJson(limit("`" + result.jarPath().getFileName() + "`", MAX_EMBED_DESCRIPTION_LENGTH)))
                .append("\",")
                .append("\"color\":").append(result.suspicious() ? SUSPICIOUS_COLOR : CLEAN_COLOR).append(',')
                .append("\"timestamp\":\"").append(Instant.now()).append("\",")
                .append("\"fields\":[");

        appendField(payload, "Status", result.suspicious() ? "SUSPICIOUS" : "CLEAN", true, false);
        appendField(payload, "Score", Integer.toString(result.score()), true, true);
        appendField(payload, "Threshold", Integer.toString(configuration.suspiciousScoreThreshold()), true, true);
        if (!result.version().isBlank()) {
            appendField(payload, "Version", result.version(), true, true);
        }
        if (!result.mainClass().isBlank()) {
            appendField(payload, "Main class", result.mainClass(), false, true);
        }

        List<String> findingChunks = buildFindingChunks(result.findings(), result.notes());
        if (findingChunks.isEmpty()) {
            appendField(payload, "Findings", "No suspicious patterns matched.", false, true);
        } else {
            for (int i = 0; i < findingChunks.size(); i++) {
                String name = i == 0 ? "Findings" : "Findings " + (i + 1);
                appendField(payload, name, findingChunks.get(i), false, true);
            }
        }

        payload.append("]}]}");
        return payload.toString();
    }

    private void postJson(String json) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(configuration.webhookUrl()))
                    .timeout(Duration.ofSeconds(15))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                    .build();

            httpClient.sendAsync(request, HttpResponse.BodyHandlers.discarding())
                    .thenAccept(response -> {
                        if (response.statusCode() < 200 || response.statusCode() >= 300) {
                            logger.warning("Discord webhook returned HTTP " + response.statusCode());
                        }
                    })
                    .exceptionally(throwable -> {
                        logger.warning("Failed to send Discord webhook: " + throwable.getMessage());
                        return null;
                    });
        } catch (Exception exception) {
            logger.warning("Failed to send Discord webhook: " + exception.getMessage());
        }
    }

    private List<String> buildFindingChunks(List<ScanFinding> findings, List<String> notes) {
        List<String> lines = new ArrayList<>();
        for (ScanFinding finding : findings) {
            String evidenceText = finding.evidence().isEmpty()
                    ? "no extra evidence"
                    : String.join("; ", finding.evidence());
            lines.add("[" + finding.score() + "] " + finding.title() + "\n" + truncate(evidenceText, 220));
        }

        for (String note : notes) {
            lines.add("Note\n" + truncate(note, 220));
        }

        if (lines.isEmpty()) {
            return List.of();
        }

        List<String> chunks = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (String line : lines) {
            String candidate = current.length() == 0 ? line : current + "\n\n" + line;
            if (candidate.length() > MAX_FIELD_VALUE_LENGTH) {
                chunks.add(current.toString());
                current.setLength(0);
                current.append(limit(line, MAX_FIELD_VALUE_LENGTH));
            } else {
                if (current.length() > 0) {
                    current.append("\n\n");
                }
                current.append(line);
            }
        }
        if (current.length() > 0) {
            chunks.add(current.toString());
        }
        return chunks;
    }

    private String summarizeTopResults(List<ScanResult> results) {
        return results.stream()
                .filter(ScanResult::suspicious)
                .sorted((left, right) -> Integer.compare(right.score(), left.score()))
                .limit(5)
                .map(result -> result.pluginName() + " (" + result.score() + ")")
                .reduce((left, right) -> left + "\n" + right)
                .orElse("");
    }

    private void appendField(StringBuilder payload, String name, String value, boolean inline, boolean prependComma) {
        if (prependComma) {
            payload.append(',');
        }
        payload.append("{\"name\":\"")
                .append(escapeJson(name))
                .append("\",\"value\":\"")
                .append(escapeJson(limit(value, MAX_FIELD_VALUE_LENGTH)))
                .append("\",\"inline\":")
                .append(inline)
                .append('}');
    }

    private String truncate(String value, int maxLength) {
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, Math.max(0, maxLength - 3)) + "...";
    }

    private String limit(String value, int maxLength) {
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, Math.max(0, maxLength - 3)) + "...";
    }

    private String escapeJson(String input) {
        StringBuilder builder = new StringBuilder(input.length() + 32);
        for (int i = 0; i < input.length(); i++) {
            char character = input.charAt(i);
            switch (character) {
                case '\\' -> builder.append("\\\\");
                case '"' -> builder.append("\\\"");
                case '\n' -> builder.append("\\n");
                case '\r' -> builder.append("\\r");
                case '\t' -> builder.append("\\t");
                default -> {
                    if (character < 0x20) {
                        builder.append(String.format("\\u%04x", (int) character));
                    } else {
                        builder.append(character);
                    }
                }
            }
        }
        return builder.toString();
    }
}
