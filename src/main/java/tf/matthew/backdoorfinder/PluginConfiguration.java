package tf.matthew.backdoorfinder;

import org.bukkit.configuration.file.FileConfiguration;

public final class PluginConfiguration {
    private final String webhookUrl;
    private final boolean autoScanOnStartup;
    private final boolean includeCleanResults;
    private final int suspiciousScoreThreshold;
    private final int minScoreToSend;
    private final int maxEvidencePerRule;

    public PluginConfiguration(String webhookUrl, boolean autoScanOnStartup, boolean includeCleanResults,
                               int suspiciousScoreThreshold, int minScoreToSend, int maxEvidencePerRule) {
        this.webhookUrl = webhookUrl;
        this.autoScanOnStartup = autoScanOnStartup;
        this.includeCleanResults = includeCleanResults;
        this.suspiciousScoreThreshold = suspiciousScoreThreshold;
        this.minScoreToSend = minScoreToSend;
        this.maxEvidencePerRule = maxEvidencePerRule;
    }

    public static PluginConfiguration from(FileConfiguration config) {
        return new PluginConfiguration(
                config.getString("webhook-url", "").trim(),
                config.getBoolean("auto-scan-on-startup", false),
                config.getBoolean("include-clean-results", false),
                Math.max(0, config.getInt("suspicious-score-threshold", 50)),
                Math.max(0, config.getInt("min-score-to-send", 0)),
                Math.max(1, config.getInt("max-evidence-per-rule", 4))
        );
    }

    public String webhookUrl() { return this.webhookUrl; }
    public boolean autoScanOnStartup() { return this.autoScanOnStartup; }
    public boolean includeCleanResults() { return this.includeCleanResults; }
    public int suspiciousScoreThreshold() { return this.suspiciousScoreThreshold; }
    public int minScoreToSend() { return this.minScoreToSend; }
    public int maxEvidencePerRule() { return this.maxEvidencePerRule; }

    public boolean hasWebhook() {
        return this.webhookUrl != null && !this.webhookUrl.trim().isEmpty();
    }
}