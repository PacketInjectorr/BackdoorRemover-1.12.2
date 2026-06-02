package tf.matthew.backdoorfinder;

import org.bukkit.configuration.file.FileConfiguration;

public record PluginConfiguration(
        String webhookUrl,
        boolean autoScanOnStartup,
        boolean includeCleanResults,
        int suspiciousScoreThreshold,
        int minScoreToSend,
        int maxEvidencePerRule
) {

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

    public boolean hasWebhook() {
        return !webhookUrl.isBlank();
    }
}
