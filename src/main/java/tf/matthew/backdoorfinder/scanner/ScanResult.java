package tf.matthew.backdoorfinder.scanner;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public record ScanResult(
        Path jarPath,
        String pluginName,
        String version,
        String mainClass,
        int score,
        boolean suspicious,
        List<ScanFinding> findings,
        List<String> notes
) {

    public String toDiscordMessage() {
        List<String> lines = new ArrayList<>();
        lines.add("BackdoorFinder scan result");
        lines.add("Plugin: " + pluginName + " (`" + jarPath.getFileName() + "`)");
        if (!version.isBlank()) {
            lines.add("Version: " + version);
        }
        if (!mainClass.isBlank()) {
            lines.add("Main: " + mainClass);
        }
        lines.add("Score: " + score);
        lines.add("Status: " + (suspicious ? "SUSPICIOUS" : "CLEAN"));

        if (findings.isEmpty()) {
            lines.add("Findings: none");
        } else {
            lines.add("Findings:");
            for (ScanFinding finding : findings) {
                String evidenceText = finding.evidence().isEmpty()
                        ? "no extra evidence"
                        : String.join("; ", finding.evidence());
                lines.add("- [" + finding.score() + "] " + finding.title() + ": " + evidenceText);
            }
        }

        if (!notes.isEmpty()) {
            lines.add("Notes:");
            for (String note : notes) {
                lines.add("- " + note);
            }
        }

        return String.join("\n", lines);
    }

    public record ScanFinding(String id, String title, int score, List<String> evidence) {
    }
}
