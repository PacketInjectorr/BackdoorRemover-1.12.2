package tf.matthew.backdoorfinder.scanner;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class ScanResult {
    private final Path jarPath;
    private final String pluginName;
    private final String version;
    private final String mainClass;
    private final int score;
    private final boolean suspicious;
    private final List<ScanFinding> findings;
    private final List<String> notes;

    public ScanResult(Path jarPath, String pluginName, String version, String mainClass,
                      int score, boolean suspicious, List<ScanFinding> findings, List<String> notes) {
        this.jarPath = jarPath;
        this.pluginName = pluginName;
        this.version = version;
        this.mainClass = mainClass;
        this.score = score;
        this.suspicious = suspicious;
        this.findings = findings;
        this.notes = notes;
    }

    public Path jarPath() { return jarPath; }
    public String pluginName() { return pluginName; }
    public String version() { return version; }
    public String mainClass() { return mainClass; }
    public int score() { return score; }
    public boolean suspicious() { return suspicious; }
    public List<ScanFinding> findings() { return findings; }
    public List<String> notes() { return notes; }

    public String toDiscordMessage() {
        List<String> lines = new ArrayList<>();
        lines.add("BackdoorFinder scan result");
        lines.add("Plugin: " + pluginName + " (`" + (jarPath.getFileName() != null ? jarPath.getFileName().toString() : "unknown") + "`)");
        if (version != null && !version.trim().isEmpty()) {
            lines.add("Version: " + version);
        }
        if (mainClass != null && !mainClass.trim().isEmpty()) {
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

    public static final class ScanFinding {
        private final String id;
        private final String title;
        private final int score;
        private final List<String> evidence;

        public ScanFinding(String id, String title, int score, List<String> evidence) {
            this.id = id;
            this.title = title;
            this.score = score;
            this.evidence = evidence;
        }

        public String id() { return id; }
        public String title() { return title; }
        public int score() { return score; }
        public List<String> evidence() { return evidence; }
    }
}