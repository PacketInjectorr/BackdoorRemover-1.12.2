package tf.matthew.backdoorfinder.scanner;

import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import tf.matthew.backdoorfinder.PluginConfiguration;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class PluginScanner {
    public static final String THICC_INDUSTRIES_RAT_FINDING_ID = "thiccindustries-debugger-rat";
    public static final String THICC_INDUSTRIES_SPREADER_FINDING_ID = "thiccindustries-debugger-spreader";
    public static final String THICC_INDUSTRIES_REMNANT_FINDING_ID = "thiccindustries-debugger-remnant";

    private static final String PLUGIN_YML = "plugin.yml";
    private static final String PAPER_PLUGIN_YML = "paper-plugin.yml";
    private static final String THICC_INDUSTRIES_PACKAGE = "com/thiccindustries/debugger/";

    private static final Set<String> THICC_INDUSTRIES_PAYLOAD_CLASSES = new HashSet<>();
    private static final Set<String> THICC_INDUSTRIES_SPREADER_CLASSES = new HashSet<>();
    private static final Set<String> SCRIPT_EXTENSIONS = new HashSet<>();
    private static final Set<String> NATIVE_EXTENSIONS = new HashSet<>();
    private static final Set<String> SECRET_RESOURCE_NAMES = new HashSet<>();
    private static final List<String> SUSPICIOUS_NAME_MARKERS = new ArrayList<>();
    private static final Set<String> SAFE_NESTED_JAR_FRAGMENTS = new HashSet<>();
    private static final Set<String> SAFE_NATIVE_NAME_FRAGMENTS = new HashSet<>();
    private static final Set<String> SAFE_JS_NAME_FRAGMENTS = new HashSet<>();
    private static final List<String> EXFIL_URL_PATTERNS = new ArrayList<>();
    private static final Set<String> KNOWN_SAFE_PACKAGES = new HashSet<>();
    private static final Set<String> KNOWN_DEPENDENCY_LOADERS = new HashSet<>();
    private static final Set<String> KNOWN_LOADBEFORE_PAIRS = new HashSet<>();
    private static final java.util.regex.Pattern SUSPICIOUS_NAME_PATTERN = 
        java.util.regex.Pattern.compile("(?:backdoor|spigotspy|exploit|nodus|forceop|skidded|debugger)", java.util.regex.Pattern.CASE_INSENSITIVE);

    static {
        THICC_INDUSTRIES_PAYLOAD_CLASSES.add("com/thiccindustries/debugger/Debugger.class");
        THICC_INDUSTRIES_PAYLOAD_CLASSES.add("com/thiccindustries/debugger/Config.class");
        THICC_INDUSTRIES_PAYLOAD_CLASSES.add("com/thiccindustries/debugger/DWeb.class");

        THICC_INDUSTRIES_SPREADER_CLASSES.add("com/thiccindustries/debugger/Injector.class");
        THICC_INDUSTRIES_SPREADER_CLASSES.add("com/thiccindustries/debugger/Injector$SimpleConfig.class");

        SCRIPT_EXTENSIONS.add(".groovy"); SCRIPT_EXTENSIONS.add(".kts"); SCRIPT_EXTENSIONS.add(".py");
        SCRIPT_EXTENSIONS.add(".ps1"); SCRIPT_EXTENSIONS.add(".bat"); SCRIPT_EXTENSIONS.add(".cmd"); SCRIPT_EXTENSIONS.add(".sh");

        NATIVE_EXTENSIONS.add(".exe"); NATIVE_EXTENSIONS.add(".dll"); NATIVE_EXTENSIONS.add(".so"); NATIVE_EXTENSIONS.add(".dylib");

        SECRET_RESOURCE_NAMES.add(".env"); SECRET_RESOURCE_NAMES.add("credentials.json"); SECRET_RESOURCE_NAMES.add("credentials.yml");
        SECRET_RESOURCE_NAMES.add("credentials.yaml"); SECRET_RESOURCE_NAMES.add("password.txt"); SECRET_RESOURCE_NAMES.add("secrets.txt");
        SECRET_RESOURCE_NAMES.add("secret.txt"); SECRET_RESOURCE_NAMES.add("token.txt"); SECRET_RESOURCE_NAMES.add("tokens.txt");
        SECRET_RESOURCE_NAMES.add("webhook.txt"); SECRET_RESOURCE_NAMES.add("id_rsa"); SECRET_RESOURCE_NAMES.add("authorized_keys");

        SUSPICIOUS_NAME_MARKERS.add("backdoor"); SUSPICIOUS_NAME_MARKERS.add("stealer"); SUSPICIOUS_NAME_MARKERS.add("grabber");
        SUSPICIOUS_NAME_MARKERS.add("exploit"); SUSPICIOUS_NAME_MARKERS.add("rootkit"); SUSPICIOUS_NAME_MARKERS.add("keylogger");
        SUSPICIOUS_NAME_MARKERS.add("botnet"); SUSPICIOUS_NAME_MARKERS.add("trojan"); SUSPICIOUS_NAME_MARKERS.add("malware");
        SUSPICIOUS_NAME_MARKERS.add("ransomware");

        SAFE_NESTED_JAR_FRAGMENTS.add("netty"); SAFE_NESTED_JAR_FRAGMENTS.add("epoll"); SAFE_NESTED_JAR_FRAGMENTS.add("kqueue");
        SAFE_NESTED_JAR_FRAGMENTS.add("liblz4"); SAFE_NESTED_JAR_FRAGMENTS.add("lz4"); SAFE_NESTED_JAR_FRAGMENTS.add("libzstd");
        SAFE_NESTED_JAR_FRAGMENTS.add("snappy"); SAFE_NESTED_JAR_FRAGMENTS.add("mavenecjbootstrapdep");
        SAFE_NESTED_JAR_FRAGMENTS.add("mavenecjbootstrapagent"); SAFE_NESTED_JAR_FRAGMENTS.add("asm"); SAFE_NESTED_JAR_FRAGMENTS.add("slf4j");

        SAFE_NATIVE_NAME_FRAGMENTS.add("lz4"); SAFE_NATIVE_NAME_FRAGMENTS.add("zstd"); SAFE_NATIVE_NAME_FRAGMENTS.add("netty");
        SAFE_NATIVE_NAME_FRAGMENTS.add("epoll"); SAFE_NATIVE_NAME_FRAGMENTS.add("kqueue"); SAFE_NATIVE_NAME_FRAGMENTS.add("snappy");
        SAFE_NATIVE_NAME_FRAGMENTS.add("leveldb"); SAFE_NATIVE_NAME_FRAGMENTS.add("sqlite"); SAFE_NATIVE_NAME_FRAGMENTS.add("jpountz");

        SAFE_JS_NAME_FRAGMENTS.add("bootstrap"); SAFE_JS_NAME_FRAGMENTS.add("base.js"); SAFE_JS_NAME_FRAGMENTS.add("nashorncompat");
        SAFE_JS_NAME_FRAGMENTS.add("rhino"); SAFE_JS_NAME_FRAGMENTS.add("polyfill"); SAFE_JS_NAME_FRAGMENTS.add("es2015");
        SAFE_JS_NAME_FRAGMENTS.add("craftscript"); SAFE_JS_NAME_FRAGMENTS.add("controls.js"); SAFE_JS_NAME_FRAGMENTS.add("fxml.js");
        SAFE_JS_NAME_FRAGMENTS.add("mozilla");

        EXFIL_URL_PATTERNS.add("pastebin.com/raw"); EXFIL_URL_PATTERNS.add("hastebin.com/raw");
        EXFIL_URL_PATTERNS.add("ngrok.io"); EXFIL_URL_PATTERNS.add("ngrok.app");
        EXFIL_URL_PATTERNS.add("requestbin.com"); EXFIL_URL_PATTERNS.add("requestbin.net");
        EXFIL_URL_PATTERNS.add("webhook.site/"); EXFIL_URL_PATTERNS.add("pipedream.net");

        KNOWN_SAFE_PACKAGES.add("com/google/gson/"); KNOWN_SAFE_PACKAGES.add("com/google/common/"); KNOWN_SAFE_PACKAGES.add("com/google/protobuf/");
        KNOWN_SAFE_PACKAGES.add("com/fasterxml/jackson/"); KNOWN_SAFE_PACKAGES.add("it/unimi/dsi/fastutil/");
        KNOWN_SAFE_PACKAGES.add("org/apache/commons/"); KNOWN_SAFE_PACKAGES.add("org/slf4j/"); KNOWN_SAFE_PACKAGES.add("org/json/");
        KNOWN_SAFE_PACKAGES.add("org/junit/"); KNOWN_SAFE_PACKAGES.add("junit/"); KNOWN_SAFE_PACKAGES.add("org/hamcrest/");
        KNOWN_SAFE_PACKAGES.add("io/netty/"); KNOWN_SAFE_PACKAGES.add("net/kyori/"); KNOWN_SAFE_PACKAGES.add("org/yaml/snakeyaml/");
        KNOWN_SAFE_PACKAGES.add("kyori/adventure/"); KNOWN_SAFE_PACKAGES.add("kyori/examination/");
        KNOWN_SAFE_PACKAGES.add("com/zaxxer/hikari/"); KNOWN_SAFE_PACKAGES.add("org/h2/"); KNOWN_SAFE_PACKAGES.add("org/mariadb/");
        KNOWN_SAFE_PACKAGES.add("org/postgresql/"); KNOWN_SAFE_PACKAGES.add("com/mysql/"); KNOWN_SAFE_PACKAGES.add("org/sqlite/");
        KNOWN_SAFE_PACKAGES.add("org/objectweb/asm/"); KNOWN_SAFE_PACKAGES.add("net/bytebuddy/");
        KNOWN_SAFE_PACKAGES.add("org/javassist/"); KNOWN_SAFE_PACKAGES.add("javassist/");
        KNOWN_SAFE_PACKAGES.add("org/mozilla/javascript/"); KNOWN_SAFE_PACKAGES.add("org/rhino/");
        KNOWN_SAFE_PACKAGES.add("javax/annotation/"); KNOWN_SAFE_PACKAGES.add("org/checkerframework/");
        KNOWN_SAFE_PACKAGES.add("org/intellij/"); KNOWN_SAFE_PACKAGES.add("org/jetbrains/");
        KNOWN_SAFE_PACKAGES.add("com/rabbitmq/"); KNOWN_SAFE_PACKAGES.add("redis/clients/");
        KNOWN_SAFE_PACKAGES.add("net/jpountz/"); KNOWN_SAFE_PACKAGES.add("com/github/benmanes/");
        KNOWN_SAFE_PACKAGES.add("org/kohsuke/github/"); KNOWN_SAFE_PACKAGES.add("okhttp3/"); KNOWN_SAFE_PACKAGES.add("com/squareup/");
        KNOWN_SAFE_PACKAGES.add("lombok/"); KNOWN_SAFE_PACKAGES.add("net/querz/nbt/");
        KNOWN_SAFE_PACKAGES.add("me/lucko/jarrelocator/");
        KNOWN_SAFE_PACKAGES.add("org/bstats/"); KNOWN_SAFE_PACKAGES.add("net/byteflux/libby/");
        KNOWN_SAFE_PACKAGES.add("com/github/retrooper/packetevents/");
        KNOWN_SAFE_PACKAGES.add("io/github/retrooper/packetevents/");
        KNOWN_SAFE_PACKAGES.add("fr/mrmicky/fastboard/");

        KNOWN_DEPENDENCY_LOADERS.add("slimjar"); KNOWN_DEPENDENCY_LOADERS.add("zapper"); KNOWN_DEPENDENCY_LOADERS.add("jarinjarclassloader");
        KNOWN_DEPENDENCY_LOADERS.add("libby"); KNOWN_DEPENDENCY_LOADERS.add("dependencymanager"); KNOWN_DEPENDENCY_LOADERS.add("relocator");

        KNOWN_LOADBEFORE_PAIRS.add("worldguard"); KNOWN_LOADBEFORE_PAIRS.add("plotsquared"); KNOWN_LOADBEFORE_PAIRS.add("vault");
        KNOWN_LOADBEFORE_PAIRS.add("protocollib"); KNOWN_LOADBEFORE_PAIRS.add("viaversion"); KNOWN_LOADBEFORE_PAIRS.add("essentials");
        KNOWN_LOADBEFORE_PAIRS.add("placeholderapi"); KNOWN_LOADBEFORE_PAIRS.add("denizen");

        StringBuilder regex = new StringBuilder();
        for (int i = 0; i < SUSPICIOUS_NAME_MARKERS.size(); i++) {
            if (i > 0) regex.append('|');
            regex.append("(?<![a-z])");
            regex.append(Pattern.quote(SUSPICIOUS_NAME_MARKERS.get(i)));
            regex.append("(?![a-z])");
        }
        // SUSPICIOUS_NAME_PATTERN = Pattern.compile(regex.toString(), Pattern.CASE_INSENSITIVE);
    }

    private final PluginConfiguration configuration;

    public PluginScanner(PluginConfiguration configuration) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
    }

    public static boolean isThiccIndustriesFinding(ScanResult.ScanFinding finding) {
        return THICC_INDUSTRIES_RAT_FINDING_ID.equals(finding.id())
                || THICC_INDUSTRIES_SPREADER_FINDING_ID.equals(finding.id())
                || THICC_INDUSTRIES_REMNANT_FINDING_ID.equals(finding.id());
    }

    public ScanResult scan(Path jarPath) {
        Map<String, FindingAccumulator> findings = new LinkedHashMap<>();
        List<String> notes = new ArrayList<>();
        PluginDescriptor descriptor = PluginDescriptor.fromPath(jarPath);
        int totalClasses = 0;
        int safeLibraryClasses = 0;

        try (ZipFile zipFile = new ZipFile(jarPath.toFile())) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory()) continue;

                String entryName = entry.getName();

                if (isManifest(entryName)) {
                    String yamlText = readText(zipFile, entry);
                    descriptor = descriptor.merge(parseDescriptor(yamlText, jarPath));
                    inspectManifest(yamlText, entryName, findings);
                    continue;
                }

                if (entryName.endsWith(".class")) {
                    totalClasses++;
                    if (isKnownSafePackage(entryName)) {
                        safeLibraryClasses++;
                        continue;
                    }
                    inspectEntryName(entryName, findings);
                    inspectClassBytes(readBytes(zipFile, entry), entryName, findings);
                    continue;
                }

                if (!entryName.endsWith(".class")) {
                    inspectEntryName(entryName, findings);
                }

                if (entryName.endsWith(".jar")) {
                    String lowerJarName = entryName.toLowerCase(Locale.ROOT);
                    boolean knownSafe = false;
                    for (String frag : SAFE_NESTED_JAR_FRAGMENTS) {
                        if (lowerJarName.contains(frag)) { knownSafe = true; break; }
                    }
                    if (knownSafe) {
                        addFinding(findings, "nested-archive-known", "Contains nested archive (known-safe library)", 1, entryName);
                    } else {
                        addFinding(findings, "nested-archive", "Contains unknown nested archive", 12, entryName);
                    }
                    continue;
                }

                if (hasAnyExtension(entryName, SCRIPT_EXTENSIONS)) {
                    addFinding(findings, "embedded-script", "Contains embedded script", 22, entryName);
                    continue;
                }

                if (entryName.toLowerCase(Locale.ROOT).endsWith(".js")) {
                    String lowerJs = entryName.toLowerCase(Locale.ROOT);
                    boolean safeJs = false;
                    for (String frag : SAFE_JS_NAME_FRAGMENTS) {
                        if (lowerJs.contains(frag)) { safeJs = true; break; }
                    }
                    if (!safeJs) {
                        addFinding(findings, "embedded-script", "Contains embedded script", 18, entryName);
                    }
                    continue;
                }

                if (hasAnyExtension(entryName, NATIVE_EXTENSIONS)) {
                    String lowerName = entryName.toLowerCase(Locale.ROOT);
                    boolean knownNative = false;
                    for (String frag : SAFE_NATIVE_NAME_FRAGMENTS) {
                        if (lowerName.contains(frag)) { knownNative = true; break; }
                    }
                    if (knownNative) {
                        addFinding(findings, "native-binary-known", "Contains native binary (known-safe library)", 1, entryName);
                    } else {
                        addFinding(findings, "native-binary", "Contains native platform binary", 35, entryName);
                    }
                }
            }
        } catch (IOException exception) {
            notes.add("Failed to read completely or error processing zip contents: " + exception.getMessage());
        }

        if (totalClasses > 0 && safeLibraryClasses == totalClasses) {
            notes.add("100% of all code classes match trusted structural namespaces.");
        }

        List<ScanResult.ScanFinding> finalFindings = new ArrayList<>();
        int accumulatedScore = 0;
        for (FindingAccumulator acc : findings.values()) {
            accumulatedScore += acc.score;
            finalFindings.add(new ScanResult.ScanFinding(acc.id, acc.title, acc.score, new ArrayList<>(acc.evidence)));
        }

        boolean suspicious = accumulatedScore >= configuration.suspiciousScoreThreshold();
        return new ScanResult(jarPath, descriptor.name(), descriptor.version(), descriptor.mainClass(),
                accumulatedScore, suspicious, finalFindings, notes);
    }

    private boolean isManifest(String entryName) {
        return PLUGIN_YML.equalsIgnoreCase(entryName) || PAPER_PLUGIN_YML.equalsIgnoreCase(entryName);
    }

    private boolean isKnownSafePackage(String entryName) {
        for (String safePkg : KNOWN_SAFE_PACKAGES) {
            if (entryName.startsWith(safePkg)) return true;
        }
        return false;
    }

    private boolean hasAnyExtension(String entryName, Set<String> extensions) {
        String lower = entryName.toLowerCase(Locale.ROOT);
        for (String ext : extensions) {
            if (lower.endsWith(ext)) return true;
        }
        return false;
    }

    private void inspectEntryName(String entryName, Map<String, FindingAccumulator> findings) {
        if (THICC_INDUSTRIES_PAYLOAD_CLASSES.contains(entryName)) {
            addFinding(findings, THICC_INDUSTRIES_RAT_FINDING_ID, "Thicc Industries Debugger Core RAT Payload", 100, entryName);
            return;
        }
        if (THICC_INDUSTRIES_SPREADER_CLASSES.contains(entryName)) {
            addFinding(findings, THICC_INDUSTRIES_SPREADER_FINDING_ID, "Thicc Industries Debugger Spreader Module", 90, entryName);
            return;
        }
        if (entryName.startsWith(THICC_INDUSTRIES_PACKAGE)) {
            addFinding(findings, THICC_INDUSTRIES_REMNANT_FINDING_ID, "Thicc Industries Debugger Residual Artifact Class", 60, entryName);
            return;
        }

        String pathLower = entryName.toLowerCase(Locale.ROOT);
        if (SUSPICIOUS_NAME_PATTERN.matcher(pathLower).find()) {
            addFinding(findings, "suspicious-filepath", "Malicious naming conventions in file path", 15, entryName);
        }

        int lastSlash = entryName.lastIndexOf('/');
        String filename = lastSlash >= 0 ? entryName.substring(lastSlash + 1) : entryName;
        if (SECRET_RESOURCE_NAMES.contains(filename.toLowerCase(Locale.ROOT))) {
            addFinding(findings, "sensitive-asset", "Contains highly sensitive environment configuration or credential file", 15, entryName);
        }
    }

    private void inspectClassBytes(byte[] bytes, String entryName, Map<String, FindingAccumulator> findings) {
        if (bytes == null || bytes.length < 10) return;
        String contentString = new String(bytes, StandardCharsets.ISO_8859_1);

        if (contentString.contains("com/thiccindustries/debugger/Debugger")) {
            addFinding(findings, "thiccindustries-hook", "Injects active hooks to Thicc Industries core malware", 85, entryName);
        }

        for (String urlPattern : EXFIL_URL_PATTERNS) {
            if (contentString.contains(urlPattern)) {
                addFinding(findings, "exfiltration-url", "Contains known paste, runtime proxy, or webhook exfiltration URL", 30, entryName + " (" + urlPattern + ")");
            }
        }

        if (contentString.contains("java/net/URLClassLoader") && contentString.contains(".jar")) {
            boolean matchesLoader = false;
            for (String loader : KNOWN_DEPENDENCY_LOADERS) {
                if (entryName.toLowerCase(Locale.ROOT).contains(loader)) { matchesLoader = true; break; }
            }
            if (!matchesLoader) {
                addFinding(findings, "dynamic-classloading", "Executes manual runtime jar injection or custom ClassLoading bytecode", 15, entryName);
            }
        }

        if (contentString.contains("java/lang/Runtime") && contentString.contains("exec")) {
            addFinding(findings, "process-execution", "Invokes external shell command execution pipeline natively", 20, entryName);
        }
    }

    private void inspectManifest(String yamlText, String entryName, Map<String, FindingAccumulator> findings) {
        try {
            YamlConfiguration yaml = YamlConfiguration.loadConfiguration(new StringReader(yamlText));
            List<String> loadBefore = yaml.getStringList("loadbefore");
            if (loadBefore != null) {
                for (String lb : loadBefore) {
                    if (lb != null && KNOWN_LOADBEFORE_PAIRS.contains(lb.toLowerCase(Locale.ROOT))) {
                        addFinding(findings, "loadbefore-hijack", "Attempts critical load sequence priority hijacking against structural plugins", 40, entryName + " -> loadbefore: " + lb);
                    }
                }
            }
        } catch (Exception ignored) {}
    }

    private void addFinding(Map<String, FindingAccumulator> findings, String id, String title, int score, String evidence) {
        FindingAccumulator acc = findings.get(id);
        if (acc == null) {
            acc = new FindingAccumulator(id, title, score);
            findings.put(id, acc);
        }
        acc.evidence.add(evidence);
    }

    private byte[] readBytes(ZipFile zipFile, ZipEntry entry) throws IOException {
        try (InputStream is = zipFile.getInputStream(entry); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int read;
            while ((read = is.read(buf)) != -1) { baos.write(buf, 0, read); }
            return baos.toByteArray();
        }
    }

    private String readText(ZipFile zipFile, ZipEntry entry) throws IOException {
        return new String(readBytes(zipFile, entry), StandardCharsets.UTF_8);
    }

    private PluginDescriptor parseDescriptor(String yamlText, Path jarPath) {
        try {
            YamlConfiguration yaml = YamlConfiguration.loadConfiguration(new StringReader(yamlText));
            String name = yaml.getString("name", "");
            String version = yaml.getString("version", "");
            String main = yaml.getString("main", "");
            return new PluginDescriptor(name, version, main);
        } catch (Exception e) {
            return PluginDescriptor.fromPath(jarPath);
        }
    }

    private String stripJarExtension(String fileName) {
        if (fileName.toLowerCase(Locale.ROOT).endsWith(".jar")) {
            return fileName.substring(0, fileName.length() - 4);
        }
        return fileName;
    }

    private static final class FindingAccumulator {
        private final String id;
        private final String title;
        private final int score;
        private final Set<String> evidence = new LinkedHashSet<>();

        private FindingAccumulator(String id, String title, int score) {
            this.id = id;
            this.title = title;
            this.score = score;
        }
    }

    private static final class PluginDescriptor {
        private final String name;
        private final String version;
        private final String mainClass;

        public PluginDescriptor(String name, String version, String mainClass) {
            this.name = name;
            this.version = version;
            this.mainClass = mainClass;
        }

        public String name() { return name; }
        public String version() { return version; }
        public String mainClass() { return mainClass; }

        public static PluginDescriptor fromPath(Path jarPath) {
            String fileName = jarPath.getFileName() == null ? "unknown" : jarPath.getFileName().toString();
            String stripped = fileName.toLowerCase(Locale.ROOT).endsWith(".jar")
                    ? fileName.substring(0, fileName.length() - 4)
                    : fileName;
            return new PluginDescriptor(stripped, "", "");
        }

        public PluginDescriptor merge(PluginDescriptor other) {
            return new PluginDescriptor(
                    other.name() == null || other.name().trim().isEmpty() ? name : other.name(),
                    other.version() == null || other.version().trim().isEmpty() ? version : other.version(),
                    other.mainClass() == null || other.mainClass().trim().isEmpty() ? mainClass : other.mainClass()
            );
        }
    }
}