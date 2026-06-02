package tf.matthew.backdoorfinder.scanner;

import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import tf.matthew.backdoorfinder.PluginConfiguration;
import tf.matthew.backdoorfinder.scanner.ScanResult.ScanFinding;

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

    private static final Set<String> THICC_INDUSTRIES_PAYLOAD_CLASSES = Set.of(
            "com/thiccindustries/debugger/Debugger.class",
            "com/thiccindustries/debugger/Config.class",
            "com/thiccindustries/debugger/DWeb.class"
    );

    private static final Set<String> THICC_INDUSTRIES_SPREADER_CLASSES = Set.of(
            "com/thiccindustries/debugger/Injector.class",
            "com/thiccindustries/debugger/Injector$SimpleConfig.class"
    );

    private static final Set<String> SCRIPT_EXTENSIONS = Set.of(
            ".groovy", ".kts", ".py", ".ps1", ".bat", ".cmd", ".sh"
    );

    private static final Set<String> NATIVE_EXTENSIONS = Set.of(
            ".exe", ".dll", ".so", ".dylib"
    );

    private static final Set<String> SECRET_RESOURCE_NAMES = Set.of(
            ".env", "credentials.json", "credentials.yml", "credentials.yaml",
            "password.txt", "secrets.txt", "secret.txt", "token.txt",
            "tokens.txt", "webhook.txt", "id_rsa", "authorized_keys"
    );

    private static final List<String> SUSPICIOUS_NAME_MARKERS = List.of(
            "backdoor", "stealer", "grabber", "exploit", "rootkit",
            "keylogger", "botnet", "trojan", "malware", "ransomware"
    );

    private static final Pattern SUSPICIOUS_NAME_PATTERN;
    static {
        StringBuilder regex = new StringBuilder();
        for (int i = 0; i < SUSPICIOUS_NAME_MARKERS.size(); i++) {
            if (i > 0) regex.append('|');
            regex.append("(?<![a-z])");
            regex.append(Pattern.quote(SUSPICIOUS_NAME_MARKERS.get(i)));
            regex.append("(?![a-z])");
        }
        SUSPICIOUS_NAME_PATTERN = Pattern.compile(regex.toString(), Pattern.CASE_INSENSITIVE);
    }

    private static final Set<String> SAFE_NESTED_JAR_FRAGMENTS = Set.of(
            "netty", "epoll", "kqueue", "liblz4", "lz4", "libzstd", "snappy",
            "mavenecjbootstrapdep", "mavenecjbootstrapagent", "asm", "slf4j"
    );

    private static final Set<String> SAFE_NATIVE_NAME_FRAGMENTS = Set.of(
            "lz4", "zstd", "netty", "epoll", "kqueue", "snappy", "leveldb",
            "sqlite", "jpountz"
    );

    private static final Set<String> SAFE_JS_NAME_FRAGMENTS = Set.of(
            "bootstrap", "base.js", "nashorncompat", "rhino", "polyfill",
            "es2015", "craftscript", "controls.js", "fxml.js", "mozilla"
    );

    private static final List<String> EXFIL_URL_PATTERNS = List.of(
            "pastebin.com/raw", "hastebin.com/raw",
            "ngrok.io", "ngrok.app",
            "requestbin.com", "requestbin.net",
            "webhook.site/", "pipedream.net"
    );

    private static final Set<String> KNOWN_SAFE_PACKAGES = Set.of(
            "com/google/gson/", "com/google/common/", "com/google/protobuf/",
            "com/fasterxml/jackson/", "it/unimi/dsi/fastutil/",
            "org/apache/commons/", "org/slf4j/", "org/json/",
            "org/junit/", "junit/", "org/hamcrest/",
            "io/netty/", "net/kyori/", "org/yaml/snakeyaml/",
            "kyori/adventure/", "kyori/examination/",
            "com/zaxxer/hikari/", "org/h2/", "org/mariadb/",
            "org/postgresql/", "com/mysql/", "org/sqlite/",
            "org/objectweb/asm/", "net/bytebuddy/",
            "org/javassist/", "javassist/",
            "org/mozilla/javascript/", "org/rhino/",
            "javax/annotation/", "org/checkerframework/",
            "org/intellij/", "org/jetbrains/",
            "com/rabbitmq/", "redis/clients/",
            "net/jpountz/", "com/github/benmanes/",
            "org/kohsuke/github/", "okhttp3/", "com/squareup/",
            "lombok/", "net/querz/nbt/",
            "me/lucko/jarrelocator/",
            "org/bstats/", "net/byteflux/libby/",
            "com/github/retrooper/packetevents/",
            "io/github/retrooper/packetevents/",
            "fr/mrmicky/fastboard/"
    );

    private static final Set<String> KNOWN_DEPENDENCY_LOADERS = Set.of(
            "slimjar", "zapper", "jarinjarclassloader", "libby",
            "dependencymanager", "relocator"
    );

    private static final Set<String> KNOWN_LOADBEFORE_PAIRS = Set.of(
            "worldguard", "plotsquared", "vault", "protocollib",
            "viaversion", "essentials", "placeholderapi", "denizen"
    );

    private final PluginConfiguration configuration;

    public PluginScanner(PluginConfiguration configuration) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
    }

    public static boolean isThiccIndustriesFinding(ScanFinding finding) {
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
                    boolean knownSafe = SAFE_NESTED_JAR_FRAGMENTS.stream().anyMatch(lowerJarName::contains);
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
                    boolean safeJs = SAFE_JS_NAME_FRAGMENTS.stream().anyMatch(lowerJs::contains);
                    if (!safeJs) {
                        addFinding(findings, "embedded-script", "Contains embedded script", 18, entryName);
                    }
                    continue;
                }

                if (hasAnyExtension(entryName, NATIVE_EXTENSIONS)) {
                    String lowerName = entryName.toLowerCase(Locale.ROOT);
                    boolean knownNative = SAFE_NATIVE_NAME_FRAGMENTS.stream().anyMatch(lowerName::contains);
                    if (knownNative) {
                        addFinding(findings, "native-binary-known", "Contains native binary (known-safe library)", 1, entryName);
                    } else {
                        addFinding(findings, "native-binary", "Contains native binary", 20, entryName);
                    }
                }
            }
        } catch (Exception exception) {
            addFinding(findings, "scan-error", "Archive could not be scanned", 35, exception.getMessage());
            notes.add("The jar could not be read as a normal plugin archive.");
        }

        List<ScanFinding> finalizedFindings = finalizeFindings(findings);
        int totalScore = finalizedFindings.stream().mapToInt(ScanFinding::score).sum();
        boolean suspicious = totalScore >= configuration.suspiciousScoreThreshold();

        return new ScanResult(
                jarPath,
                descriptor.name(),
                descriptor.version(),
                descriptor.mainClass(),
                totalScore,
                suspicious,
                finalizedFindings,
                notes
        );
    }

    private boolean isKnownSafePackage(String entryName) {
        for (String prefix : KNOWN_SAFE_PACKAGES) {
            if (entryName.startsWith(prefix)) return true;
            if (entryName.contains("/" + prefix)) return true;
            if (entryName.contains("/libs/" + prefix)) return true;
            if (entryName.contains("/lib/" + prefix)) return true;
            if (entryName.contains("/shaded/" + prefix)) return true;
            if (entryName.contains("/shadow/" + prefix)) return true;
            if (entryName.contains("/relocated/" + prefix)) return true;
        }
        return false;
    }

    private boolean isKnownDependencyLoader(String entryName) {
        String lower = entryName.toLowerCase(Locale.ROOT);
        for (String loader : KNOWN_DEPENDENCY_LOADERS) {
            if (lower.contains(loader)) return true;
        }
        return false;
    }

    private void inspectEntryName(String entryName, Map<String, FindingAccumulator> findings) {
        String lowerEntryName = entryName.toLowerCase(Locale.ROOT);
        String fileName = fileName(lowerEntryName);

        inspectThiccIndustriesEntry(entryName, findings);

        if (!lowerEntryName.endsWith(".class") && SECRET_RESOURCE_NAMES.contains(fileName)) {
            addFinding(findings, "secret-file", "Contains suspicious secret-like file names", 30, entryName);
        }

        if (SUSPICIOUS_NAME_PATTERN.matcher(lowerEntryName).find()) {
            if (!isKnownSafePackage(entryName)) {
                addFinding(findings, "suspicious-naming", "Contains files with malware-associated names", 4, entryName);
            }
        }
    }

    private void inspectManifest(String yamlText, String sourceName, Map<String, FindingAccumulator> findings) {
        YamlConfiguration yaml = YamlConfiguration.loadConfiguration(new StringReader(yamlText));
        inspectPermissionSection(yaml.getConfigurationSection("permissions"), findings, sourceName);
        inspectCommands(yaml.getConfigurationSection("commands"), findings, sourceName);

        List<String> loadBefore = yaml.getStringList("loadbefore");
        if (loadBefore.isEmpty()) {
            String single = yaml.getString("loadbefore", "");
            if (!single.isBlank()) {
                loadBefore = List.of(single.split("[,\\s]+"));
            }
        }

        for (String target : loadBefore) {
            String lower = target.trim().toLowerCase(Locale.ROOT);
            if (!lower.isBlank() && !KNOWN_LOADBEFORE_PAIRS.contains(lower)) {
                addFinding(findings, "loadbefore-unknown", "Tries to load before non-standard plugin: " + target, 2, sourceName);
            }
        }
    }

    private void inspectPermissionSection(ConfigurationSection permissions, Map<String, FindingAccumulator> findings, String sourceName) {
        if (permissions == null) return;

        for (String key : permissions.getKeys(false)) {
            String lowerKey = key.toLowerCase(Locale.ROOT);
            ConfigurationSection permissionSection = permissions.getConfigurationSection(key);

            if ("*".equals(key) || lowerKey.contains("bukkit.command.op") || lowerKey.contains("minecraft.command.op")) {
                addFinding(findings, "dangerous-permission", "Declares OP-level or wildcard permissions", 50, sourceName + ": permission " + key);
            }

            if (permissionSection == null) continue;

            String permissionDefault = permissionSection.getString("default", "");
            if ("true".equalsIgnoreCase(permissionDefault) && ("*".equals(key) || lowerKey.contains(".op"))) {
                addFinding(findings, "default-true-dangerous", "Grants a dangerous permission to everyone by default", 40, sourceName + ": permission " + key);
            }

            ConfigurationSection children = permissionSection.getConfigurationSection("children");
            if (children == null) continue;

            for (String childKey : children.getKeys(false)) {
                if (!children.getBoolean(childKey, false)) continue;
                String lowerChild = childKey.toLowerCase(Locale.ROOT);
                if ("*".equals(childKey) || lowerChild.contains("bukkit.command.op") || lowerChild.contains("minecraft.command.op")) {
                    addFinding(findings, "dangerous-child-permission", "Permission tree grants wildcard or OP access", 55, sourceName + ": " + key + " -> " + childKey);
                }
            }
        }
    }

    private void inspectCommands(ConfigurationSection commands, Map<String, FindingAccumulator> findings, String sourceName) {
        if (commands == null) return;

        for (String commandName : commands.getKeys(false)) {
            String lowerCommand = commandName.toLowerCase(Locale.ROOT);
            if ("op".equals(lowerCommand) || "deop".equals(lowerCommand)) {
                addFinding(findings, "op-command", "Registers OP management commands", 30, sourceName + ": command " + commandName);
            }
        }
    }

    private void inspectClassBytes(byte[] bytes, String entryName, Map<String, FindingAccumulator> findings) {
        List<String> strings = extractStrings(bytes);
        String lowerText = joinLowercase(strings);

        inspectThiccIndustriesClassStrings(lowerText, entryName, findings);
        boolean writesOp = inspectOperatorAbuse(strings, lowerText, entryName, findings);
        boolean hasHardcodedDiscordWebhook = inspectWebhookIndicators(strings, lowerText, entryName, findings);

        inspectRuntimeCodeLoading(lowerText, entryName, findings);
        inspectProcessExecution(strings, lowerText, entryName, findings);
        inspectReflectionUsage(lowerText, entryName, findings);
        inspectNetworkUsage(lowerText, entryName, findings);
        inspectDataExfiltration(lowerText, entryName, findings);
        inspectBytecodeManipulation(lowerText, entryName, findings);
        inspectEncodedPayloads(strings, entryName, findings);
        inspectPingResponseTampering(lowerText, entryName, writesOp, hasHardcodedDiscordWebhook, findings);
    }

    private boolean inspectOperatorAbuse(
            List<String> strings,
            String lowerText,
            String entryName,
            Map<String, FindingAccumulator> findings
    ) {
        boolean writesOp = containsToken(strings, "setop");
        if (writesOp) {
            addFinding(findings, "op-escalation-write", "Calls setOp() to grant/revoke operator status", 70, entryName);
            return true;
        }

        boolean readsOpPermission = containsAny(lowerText, "bukkit.command.op", "minecraft.command.op");
        if (readsOpPermission && !entryName.contains("permission")) {
            addFinding(findings, "op-escalation-read", "References OP permission node", 8, entryName);
        }

        if ((containsAny(lowerText, "dispatchcommand", "performcommand"))
                && containsAny(lowerText, "/op", "/deop", "minecraft:op", "minecraft:deop")) {
            addFinding(findings, "command-op", "Dispatches OP-related commands programmatically", 15, entryName);
        }

        if (containsAny(lowerText, "permissionattachment")
                && containsAny(lowerText, "setpermission")
                && (containsToken(strings, "*") || lowerText.contains(".*"))) {
            addFinding(findings, "wildcard-permission", "Adds wildcard permission via PermissionAttachment", 12, entryName);
        }
        return false;
    }

    private boolean inspectWebhookIndicators(
            List<String> strings,
            String lowerText,
            String entryName,
            Map<String, FindingAccumulator> findings
    ) {
        for (String pattern : EXFIL_URL_PATTERNS) {
            if (lowerText.contains(pattern)) {
                addFinding(findings, "external-exfil", "References known data exfiltration endpoints", 35, entryName);
                break;
            }
        }

        boolean hasHardcodedDiscordWebhook = false;
        for (String s : strings) {
            if (s.contains("discord.com/api/webhooks/") || s.contains("discordapp.com/api/webhooks/")) {
                if (s.matches(".*webhooks/\\d+/[A-Za-z0-9_-]+.*")) {
                    hasHardcodedDiscordWebhook = true;
                    break;
                }
            }
        }
        if (hasHardcodedDiscordWebhook) {
            addFinding(findings, "hardcoded-webhook", "Contains hardcoded Discord webhook URL with token", 50, entryName);
        }
        return hasHardcodedDiscordWebhook;
    }

    private void inspectRuntimeCodeLoading(String lowerText, String entryName, Map<String, FindingAccumulator> findings) {
        if (isKnownDependencyLoader(entryName)) {
            addFinding(findings, "dependency-loader", "Uses runtime dependency loading (known pattern)", 1, entryName);
        } else if (containsAny(lowerText, "defineclass") && containsAny(lowerText, "urlclassloader")) {
            addFinding(findings, "dynamic-code-loading", "Loads and defines classes dynamically at runtime", 18, entryName);
        } else if (containsAny(lowerText, "scriptenginemanager", "javax/script")) {
            String lowerEntryName = entryName.toLowerCase(Locale.ROOT);
            if (!lowerEntryName.contains("nashorn") && !lowerEntryName.contains("rhino")
                    && !lowerEntryName.contains("craftscript")) {
                addFinding(findings, "script-engine", "Uses script engine to execute dynamic code", 8, entryName);
            }
        }
    }

    private void inspectProcessExecution(
            List<String> strings,
            String lowerText,
            String entryName,
            Map<String, FindingAccumulator> findings
    ) {
        if (containsAny(lowerText, "processbuilder", "cmd.exe", "powershell", "/bin/sh", "/bin/bash")
                || (lowerText.contains("getruntime") && containsToken(strings, "exec"))) {
            String lowerEntryName = entryName.toLowerCase(Locale.ROOT);
            if (!lowerEntryName.contains("nashorn") && !lowerEntryName.contains("rhino")) {
                addFinding(findings, "command-exec", "Executes external system processes", 25, entryName);
            }
        }
    }

    private void inspectReflectionUsage(String lowerText, String entryName, Map<String, FindingAccumulator> findings) {
        if (containsAny(lowerText, "setaccessible", "getdeclaredfield", "getdeclaredmethod")) {
            if (entryName.contains("/nms/") || entryName.contains("/craftbukkit/")
                    || entryName.contains("/reflect/") || entryName.contains("Reflection")
                    || entryName.contains("NMS") || entryName.contains("VersionSupport")) {
                addFinding(findings, "nms-reflection", "Uses reflection for NMS/CraftBukkit access (expected)", 2, entryName);
            } else {
                addFinding(findings, "deep-reflection", "Uses deep reflection or unsafe access", 4, entryName);
            }
        }

        if (lowerText.contains("sun/misc/unsafe") || lowerText.contains("jdk/internal/misc/unsafe")) {
            addFinding(findings, "unsafe-access", "Uses sun.misc.Unsafe or JDK internal Unsafe", 2, entryName);
        }
    }

    private void inspectNetworkUsage(String lowerText, String entryName, Map<String, FindingAccumulator> findings) {
        if (lowerText.contains("java/net/socket") && !entryName.contains("netty")
                && !entryName.contains("rabbitmq") && !entryName.contains("redis")) {
            addFinding(findings, "raw-socket", "Opens raw network sockets", 3, entryName);
        }
    }

    private void inspectDataExfiltration(String lowerText, String entryName, Map<String, FindingAccumulator> findings) {
        boolean hasBase64 = containsAny(lowerText, "base64", "getdecoder", "getencoder");
        boolean hasUrlConnection = containsAny(lowerText, "httpurlconnection", "urlconnection");
        boolean hasFileRead = containsAny(lowerText, "fileinputstream", "files.readallbytes", "fileutils.read");
        if (hasBase64 && hasUrlConnection && hasFileRead) {
            addFinding(findings, "data-exfil-pattern", "Combines file reading, encoding, and HTTP sending (potential data exfiltration)", 8, entryName);
        }
    }

    private void inspectBytecodeManipulation(String lowerText, String entryName, Map<String, FindingAccumulator> findings) {
        if (containsAny(lowerText, "bcel", "javassist/ctclass", "cglib", "bytebuddy")
                && containsAny(lowerText, "defineclas")) {
            if (!isKnownSafePackage(entryName) && !isKnownDependencyLoader(entryName)) {
                addFinding(findings, "bytecode-manipulation", "Uses bytecode manipulation to define new classes", 6, entryName);
            }
        }
    }

    private void inspectEncodedPayloads(List<String> strings, String entryName, Map<String, FindingAccumulator> findings) {
        for (String s : strings) {
            if (s.length() > 80 && looksLikeBase64(s) && !isKnownSafePackage(entryName)) {
                addFinding(findings, "obfuscated-string", "Contains long Base64-encoded strings (possible obfuscated payload)", 6, entryName);
                break;
            }
        }
    }

    private void inspectPingResponseTampering(
            String lowerText,
            String entryName,
            boolean writesOp,
            boolean hasHardcodedDiscordWebhook,
            Map<String, FindingAccumulator> findings
    ) {
        if (containsAny(lowerText, "serverlistpingevent", "motd")
                && containsAny(lowerText, "setmaxplayers", "setversionname")) {
            if (writesOp || hasHardcodedDiscordWebhook) {
                addFinding(findings, "server-info-leak", "Modifies server ping response alongside other suspicious activity", 15, entryName);
            }
        }
    }

    private void inspectThiccIndustriesEntry(String entryName, Map<String, FindingAccumulator> findings) {
        if (!entryName.startsWith(THICC_INDUSTRIES_PACKAGE)) return;

        if (THICC_INDUSTRIES_PAYLOAD_CLASSES.contains(entryName) || entryName.startsWith("com/thiccindustries/debugger/Debugger$")) {
            addFinding(findings, THICC_INDUSTRIES_RAT_FINDING_ID,
                    "Contains Thicc Industries Debugger RAT payload classes", 100, entryName);
            return;
        }

        if (THICC_INDUSTRIES_SPREADER_CLASSES.contains(entryName)) {
            addFinding(findings, THICC_INDUSTRIES_SPREADER_FINDING_ID,
                    "Contains Thicc Industries injector/spreader code", 100, entryName);
            return;
        }

        addFinding(findings, THICC_INDUSTRIES_RAT_FINDING_ID,
                "Contains Thicc Industries Debugger package", 75, entryName);
    }

    private void inspectThiccIndustriesClassStrings(String lowerText, String entryName, Map<String, FindingAccumulator> findings) {
        if (containsAny(lowerText,
                "com.thiccindustries.debugger.debugger",
                "## bd ## plugin",
                "spigot-stats-server",
                "authorized_uuids",
                "you have been banned but we got your back")) {
            addFinding(findings, THICC_INDUSTRIES_RAT_FINDING_ID,
                    "Contains Thicc Industries Debugger RAT behavior markers", 100, entryName);
        }

        if (containsAny(lowerText,
                "injecting thicc industries into",
                "inject_into_other_plugins",
                "hostifymonitor.jar",
                "fakahedaminequery.jar")) {
            addFinding(findings, THICC_INDUSTRIES_SPREADER_FINDING_ID,
                    "Contains Thicc Industries injector/spreader behavior markers", 100, entryName);
        }

        if (containsAny(lowerText, "askarax200", "askarax20", "mythix", "burhxdxd", "bruhxdxd", "creeperman")
                && containsAny(lowerText, "thicc", "industries", "backdoor")
                && containsAny(lowerText, "discord.com/api/webhooks/", "discordapp.com/api/webhooks/")) {
            addFinding(findings, THICC_INDUSTRIES_REMNANT_FINDING_ID,
                    "Contains Thicc Industries RAT config/webhook remnants", 90, entryName);
        }
    }

    private boolean looksLikeBase64(String s) {
        if (s.length() < 80) return false;
        int validChars = 0;
        for (char c : s.toCharArray()) {
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
                validChars++;
            }
        }
        return (double) validChars / s.length() > 0.95;
    }

    private PluginDescriptor parseDescriptor(String yamlText, Path jarPath) {
        YamlConfiguration yaml = YamlConfiguration.loadConfiguration(new StringReader(yamlText));
        return new PluginDescriptor(
                defaultString(yaml.getString("name"), stripJarExtension(jarPath.getFileName().toString())),
                defaultString(yaml.getString("version"), ""),
                defaultString(yaml.getString("main"), "")
        );
    }

    private List<ScanFinding> finalizeFindings(Map<String, FindingAccumulator> findings) {
        List<ScanFinding> finalized = new ArrayList<>(findings.size());
        for (FindingAccumulator accumulator : findings.values()) {
            finalized.add(new ScanFinding(
                    accumulator.id,
                    accumulator.title,
                    accumulator.score,
                    List.copyOf(accumulator.evidence)
            ));
        }
        return Collections.unmodifiableList(finalized);
    }

    private void addFinding(Map<String, FindingAccumulator> findings, String id, String title, int score, String evidence) {
        FindingAccumulator accumulator = findings.computeIfAbsent(id, key -> new FindingAccumulator(id, title, score));
        if (accumulator.evidence.size() >= configuration.maxEvidencePerRule()) return;
        if (evidence != null && !evidence.isBlank()) {
            accumulator.evidence.add(evidence);
        }
    }

    private boolean containsAny(String haystack, String... needles) {
        for (String needle : needles) {
            if (haystack.contains(needle)) return true;
        }
        return false;
    }

    private boolean hasAnyExtension(String entryName, Collection<String> extensions) {
        String lowerName = entryName.toLowerCase(Locale.ROOT);
        for (String extension : extensions) {
            if (lowerName.endsWith(extension)) return true;
        }
        return false;
    }

    private boolean isManifest(String entryName) {
        return PLUGIN_YML.equalsIgnoreCase(entryName) || PAPER_PLUGIN_YML.equalsIgnoreCase(entryName);
    }

    private String readText(ZipFile zipFile, ZipEntry entry) throws IOException {
        return new String(readBytes(zipFile, entry), StandardCharsets.UTF_8);
    }

    private String fileName(String entryName) {
        int slashIndex = entryName.lastIndexOf('/');
        return slashIndex >= 0 ? entryName.substring(slashIndex + 1) : entryName;
    }

    private List<String> extractStrings(byte[] bytes) {
        List<String> strings = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (byte value : bytes) {
            int unsigned = value & 0xFF;
            if (unsigned >= 0x20 && unsigned <= 0x7E) {
                current.append((char) unsigned);
                continue;
            }
            if (current.length() >= 4) {
                strings.add(current.toString());
            }
            current.setLength(0);
        }
        if (current.length() >= 4) {
            strings.add(current.toString());
        }
        return strings;
    }

    private String joinLowercase(List<String> strings) {
        return strings.stream()
                .map(value -> value.toLowerCase(Locale.ROOT))
                .collect(java.util.stream.Collectors.joining("\n"));
    }

    private boolean containsToken(List<String> strings, String token) {
        for (String value : strings) {
            String lowerValue = value.toLowerCase(Locale.ROOT);
            int index = lowerValue.indexOf(token.toLowerCase(Locale.ROOT));
            while (index >= 0) {
                boolean leftBoundary = index == 0 || !Character.isLetterOrDigit(lowerValue.charAt(index - 1));
                int endIndex = index + token.length();
                boolean rightBoundary = endIndex >= lowerValue.length() || !Character.isLetterOrDigit(lowerValue.charAt(endIndex));
                if (leftBoundary && rightBoundary) return true;
                index = lowerValue.indexOf(token.toLowerCase(Locale.ROOT), index + 1);
            }
        }
        return false;
    }

    private byte[] readBytes(ZipFile zipFile, ZipEntry entry) throws IOException {
        try (InputStream inputStream = zipFile.getInputStream(entry);
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            inputStream.transferTo(outputStream);
            return outputStream.toByteArray();
        }
    }

    private String defaultString(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
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

    private record PluginDescriptor(String name, String version, String mainClass) {
        private static PluginDescriptor fromPath(Path jarPath) {
            String fileName = jarPath.getFileName() == null ? "unknown" : jarPath.getFileName().toString();
            String stripped = fileName.toLowerCase(Locale.ROOT).endsWith(".jar")
                    ? fileName.substring(0, fileName.length() - 4)
                    : fileName;
            return new PluginDescriptor(stripped, "", "");
        }

        private PluginDescriptor merge(PluginDescriptor other) {
            return new PluginDescriptor(
                    other.name().isBlank() ? name : other.name(),
                    other.version().isBlank() ? version : other.version(),
                    other.mainClass().isBlank() ? mainClass : other.mainClass()
            );
        }
    }
}
