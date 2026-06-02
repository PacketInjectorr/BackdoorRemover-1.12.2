package tf.matthew.backdoorfinder;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.PluginCommand;
import org.bukkit.plugin.java.JavaPlugin;
import tf.matthew.backdoorfinder.l10.AntiL10Command;
import tf.matthew.backdoorfinder.discord.DiscordWebhookClient;
import tf.matthew.backdoorfinder.scanner.PluginDisinfector;
import tf.matthew.backdoorfinder.scanner.PluginScanner;
import tf.matthew.backdoorfinder.scanner.ScanResult;
import tf.matthew.backdoorfinder.scanner.ScanResult.ScanFinding;
import tf.matthew.backdoorfinder.util.PathCollisionResolver;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import java.util.stream.Stream;

// Todo in scanner
// fix false positives in famous legit plugins

public final class BackdoorFinderPlugin extends JavaPlugin {
    private PluginConfiguration configuration;
    private DiscordWebhookClient webhookClient;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        reloadLocalConfiguration();
        printStartupBanner();

        PluginCommand command = getCommand("backdoorfinder");
        if (command != null) {
            BackdoorFinderCommand executor = new BackdoorFinderCommand(this);
            command.setExecutor(executor);
            command.setTabCompleter(executor);
        } else {
            getLogger().warning("Command backdoorfinder is missing from plugin.yml");
        }

        PluginCommand antiL10Command = getCommand("antil10");
        if (antiL10Command != null) {
            AntiL10Command antiL10Executor = new AntiL10Command(this);
            antiL10Command.setExecutor(antiL10Executor);
            antiL10Command.setTabCompleter(antiL10Executor);
        } else {
            getLogger().warning("Command antil10 is missing from plugin.yml");
        }

        if (configuration.autoScanOnStartup()) {
            scheduleScanAll(Bukkit.getConsoleSender(), "startup");
        }
    }

    public void reloadLocalConfiguration() {
        reloadConfig();
        configuration = PluginConfiguration.from(getConfig());
        webhookClient = new DiscordWebhookClient(configuration, getLogger());
    }

    public void scheduleScanAll(CommandSender sender, String reason) {
        Path pluginsDirectory = getPluginsDirectory();
        List<Path> jars = listPluginJars();

        if (jars.isEmpty()) {
            sendMessage(sender, ChatColor.YELLOW + "No plugin jars were found in " + pluginsDirectory);
            return;
        }

        sendMessage(sender, ChatColor.YELLOW + "Scanning " + jars.size() + " plugin jars...");
        Bukkit.getScheduler().runTaskAsynchronously(this, () -> {
            PluginScanner scanner = new PluginScanner(configuration);
            List<ScanResult> results = new ArrayList<>();
            for (Path jar : jars) {
                ScanResult result = scanner.scan(jar);
                results.add(result);
                webhookClient.sendScanResult(result);
            }

            webhookClient.sendSummary(reason, results);
            long suspiciousCount = results.stream().filter(ScanResult::suspicious).count();
            int highestScore = results.stream().mapToInt(ScanResult::score).max().orElse(0);

            sendMessage(sender, ChatColor.GREEN + "Scan finished. Suspicious: " + suspiciousCount
                    + "/" + results.size() + ", highest score: " + highestScore);
        });
    }

    public void scheduleCleanupAll(CommandSender sender) {
        Path pluginsDirectory = getPluginsDirectory();
        List<Path> jars = listPluginJars();

        if (jars.isEmpty()) {
            sendMessage(sender, ChatColor.YELLOW + "No plugin jars were found in " + pluginsDirectory);
            return;
        }

        scheduleCleanup(sender, jars, "all plugin jars");
    }

    public void scheduleCleanupSingle(CommandSender sender, Path jarPath) {
        scheduleCleanup(sender, List.of(jarPath), jarPath.getFileName().toString());
    }

    public void scheduleThiccScanAll(CommandSender sender) {
        Path pluginsDirectory = getPluginsDirectory();
        List<Path> jars = listPluginJars();

        if (jars.isEmpty()) {
            sendMessage(sender, ChatColor.YELLOW + "No plugin jars were found in " + pluginsDirectory);
            return;
        }

        scheduleThiccScan(sender, jars, "all plugin jars");
    }

    public void scheduleThiccScanSingle(CommandSender sender, Path jarPath) {
        scheduleThiccScan(sender, List.of(jarPath), jarPath.getFileName().toString());
    }

    public void scheduleScanSingle(CommandSender sender, Path jarPath, String reason) {
        sendMessage(sender, ChatColor.YELLOW + "Scanning " + jarPath.getFileName() + "...");
        Bukkit.getScheduler().runTaskAsynchronously(this, () -> {
            PluginScanner scanner = new PluginScanner(configuration);
            ScanResult result = scanner.scan(jarPath);
            webhookClient.sendScanResult(result);
            webhookClient.sendSummary(reason + " (" + jarPath.getFileName() + ")", List.of(result));

            ChatColor statusColor = result.suspicious() ? ChatColor.RED : ChatColor.GREEN;
            sendMessage(sender, statusColor + "Finished " + jarPath.getFileName() + ": "
                    + (result.suspicious() ? "suspicious" : "clean")
                    + " (score " + result.score() + ")");
        });
    }

    public Path resolvePluginJar(String query) {
        String normalized = query.toLowerCase(Locale.ROOT);
        for (Path jarPath : listPluginJars()) {
            String fileName = jarPath.getFileName().toString().toLowerCase(Locale.ROOT);
            String withoutExtension = fileName.endsWith(".jar") ? fileName.substring(0, fileName.length() - 4) : fileName;
            if (fileName.equals(normalized) || withoutExtension.equals(normalized)) {
                return jarPath;
            }
        }
        return null;
    }

    public List<String> listPluginJarNames() {
        return listPluginJars().stream()
                .map(path -> path.getFileName().toString())
                .sorted()
                .toList();
    }

    private void scheduleCleanup(CommandSender sender, List<Path> jars, String scope) {
        sendMessage(sender, ChatColor.YELLOW + "Disinfecting confirmed Thicc Industries RAT matches in " + scope + "...");
        Bukkit.getScheduler().runTaskAsynchronously(this, () -> {
            PluginScanner scanner = new PluginScanner(configuration);
            PluginDisinfector disinfector = new PluginDisinfector();
            Path backupDirectory = getPluginsDirectory().resolve("_backdoorfinder-cleanup-backups");
            Path quarantineDirectory = getPluginsDirectory().resolve("_backdoorfinder-quarantine");
            List<CleanupAction> cleaned = new ArrayList<>();
            List<CleanupAction> quarantined = new ArrayList<>();
            int scanned = 0;
            int matched = 0;
            int quarantineFallbacks = 0;

            try {
                Files.createDirectories(backupDirectory);
                Files.createDirectories(quarantineDirectory);
            } catch (IOException exception) {
                getLogger().warning("Failed to create cleanup directories: " + exception.getMessage());
                sendMessage(sender, ChatColor.RED + "Could not create cleanup folders in " + getPluginsDirectory());
                return;
            }

            for (Path jar : jars) {
                scanned++;
                ScanResult result = scanner.scan(jar);
                if (!isConfirmedThiccIndustriesRat(result)) {
                    continue;
                }

                matched++;
                try {
                    PluginDisinfector.CleanResult cleanResult = disinfector.disinfect(jar, backupDirectory);
                    if (cleanResult.cleaned()) {
                        cleaned.add(new CleanupAction(result.pluginName(), jar, cleanResult.backupPath()));
                        List<String> cleanDetails = new ArrayList<>();
                        if (cleanResult.hookRemoved()) {
                            cleanDetails.add("startup hook removed");
                        }
                        if (cleanResult.remnantsRemoved()) {
                            cleanDetails.add("config/webhook remnants removed");
                        }
                        if (cleanDetails.isEmpty()) {
                            cleanDetails.add("payload classes removed");
                        }
                        sendMessage(sender, ChatColor.GREEN + "Cleaned RAT from " + jar.getFileName()
                                + " (" + String.join(", ", cleanDetails) + "). Backup: " + cleanResult.backupPath().getFileName());
                    }
                } catch (Exception exception) {
                    quarantineFallbacks++;
                    getLogger().warning("Failed to disinfect " + jar.getFileName()
                            + ", quarantining instead: " + exception.getMessage());
                    Path target = PathCollisionResolver.uniqueTarget(quarantineDirectory, jar.getFileName().toString());
                    try {
                        Files.move(jar, target, StandardCopyOption.REPLACE_EXISTING);
                        quarantined.add(new CleanupAction(result.pluginName(), jar, target));
                        sendMessage(sender, ChatColor.RED + "Could not safely repair " + jar.getFileName()
                                + "; quarantined it instead.");
                    } catch (IOException moveException) {
                        getLogger().warning("Failed to quarantine " + jar.getFileName() + ": " + moveException.getMessage());
                        sendMessage(sender, ChatColor.RED + "Failed to disinfect or quarantine: " + jar.getFileName());
                    }
                }
            }

            List<CleanupAction> affected = new ArrayList<>(cleaned);
            affected.addAll(quarantined);
            if (!affected.isEmpty()) {
                disableAffectedPlugins(sender, affected);
            }

            sendMessage(sender, ChatColor.GREEN + "Cleanup finished. Scanned: " + scanned
                    + ", confirmed RAT matches: " + matched
                    + ", cleaned: " + cleaned.size()
                    + ", quarantine fallbacks: " + quarantineFallbacks + ".");

            if (!affected.isEmpty()) {
                sendMessage(sender, ChatColor.YELLOW + "Restart the server to fully unload any RAT classes already loaded in memory.");
            }
        });
    }

    private void scheduleThiccScan(CommandSender sender, List<Path> jars, String scope) {
        sendMessage(sender, ChatColor.YELLOW + "Scanning " + scope + " for Thicc Industries RAT markers only...");
        Bukkit.getScheduler().runTaskAsynchronously(this, () -> {
            PluginScanner scanner = new PluginScanner(configuration);
            int scanned = 0;
            int matched = 0;

            for (Path jar : jars) {
                scanned++;
                ScanResult result = scanner.scan(jar);
                List<ScanFinding> thiccFindings = result.findings().stream()
                        .filter(PluginScanner::isThiccIndustriesFinding)
                        .toList();

                if (thiccFindings.isEmpty()) {
                    continue;
                }

                matched++;
                sendMessage(sender, ChatColor.RED + "[THICC] " + jar.getFileName()
                        + " (" + result.pluginName() + ") matched " + thiccFindings.size() + " marker(s).");
                for (ScanFinding finding : thiccFindings) {
                    String evidence = finding.evidence().isEmpty()
                            ? "no extra evidence"
                            : String.join("; ", finding.evidence());
                    sendMessage(sender, ChatColor.RED + " - " + finding.title() + ": " + evidence);
                }
            }

            ChatColor color = matched == 0 ? ChatColor.GREEN : ChatColor.RED;
            sendMessage(sender, color + "Thicc scan finished. Matches: " + matched + "/" + scanned + ".");
        });
    }

    private boolean isConfirmedThiccIndustriesRat(ScanResult result) {
        return result.findings().stream().anyMatch(PluginScanner::isThiccIndustriesFinding);
    }

    private void disableAffectedPlugins(CommandSender sender, List<CleanupAction> actions) {
        Bukkit.getScheduler().runTask(this, () -> {
            for (CleanupAction action : actions) {
                if (action.pluginName().isBlank() || getDescription().getName().equalsIgnoreCase(action.pluginName())) {
                    continue;
                }

                org.bukkit.plugin.Plugin loadedPlugin = Bukkit.getPluginManager().getPlugin(action.pluginName());
                if (loadedPlugin == null || !loadedPlugin.isEnabled()) {
                    continue;
                }

                Bukkit.getPluginManager().disablePlugin(loadedPlugin);
                sender.sendMessage(ChatColor.YELLOW + "Disabled loaded plugin instance: " + loadedPlugin.getName());
            }
        });
    }

    private List<Path> listPluginJars() {
        Path pluginsDirectory = getPluginsDirectory();
        if (!Files.isDirectory(pluginsDirectory)) {
            return List.of();
        }

        try (Stream<Path> stream = Files.list(pluginsDirectory)) {
            return stream
                    .filter(path -> Files.isRegularFile(path) && path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".jar"))
                    .filter(path -> !path.getFileName().toString().equalsIgnoreCase(guessOwnJarName()))
                    .sorted(Comparator.comparing(path -> path.getFileName().toString().toLowerCase(Locale.ROOT)))
                    .collect(Collectors.toList());
        } catch (Exception exception) {
            getLogger().warning("Failed to list plugin jars: " + exception.getMessage());
            return List.of();
        }
    }

    private Path getPluginsDirectory() {
        File dataFolder = getDataFolder();
        File parent = dataFolder.getParentFile();
        return parent == null ? dataFolder.toPath() : parent.toPath();
    }

    private String guessOwnJarName() {
        return getDescription().getName() + "-" + getDescription().getVersion() + ".jar";
    }

    private void sendMessage(CommandSender sender, String message) {
        Bukkit.getScheduler().runTask(this, () -> sender.sendMessage(message));
    }

    private void printStartupBanner() {
        String banner = """
                __________                __       .___                 __________
                \\______   \\_____    ____ |  | __ __| _/____   __________\\______   \\ ____   _____   _______  __ ___________
                 |    |  _/\\__  \\ _/ ___\\|  |/ // __ |/  _ \\ /  _ \\_  __ \\       _// __ \\ /     \\ /  _ \\  \\/ // __ \\_  __ \\
                 |    |   \\ / __ \\\\  \\___|    </ /_/ (  <_> |  <_> )  | \\/    |   \\  ___/|  Y Y  (  <_> )   /\\  ___/|  | \\/
                 |______  /(____  /\\___  >__|_ \\____ |\\____/ \\____/|__|  |____|_  /\\___  >__|_|  /\\____/ \\_/  \\___  >__|
                         \\/      \\/     \\/     \\/    \\/                          \\/     \\/      \\/                 \\/
                """;

        for (String line : banner.stripTrailing().split("\\R")) {
            Bukkit.getConsoleSender().sendMessage(ChatColor.YELLOW + line);
        }
    }

    private record CleanupAction(String pluginName, Path originalPath, Path evidencePath) {
    }
}
