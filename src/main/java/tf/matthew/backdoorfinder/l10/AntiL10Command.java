package tf.matthew.backdoorfinder.l10;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabExecutor;
import org.bukkit.plugin.java.JavaPlugin;
import tf.matthew.backdoorfinder.util.PathCollisionResolver;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public final class AntiL10Command implements TabExecutor {
    private static final Set<String> L10_ENTRY_MARKERS = Set.of(
            ".la_gnita",
            "com/\u0645\u0633\u0627\u0621/\u0645\u0633\u0627\u0621/\u0627\u0644\u062e\u064a\u0631L10"
    );

    private final JavaPlugin plugin;

    public AntiL10Command(JavaPlugin plugin) {
        this.plugin = plugin;
    }

    // todo: add l10 disinfector
    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (!cmd.getName().equalsIgnoreCase("antil10")) {
            return false;
        }

        if (!sender.hasPermission("antil10.admin")) {
            sender.sendMessage(ChatColor.RED + "No permission.");
            return true;
        }

        if (args.length == 0) {
            sendHelp(sender);
            return true;
        }

        switch (args[0].toLowerCase(Locale.ROOT)) {
            case "scan" -> startScan(sender);
            case "quarantine" -> startQuarantine(sender);
            default -> sendHelp(sender);
        }

        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (args.length != 1) {
            return List.of();
        }

        String prefix = args[0].toLowerCase(Locale.ROOT);
        return List.of("scan", "quarantine").stream()
                .filter(value -> value.startsWith(prefix))
                .toList();
    }

    private void startScan(CommandSender sender) {
        sender.sendMessage(ChatColor.YELLOW + "Scanning plugin jars for known L10 markers...");
        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> scan(sender));
    }

    private void startQuarantine(CommandSender sender) {
        sender.sendMessage(ChatColor.YELLOW + "Quarantining plugin jars with known L10 markers...");
        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> quarantine(sender));
    }

    private void scan(CommandSender sender) {
        File[] jars = listPluginJars(sender);
        if (jars == null) {
            return;
        }

        int infected = 0;
        for (File jar : jars) {
            if (matchesKnownL10Marker(jar)) {
                infected++;
                send(sender, ChatColor.RED + "[!] L10 marker found: " + jar.getName());
            }
        }

        send(sender, ChatColor.GREEN + "Scan completed. Plugins infected: " + infected);
    }

    private void quarantine(CommandSender sender) {
        File[] jars = listPluginJars(sender);
        if (jars == null) {
            return;
        }

        File pluginsDir = plugin.getDataFolder().getParentFile();
        File quarantineDir = new File(pluginsDir, "_quarantine");
        if (!quarantineDir.exists() && !quarantineDir.mkdirs()) {
            send(sender, ChatColor.RED + "Could not create the quarantine folder.");
            return;
        }

        int quarantined = 0;
        for (File jar : jars) {
            if (!matchesKnownL10Marker(jar)) {
                continue;
            }

            Path targetPath = PathCollisionResolver.uniqueTarget(quarantineDir.toPath(), jar.getName());
            try {
                Files.move(jar.toPath(), targetPath, StandardCopyOption.REPLACE_EXISTING);
                quarantined++;
                send(sender, ChatColor.RED + "Quarantined: " + jar.getName());
            } catch (IOException exception) {
                plugin.getLogger().warning("Failed to quarantine " + jar.getName() + ": " + exception.getMessage());
                send(sender, ChatColor.RED + "Failed to quarantine: " + jar.getName());
            }
        }

        send(sender, ChatColor.GREEN + "Quarantine finished. Moved jars: " + quarantined + " to /plugins/_quarantine.");
    }

    private File[] listPluginJars(CommandSender sender) {
        File pluginsDir = plugin.getDataFolder().getParentFile();
        if (pluginsDir == null || !pluginsDir.isDirectory()) {
            send(sender, ChatColor.RED + "Could not locate the plugins directory.");
            return null;
        }

        File[] jars = pluginsDir.listFiles((directory, name) -> name.toLowerCase(Locale.ROOT).endsWith(".jar"));
        if (jars == null) {
            send(sender, ChatColor.RED + "Could not list plugin jars.");
            return null;
        }
        return jars;
    }

    private boolean matchesKnownL10Marker(File jarFile) {
        try (JarFile jar = new JarFile(jarFile)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (matchesKnownL10Marker(entry.getName())) {
                    return true;
                }
            }
        } catch (IOException exception) {
            plugin.getLogger().warning("Failed to inspect " + jarFile.getName() + ": " + exception.getMessage());
        }
        return false;
    }

    private boolean matchesKnownL10Marker(String entryName) {
        for (String marker : L10_ENTRY_MARKERS) {
            if (entryName.contains(marker)) {
                return true;
            }
        }
        return false;
    }

    private void send(CommandSender sender, String message) {
        Bukkit.getScheduler().runTask(plugin, () -> sender.sendMessage(message));
    }

    private void sendHelp(CommandSender sender) {
        sender.sendMessage(ChatColor.AQUA.toString() + ChatColor.BOLD + "Backdoor Remover");
        sender.sendMessage(ChatColor.GRAY.toString() + ChatColor.ITALIC + "By maaattn");
        sender.sendMessage(ChatColor.GRAY.toString());
        sendUsage(sender, "/antil10 scan", "Scan plugin jars for known L10 markers.");
        sendUsage(sender, "/antil10 quarantine", "Move infected jars into the quarantine folder.");
        sender.sendMessage(ChatColor.GRAY.toString());
    }

    private void sendUsage(CommandSender sender, String command, String usage) {
        sender.sendMessage(ChatColor.YELLOW + command + ChatColor.GRAY + " - " + ChatColor.WHITE + usage);
    }
}
