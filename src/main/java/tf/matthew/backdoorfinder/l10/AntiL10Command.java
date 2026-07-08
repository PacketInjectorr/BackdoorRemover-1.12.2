package tf.matthew.backdoorfinder.l10;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabExecutor;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public final class AntiL10Command implements TabExecutor {
    private static final Set<String> L10_ENTRY_MARKERS = new HashSet<>();
    static {
        L10_ENTRY_MARKERS.add(".la_gnita");
        L10_ENTRY_MARKERS.add("com/\u0645\u0633\u0627\u0621/\u0645\u0633\u0627\u0621/\u0627\u0644\u062e\u064a\u0631L10");
    }

    private final JavaPlugin plugin;

    public AntiL10Command(JavaPlugin plugin) {
        this.plugin = plugin;
    }

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
            case "scan":
                startScan(sender);
                break;
            case "quarantine":
                startQuarantine(sender);
                break;
            default:
                sendHelp(sender);
                break;
        }
        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        List<String> completions = new ArrayList<>();
        if (args.length == 1) {
            String input = args[0].toLowerCase(Locale.ROOT);
            if ("scan".startsWith(input)) completions.add("scan");
            if ("quarantine".startsWith(input)) completions.add("quarantine");
        }
        return completions;
    }

    private void startScan(CommandSender sender) {
        send(sender, ChatColor.YELLOW + "[AntiL10] Starting manual scan...");
        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            File pluginsDir = plugin.getDataFolder().getParentFile();
            File[] files = pluginsDir != null ? pluginsDir.listFiles() : null;
            if (files == null) {
                send(sender, ChatColor.RED + "[AntiL10] Could not access plugins directory.");
                return;
            }

            int matches = 0;
            for (File file : files) {
                if (file.isFile() && file.getName().toLowerCase(Locale.ROOT).endsWith(".jar")) {
                    if (inspectJarFile(file)) {
                        send(sender, ChatColor.RED + "[AntiL10] MATCH FOUND: " + file.getName());
                        matches++;
                    }
                }
            }
            send(sender, ChatColor.GREEN + "[AntiL10] Scan finished. Matches found: " + matches);
        });
    }

    private void startQuarantine(CommandSender sender) {
        send(sender, ChatColor.YELLOW + "[AntiL10] Moving items to quarantine is not yet fully implemented.");
    }

    private boolean inspectJarFile(File jarFile) {
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
        sender.sendMessage(ChatColor.GRAY.toString() + ChatColor.ITALIC + "By maaattn (ported back to 1.12.2 by PacketInjector");
        sender.sendMessage(ChatColor.GRAY.toString());
        sendUsage(sender, "/antil10 scan", "Scan plugin jars for known L10 markers.");
        sendUsage(sender, "/antil10 quarantine", "Move infected jars into the quarantine folder.");
        sender.sendMessage(ChatColor.GRAY.toString());
    }

    private void sendUsage(CommandSender sender, String command, String usage) {
        sender.sendMessage(ChatColor.YELLOW + command + ChatColor.GRAY + " - " + ChatColor.WHITE + usage);
    }
}