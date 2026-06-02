package tf.matthew.backdoorfinder;

import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabExecutor;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class BackdoorFinderCommand implements TabExecutor {
    private final BackdoorFinderPlugin plugin;

    public BackdoorFinderCommand(BackdoorFinderPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (args.length == 0) {
            sendHelp(sender);
            return true;
        }

        String subCommand = args[0].toLowerCase(Locale.ROOT);
        switch (subCommand) {
            case "scan" -> {
                if (!sender.hasPermission("backdoorfinder.scan")) {
                    sender.sendMessage(ChatColor.RED + "You do not have permission to scan plugins.");
                    return true;
                }

                if (args.length == 1 || "all".equalsIgnoreCase(args[1])) {
                    plugin.scheduleScanAll(sender, "manual command");
                    return true;
                }

                Path jarPath = plugin.resolvePluginJar(args[1]);
                if (jarPath == null) {
                    sender.sendMessage(ChatColor.RED + "Could not find a plugin jar matching " + args[1]);
                    return true;
                }

                plugin.scheduleScanSingle(sender, jarPath, "manual command");
                return true;
            }
            case "thicc", "thiccindustries" -> {
                if (!sender.hasPermission("backdoorfinder.scan")) {
                    sender.sendMessage(ChatColor.RED + "You do not have permission to scan plugins.");
                    return true;
                }

                if (args.length == 1 || "all".equalsIgnoreCase(args[1])) {
                    plugin.scheduleThiccScanAll(sender);
                    return true;
                }

                Path jarPath = plugin.resolvePluginJar(args[1]);
                if (jarPath == null) {
                    sender.sendMessage(ChatColor.RED + "Could not find a plugin jar matching " + args[1]);
                    return true;
                }

                plugin.scheduleThiccScanSingle(sender, jarPath);
                return true;
            }
            case "cleanup" -> {
                if (!sender.hasPermission("backdoorfinder.cleanup")) {
                    sender.sendMessage(ChatColor.RED + "You do not have permission to clean infected plugins.");
                    return true;
                }

                if (args.length == 1 || "all".equalsIgnoreCase(args[1])) {
                    plugin.scheduleCleanupAll(sender);
                    return true;
                }

                Path jarPath = plugin.resolvePluginJar(args[1]);
                if (jarPath == null) {
                    sender.sendMessage(ChatColor.RED + "Could not find a plugin jar matching " + args[1]);
                    return true;
                }

                plugin.scheduleCleanupSingle(sender, jarPath);
                return true;
            }
            case "reload" -> {
                if (!sender.hasPermission("backdoorfinder.reload")) {
                    sender.sendMessage(ChatColor.RED + "You do not have permission to reload BackdoorFinder.");
                    return true;
                }

                plugin.reloadLocalConfiguration();
                sender.sendMessage(ChatColor.GREEN + "BackdoorFinder configuration reloaded.");
                return true;
            }
            default -> {
                sender.sendMessage(ChatColor.RED + "Unknown subcommand.");
                sendHelp(sender);
                return true;
            }
        }
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (args.length == 1) {
            return filter(List.of("scan", "thicc", "cleanup", "reload"), args[0]);
        }

        if (args.length == 2 && ("scan".equalsIgnoreCase(args[0])
                || "thicc".equalsIgnoreCase(args[0])
                || "thiccindustries".equalsIgnoreCase(args[0])
                || "cleanup".equalsIgnoreCase(args[0]))) {
            List<String> completions = new ArrayList<>();
            completions.add("all");
            completions.addAll(plugin.listPluginJarNames());
            return filter(completions, args[1]);
        }

        return List.of();
    }

    private List<String> filter(List<String> values, String prefix) {
        String lowerPrefix = prefix.toLowerCase(Locale.ROOT);
        return values.stream()
                .filter(value -> value.toLowerCase(Locale.ROOT).startsWith(lowerPrefix))
                .distinct()
                .sorted()
                .toList();
    }

    private void sendHelp(CommandSender sender) {
        sender.sendMessage(ChatColor.AQUA.toString() + ChatColor.BOLD + "Backdoor Remover");
        sender.sendMessage(ChatColor.GRAY.toString() + ChatColor.ITALIC + "By maaattn");
        sender.sendMessage(ChatColor.GRAY.toString());
        sendUsage(sender, "/backdoorfinder scan [plugin.jar|all]", "Scan one plugin jar or check every jar in /plugins.");
        sendUsage(sender, "/backdoorfinder thicc [plugin.jar|all]", "Look only for known Thicc Industries RAT markers.");
        sendUsage(sender, "/backdoorfinder cleanup [plugin.jar|all]", "Repair confirmed RAT matches and back up anything changed.");
        sendUsage(sender, "/backdoorfinder reload", "Reload the config and Discord webhook settings.");
        sender.sendMessage(ChatColor.GRAY.toString());
    }

    private void sendUsage(CommandSender sender, String command, String usage) {
        sender.sendMessage(ChatColor.YELLOW + command + ChatColor.GRAY + " - " + ChatColor.WHITE + usage);
    }
}
