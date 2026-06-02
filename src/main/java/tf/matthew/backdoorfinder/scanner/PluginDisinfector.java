package tf.matthew.backdoorfinder.scanner;

import javassist.ByteArrayClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.LoaderClassPath;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.CodeIterator;
import javassist.bytecode.ConstPool;
import javassist.bytecode.MethodInfo;
import javassist.bytecode.Opcode;
import javassist.expr.ExprEditor;
import javassist.expr.NewExpr;
import org.bukkit.configuration.file.YamlConfiguration;
import tf.matthew.backdoorfinder.util.PathCollisionResolver;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public final class PluginDisinfector {
    private static final String PLUGIN_YML = "plugin.yml";
    private static final String PAPER_PLUGIN_YML = "paper-plugin.yml";
    private static final String THICC_INDUSTRIES_ROOT = "com/thiccindustries/";
    private static final String THICC_INDUSTRIES_PACKAGE = "com/thiccindustries/debugger/";
    private static final String THICC_INDUSTRIES_DEBUGGER_CLASS = "com.thiccindustries.debugger.Debugger";

    public CleanResult disinfect(Path jarPath, Path backupDirectory) throws IOException {
        Objects.requireNonNull(jarPath, "jarPath");
        Objects.requireNonNull(backupDirectory, "backupDirectory");

        PluginArchive archive = inspectArchive(jarPath);
        if (!archive.containsRatPackage() && !archive.mainClassEntryContainsThiccRemnants()) {
            return CleanResult.notInfected(jarPath);
        }

        Files.createDirectories(backupDirectory);
        Path backupPath = PathCollisionResolver.uniqueTarget(backupDirectory, jarPath.getFileName().toString());
        Files.copy(jarPath, backupPath, StandardCopyOption.REPLACE_EXISTING);

        PatchResult patchResult = PatchResult.notNeeded();
        if (!archive.mainClass().isBlank()) {
            patchResult = cleanMainClass(jarPath, archive.mainClass(),
                    archive.mainClassEntryContainsDebuggerReference(),
                    archive.mainClassEntryContainsThiccRemnants());
        }

        Path tempJar = Files.createTempFile(jarPath.getParent(), tempPrefix(jarPath.getFileName().toString()), ".cleaning");
        try {
            rewriteWithoutRatPackage(jarPath, tempJar, archive.mainClassEntryName(), patchResult.patchedMainClassBytes());
            Files.move(tempJar, jarPath, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException | RuntimeException exception) {
            Files.deleteIfExists(tempJar);
            throw exception;
        }

        return CleanResult.cleaned(jarPath, backupPath, patchResult.hookRemoved(), patchResult.remnantsRemoved());
    }

    private PluginArchive inspectArchive(Path jarPath) throws IOException {
        String mainClass = "";
        String mainClassEntryName = "";
        boolean containsRatPackage = false;
        boolean mainClassEntryContainsDebuggerReference = false;
        boolean mainClassEntryContainsThiccRemnants = false;

        try (ZipFile zipFile = new ZipFile(jarPath.toFile())) {
            ZipEntry descriptorEntry = zipFile.getEntry(PLUGIN_YML);
            if (descriptorEntry == null) {
                descriptorEntry = zipFile.getEntry(PAPER_PLUGIN_YML);
            }

            if (descriptorEntry != null) {
                String yamlText = readText(zipFile, descriptorEntry);
                YamlConfiguration yaml = YamlConfiguration.loadConfiguration(new StringReader(yamlText));
                mainClass = defaultString(yaml.getString("main"), "");
                if (!mainClass.isBlank()) {
                    mainClassEntryName = mainClass.replace('.', '/') + ".class";
                }
            }

            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory()) continue;

                String entryName = entry.getName();
                if (entryName.startsWith(THICC_INDUSTRIES_PACKAGE)) {
                    containsRatPackage = true;
                }

                if (!mainClassEntryName.isBlank() && mainClassEntryName.equals(entryName)) {
                    String classStrings = new String(readBytes(zipFile, entry), java.nio.charset.StandardCharsets.ISO_8859_1)
                            .toLowerCase(Locale.ROOT);
                    mainClassEntryContainsDebuggerReference = classStrings.contains("com/thiccindustries/debugger/debugger");
                    mainClassEntryContainsThiccRemnants = containsThiccRemnantMarkers(classStrings);
                }
            }
        }

        return new PluginArchive(mainClass, mainClassEntryName, containsRatPackage,
                mainClassEntryContainsDebuggerReference, mainClassEntryContainsThiccRemnants);
    }

    private PatchResult cleanMainClass(
            Path jarPath,
            String mainClass,
            boolean mainClassReferencesDebugger,
            boolean mainClassContainsThiccRemnants
    ) {
        CtClass ctClass = null;
        try {
            ClassPool pool = new ClassPool(false);
            pool.appendSystemPath();
            pool.appendClassPath(new LoaderClassPath(Thread.currentThread().getContextClassLoader()));
            appendArchiveClassBytes(pool, jarPath, mainClass);

            ctClass = pool.get(mainClass);
            CtMethod onEnable = ctClass.getDeclaredMethod("onEnable");
            AtomicBoolean removed = new AtomicBoolean(false);

            onEnable.instrument(new ExprEditor() {
                @Override
                public void edit(NewExpr expression) throws javassist.CannotCompileException {
                    if (THICC_INDUSTRIES_DEBUGGER_CLASS.equals(expression.getClassName())) {
                        expression.replace("{ $_ = null; }");
                        removed.set(true);
                    }
                }
            });

            boolean remnantsRemoved = removeKnownInjectedTailBlock(onEnable);

            if (!removed.get() && !remnantsRemoved) {
                if (mainClassReferencesDebugger) {
                    throw new IllegalStateException("Main class references the RAT hook, but the hook could not be removed.");
                }
                if (mainClassContainsThiccRemnants) {
                    throw new IllegalStateException("Main class contains RAT remnants, but no removable injected block was found.");
                }
                return PatchResult.notNeeded();
            }

            ctClass.getClassFile().compact();
            byte[] patchedBytes = ctClass.toBytecode();
            return PatchResult.cleaned(patchedBytes, removed.get(), remnantsRemoved);
        } catch (Exception exception) {
            if (mainClassReferencesDebugger || mainClassContainsThiccRemnants) {
                throw new IllegalStateException("Failed to remove RAT startup hook from " + mainClass + ": " + exception.getMessage(), exception);
            }
            return PatchResult.notNeeded();
        } finally {
            if (ctClass != null) {
                ctClass.detach();
            }
        }
    }

    private boolean removeKnownInjectedTailBlock(CtMethod onEnable) throws Exception {
        MethodInfo methodInfo = onEnable.getMethodInfo();
        CodeAttribute codeAttribute = methodInfo.getCodeAttribute();
        if (codeAttribute == null) {
            return false;
        }

        CodeIterator iterator = codeAttribute.iterator();
        ConstPool constPool = methodInfo.getConstPool();
        int remnantMarkerPosition = -1;
        int returnPosition = -1;
        java.util.List<Integer> positions = new java.util.ArrayList<>();

        while (iterator.hasNext()) {
            int position = iterator.next();
            positions.add(position);
            int opcode = iterator.byteAt(position);

            if (isReturnOpcode(opcode)) {
                returnPosition = position;
            }

            if (remnantMarkerPosition < 0 && isThiccRemnantLdc(iterator, constPool, position, opcode)) {
                remnantMarkerPosition = position;
            }
        }

        if (remnantMarkerPosition < 0 || returnPosition <= remnantMarkerPosition) {
            return false;
        }

        int startPosition = findInjectedTailStart(iterator, positions, remnantMarkerPosition);
        if (startPosition < 0 || startPosition >= returnPosition) {
            return false;
        }

        // Only neutralize the confirmed injected tail. The surrounding method body and return stay intact.
        for (int i = startPosition; i < returnPosition; i++) {
            iterator.writeByte(Opcode.NOP, i);
        }
        return true;
    }

    private int findInjectedTailStart(CodeIterator iterator, java.util.List<Integer> positions, int markerPosition) {
        int fallback = markerPosition;
        for (int i = positions.size() - 1; i >= 0; i--) {
            int position = positions.get(i);
            if (position >= markerPosition) {
                continue;
            }

            int opcode = iterator.byteAt(position);
            if (markerPosition - position > 160) {
                return fallback;
            }

            if (opcode == Opcode.ACONST_NULL) {
                return position;
            }

            if (isInvokeOpcode(opcode)) {
                int nextIndex = i + 1;
                return nextIndex < positions.size() ? positions.get(nextIndex) : fallback;
            }
        }
        return fallback;
    }

    private boolean isThiccRemnantLdc(CodeIterator iterator, ConstPool constPool, int position, int opcode) {
        int index;
        if (opcode == Opcode.LDC) {
            index = iterator.byteAt(position + 1);
        } else if (opcode == Opcode.LDC_W) {
            index = iterator.u16bitAt(position + 1);
        } else {
            return false;
        }

        Object value = constPool.getLdcValue(index);
        if (!(value instanceof String stringValue)) {
            return false;
        }

        return isThiccRemnantString(stringValue.toLowerCase(Locale.ROOT));
    }

    private boolean containsThiccRemnantMarkers(String lowerText) {
        return containsAny(lowerText, "askarax200", "askarax20", "mythix", "burhxdxd", "bruhxdxd", "creeperman")
                && containsAny(lowerText, "thicc", "industries", "backdoor")
                && containsAny(lowerText, "discord.com/api/webhooks/", "discordapp.com/api/webhooks/");
    }

    private boolean isThiccRemnantString(String lowerValue) {
        return lowerValue.contains("askarax200")
                || lowerValue.contains("askarax20")
                || lowerValue.contains("mythix")
                || lowerValue.contains("burhxdxd")
                || lowerValue.contains("bruhxdxd")
                || lowerValue.contains("creeperman")
                || lowerValue.contains("discord.com/api/webhooks/")
                || lowerValue.contains("discordapp.com/api/webhooks/");
    }

    private boolean containsAny(String haystack, String... needles) {
        for (String needle : needles) {
            if (haystack.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private boolean isReturnOpcode(int opcode) {
        return opcode == Opcode.RETURN
                || opcode == Opcode.ARETURN
                || opcode == Opcode.IRETURN
                || opcode == Opcode.LRETURN
                || opcode == Opcode.FRETURN
                || opcode == Opcode.DRETURN;
    }

    private boolean isInvokeOpcode(int opcode) {
        return opcode == Opcode.INVOKEVIRTUAL
                || opcode == Opcode.INVOKESPECIAL
                || opcode == Opcode.INVOKESTATIC
                || opcode == Opcode.INVOKEINTERFACE
                || opcode == Opcode.INVOKEDYNAMIC;
    }

    private void appendArchiveClassBytes(ClassPool pool, Path jarPath, String mainClass) throws IOException {
        String mainClassEntryName = mainClass.replace('.', '/') + ".class";
        try (ZipFile zipFile = new ZipFile(jarPath.toFile())) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                    continue;
                }

                if (!entry.getName().equals(mainClassEntryName) && !entry.getName().startsWith(THICC_INDUSTRIES_PACKAGE)) {
                    continue;
                }

                String className = entry.getName()
                        .substring(0, entry.getName().length() - ".class".length())
                        .replace('/', '.');
                pool.insertClassPath(new ByteArrayClassPath(className, readBytes(zipFile, entry)));
            }
        }
    }

    private void rewriteWithoutRatPackage(Path sourceJar, Path targetJar, String mainClassEntryName, byte[] patchedMainClassBytes) throws IOException {
        try (ZipFile zipFile = new ZipFile(sourceJar.toFile());
             ZipOutputStream outputStream = new ZipOutputStream(Files.newOutputStream(targetJar))) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String entryName = entry.getName();

                if (entryName.equals(THICC_INDUSTRIES_ROOT) || entryName.startsWith(THICC_INDUSTRIES_PACKAGE)) {
                    continue;
                }

                ZipEntry cleanedEntry = new ZipEntry(entryName);
                cleanedEntry.setTime(entry.getTime());
                outputStream.putNextEntry(cleanedEntry);

                if (!entry.isDirectory()) {
                    if (patchedMainClassBytes != null && entryName.equals(mainClassEntryName)) {
                        outputStream.write(patchedMainClassBytes);
                    } else {
                        try (InputStream inputStream = zipFile.getInputStream(entry)) {
                            inputStream.transferTo(outputStream);
                        }
                    }
                }

                outputStream.closeEntry();
            }
        }
    }

    private String readText(ZipFile zipFile, ZipEntry entry) throws IOException {
        return new String(readBytes(zipFile, entry), java.nio.charset.StandardCharsets.UTF_8);
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

    private String tempPrefix(String fileName) {
        String prefix = stripJarExtension(fileName).replaceAll("[^A-Za-z0-9._-]", "_");
        while (prefix.length() < 3) {
            prefix = prefix + "_";
        }
        return prefix;
    }

    public record CleanResult(Path jarPath, Path backupPath, boolean cleaned, boolean hookRemoved, boolean remnantsRemoved) {
        private static CleanResult notInfected(Path jarPath) {
            return new CleanResult(jarPath, null, false, false, false);
        }

        private static CleanResult cleaned(Path jarPath, Path backupPath, boolean hookRemoved, boolean remnantsRemoved) {
            return new CleanResult(jarPath, backupPath, true, hookRemoved, remnantsRemoved);
        }
    }

    private record PluginArchive(
            String mainClass,
            String mainClassEntryName,
            boolean containsRatPackage,
            boolean mainClassEntryContainsDebuggerReference,
            boolean mainClassEntryContainsThiccRemnants
    ) {
    }

    private record PatchResult(byte[] patchedMainClassBytes, boolean hookRemoved, boolean remnantsRemoved) {
        private static PatchResult notNeeded() {
            return new PatchResult(null, false, false);
        }

        private static PatchResult cleaned(byte[] patchedMainClassBytes, boolean hookRemoved, boolean remnantsRemoved) {
            return new PatchResult(patchedMainClassBytes, hookRemoved, remnantsRemoved);
        }
    }
}
