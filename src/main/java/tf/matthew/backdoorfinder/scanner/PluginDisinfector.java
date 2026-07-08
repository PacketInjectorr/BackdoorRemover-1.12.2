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
        if (archive.mainClass() != null && !archive.mainClass().trim().isEmpty()) {
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
                if (mainClass != null && !mainClass.trim().isEmpty()) {
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

                if (mainClassEntryName != null && !mainClassEntryName.trim().isEmpty() && mainClassEntryName.equals(entryName)) {
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

    private boolean containsThiccRemnantMarkers(String classStrings) {
        return classStrings.contains("java/net/urlclassloader") && classStrings.contains("getsystemclassloader");
    }

    private PatchResult cleanMainClass(Path jarPath, String mainClass, boolean removeHook, boolean removeRemnants) {
        try {
            ClassPool pool = new ClassPool(null);
            pool.appendClassPath(new LoaderClassPath(getClass().getClassLoader()));

            byte[] originalBytes;
            try (ZipFile zipFile = new ZipFile(jarPath.toFile())) {
                ZipEntry entry = zipFile.getEntry(mainClass.replace('.', '/') + ".class");
                originalBytes = readBytes(zipFile, entry);
            }

            pool.appendClassPath(new ByteArrayClassPath(mainClass, originalBytes));
            CtClass ctClass = pool.get(mainClass);

            AtomicBoolean hookRemoved = new AtomicBoolean(false);
            AtomicBoolean remnantsRemoved = new AtomicBoolean(false);

            if (removeHook) {
                for (CtMethod method : ctClass.getDeclaredMethods()) {
                    method.instrument(new ExprEditor() {
                        @Override
                        public void edit(NewExpr e) throws javassist.CannotCompileException {
                            if (THICC_INDUSTRIES_DEBUGGER_CLASS.equals(e.getClassName())) {
                                e.replace("{$_ = null;}");
                                hookRemoved.set(true);
                            }
                        }
                    });
                }
            }

            if (removeRemnants) {
                for (CtMethod method : ctClass.getDeclaredMethods()) {
                    MethodInfo methodInfo = method.getMethodInfo();
                    CodeAttribute codeAttribute = methodInfo.getCodeAttribute();
                    if (codeAttribute == null) continue;

                    CodeIterator iterator = codeAttribute.iterator();
                    ConstPool constPool = methodInfo.getConstPool();

                    while (iterator.hasNext()) {
                        int index = iterator.next();
                        int opcode = iterator.byteAt(index);

                        if (opcode == Opcode.INVOKESTATIC) {
                            int methodRef = iterator.u16bitAt(index + 1);
                            String className = constPool.getMethodrefClassName(methodRef);
                            String methodName = constPool.getMethodrefName(methodRef);

                            if ("java.lang.ClassLoader".equals(className) && "getSystemClassLoader".equals(methodName)) {
                                iterator.writeByte(Opcode.NOP, index);
                                iterator.writeByte(Opcode.NOP, index + 1);
                                iterator.writeByte(Opcode.NOP, index + 2);
                                remnantsRemoved.set(true);
                            }
                        }
                    }
                }
            }

            if (hookRemoved.get() || remnantsRemoved.get()) {
                byte[] patched = ctClass.toBytecode();
                ctClass.detach();
                return PatchResult.cleaned(patched, hookRemoved.get(), remnantsRemoved.get());
            }

            ctClass.detach();
        } catch (Exception ignored) {}

        return PatchResult.notNeeded();
    }

    private void rewriteWithoutRatPackage(Path sourceJar, Path targetJar, String mainClassEntryName, byte[] patchedMainClassBytes) throws IOException {
        try (ZipFile zipFile = new ZipFile(sourceJar.toFile());
             ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(targetJar))) {

            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String entryName = entry.getName();

                if (entryName.startsWith(THICC_INDUSTRIES_ROOT)) {
                    continue;
                }

                ZipEntry newEntry = new ZipEntry(entryName);
                zos.putNextEntry(newEntry);

                if (patchedMainClassBytes != null && entryName.equals(mainClassEntryName)) {
                    zos.write(patchedMainClassBytes);
                } else {
                    try (InputStream is = zipFile.getInputStream(entry)) {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        while ((bytesRead = is.read(buffer)) != -1) {
                            zos.write(buffer, 0, bytesRead);
                        }
                    }
                }
                zos.closeEntry();
            }
        }
    }

    private byte[] readBytes(ZipFile zipFile, ZipEntry entry) throws IOException {
        try (InputStream is = zipFile.getInputStream(entry); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int read;
            while ((read = is.read(buf)) != -1) {
                baos.write(buf, 0, read);
            }
            return baos.toByteArray();
        }
    }

    private String readText(ZipFile zipFile, ZipEntry entry) throws IOException {
        return new String(readBytes(zipFile, entry), java.nio.charset.StandardCharsets.UTF_8);
    }

    private String defaultString(String val, String def) {
        return val == null ? def : val;
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

    public static final class CleanResult {
        private final Path jarPath;
        private final Path backupPath;
        private final boolean cleaned;
        private final boolean hookRemoved;
        private final boolean remnantsRemoved;

        public CleanResult(Path jarPath, Path backupPath, boolean cleaned, boolean hookRemoved, boolean remnantsRemoved) {
            this.jarPath = jarPath;
            this.backupPath = backupPath;
            this.cleaned = cleaned;
            this.hookRemoved = hookRemoved;
            this.remnantsRemoved = remnantsRemoved;
        }

        public Path jarPath() { return jarPath; }
        public Path backupPath() { return backupPath; }
        public boolean cleaned() { return cleaned; }
        public boolean hookRemoved() { return hookRemoved; }
        public boolean remnantsRemoved() { return remnantsRemoved; }

        public static CleanResult notInfected(Path jarPath) {
            return new CleanResult(jarPath, null, false, false, false);
        }

        public static CleanResult cleaned(Path jarPath, Path backupPath, boolean hookRemoved, boolean remnantsRemoved) {
            return new CleanResult(jarPath, backupPath, true, hookRemoved, remnantsRemoved);
        }
    }

    private static final class PluginArchive {
        private final String mainClass;
        private final String mainClassEntryName;
        private final boolean containsRatPackage;
        private final boolean mainClassEntryContainsDebuggerReference;
        private final boolean mainClassEntryContainsThiccRemnants;

        public PluginArchive(String mainClass, String mainClassEntryName, boolean containsRatPackage,
                             boolean mainClassEntryContainsDebuggerReference, boolean mainClassEntryContainsThiccRemnants) {
            this.mainClass = mainClass;
            this.mainClassEntryName = mainClassEntryName;
            this.containsRatPackage = containsRatPackage;
            this.mainClassEntryContainsDebuggerReference = mainClassEntryContainsDebuggerReference;
            this.mainClassEntryContainsThiccRemnants = mainClassEntryContainsThiccRemnants;
        }

        public String mainClass() { return mainClass; }
        public String mainClassEntryName() { return mainClassEntryName; }
        public boolean containsRatPackage() { return containsRatPackage; }
        public boolean mainClassEntryContainsDebuggerReference() { return mainClassEntryContainsDebuggerReference; }
        public boolean mainClassEntryContainsThiccRemnants() { return mainClassEntryContainsThiccRemnants; }
    }

    private static final class PatchResult {
        private final byte[] patchedMainClassBytes;
        private final boolean hookRemoved;
        private final boolean remnantsRemoved;

        public PatchResult(byte[] patchedMainClassBytes, boolean hookRemoved, boolean remnantsRemoved) {
            this.patchedMainClassBytes = patchedMainClassBytes;
            this.hookRemoved = hookRemoved;
            this.remnantsRemoved = remnantsRemoved;
        }

        public byte[] patchedMainClassBytes() { return patchedMainClassBytes; }
        public boolean hookRemoved() { return hookRemoved; }
        public boolean remnantsRemoved() { return remnantsRemoved; }

        public static PatchResult notNeeded() {
            return new PatchResult(null, false, false);
        }

        public static PatchResult cleaned(byte[] patchedMainClassBytes, boolean hookRemoved, boolean remnantsRemoved) {
            return new PatchResult(patchedMainClassBytes, hookRemoved, remnantsRemoved);
        }
    }
}