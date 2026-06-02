package tf.matthew.backdoorfinder.util;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

public final class PathCollisionResolver {
    private PathCollisionResolver() {
    }

    public static Path uniqueTarget(Path directory, String fileName) {
        Path target = directory.resolve(fileName);
        if (!Files.exists(target)) {
            return target;
        }

        String baseName = fileName;
        String extension = "";
        int extensionIndex = fileName.toLowerCase(Locale.ROOT).lastIndexOf(".jar");
        if (extensionIndex >= 0) {
            baseName = fileName.substring(0, extensionIndex);
            extension = fileName.substring(extensionIndex);
        }

        int counter = 1;
        while (Files.exists(target)) {
            target = directory.resolve(baseName + "-" + counter + extension);
            counter++;
        }
        return target;
    }
}
