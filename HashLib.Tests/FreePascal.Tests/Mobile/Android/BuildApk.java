import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Packages an FPC test library and the Java host into a signed arm64-v8a APK (JDK 11+): java BuildApk.java --library NAME --app-id ID [options]. */
public final class BuildApk {
    private static final String DebugPassword = "android";
    private static final List<String> Known = List.of("library", "app-id", "title", "jdk", "build-tools",
        "android-jar", "strip", "keystore", "version-code", "install", "target-os", "project-dir");

    private final boolean windows = System.getProperty("os.name").toLowerCase().contains("win");
    private final boolean mac = System.getProperty("os.name").toLowerCase().contains("mac");
    private final Map<String, String> env = System.getenv();
    private final Map<String, String> options = new HashMap<>();

    public static void main(String[] args) {
        try {
            new BuildApk().run(args);
        } catch (Exception e) {
            System.err.println("build-apk: " + (e.getMessage() == null ? e.toString() : e.getMessage()));
            System.exit(1);
        }
    }

    private void run(String[] args) throws Exception {
        for (int i = 0; i < args.length; i++) {
            if (!args[i].startsWith("--")) {
                throw new IllegalArgumentException("unexpected argument " + args[i]);
            }
            String name = args[i].substring(2);
            if (!Known.contains(name)) {
                throw new IllegalArgumentException("unknown option " + args[i] + " (options: --"
                    + String.join(", --", Known) + ")");
            }
            options.put(name, name.equals("install") ? "true" : value(args, ++i));
        }
        if (!options.getOrDefault("target-os", "android").equals("android")) {
            return;
        }

        String libraryName = required("library");
        String appId = required("app-id");
        if (!appId.matches("[a-z][a-z0-9_]*")) {
            throw new IllegalArgumentException("--app-id must be lower case letters, digits and underscores: " + appId);
        }
        String title = options.getOrDefault("title", libraryName);
        String libraryFile = "lib" + libraryName + ".so";

        Path projectDir = Paths.get(options.getOrDefault("project-dir", ".")).toAbsolutePath().normalize();
        Path hostDir = projectDir.resolve("Mobile").resolve("Android");
        if (!Files.exists(hostDir.resolve("AndroidManifest.xml"))) {
            throw new IllegalStateException("run from the FreePascal.Tests folder or pass --project-dir; no "
                + hostDir.resolve("AndroidManifest.xml"));
        }
        Path build = hostDir.resolve("build");

        Path jdk = jdk();
        Path java = require(tool(jdk.resolve("bin"), "java"), "java was not found in the JDK; pass --jdk or set JAVA_HOME");
        Path sdk = fromEnv("ANDROID_HOME", "ANDROID_SDK_ROOT");
        Path buildTools = buildTools(sdk);
        Path aapt2 = require(tool(buildTools, "aapt2"), "aapt2 was not found in build-tools");
        Path zipalign = require(tool(buildTools, "zipalign"), "zipalign was not found in build-tools");
        Path d8Jar = require(buildTools.resolve("lib").resolve("d8.jar"), "lib/d8.jar was not found in build-tools");
        Path apksignerJar = require(buildTools.resolve("lib").resolve("apksigner.jar"),
            "lib/apksigner.jar was not found in build-tools");
        Path androidJar = androidJar(sdk);
        Path strip = strip(sdk);
        Path keystore = keystore();
        Path library = projectDir.resolve("bin").resolve(libraryFile);
        Path testsRoot = projectDir.getParent();
        Path dataRoot = testsRoot.resolve("Data");
        require(library, "the library was not found; build it first");

        deleteTree(build);
        Path classes = Files.createDirectories(build.resolve("classes"));
        Path dex = Files.createDirectories(build.resolve("dex"));
        Path assets = Files.createDirectories(build.resolve("assets"));
        Path libFolder = Files.createDirectories(build.resolve("lib").resolve("arm64-v8a"));

        // the test data goes in as one archive; the app unpacks it beside the tests' own folder name
        zipTestData(dataRoot, assets.resolve("testdata.zip"));
        Properties host = new Properties();
        host.setProperty("library", libraryName);
        host.setProperty("title", title);
        try (OutputStream out = Files.newOutputStream(assets.resolve("host.properties"))) {
            host.store(out, null);
        }
        Path stripped = libFolder.resolve(libraryFile);
        exec(List.of(strip.toString(), "--strip-unneeded", "-o", stripped.toString(), library.toString()));

        List<String> javac = new ArrayList<>(List.of(tool(jdk.resolve("bin"), "javac").toString(),
            "--release", "8", "-Xlint:-options", "-cp", androidJar.toString(), "-d", classes.toString()));
        try (Stream<Path> sources = Files.walk(hostDir.resolve("src"))) {
            sources.filter(p -> p.toString().endsWith(".java")).forEach(p -> javac.add(p.toString()));
        }
        exec(javac);

        List<String> d8 = new ArrayList<>(List.of(java.toString(), "-cp", d8Jar.toString(),
            "com.android.tools.r8.D8", "--lib", androidJar.toString(), "--min-api", "24", "--output", dex.toString()));
        try (Stream<Path> files = Files.walk(classes)) {
            files.filter(p -> p.toString().endsWith(".class")).forEach(p -> d8.add(p.toString()));
        }
        exec(d8);

        Path manifest = build.resolve("AndroidManifest.xml");
        String template = new String(Files.readAllBytes(hostDir.resolve("AndroidManifest.xml")), StandardCharsets.UTF_8);
        Files.write(manifest, template.replace("@PACKAGE@", "org.fpctests." + appId)
            .replace("@LABEL@", escapeXml(title)).getBytes(StandardCharsets.UTF_8));

        int versionCode = (int) Duration.between(Instant.parse("2026-01-01T00:00:00Z"), Instant.now()).toMinutes();
        if (options.containsKey("version-code")) {
            try {
                versionCode = Integer.parseInt(options.get("version-code"));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("--version-code must be an integer");
            }
        }
        Path unsigned = build.resolve("unsigned.apk");
        exec(List.of(aapt2.toString(), "link", "-o", unsigned.toString(),
            "--manifest", manifest.toString(), "-I", androidJar.toString(),
            "-A", assets.toString(), "--min-sdk-version", "24", "--target-sdk-version", "35",
            "--version-code", String.valueOf(versionCode), "--version-name", "1." + versionCode));

        addToZip(unsigned, "classes.dex", dex.resolve("classes.dex"));
        addToZip(unsigned, "lib/arm64-v8a/" + libraryFile, stripped);

        Path aligned = build.resolve("aligned.apk");
        exec(List.of(zipalign.toString(), "-f", "-p", "4", unsigned.toString(), aligned.toString()));

        if (!Files.exists(keystore)) {
            Path keytool = require(tool(jdk.resolve("bin"), "keytool"), "keytool was not found in the JDK");
            Files.createDirectories(keystore.getParent());
            exec(List.of(keytool.toString(), "-genkeypair", "-keystore", keystore.toString(),
                "-alias", "fpctestsdebug", "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
                "-storepass", DebugPassword, "-keypass", DebugPassword, "-dname", "CN=FPC Tests Debug"));
        }
        Path apk = build.resolve(appId + ".apk");
        exec(List.of(java.toString(), "-jar", apksignerJar.toString(), "sign", "--ks", keystore.toString(),
            "--ks-pass", "pass:" + DebugPassword, "--key-pass", "pass:" + DebugPassword,
            "--out", apk.toString(), aligned.toString()));
        exec(List.of(java.toString(), "-jar", apksignerJar.toString(), "verify", "--verbose", apk.toString()));

        System.out.println(apk + " " + Files.size(apk) + " bytes");

        if (options.containsKey("install")) {
            Path adb = sdk == null ? null : sdk.resolve("platform-tools").resolve(windows ? "adb.exe" : "adb");
            exec(List.of(adb != null && Files.exists(adb) ? adb.toString() : "adb", "install", "-r", apk.toString()));
        }
    }

    private static String value(String[] args, int index) {
        if (index >= args.length) {
            throw new IllegalArgumentException("missing value for " + args[index - 1]);
        }
        return args[index];
    }

    private String required(String option) {
        String given = options.get(option);
        if (given == null || given.isEmpty()) {
            throw new IllegalArgumentException("--" + option + " is required");
        }
        return given;
    }

    private String setting(String option, String environment) {
        String fromOption = options.get(option);
        if (fromOption != null && !fromOption.isEmpty()) {
            return fromOption;
        }
        String fromEnv = environment == null ? null : env.get(environment);
        return fromEnv == null || fromEnv.isEmpty() ? null : fromEnv;
    }

    private Path jdk() {
        String given = setting("jdk", "JAVA_HOME");
        Path jdk = Paths.get(given != null ? given : System.getProperty("java.home"));
        require(tool(jdk.resolve("bin"), "javac"), "javac was not found in the JDK; pass --jdk or set JAVA_HOME");
        return jdk;
    }

    // the folder named by the first of these variables that is set
    private Path fromEnv(String... names) {
        for (String name : names) {
            String given = env.get(name);
            if (given != null && !given.isEmpty()) {
                return Paths.get(given);
            }
        }
        return null;
    }

    private Path buildTools(Path sdk) {
        String given = setting("build-tools", "ANDROID_BUILD_TOOLS");
        Path folder = given != null ? Paths.get(given) : newest(sdk == null ? null : sdk.resolve("build-tools"), null);
        return require(folder, "no build-tools folder; pass --build-tools, or set ANDROID_BUILD_TOOLS or ANDROID_HOME");
    }

    private Path androidJar(Path sdk) {
        String given = setting("android-jar", null);
        Path jar = given != null ? Paths.get(given) : null;
        if (jar == null && sdk != null) {
            Path platform = newest(sdk.resolve("platforms"), "android.jar");
            jar = platform == null ? null : platform.resolve("android.jar");
        }
        return require(jar, "no android.jar; pass --android-jar, or set ANDROID_HOME to an SDK with a platform installed");
    }

    private Path strip(Path sdk) {
        String given = setting("strip", null);
        if (given != null) {
            return require(Paths.get(given), "llvm-strip was not found");
        }
        Path ndk = fromEnv("ANDROID_NDK_ROOT", "ANDROID_NDK_HOME");
        if (ndk == null) {
            ndk = newest(sdk == null ? null : sdk.resolve("ndk"), null);
        }
        Path strip = ndk == null ? null : tool(ndk.resolve("toolchains").resolve("llvm").resolve("prebuilt")
            .resolve(hostTag()).resolve("bin"), "llvm-strip");
        return require(strip,
            "no llvm-strip; pass --strip, or set ANDROID_NDK_ROOT or ANDROID_NDK_HOME (or ANDROID_HOME with an ndk folder)");
    }

    private Path keystore() {
        String given = setting("keystore", "FPCTESTS_ANDROID_KEYSTORE");
        Path keystore = given != null ? Paths.get(given)
            : Paths.get(System.getProperty("user.home"), ".android", "fpctests-debug.keystore");
        return keystore.toAbsolutePath();
    }

    // the NDK ships one prebuilt folder per host; macOS has a single one for both CPUs
    private String hostTag() {
        if (windows) {
            return "windows-x86_64";
        }
        return mac ? "darwin-x86_64" : "linux-x86_64";
    }

    private Path tool(Path folder, String name) {
        return folder.resolve(windows ? name + ".exe" : name);
    }

    /** The folder under parent with the highest version in its name; one holding the given file if named. */
    private static Path newest(Path parent, String mustContain) {
        if (parent == null || !Files.isDirectory(parent)) {
            return null;
        }
        try (Stream<Path> folders = Files.list(parent)) {
            return folders.filter(Files::isDirectory)
                .filter(p -> mustContain == null || Files.exists(p.resolve(mustContain)))
                .max(Comparator.comparing(p -> numbers(p.getFileName().toString()), BuildApk::compareNumbers))
                .orElse(null);
        } catch (IOException e) {
            return null;
        }
    }

    private static List<Integer> numbers(String text) {
        List<Integer> result = new ArrayList<>();
        Matcher matcher = Pattern.compile("\\d+").matcher(text);
        while (matcher.find()) {
            result.add(Integer.parseInt(matcher.group()));
        }
        return result;
    }

    private static int compareNumbers(List<Integer> left, List<Integer> right) {
        for (int i = 0; i < Math.min(left.size(), right.size()); i++) {
            int order = Integer.compare(left.get(i), right.get(i));
            if (order != 0) {
                return order;
            }
        }
        return Integer.compare(left.size(), right.size());
    }

    private static Path require(Path path, String what) {
        if (path == null || !Files.exists(path)) {
            throw new IllegalStateException(what + (path == null ? "" : " (looked at " + path + ")"));
        }
        return path;
    }

    // aapt2 reads a leading @ or ? in an attribute value as a resource reference
    private static String escapeXml(String text) {
        String escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
        return escaped.startsWith("@") || escaped.startsWith("?") ? "\\" + escaped : escaped;
    }

    private static void zipTestData(Path dataRoot, Path target) throws IOException {
        Path testsRoot = dataRoot.getParent();
        String prefix = testsRoot.getFileName() + "/";
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(target))) {
            // a library whose tests carry no data folder gets an empty archive
            if (!Files.isDirectory(dataRoot)) {
                return;
            }
            try (Stream<Path> files = Files.walk(dataRoot)) {
                for (Path file : files.filter(Files::isRegularFile).collect(Collectors.toList())) {
                    String name = prefix + testsRoot.relativize(file).toString().replace('\\', '/');
                    zip.putNextEntry(new ZipEntry(name));
                    Files.copy(file, zip);
                    zip.closeEntry();
                }
            }
        }
    }

    private static void addToZip(Path zip, String entry, Path file) throws IOException {
        try (FileSystem fs = FileSystems.newFileSystem(zip, (ClassLoader) null)) {
            Path inside = fs.getPath(entry);
            if (inside.getParent() != null) {
                Files.createDirectories(inside.getParent());
            }
            Files.copy(file, inside, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void deleteTree(Path folder) throws IOException {
        if (!Files.exists(folder)) {
            return;
        }
        try (Stream<Path> files = Files.walk(folder)) {
            for (Path file : files.sorted(Comparator.reverseOrder()).collect(Collectors.toList())) {
                Files.delete(file);
            }
        }
    }

    // a tool's stderr is not an error in itself; the exit code decides
    private static void exec(List<String> command) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(command).inheritIO().start();
        int code = process.waitFor();
        if (code != 0) {
            throw new IllegalStateException("failed (" + code + "): " + command.stream()
                .map(argument -> argument.contains(" ") ? "\"" + argument + "\"" : argument)
                .collect(Collectors.joining(" ")));
        }
    }
}
