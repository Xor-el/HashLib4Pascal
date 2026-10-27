package org.fpctests.host;

import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.system.Os;
import android.text.InputType;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Runs an FPC test library and reports it to a TestInsight server; host.properties names the library. */
public class MainActivity extends Activity {
    private static final String LogTag = "FpcTests";
    private static final String UrlKey = "baseUrl";
    private static final String DataArchive = "testdata.zip";
    private static final String DataStamp = ".data-stamp";
    private static final String WorkDirVariable = "FPCTESTS_WORKDIR";
    private static final String SettingsFile = "TestInsightSettings.ini";
    private static final long StackBytes = 64L << 20;

    // one worker with a big stack for loading the library and for every run
    private final ExecutorService worker = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(null, task, "fpc-tests", StackBytes);
        thread.setDaemon(true);
        return thread;
    });
    private EditText urlField;
    private TextView status;
    private Button runButton;
    private String suite = "";
    private volatile boolean libraryLoaded;
    // static: a recreated activity (rotation) must not start a second run in the same process
    private static final AtomicBoolean running = new AtomicBoolean();

    public native int nativeRun(String baseUrl);

    @Override
    @SuppressWarnings("deprecation")
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        // adb shell am start ... --ez autorun true --es url http://host:6789/tests --es suite TestName
        final boolean autorun = state == null && getIntent().getBooleanExtra("autorun", false);
        final String autorunUrl = getIntent().getStringExtra("url");
        String suiteExtra = getIntent().getStringExtra("suite");
        // only suite and test names may reach the ini file, so no extra keys can be injected
        suite = state != null || suiteExtra == null ? "" : suiteExtra.replaceAll("[^A-Za-z0-9_.,]", "");
        Properties host = new Properties();
        try (InputStream in = getAssets().open("host.properties")) {
            host.load(in);
        } catch (IOException e) {
            throw new IllegalStateException("host.properties is missing from the APK", e);
        }
        final String library = host.getProperty("library");

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);
        // the window is drawn edge to edge on recent Android, so keep clear of the system bars
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            v.setPadding(pad + insets.getSystemWindowInsetLeft(), pad + insets.getSystemWindowInsetTop(),
                    pad + insets.getSystemWindowInsetRight(), pad + insets.getSystemWindowInsetBottom());
            return insets;
        });

        TextView title = new TextView(this);
        title.setText(host.getProperty("title", library));
        title.setTextSize(22);
        title.setPadding(0, 0, 0, pad);
        root.addView(title);

        urlField = new EditText(this);
        urlField.setHint("http://192.168.0.10:6789/tests");
        urlField.setSingleLine(true);
        urlField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        urlField.setText(getPreferences(MODE_PRIVATE).getString(UrlKey, ""));
        root.addView(urlField);

        Button saveButton = new Button(this);
        saveButton.setText("Save URL");
        saveButton.setOnClickListener(v -> {
            String url = normalise(urlField.getText().toString());
            urlField.setText(url);
            getPreferences(MODE_PRIVATE).edit().putString(UrlKey, url).apply();
            setStatus("Saved " + url);
        });
        root.addView(saveButton);

        runButton = new Button(this);
        runButton.setText("Run tests");
        runButton.setOnClickListener(v -> startRun());
        root.addView(runButton);

        status = new TextView(this);
        status.setPadding(0, pad, 0, 0);
        root.addView(status);
        setContentView(root);

        runButton.setEnabled(false);
        setStatus("Preparing the test data for " + library + "...");
        worker.execute(() -> loadLibrary(library, autorun, autorunUrl));
    }

    @Override
    protected void onDestroy() {
        worker.shutdown();
        super.onDestroy();
    }

    /** Unpacks the test data, then loads the library: its units may read that data while they load. */
    private void loadLibrary(String library, boolean autorun, String autorunUrl) {
        try {
            File work = getFilesDir();
            extractData(work);
            Os.setenv(WorkDirVariable, work.getAbsolutePath(), true);
            System.loadLibrary(library);
        } catch (Exception | UnsatisfiedLinkError e) {
            setStatus("Could not load " + library + ": " + e);
            return;
        }
        libraryLoaded = true;
        runOnUiThread(() -> runButton.setEnabled(true));
        setStatus("Ready. Enter the TestInsight URL, save it, and tap Run tests.");

        if (autorun) {
            runOnUiThread(() -> {
                if (autorunUrl != null) {
                    urlField.setText(normalise(autorunUrl));
                }
                startRun();
            });
        }
    }

    /** A bare host:port becomes http://host:port/tests, the base path of the IDE's server. */
    private static String normalise(String text) {
        String url = text.trim();
        if (url.isEmpty()) {
            return url;
        }
        if (!url.contains("://")) {
            url = "http://" + url;
        }
        int schemeEnd = url.indexOf("://") + 3;
        if (url.indexOf('/', schemeEnd) < 0) {
            url = url + "/tests";
        }
        return url;
    }

    private void setStatus(String message) {
        android.util.Log.i(LogTag, message);
        runOnUiThread(() -> status.setText(message));
    }

    private void startRun() {
        if (!libraryLoaded) {
            return;
        }
        final String url = normalise(urlField.getText().toString());
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            setStatus("Enter an http:// or https:// TestInsight URL first.");
            return;
        }
        if (!running.compareAndSet(false, true)) {
            setStatus("A run is already in progress.");
            return;
        }
        getPreferences(MODE_PRIVATE).edit().putString(UrlKey, url).apply();
        runButton.setEnabled(false);
        setStatus("Running against " + url);
        // the suite filter applies to the first run only
        final String runSuite = suite;
        suite = "";
        worker.execute(() -> {
            String result;
            try {
                File settings = new File(getFilesDir(), SettingsFile);
                if (runSuite.isEmpty()) {
                    settings.delete();
                } else {
                    try (OutputStream out = new FileOutputStream(settings)) {
                        out.write(("[Config]\nSuite=" + runSuite + "\n").getBytes(StandardCharsets.UTF_8));
                    }
                }
                int code = nativeRun(url);
                result = code == 0 ? "Finished. Results are in TestInsight." : "Run failed (code " + code + ").";
            } catch (Throwable e) {
                result = "Run failed: " + e;
            } finally {
                running.set(false);
            }
            final String message = result;
            android.util.Log.i(LogTag, message);
            runOnUiThread(() -> {
                status.setText(message);
                runButton.setEnabled(true);
            });
        });
    }

    /** Unpacks the test data under the work folder once per install, where the tests look for it. */
    private void extractData(File work) throws IOException, PackageManager.NameNotFoundException {
        String stamp = String.valueOf(getPackageManager().getPackageInfo(getPackageName(), 0).lastUpdateTime);
        File stampFile = new File(work, DataStamp);
        if (stampFile.exists() && stamp.equals(readText(stampFile))) {
            return;
        }
        deleteChildren(work);
        String root = work.getCanonicalPath() + File.separator;
        try (ZipInputStream zip = new ZipInputStream(getAssets().open(DataArchive))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                File target = new File(work, entry.getName());
                if (!target.getCanonicalPath().startsWith(root)) {
                    throw new IOException("unexpected entry " + entry.getName());
                }
                if (entry.isDirectory()) {
                    target.mkdirs();
                    continue;
                }
                target.getParentFile().mkdirs();
                try (OutputStream out = new FileOutputStream(target)) {
                    byte[] buffer = new byte[65536];
                    int read;
                    while ((read = zip.read(buffer)) > 0) {
                        out.write(buffer, 0, read);
                    }
                }
            }
        }
        try (OutputStream out = new FileOutputStream(stampFile)) {
            out.write(stamp.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String readText(File file) throws IOException {
        try (InputStream in = new FileInputStream(file)) {
            byte[] bytes = new byte[(int) file.length()];
            int read = in.read(bytes);
            return new String(bytes, 0, Math.max(read, 0), StandardCharsets.UTF_8);
        }
    }

    private static void deleteChildren(File folder) {
        File[] children = folder.listFiles();
        if (children == null) {
            return;
        }
        for (File child : children) {
            if (child.isDirectory()) {
                deleteChildren(child);
            }
            child.delete();
        }
    }
}
