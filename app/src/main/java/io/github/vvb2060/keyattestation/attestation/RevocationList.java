package io.github.vvb2060.keyattestation.attestation;

import android.os.Build;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import javax.net.ssl.HttpsURLConnection;

import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.R;

public class RevocationList {
    private static final String TAG = "RevocationList";
    private static final String STATUS_URL = "https://android.googleapis.com/attestation/status";
    private static final String CACHE_FILE = "revocation_status.json";
    private static final long CACHE_VALIDITY_MS = 3 * 60 * 60 * 1000L; // 3 hours
    private static final int NETWORK_TIMEOUT_MS = 8000; // 8 seconds

    private static volatile JSONObject data;
    private static volatile long lastFetchTime;
    private static volatile String source = "";
    private static volatile boolean loading;

    private final String status;
    private final String reason;

    public RevocationList(String status, String reason) {
        this.status = status;
        this.reason = reason;
    }

    public String status() {
        return status;
    }

    public String reason() {
        return reason;
    }

    @Override
    public String toString() {
        return "status is " + status + ", reason is " + reason;
    }

    /**
     * Initialize the revocation list. Called from a background thread.
     * Tries cache first, then network, then falls back to bundled data.
     */
    public static void init() {
        var context = AppApplication.app;

        // Check vendor URL
        var resName = "android:string/vendor_required_attestation_revocation_list_url";
        var res = context.getResources();
        // noinspection DiscouragedApi
        var id = res.getIdentifier(resName, null, null);
        if (id != 0) {
            var url = res.getString(id);
            if (!STATUS_URL.equals(url) && url.toLowerCase(Locale.ROOT).startsWith("https")) {
                Log.w(TAG, "unknown vendor status url: " + url);
            }
        }

        // Try cache first
        File cacheFile = new File(context.getFilesDir(), CACHE_FILE);
        if (cacheFile.exists()) {
            long cacheTime = cacheFile.lastModified();
            long cacheAge = System.currentTimeMillis() - cacheTime;
            if (cacheAge < CACHE_VALIDITY_MS) {
                try (var input = new FileInputStream(cacheFile)) {
                    data = parseStatus(readStream(input));
                    lastFetchTime = cacheTime;
                    source = "cache";
                    Log.i(TAG, "Loaded from cache, age: " + (cacheAge / 1000) + "s");
                    return;
                } catch (IOException e) {
                    Log.w(TAG, "Failed to read cache", e);
                }
            }
        }

        // Load bundled as initial data
        loadBundled();

        // Try to fetch from network
        fetchFromNetwork();
    }

    /**
     * Refresh the revocation list from network. Called from a background thread.
     *
     * @return true if fetch succeeded
     */
    public static boolean refresh() {
        return fetchFromNetwork();
    }

    private static boolean fetchFromNetwork() {
        loading = true;
        try {
            var context = AppApplication.app;
            URL url = new URL(STATUS_URL);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setConnectTimeout(NETWORK_TIMEOUT_MS);
            conn.setReadTimeout(NETWORK_TIMEOUT_MS);
            conn.setRequestMethod("GET");

            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                Log.w(TAG, "HTTP " + responseCode);
                return false;
            }

            String responseBody;
            try (var input = conn.getInputStream()) {
                responseBody = readStream(input);
            }

            JSONObject entries = parseStatus(responseBody);

            // Save to cache file
            File cacheFile = new File(context.getFilesDir(), CACHE_FILE);
            try (var output = new FileOutputStream(cacheFile)) {
                output.write(responseBody.getBytes(StandardCharsets.UTF_8));
            }

            data = entries;
            lastFetchTime = System.currentTimeMillis();
            source = "network";
            Log.i(TAG, "Fetched from network successfully");
            return true;
        } catch (Exception e) {
            Log.w(TAG, "Failed to fetch revocation list", e);
            return false;
        } finally {
            loading = false;
        }
    }

    private static void loadBundled() {
        try (var input = AppApplication.app.getResources().openRawResource(R.raw.status)) {
            data = parseStatus(readStream(input));
            source = "bundled";
            lastFetchTime = 0;
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse bundled revocation status", e);
        }
    }

    private static String readStream(InputStream input) throws IOException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } else {
            var output = new ByteArrayOutputStream(8192);
            var buffer = new byte[8192];
            for (int length; (length = input.read(buffer)) != -1; ) {
                output.write(buffer, 0, length);
            }
            return output.toString();
        }
    }

    private static JSONObject parseStatus(String json) throws IOException {
        try {
            return new JSONObject(json).getJSONObject("entries");
        } catch (JSONException e) {
            throw new IOException(e);
        }
    }

    public static RevocationList get(BigInteger serialNumber) {
        JSONObject currentData = data;
        if (currentData == null) return null;

        String serialNumberString = serialNumber.toString(16).toLowerCase();
        JSONObject revocationStatus;
        try {
            revocationStatus = currentData.getJSONObject(serialNumberString);
        } catch (JSONException e) {
            return null;
        }
        try {
            var status = revocationStatus.getString("status");
            var reason = revocationStatus.optString("reason", "");
            return new RevocationList(status, reason);
        } catch (JSONException e) {
            return new RevocationList("", "");
        }
    }

    public static int getEntryCount() {
        JSONObject currentData = data;
        return currentData != null ? currentData.length() : 0;
    }

    public static long getLastFetchTime() {
        return lastFetchTime;
    }

    public static String getSource() {
        return source;
    }

    public static boolean isLoading() {
        return loading;
    }

    public static long getCacheExpiryTime() {
        if (lastFetchTime == 0) return 0;
        return lastFetchTime + CACHE_VALIDITY_MS;
    }
}
