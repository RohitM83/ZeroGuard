
package com.zeroguard.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.provider.Settings

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

import org.json.JSONArray
import org.json.JSONObject

import java.io.IOException
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

class MainActivity : ComponentActivity() {

    companion object {
        // Use your PC's current Wi-Fi IPv4 address.
        private val BACKEND_URL = BuildConfig.ZEROGUARD_BACKEND_URL

        private const val PREFS_NAME = "zeroguard_agent_preferences"
        private const val AGENT_TOKEN_KEY = "agent_token"
        private const val DEVICE_ID_KEY = "device_id"
        private const val AGENT_ID_KEY = "agent_id"

        private const val HEARTBEAT_INTERVAL_SECONDS = 30L
        private const val TELEMETRY_INTERVAL_SECONDS = 30L
    }

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        .build()

    private var heartbeatExecutor: ScheduledExecutorService? = null
    private var telemetryExecutor: ScheduledExecutorService? = null

    private val preferences by lazy {
        getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    private val heartbeatStatus = mutableStateOf("Heartbeat: not active")
    private val telemetryStatus = mutableStateOf("Telemetry: not active")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val savedToken = preferences.getString(AGENT_TOKEN_KEY, null)
        if (!savedToken.isNullOrBlank()) {
            startHeartbeat(savedToken)
            startTelemetry(savedToken)
        }

        setContent {
            MaterialTheme {
                ZeroGuardApp()
            }
        }
    }

    override fun onDestroy() {
        stopHeartbeat()
        stopTelemetry()
        httpClient.dispatcher.cancelAll()
        httpClient.connectionPool.evictAll()
        super.onDestroy()
    }

    private fun getDeviceName(): String {
        return "${Build.MANUFACTURER} ${Build.MODEL}".trim()
    }

    private fun getAndroidVersion(): String {
        return "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"
    }

    private fun getAndroidId(): String {
        return Settings.Secure.getString(
            contentResolver,
            Settings.Secure.ANDROID_ID
        ) ?: "unknown"
    }

    // ------------------------------------------------------------
    // PAIR DEVICE
    // ------------------------------------------------------------

    private fun pairDevice(
        pairingCode: String,
        onResult: (Boolean, String) -> Unit
    ) {
        val json = JSONObject().apply {
            put("pairing_code", pairingCode.trim().uppercase())
            put("agent_name", "ZeroGuard-Android")
            put("device_name", getDeviceName())
            put("mac_address", "")
            put("device_type", "Android")
            put("ip_address", "unknown")
            put("operating_system", getAndroidVersion())
            put("device_identifier", getAndroidId())
        }

        val requestBody = json.toString().toRequestBody(
            "application/json; charset=utf-8".toMediaType()
        )

        val request = Request.Builder()
            .url("$BACKEND_URL/api/device-pairings/register")
            .post(requestBody)
            .build()

        Thread {
            try {
                httpClient.newCall(request).execute().use { response ->
                    val body = response.body?.string().orEmpty()

                    if (!response.isSuccessful) {
                        val detail = try {
                            JSONObject(body).optString(
                                "detail",
                                body.take(200)
                            )
                        } catch (_: Exception) {
                            body.take(200)
                        }

                        runOnUiThread {
                            onResult(
                                false,
                                "Pairing failed: HTTP ${response.code}\n$detail"
                            )
                        }
                        return@Thread
                    }

                    val result = try {
                        JSONObject(body)
                    } catch (_: Exception) {
                        runOnUiThread {
                            onResult(false, "Invalid pairing response from backend.")
                        }
                        return@Thread
                    }

                    val deviceId = result.optInt("device_id", -1)
                    val agentId = result.optInt("agent_id", -1)
                    val token = result.optString("agent_token", "")

                    if (token.isBlank()) {
                        runOnUiThread {
                            onResult(
                                false,
                                "The backend response did not contain an agent token.\n" +
                                        "Response: ${body.take(250)}"
                            )
                        }
                        return@Thread
                    }

                    preferences.edit()
                        .putString(AGENT_TOKEN_KEY, token)
                        .putInt(DEVICE_ID_KEY, deviceId)
                        .putInt(AGENT_ID_KEY, agentId)
                        .apply()

                    startHeartbeat(token)
                    startTelemetry(token)

                    runOnUiThread {
                        onResult(
                            true,
                            "Paired successfully!\n\n" +
                                    "Device ID: $deviceId\n" +
                                    "Agent ID: $agentId\n" +
                                    "Device: ${getDeviceName()}\n\n" +
                                    "Heartbeat and telemetry started."
                        )
                    }
                }
            } catch (error: Exception) {
                runOnUiThread {
                    onResult(
                        false,
                        "Could not pair with ZeroGuard.\n" +
                                "${error.javaClass.simpleName}: ${error.message}\n\n" +
                                "Check the Wi-Fi connection, backend URL, and server logs."
                    )
                }
            }
        }.start()
    }

    // ------------------------------------------------------------
    // HEARTBEAT
    // ------------------------------------------------------------

    private fun startHeartbeat(token: String) {
        if (token.isBlank()) return

        stopHeartbeat()
        heartbeatStatus.value = "Heartbeat: starting..."

        heartbeatExecutor = Executors.newSingleThreadScheduledExecutor()
        heartbeatExecutor?.scheduleWithFixedDelay(
            {
                sendHeartbeat(token)
            },
            0L,
            HEARTBEAT_INTERVAL_SECONDS,
            TimeUnit.SECONDS
        )
    }

    private fun stopHeartbeat() {
        heartbeatExecutor?.shutdownNow()
        heartbeatExecutor = null
    }

    private fun sendHeartbeat(token: String) {
        val request = Request.Builder()
            .url("$BACKEND_URL/api/agents/heartbeat")
            .post(
                ByteArray(0).toRequestBody(
                    "application/json; charset=utf-8".toMediaType()
                )
            )
            .header("Authorization", "Bearer $token")
            .build()

        try {
            httpClient.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    runOnUiThread {
                        heartbeatStatus.value = "Heartbeat: ONLINE"
                    }
                } else {
                    val body = response.body?.string().orEmpty()
                    val detail = try {
                        JSONObject(body).optString("detail", body.take(100))
                    } catch (_: Exception) {
                        body.take(100)
                    }

                    runOnUiThread {
                        heartbeatStatus.value =
                            "Heartbeat: HTTP ${response.code} • $detail"
                    }

                    if (response.code == 401 || response.code == 403) {
                        stopHeartbeat()
                        stopTelemetry()
                    }
                }
            }
        } catch (error: Exception) {
            runOnUiThread {
                heartbeatStatus.value =
                    "Heartbeat: connection error • " +
                            (error.message ?: error.javaClass.simpleName)
            }
        }
    }

    // ------------------------------------------------------------
    // NETWORK INFORMATION
    // ------------------------------------------------------------

    private fun getNetworkInformation(): JSONObject {
        val result = JSONObject()

        val manager = getSystemService(
            Context.CONNECTIVITY_SERVICE
        ) as ConnectivityManager

        val network = manager.activeNetwork
        val capabilities = network?.let {
            manager.getNetworkCapabilities(it)
        }

        val connected = capabilities != null &&
                (
                        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
                        )

        val protocol = when {
            capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true ->
                "WIFI"
            capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true ->
                "CELLULAR"
            capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true ->
                "ETHERNET"
            else -> "OTHER"
        }

        result.put("connected", connected)
        result.put("source_ip", "unknown")
        result.put("destination_ip", "")
        result.put("protocol", protocol)
        result.put(
            "event_type",
            if (connected) "ANDROID_NETWORK_STATE"
            else "ANDROID_NETWORK_DISCONNECTED"
        )

        return result
    }

    // ------------------------------------------------------------
    // TELEMETRY
    // ------------------------------------------------------------

    private fun startTelemetry(token: String) {
        if (token.isBlank()) return

        stopTelemetry()
        telemetryStatus.value = "Telemetry: starting..."

        telemetryExecutor = Executors.newSingleThreadScheduledExecutor()
        telemetryExecutor?.scheduleWithFixedDelay(
            {
                collectAndSendNetworkTelemetry(token)
            },
            2L,
            TELEMETRY_INTERVAL_SECONDS,
            TimeUnit.SECONDS
        )
    }

    private fun stopTelemetry() {
        telemetryExecutor?.shutdownNow()
        telemetryExecutor = null
    }

    private fun collectAndSendNetworkTelemetry(token: String) {
        try {
            val info = getNetworkInformation()

            val event = JSONObject().apply {
                put("source_ip", info.optString("source_ip", "unknown"))
                put("destination_ip", info.optString("destination_ip", ""))
                put("protocol", info.optString("protocol", "OTHER"))
                put("port", JSONObject.NULL)
                put("event_type", info.optString("event_type", "ANDROID_NETWORK_STATE"))
                put("risk", "low")
                put("timestamp", Instant.now().toString())
            }

            val payload = JSONObject().apply {
                put("events", JSONArray().put(event))
            }

            val request = Request.Builder()
                .url("$BACKEND_URL/api/agents/events")
                .header("Authorization", "Bearer $token")
                .header("Content-Type", "application/json")
                .post(
                    payload.toString().toRequestBody(
                        "application/json; charset=utf-8".toMediaType()
                    )
                )
                .build()

            httpClient.newCall(request).execute().use { response ->
                val body = response.body?.string().orEmpty()

                if (response.isSuccessful) {
                    val saved = try {
                        JSONObject(body).optInt("saved", 1)
                    } catch (_: Exception) {
                        1
                    }

                    runOnUiThread {
                        telemetryStatus.value =
                            "Telemetry: ONLINE • saved $saved event(s)"
                    }
                } else {
                    val detail = try {
                        JSONObject(body).optString("detail", body.take(100))
                    } catch (_: Exception) {
                        body.take(100)
                    }

                    runOnUiThread {
                        telemetryStatus.value =
                            "Telemetry: HTTP ${response.code} • $detail"
                    }

                    if (response.code == 401 || response.code == 403) {
                        stopHeartbeat()
                        stopTelemetry()
                    }
                }
            }
        } catch (error: Exception) {
            runOnUiThread {
                telemetryStatus.value =
                    "Telemetry: ERROR • " +
                            (error.message ?: error.javaClass.simpleName)
            }
        }
    }

    // ------------------------------------------------------------
    // USER INTERFACE
    // ------------------------------------------------------------

    @Composable
    private fun ZeroGuardApp() {
        var pairingCode by remember { mutableStateOf("") }
        var status by remember { mutableStateOf("Not connected") }
        var connecting by remember { mutableStateOf(false) }

        Surface(
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.background
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Text(
                    text = "ZeroGuard",
                    style = MaterialTheme.typography.headlineLarge,
                    fontWeight = FontWeight.Bold
                )

                Spacer(Modifier.height(8.dp))

                Text(
                    text = "Android Security Agent",
                    style = MaterialTheme.typography.titleMedium
                )

                Spacer(Modifier.height(24.dp))

                Text(
                    text = "Connect this phone to your ZeroGuard SOC.",
                    style = MaterialTheme.typography.bodyLarge
                )

                Spacer(Modifier.height(24.dp))

                OutlinedTextField(
                    value = pairingCode,
                    onValueChange = { pairingCode = it.uppercase() },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Pairing Code") },
                    placeholder = { Text("Enter pairing code") },
                    singleLine = true
                )

                Spacer(Modifier.height(20.dp))

                Button(
                    enabled = !connecting && pairingCode.isNotBlank(),
                    onClick = {
                        connecting = true
                        status = "Connecting to ZeroGuard..."

                        pairDevice(pairingCode) { _, message ->
                            connecting = false
                            status = message
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(if (connecting) "CONNECTING..." else "CONNECT")
                }

                Spacer(Modifier.height(24.dp))

                Text(
                    text = "Status: $status",
                    style = MaterialTheme.typography.bodyMedium
                )

                Spacer(Modifier.height(12.dp))

                Text(
                    text = heartbeatStatus.value,
                    style = MaterialTheme.typography.bodyMedium
                )

                Spacer(Modifier.height(8.dp))

                Text(
                    text = telemetryStatus.value,
                    style = MaterialTheme.typography.bodyMedium
                )

                Spacer(Modifier.height(16.dp))

                Text(
                    text = "Android ID: ${getAndroidId()}",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}
