import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

val zeroGuardLocalProperties = Properties().apply {
    val configFile = rootProject.file("local.properties")
    if (configFile.exists()) {
        configFile.inputStream().use { load(it) }
    }
}

val zeroGuardBackendUrl = zeroGuardLocalProperties.getProperty(
    "ZEROGUARD_BACKEND_URL",
    "http://10.0.2.2:8000"
)

val zeroGuardEscapedBackendUrl = zeroGuardBackendUrl
    .replace("\\", "\\\\")
    .replace("\"", "\\\"")

android {
    namespace = "com.zeroguard.app"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.zeroguard.app"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"

        buildConfigField(
            "String",
            "ZEROGUARD_BACKEND_URL",
            "\"$zeroGuardEscapedBackendUrl\""
        )

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            optimization {
                enable = false
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}