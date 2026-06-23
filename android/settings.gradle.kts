// Standalone Gradle project for the LedgerBtcCore Android library.
// Builds an .aar containing the Rust JNI libs (.so for each ABI),
// the UniFFI-generated Kotlin glue, and the necessary metadata.

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "trezor-core"
include(":library")
