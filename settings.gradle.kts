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

rootProject.name = "Engine3.0"

// 公开审计版范围（仅 E2EE 协议栈，纯 JVM，无需 Android SDK）：
// - core/core-crypto   : 加密原语（AES-GCM / ECDSA / ECDH / 指纹 / 密封认证 / 备份容器格式）
// - core/core-protocol : 消息信封线协议与序列化
// - core/core-ipc      : Engine↔Vault 签名回调契约
//
// 产品实现（Android 客户端 / 密钥库 App / 中继服务）不包含在本仓库中。
include(":core:core-protocol")
include(":core:core-crypto")
include(":core:core-ipc")
