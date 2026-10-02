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

// 公开审计版范围（E2EE 协议栈 + 钱包记账模型）：
// - core/core-crypto   : 加密原语（AES-GCM / ECDSA / ECDH / 指纹 / 密封认证 / 备份容器格式）— 纯 JVM
// - core/core-protocol : 消息信封线协议与序列化 — 纯 JVM
// - core/core-ipc      : Engine↔Vault 签名回调契约 — Android 库模块，构建需 Android SDK (platform 34)
// - core/core-wallet   : 本地签名账本（交易规范化序列化 / 域分离签名 / append-only 链 / 全链验签）— 纯 JVM
//
// 产品实现（Android 客户端 / 密钥库 App / 中继服务）不包含在本仓库中。
include(":core:core-protocol")
include(":core:core-crypto")
include(":core:core-ipc")
include(":core:core-wallet")
