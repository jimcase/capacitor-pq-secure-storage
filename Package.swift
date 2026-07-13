// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CapacitorPqSecureStorage",
    platforms: [.iOS(.v15)],
    products: [
        .library(
            name: "CapacitorPqSecureStorage",
            targets: ["PqSecureStoragePlugin"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/ionic-team/capacitor-swift-pm.git", from: "7.0.0")
    ],
    targets: [
        .target(
            name: "PqSecureStoragePlugin",
            dependencies: [
                .product(name: "Capacitor", package: "capacitor-swift-pm"),
                .product(name: "Cordova", package: "capacitor-swift-pm")
            ],
            path: "ios/Sources/PqSecureStoragePlugin"
        )
    ]
)
