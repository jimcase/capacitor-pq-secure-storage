# BouncyCastle provides ML-KEM through the JCA and is resolved reflectively by string name
# (KeyPairGenerator/KeyFactory/KeyGenerator/Cipher.getInstance("ML-KEM" / "ChaCha20-Poly1305", bc)),
# so the host app's R8 must not strip or rename the provider or its SPI classes.
-keep class org.bouncycastle.** { *; }
-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }
-dontwarn org.bouncycastle.**
