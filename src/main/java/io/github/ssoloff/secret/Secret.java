/*
 * Copyright (c) 2016 Steven Soloff
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package io.github.ssoloff.secret;

import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.jdt.annotation.Nullable;

/**
 * A container for a value that must be kept secret and only disclosed for as
 * short of a time as possible.
 *
 * <p>
 * This class is not thread safe.
 * </p>
 */
public final class Secret implements AutoCloseable {
    private static final String DEFAULT_CIPHER_ALGORITHM = "AES";
    private static final int DEFAULT_CIPHER_KEY_SIZE_IN_BITS = 128;

    private final Cipher cipher;
    private final byte[] ciphertext;
    private final SecretKey key;

    private Secret(
            final Cipher cipher,
            final SecretKey key,
            final byte[] ciphertext) {
        this.cipher = cipher;
        this.ciphertext = ciphertext;
        this.key = key;
    }

    private static byte[] cipher(
            final Cipher cipher,
            final int opmode,
            final SecretKey key,
            final byte[] input) throws SecretException {
        try {
            cipher.init(opmode, key);
            return cipher.doFinal(input);
        } catch (final GeneralSecurityException e) {
            throw new SecretException("failed to apply cipher", e);
        }
    }

    @Override
    public void close() throws Exception {
        scrub(ciphertext);
        scrub(key);
    }

    private static byte[] decrypt(
            final Cipher cipher,
            final SecretKey key,
            final byte[] ciphertext) throws SecretException {
        return cipher(cipher, Cipher.DECRYPT_MODE, key, ciphertext);
    }

    private static byte[] encrypt(
            final Cipher cipher,
            final SecretKey key,
            final byte[] plaintext) throws SecretException {
        return cipher(cipher, Cipher.ENCRYPT_MODE, key, plaintext);
    }

    @Override
    public boolean equals(final @Nullable Object obj) {
        if (obj == this) {
            return true;
        } else if (!(obj instanceof Secret)) {
            return false;
        }

        final Secret other = (Secret) obj;
        final AtomicBoolean equals = new AtomicBoolean(false);
        try {
            use(plaintext -> {
                try {
                    other.use(otherPlaintext -> equals.set(Arrays.equals(plaintext, otherPlaintext)));
                } catch (final SecretException e) {
                    throw new RuntimeException(e);
                }
            });
        } catch (final SecretException e) {
            throw new RuntimeException(e);
        }
        return equals.get();
    }

    /**
     * Creates a new instance of the {@code Secret} class from the specified
     * plaintext value using the AES cipher and a 128-bit key to generate the
     * ciphertext.
     *
     * <p>
     * The plaintext value is not modified by this method and should be scrubbed
     * by the caller as soon as possible if it is no longer needed.
     * </p>
     *
     * @param plaintext
     *            The plaintext value to be kept secret.
     *
     * @return A new instance of the {@code Secret} class.
     *
     * @throws SecretException
     *             If an error occurs creating the secret.
     */
    public static Secret fromPlaintext(final byte[] plaintext) throws SecretException {
        final Cipher cipher = getDefaultCipher();
        final SecretKey key = generateSecretKeyForDefaultCipher();
        return fromPlaintext(plaintext, cipher, key);
    }

    /**
     * Creates a new instance of the {@code Secret} class from the specified
     * plaintext value using the specified cipher and key to generate the
     * ciphertext.
     *
     * <p>
     * The plaintext value is not modified by this method and should be scrubbed
     * by the caller as soon as possible if it is no longer needed.
     * </p>
     *
     * <p>
     * This method takes ownership of the specified key and will ensure it is
     * destroyed when the secret is closed.
     * </p>
     *
     * @param plaintext
     *            The plaintext value to be kept secret.
     *
     * @return A new instance of the {@code Secret} class.
     *
     * @throws SecretException
     *             If an error occurs creating the secret.
     */
    public static Secret fromPlaintext(
            final byte[] plaintext,
            final Cipher cipher,
            final SecretKey key) throws SecretException {
        final byte[] ciphertext = encrypt(cipher, key, plaintext);
        return new Secret(cipher, key, ciphertext);
    }

    private static SecretKey generateSecretKeyForDefaultCipher() throws SecretException {
        try {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(DEFAULT_CIPHER_ALGORITHM);
            keyGenerator.init(DEFAULT_CIPHER_KEY_SIZE_IN_BITS);
            return keyGenerator.generateKey();
        } catch (final GeneralSecurityException e) {
            throw new SecretException("failed to generate secret key", e);
        }
    }

    private static Cipher getDefaultCipher() throws SecretException {
        try {
            return Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
        } catch (final GeneralSecurityException e) {
            throw new SecretException("", e);
        }
    }

    @Override
    public int hashCode() {
        final AtomicInteger hashCode = new AtomicInteger();
        try {
            use(plaintext -> hashCode.set(Arrays.hashCode(plaintext)));
        } catch (final SecretException e) {
            throw new RuntimeException(e);
        }
        return hashCode.get();
    }

    // workaround for <https://bugs.openjdk.java.net/browse/JDK-8008795>
    private static boolean isDestroyable(final Destroyable destroyable) {
        try {
            final Method destroyMethod = destroyable.getClass().getMethod("destroy");
            return !destroyMethod.isDefault();
        } catch (final NoSuchMethodException e) {
            throw new AssertionError("should never happen", e);
        }
    }

    private static void scrub(final byte[] bytes) {
        Arrays.fill(bytes, (byte) 0);
    }

    private static void scrub(final SecretKey key) throws DestroyFailedException {
        if (!key.isDestroyed() && isDestroyable(key)) {
            key.destroy();
        }
    }

    /**
     * Allows the specified consumer to perform an operation on the plaintext
     * secret value.
     *
     * @param consumer
     *            The consumer to receive the plaintext secret value.
     *
     * @throws SecretException
     *             If an error occurs decrypting the secret or the secret has
     *             been closed.
     */
    public void use(final Consumer<byte[]> consumer) throws SecretException {
        final byte[] plaintext = decrypt(cipher, key, ciphertext);
        try {
            consumer.accept(plaintext);
        } finally {
            scrub(plaintext);
        }
    }
}
