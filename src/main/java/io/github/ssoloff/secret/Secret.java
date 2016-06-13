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
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.jdt.annotation.Nullable;

import io.github.ssoloff.secret.util.function.ThrowingConsumer;
import io.github.ssoloff.secret.util.function.ThrowingFunction;

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

    private static final Logger logger = Logger.getLogger(Secret.class.getName());

    private final Cipher cipher;
    private final byte[] ciphertext;
    private transient volatile boolean closed = false;
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
            final byte[] input) throws GeneralSecurityException {
        cipher.init(opmode, key);
        return cipher.doFinal(input);
    }

    @Override
    public void close() throws SecretException {
        try {
            scrub(ciphertext);
            scrub(key);
        } finally {
            closed = true;
        }
    }

    private static ThrowingFunction<byte[], @Nullable Void, RuntimeException> convertConsumerToThrowingFunction(
            final Consumer<byte[]> consumer) {
        return t -> {
            consumer.accept(t);
            return null;
        };
    }

    private static <R> ThrowingFunction<byte[], R, RuntimeException> convertFunctionToThrowingFunction(
            final Function<byte[], R> function) {
        return t -> function.apply(t);
    }

    private static <E extends Throwable> ThrowingFunction<byte[], @Nullable Void, E> convertThrowingConsumerToThrowingFunction(
            final ThrowingConsumer<byte[], E> consumer) {
        return t -> {
            consumer.accept(t);
            return null;
        };
    }

    private static Cipher createDefaultCipher() throws SecretException {
        try {
            return Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
        } catch (final GeneralSecurityException e) {
            throw new SecretException("failed to create default cipher", e);
        }
    }

    private static KeyGenerator createKeyGeneratorForDefaultCipher() throws SecretException {
        try {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(DEFAULT_CIPHER_ALGORITHM);
            keyGenerator.init(DEFAULT_CIPHER_KEY_SIZE_IN_BITS);
            return keyGenerator;
        } catch (final GeneralSecurityException e) {
            throw new SecretException("failed to create key generator for default cipher", e);
        }
    }

    private byte[] decrypt() {
        try {
            return cipher(cipher, Cipher.DECRYPT_MODE, key, ciphertext);
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("failed to decrypt ciphertext", e);
        }
    }

    private static byte[] encrypt(
            final Cipher cipher,
            final SecretKey key,
            final byte[] plaintext) throws SecretException {
        try {
            return cipher(cipher, Cipher.ENCRYPT_MODE, key, plaintext);
        } catch (final GeneralSecurityException e) {
            throw new SecretException("failed to encrypt plaintext", e);
        }
    }

    @Override
    public boolean equals(
            final @Nullable Object obj) {
        if (obj == this) {
            return true;
        } else if (!(obj instanceof Secret)) {
            return false;
        }

        final Secret other = (Secret) obj;
        return useAndReturn(
                plaintext -> other.useAndReturn(
                        otherPlaintext -> Arrays.equals(plaintext, otherPlaintext)));
    }

    @Override
    protected void finalize() {
        if (!closed) {
            logger.warning(String.format("%s not explicitly closed", this));
        }
    }

    /**
     * Creates a new instance of the {@code Secret} class from the specified
     * plaintext value using the AES cipher and a 128-bit key to generate the
     * ciphertext.
     *
     * <p>
     * The plaintext value is scrubbed by this method before returning. If the
     * plaintext must not be modified, call {@link #fromSharedPlaintext(byte[])}
     * instead.
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
            final byte[] plaintext) throws SecretException {
        return fromPlaintext(createDefaultCipher(), createKeyGeneratorForDefaultCipher(), plaintext);
    }

    /**
     * Creates a new instance of the {@code Secret} class from the specified
     * plaintext value using the specified cipher and key generator to generate
     * the ciphertext.
     *
     * <p>
     * The plaintext value is scrubbed by this method before returning. If the
     * plaintext must not be modified, call
     * {@link #fromSharedPlaintext(Cipher, KeyGenerator, byte[])} instead.
     * </p>
     *
     * @param cipher
     *            The cipher used to encrypt the plaintext.
     * @param keyGenerator
     *            The object used to generate the key used for encryption and
     *            decryption.
     * @param plaintext
     *            The plaintext value to be kept secret.
     *
     * @return A new instance of the {@code Secret} class.
     *
     * @throws SecretException
     *             If an error occurs creating the secret.
     */
    public static Secret fromPlaintext(
            final Cipher cipher,
            final KeyGenerator keyGenerator,
            final byte[] plaintext) throws SecretException {
        final SecretKey key = keyGenerator.generateKey();
        final byte[] ciphertext = encrypt(cipher, key, plaintext);
        final Secret secret = new Secret(cipher, key, ciphertext);
        scrub(plaintext);
        return secret;
    }

    /**
     * Creates a new instance of the {@code Secret} class from the specified
     * shared plaintext value using the AES cipher and a 128-bit key to generate
     * the ciphertext.
     *
     * <p>
     * The shared plaintext value is not modified by this method and should be
     * scrubbed by the caller as soon as possible if it is no longer needed.
     * </p>
     *
     * @param plaintext
     *            The shared plaintext value to be kept secret.
     *
     * @return A new instance of the {@code Secret} class.
     *
     * @throws SecretException
     *             If an error occurs creating the secret.
     */
    public static Secret fromSharedPlaintext(
            final byte[] plaintext) throws SecretException {
        return fromSharedPlaintext(createDefaultCipher(), createKeyGeneratorForDefaultCipher(), plaintext);
    }

    /**
     * Creates a new instance of the {@code Secret} class from the specified
     * shared plaintext value using the specified cipher and key generator to
     * generate the ciphertext.
     *
     * <p>
     * The shared plaintext value is not modified by this method and should be
     * scrubbed by the caller as soon as possible if it is no longer needed.
     * </p>
     *
     * @param cipher
     *            The cipher used to encrypt the plaintext.
     * @param keyGenerator
     *            The object used to generate the key used for encryption and
     *            decryption.
     * @param plaintext
     *            The shared plaintext value to be kept secret.
     *
     * @return A new instance of the {@code Secret} class.
     *
     * @throws SecretException
     *             If an error occurs creating the secret.
     */
    public static Secret fromSharedPlaintext(
            final Cipher cipher,
            final KeyGenerator keyGenerator,
            final byte[] plaintext) throws SecretException {
        final SecretKey key = keyGenerator.generateKey();
        final byte[] ciphertext = encrypt(cipher, key, plaintext);
        return new Secret(cipher, key, ciphertext);
    }

    @Override
    public int hashCode() {
        return useAndReturn(plaintext -> Arrays.hashCode(plaintext));
    }

    // workaround for <https://bugs.openjdk.java.net/browse/JDK-8008795>
    private static boolean isDestroyable(
            final Destroyable destroyable) {
        try {
            final Method destroyMethod = destroyable.getClass().getMethod("destroy");
            return !destroyMethod.isDefault();
        } catch (final NoSuchMethodException e) {
            throw new AssertionError("should never happen", e);
        }
    }

    private static void scrub(
            final byte[] bytes) {
        Arrays.fill(bytes, (byte) 0);
    }

    private static void scrub(
            final SecretKey key) throws SecretException {
        if (!key.isDestroyed() && isDestroyable(key)) {
            try {
                key.destroy();
            } catch (final DestroyFailedException e) {
                throw new SecretException("failed to destroy secret key", e);
            }
        }
    }

    /**
     * Allows the specified consumer to perform an operation on the plaintext
     * secret value.
     *
     * @param consumer
     *            The consumer to receive the plaintext secret value.
     *
     * @throws IllegalStateException
     *             If the secret has been closed.
     */
    public void use(
            final Consumer<byte[]> consumer) {
        useAndReturnOrThrow(convertConsumerToThrowingFunction(consumer));
    }

    /**
     * Allows the specified function to perform an operation on the plaintext
     * secret value and return the result of the operation.
     *
     * @param function
     *            The function to receive the plaintext secret value.
     *
     * @return The result of applying the function.
     *
     * @throws IllegalStateException
     *             If the secret has been closed.
     */
    public <R> R useAndReturn(
            final Function<byte[], R> function) {
        return useAndReturnOrThrow(convertFunctionToThrowingFunction(function));
    }

    /**
     * Allows the specified function to perform an operation on the plaintext
     * secret value and return the result of the operation or throw an
     * exception.
     *
     * @param function
     *            The function to receive the plaintext secret value.
     *
     * @return The result of applying the function.
     *
     * @throws E
     *             If an error occurs in the function.
     * @throws IllegalStateException
     *             If the secret has been closed.
     */
    public <R, E extends Throwable> R useAndReturnOrThrow(
            final ThrowingFunction<byte[], R, E> function) throws E {
        final byte[] plaintext = decrypt();
        try {
            return function.apply(plaintext);
        } finally {
            scrub(plaintext);
        }
    }

    /**
     * Allows the specified consumer to perform an operation on the plaintext
     * secret value or throw an exception.
     *
     * @param consumer
     *            The consumer to receive the plaintext secret value.
     *
     * @throws E
     *             If an error occurs in the consumer.
     * @throws IllegalStateException
     *             If the secret has been closed.
     */
    public <E extends Throwable> void useOrThrow(
            final ThrowingConsumer<byte[], E> consumer) throws E {
        useAndReturnOrThrow(convertThrowingConsumerToThrowingFunction(consumer));
    }
}
